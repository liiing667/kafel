/*
   Kafel - code generator
   -----------------------------------------

   Copyright 2016 Google LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "codegen.h"

#include <limits.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "common.h"
#include "kafel.h"
#include "range_rules.h"
#include "syscall.h"

#define INVALID_LOCATION INT_MIN
#define MAX_JUMP UINT8_MAX

#ifndef CODEGEN_INITAL_BUFFER_SIZE
#define CODEGEN_INITAL_BUFFER_SIZE 1024
#endif

/*
    If headers are too old, take the define from
    include/uapi/linux/seccomp.h
*/
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

#define CURRENT_LOC (ctxt->buffer.len - 1)
#define LOC_TO_JUMP(loc) (CURRENT_LOC - (loc))

#define ADD_INSTR(inst) (add_instruction(ctxt, ((struct sock_filter)inst)))

#define ADD_JUMP_K(type, k, tloc, floc)                        \
  (((type) == BPF_JGT)                                         \
       ? add_jump_gt(ctxt, (k), (tloc), (floc))                \
       : (((type) == BPF_JGE)                                  \
              ? add_jump_ge(ctxt, (k), (tloc), (floc))         \
              : (((type) == BPF_JSET)                          \
                     ? add_jump_set(ctxt, (k), (tloc), (floc)) \
                     : add_jump(ctxt, (type) | BPF_K, (k), (tloc), (floc)))))

#define ADD_JUMP_X(type, tloc, floc) \
  add_jump(ctxt, (type) | BPF_X, 0, (tloc), (floc))

/*
 * Target architecture constraints.
 *
 * All word-width and endianness decisions taken during expression
 * planning and code generation are derived from this single description
 * of the target, so a given expression is always planned against exactly
 * one consistent view of the architecture.
 */
struct target_constraints {
  bool is_big_endian;
};

/*
 * Unified expression plan.
 *
 * Before any code is emitted for a conditional expression, the whole
 * expression is analyzed once and every load of a syscall argument word
 * it may perform is recorded here.  A distinct (argument, word) pair
 * referenced more than once - across comparisons, word widths or logical
 * branches - is loaded exactly once per expression evaluation and read
 * back from a dedicated BPF scratch memory slot; pairs referenced only
 * once keep a plain inline load.  The plan also accounts for the scratch
 * slots needed to evaluate nested bitwise expressions, so the total BPF
 * memory requirement is known - and validated against BPF_MEMWORDS -
 * before a single instruction is emitted.
 */
struct planned_load {
  int arg;
  int word;
  uint32_t offset; /* load offset resolved for the target architecture */
  size_t refs;     /* how many times the word is referenced */
  int slot;        /* BPF scratch memory slot, -1 for inline loads */
};

#define PLAN_MAX_LOADS (SYSCALL_MAX_ARGS * 2)

struct expr_plan {
  struct planned_load loads[PLAN_MAX_LOADS];
  size_t num_loads;
  size_t num_slots;  /* slots assigned to loads with refs > 1 */
  size_t temp_slots; /* scratch slots needed on top of planned loads */
};

static __u32 ACTION_TO_BPF(int action) {
  switch (action) {
    case ACTION_KILL:
      return SECCOMP_RET_KILL;
    case ACTION_KILL_PROCESS:
      return SECCOMP_RET_KILL_PROCESS;
    case ACTION_ALLOW:
      return SECCOMP_RET_ALLOW;
    case ACTION_LOG:
      return SECCOMP_RET_LOG;
    case ACTION_USER_NOTIF:
      return SECCOMP_RET_USER_NOTIF;
  }
  int masked_action = action & 0xfff0000;
  int value = action & 0xffff;
  switch (masked_action) {
    case ACTION_TRAP:
      return SECCOMP_RET_TRAP | value;
    case ACTION_ERRNO:
      return SECCOMP_RET_ERRNO | value;
    case ACTION_TRACE:
      return SECCOMP_RET_TRACE | value;
  }
  ASSERT(0);  // should not happen
}

struct codegen_ctxt {
  struct kafel_ctxt *kafel_ctxt;
  struct {
    struct sock_filter *data;
    size_t len;
    size_t capacity;
  } buffer;
  struct {
    int basic_actions[ACTION_BASIC_MAX + 1];
    struct {
      int action;
      int location;
    } cache[MAX_JUMP];
    size_t cache_size;
  } locations;
  size_t max_stack_ptr;
  struct target_constraints target;
  const struct expr_plan *plan;
  bool failed;
};

static struct codegen_ctxt *context_create(void) {
  struct codegen_ctxt *ctxt = calloc(1, sizeof(*ctxt));
  ctxt->buffer.capacity = CODEGEN_INITAL_BUFFER_SIZE;
  ctxt->buffer.data = calloc(ctxt->buffer.capacity, sizeof(*ctxt->buffer.data));
  ctxt->max_stack_ptr = 0;
  for (int i = 0; i <= ACTION_BASIC_MAX; ++i) {
    ctxt->locations.basic_actions[i] = INVALID_LOCATION;
  }
  return ctxt;
}

static void context_destroy(struct codegen_ctxt **ctxt) {
  ASSERT(ctxt != NULL);
  ASSERT((*ctxt) != NULL);

  free((*ctxt)->buffer.data);
  free(*ctxt);
  *ctxt = NULL;
}

static int add_instruction(struct codegen_ctxt *ctxt, struct sock_filter inst) {
  ASSERT(ctxt != NULL);

  if (ctxt->buffer.capacity <= ctxt->buffer.len) {
    ASSERT(ctxt->buffer.capacity <= SIZE_MAX / 2);  // overflow
    size_t newcapacity = ctxt->buffer.capacity * 2;
    if (newcapacity == 0) {
      newcapacity = 1;
    }
    ASSERT(newcapacity <= SIZE_MAX / sizeof(*ctxt->buffer.data));  // overflow
    size_t newbytes = newcapacity * sizeof(*ctxt->buffer.data);
    ctxt->buffer.data = realloc(ctxt->buffer.data, newbytes);
    ctxt->buffer.capacity = newcapacity;
  }
  ctxt->buffer.data[ctxt->buffer.len++] = inst;
  return CURRENT_LOC;
}

static void purge_location_cache(struct codegen_ctxt *ctxt) {
  ASSERT(ctxt != NULL);

  size_t j = 0;
  for (size_t i = 0; i < ctxt->locations.cache_size; ++i) {
    if (LOC_TO_JUMP(ctxt->locations.cache[i].location) < MAX_JUMP) {
      if (j != i) {
        ctxt->locations.cache[j] = ctxt->locations.cache[i];
      }
      ++j;
    }
  }
  ctxt->locations.cache_size = j;
}

static int resolve_action(struct codegen_ctxt *ctxt, int action) {
  ASSERT(ctxt != NULL);

  struct sock_filter action_inst =
      BPF_STMT(BPF_RET | BPF_K, ACTION_TO_BPF(action));

  if (action <= ACTION_BASIC_MAX) {
    if (ctxt->locations.basic_actions[action] == INVALID_LOCATION ||
        LOC_TO_JUMP(ctxt->locations.basic_actions[action]) > MAX_JUMP) {
      ctxt->locations.basic_actions[action] =
          add_instruction(ctxt, action_inst);
    }
    return ctxt->locations.basic_actions[action];
  }

  // search cache
  for (size_t i = 0; i < ctxt->locations.cache_size; ++i) {
    if (ctxt->locations.cache[i].action == action) {
      if (LOC_TO_JUMP(ctxt->locations.cache[i].location) > MAX_JUMP) {
        ctxt->locations.cache[i].location = add_instruction(ctxt, action_inst);
      }
      return ctxt->locations.cache[i].location;
    }
  }

  purge_location_cache(ctxt);
  ASSERT(ctxt->locations.cache_size <
         (sizeof(ctxt->locations.cache) / sizeof(ctxt->locations.cache[0])));

  int location = add_instruction(ctxt, action_inst);
  ctxt->locations.cache[ctxt->locations.cache_size].action = action;
  ctxt->locations.cache[ctxt->locations.cache_size].location = location;
  ++ctxt->locations.cache_size;
  return location;
}

static int resolve_location(struct codegen_ctxt *ctxt, int loc) {
  ASSERT(ctxt != NULL);

  if (loc < 0) {
    return resolve_action(ctxt, -loc);
  }

  int pos = LOC_TO_JUMP(loc);

  if (pos > MAX_JUMP) {
    loc = ADD_INSTR(BPF_STMT(BPF_JMP | BPF_JA, pos));
    pos = LOC_TO_JUMP(loc);
  }

  ASSERT(pos >= 0);
  ASSERT(pos <= MAX_JUMP);

  return loc;
}

static int add_jump(struct codegen_ctxt *ctxt, __u16 type, __u32 k, int tloc,
                    int floc) {
  ASSERT(ctxt != NULL);

  if (tloc == floc) {
    return tloc;
  }

  int tpos = resolve_location(ctxt, tloc);
  int fpos = resolve_location(ctxt, floc);
  // do tloc one more time as instruction added by floc may make it unreachable
  tpos = resolve_location(ctxt, tpos);
  return ADD_INSTR(
      BPF_JUMP(BPF_JMP | type, k, LOC_TO_JUMP(tpos), LOC_TO_JUMP(fpos)));
}

static int add_jump_ge(struct codegen_ctxt *ctxt, __u32 than, int tloc,
                       int floc) {
  ASSERT(ctxt != NULL);

  if (than == 0) {
    return tloc;
  }

  return add_jump(ctxt, BPF_K | BPF_JGE, than, tloc, floc);
}

static int add_jump_gt(struct codegen_ctxt *ctxt, __u32 than, int tloc,
                       int floc) {
  ASSERT(ctxt != NULL);

  if (than == UINT32_MAX) {
    return floc;
  }

  return add_jump(ctxt, BPF_K | BPF_JGT, than, tloc, floc);
}

static int add_jump_set(struct codegen_ctxt *ctxt, __u32 what, int tloc,
                        int floc) {
  ASSERT(ctxt != NULL);

  if (what == 0) {
    return floc;
  }

  return add_jump(ctxt, BPF_K | BPF_JSET, what, tloc, floc);
}

#define HIGH_WORD 0
#define LOW_WORD 1

/*
 * On little-endian, the low 32 bits of a 64-bit arg are at the base offset
 * and the high 32 bits are at base + 4.  On big-endian the order is reversed.
 */
static uint32_t arg_word_offset(const struct target_constraints *target,
                                int arg, int word) {
  ASSERT(target != NULL);
  ASSERT(arg >= 0 && arg < SYSCALL_MAX_ARGS);
  ASSERT(word == HIGH_WORD || word == LOW_WORD);

  uint32_t offset = offsetof(struct seccomp_data, args[(arg)]);
  /* The high word comes first in memory exactly on big-endian targets. */
  if ((word == HIGH_WORD) != target->is_big_endian) {
    offset += sizeof(uint32_t);
  }
  return offset;
}

#define NUM_LOW(num) ((num)&UINT32_MAX)
#define NUM_HIGH(num) (((num) >> 32) & UINT32_MAX)

#define NUM_WORD(num, word) ((word == HIGH_WORD) ? NUM_HIGH(num) : NUM_LOW(num))
#define BPF_LOAD_ARCH \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch))
#define BPF_LOAD_SYSCALL \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr))

static bool is_const_value(struct expr_tree *expr, int word) {
  return word == HIGH_WORD ? expr->high.is_const : expr->low.is_const;
}

static uint32_t value_of(struct expr_tree *expr, int word) {
  return word == HIGH_WORD ? expr->high.value : expr->low.value;
}

static uint32_t evaluate_expression(int type, uint32_t left, uint32_t right) {
  switch (type) {
    case EXPR_BIT_OR:
      return left | right;
    case EXPR_BIT_AND:
      return left & right;
    default:
      ASSERT(0);  // should not happen
  }
}

static void cache_constants_by_word(struct expr_tree *expr, int word) {
  ASSERT(expr != NULL);

  struct cached_value *cached = (word == HIGH_WORD) ? &expr->high : &expr->low;
  cached->is_const = false;

  switch (expr->type) {
    case EXPR_NOT:
      cache_constants_by_word(expr->child, word);
      return;
    case EXPR_NUMBER:
      cached->is_const = true;
      cached->value = NUM_WORD(expr->number, word);
      return;
    case EXPR_VAR:
      return;
  }

  ASSERT(expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX);

  cache_constants_by_word(expr->right, word);
  cache_constants_by_word(expr->left, word);

  if (expr->type != EXPR_BIT_OR && expr->type != EXPR_BIT_AND) {
    return;
  }

  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;

  if (is_const_value(left, word)) {
    if (is_const_value(right, word)) {
      cached->is_const = true;
      cached->value = evaluate_expression(expr->type, value_of(left, word),
                                          value_of(right, word));
      return;
    }
    SWAP(left, right);
  }
  // Only right may be a const value at this point
  ASSERT(!is_const_value(left, word));

  if (!is_const_value(right, word)) {
    return;
  }

  uint32_t val = value_of(right, word);
  uint32_t clobber = 0;

  switch (expr->type) {
    case EXPR_BIT_OR:
      clobber = UINT32_MAX;
      /* fall-through */
    case EXPR_BIT_AND:
      if (val == clobber) {
        cached->is_const = true;
        cached->value = clobber;
      }
      break;
  }
}

static void cache_constants(struct expr_tree *expr) {
  ASSERT(expr != NULL);

  cache_constants_by_word(expr, HIGH_WORD);
  cache_constants_by_word(expr, LOW_WORD);
}

// Returns 1 if we need to push the result of executing the right sub-tree onto
// the stack (as opposed to the index register) before evaluating the left
// sub-tree.
static bool should_use_stack(struct expr_tree *left) {
  return left->type != EXPR_VAR;
}

static bool is_64bit(struct expr_tree *expr);

static int plan_find_load(const struct expr_plan *plan, int arg, int word) {
  ASSERT(plan != NULL);

  for (size_t i = 0; i < plan->num_loads; ++i) {
    if (plan->loads[i].arg == arg && plan->loads[i].word == word) {
      return plan->loads[i].slot;
    }
  }
  return -1;
}

static struct planned_load *plan_lookup_load(struct expr_plan *plan, int arg,
                                             int word) {
  ASSERT(plan != NULL);

  for (size_t i = 0; i < plan->num_loads; ++i) {
    if (plan->loads[i].arg == arg && plan->loads[i].word == word) {
      return &plan->loads[i];
    }
  }
  return NULL;
}

static void plan_add_load(struct codegen_ctxt *ctxt, struct expr_plan *plan,
                          int arg, int word) {
  ASSERT(ctxt != NULL);
  ASSERT(plan != NULL);

  struct planned_load *existing = plan_lookup_load(plan, arg, word);
  if (existing != NULL) {
    ++existing->refs;
    return;
  }
  ASSERT(plan->num_loads < PLAN_MAX_LOADS);
  struct planned_load *load = &plan->loads[plan->num_loads];
  load->arg = arg;
  load->word = word;
  load->offset = arg_word_offset(&ctxt->target, arg, word);
  load->refs = 1;
  load->slot = -1;
  ++plan->num_loads;
}

/*
 * Records every argument word load that code generation may perform for
 * a value expression (variables, constants and bitwise operators).
 * Mirrors the reach of generate_load: words for which the subexpression
 * is a compile-time constant are never loaded and hence not planned.
 */
static void plan_value_loads(struct codegen_ctxt *ctxt,
                             struct expr_plan *plan, struct expr_tree *expr,
                             int word) {
  ASSERT(ctxt != NULL);
  ASSERT(plan != NULL);
  ASSERT(expr != NULL);

  if (is_const_value(expr, word)) {
    return;
  }
  if (expr->type == EXPR_VAR) {
    plan_add_load(ctxt, plan, expr->var, word);
    return;
  }
  ASSERT(expr->type == EXPR_BIT_AND || expr->type == EXPR_BIT_OR);
  plan_value_loads(ctxt, plan, expr->left, word);
  plan_value_loads(ctxt, plan, expr->right, word);
}

static void plan_comparison_loads(struct codegen_ctxt *ctxt,
                                  struct expr_plan *plan,
                                  struct expr_tree *expr) {
  ASSERT(ctxt != NULL);
  ASSERT(plan != NULL);
  ASSERT(expr != NULL);

  plan_value_loads(ctxt, plan, expr->left, LOW_WORD);
  plan_value_loads(ctxt, plan, expr->right, LOW_WORD);
  if (is_64bit(expr)) {
    plan_value_loads(ctxt, plan, expr->left, HIGH_WORD);
    plan_value_loads(ctxt, plan, expr->right, HIGH_WORD);
  }
}

static void plan_collect_loads(struct codegen_ctxt *ctxt,
                               struct expr_plan *plan,
                               struct expr_tree *expr) {
  ASSERT(ctxt != NULL);
  ASSERT(plan != NULL);
  ASSERT(expr != NULL);

  switch (expr->type) {
    case EXPR_AND:
    case EXPR_OR:
      plan_collect_loads(ctxt, plan, expr->left);
      plan_collect_loads(ctxt, plan, expr->right);
      return;
    case EXPR_NOT:
      plan_collect_loads(ctxt, plan, expr->child);
      return;
    default:
      ASSERT(expr->type >= EXPR_GT && expr->type <= EXPR_NEQ);
      plan_comparison_loads(ctxt, plan, expr);
      return;
  }
}

/*
 * Number of BPF scratch slots needed to evaluate a value expression,
 * mirroring the stack discipline of generate_load.
 */
static size_t value_temp_slots(struct expr_tree *expr, int word) {
  ASSERT(expr != NULL);

  if (expr->type == EXPR_VAR || is_const_value(expr, word)) {
    return 0;
  }
  ASSERT(expr->type == EXPR_BIT_AND || expr->type == EXPR_BIT_OR);

  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;
  if (is_const_value(left, word)) {
    SWAP(left, right);
  }
  if (is_const_value(right, word)) {
    return value_temp_slots(left, word);
  }
  if (!should_use_stack(left)) {
    return value_temp_slots(right, word);
  }
  size_t left_slots = value_temp_slots(left, word) + 1;
  size_t right_slots = value_temp_slots(right, word);
  return left_slots > right_slots ? left_slots : right_slots;
}

/*
 * Number of BPF scratch slots needed to evaluate one word of a
 * comparison, mirroring the operand normalization and the JSET
 * transform of generate_cmp32 so that no evaluation path can use more
 * memory than planned.
 */
static size_t comparison_temp_slots(__u32 type, struct expr_tree *expr,
                                    int word) {
  ASSERT(expr != NULL);

  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;

  if (is_const_value(left, word) && is_const_value(right, word)) {
    return 0;
  }
  if (is_const_value(left, word)) {
    SWAP(left, right);
  }

  if ((type == BPF_JEQ || type == BPF_JGT) && left->type == EXPR_BIT_AND &&
      is_const_value(right, word) && value_of(right, word) == 0) {
    right = left->right;
    left = left->left;
    if (is_const_value(left, word)) {
      SWAP(left, right);
    }
  }

  if (is_const_value(right, word)) {
    return value_temp_slots(left, word);
  }
  size_t left_slots = value_temp_slots(left, word) + 1;
  size_t right_slots = value_temp_slots(right, word);
  return left_slots > right_slots ? left_slots : right_slots;
}

static size_t expr_temp_slots(struct expr_tree *expr) {
  ASSERT(expr != NULL);

  switch (expr->type) {
    case EXPR_AND:
    case EXPR_OR: {
      size_t left_slots = expr_temp_slots(expr->left);
      size_t right_slots = expr_temp_slots(expr->right);
      return left_slots > right_slots ? left_slots : right_slots;
    }
    case EXPR_NOT:
      return expr_temp_slots(expr->child);
    default: {
      ASSERT(expr->type >= EXPR_GT && expr->type <= EXPR_NEQ);
      __u32 type = (expr->type == EXPR_EQ || expr->type == EXPR_NEQ)
                       ? BPF_JEQ
                       : ((expr->type == EXPR_GT || expr->type == EXPR_LE)
                              ? BPF_JGT
                              : BPF_JGE);
      size_t slots = comparison_temp_slots(type, expr, LOW_WORD);
      if (is_64bit(expr)) {
        size_t high_slots = comparison_temp_slots(type, expr, HIGH_WORD);
        if (high_slots > slots) {
          slots = high_slots;
        }
      }
      return slots;
    }
  }
}

/*
 * Builds the unified plan for a conditional expression: folds constants,
 * deduplicates all argument word loads across word widths, endianness
 * and logical branches, and proves that the BPF scratch memory required
 * at generation time fits in BPF_MEMWORDS before any code is emitted.
 */
static bool plan_expression(struct codegen_ctxt *ctxt, struct expr_tree *expr,
                            struct expr_plan *plan) {
  ASSERT(ctxt != NULL);
  ASSERT(expr != NULL);
  ASSERT(plan != NULL);

  memset(plan, 0, sizeof(*plan));
  cache_constants(expr);
  plan_collect_loads(ctxt, plan, expr);
  /* Only words referenced more than once are worth a scratch slot. */
  for (size_t i = 0; i < plan->num_loads; ++i) {
    if (plan->loads[i].refs > 1) {
      plan->loads[i].slot = (int)plan->num_slots++;
    }
  }
  plan->temp_slots = expr_temp_slots(expr);
  if (plan->num_slots + plan->temp_slots > BPF_MEMWORDS) {
    append_error(ctxt->kafel_ctxt,
                 "Required stack size exceeds available BPF memory\n");
    return false;
  }
  return true;
}

/*
 * Emits the planned argument word loads for words referenced more than
 * once.  Emitted last so that they execute first (the instruction buffer
 * is reversed before use), each such word is loaded exactly once per
 * expression evaluation.
 */
static int emit_planned_loads(struct codegen_ctxt *ctxt,
                              const struct expr_plan *plan, int next) {
  ASSERT(ctxt != NULL);
  ASSERT(plan != NULL);

  for (size_t i = plan->num_loads; i-- > 0;) {
    if (plan->loads[i].slot < 0) {
      continue;
    }
    ADD_INSTR(BPF_STMT(BPF_ST, plan->loads[i].slot));
    next = ADD_INSTR(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, plan->loads[i].offset));
  }
  return next;
}

static int generate_load(struct codegen_ctxt *ctxt, struct expr_tree *expr,
                         int word, size_t stack_ptr) {
  ASSERT(ctxt != NULL);
  ASSERT(expr != NULL);

  if (expr->type == EXPR_VAR) {
    ASSERT(ctxt->plan != NULL);
    int slot = plan_find_load(ctxt->plan, expr->var, word);
    if (slot >= 0) {
      return ADD_INSTR(BPF_STMT(BPF_LD | BPF_MEM, slot));
    }
    /* Referenced only once: load it inline. */
    return ADD_INSTR(BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS,
        arg_word_offset(&ctxt->target, expr->var, word)));
  }

  if (is_const_value(expr, word)) {
    ASSERT(0); /* valid but should not happen */
    return ADD_INSTR(BPF_STMT(BPF_LD | BPF_IMM, value_of(expr, word)));
  }

  ASSERT(expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX);

  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;

  if (is_const_value(left, word)) {
    SWAP(left, right);
  }

  // Only right may be a const value at this point
  ASSERT(!is_const_value(left, word));

  int op = BPF_OR;
  uint32_t identity_element = 0;

  switch (expr->type) {
    case EXPR_BIT_AND:
      op = BPF_AND;
      identity_element = UINT32_MAX;
      // fall-through
    case EXPR_BIT_OR:
      if (is_const_value(right, word)) {
        if (value_of(right, word) != identity_element) {
          ADD_INSTR(BPF_STMT(BPF_ALU | op | BPF_K, value_of(right, word)));
        }
        return generate_load(ctxt, left, word, stack_ptr);
      }
      bool use_stack = should_use_stack(left);
      ADD_INSTR(BPF_STMT(BPF_ALU | op | BPF_X, 0));
      if (use_stack) {
        ADD_INSTR(BPF_STMT(BPF_LDX | BPF_MEM, stack_ptr));
        generate_load(ctxt, left, word, stack_ptr + 1);
        if (stack_ptr > ctxt->max_stack_ptr) {
          ctxt->max_stack_ptr = stack_ptr;
        }
        ADD_INSTR(BPF_STMT(BPF_ST, stack_ptr));
      } else {
        generate_load(ctxt, left, word, stack_ptr);
        ADD_INSTR(BPF_STMT(BPF_MISC | BPF_TAX, 0));
      }
      return generate_load(ctxt, right, word, stack_ptr);
    default:
      ASSERT(0);  // should not happen
  }
}

static bool is_64bit(struct expr_tree *expr) {
  if (expr->type >= EXPR_BINARY_MIN && expr->type <= EXPR_BINARY_MAX) {
    return is_64bit(expr->left) || is_64bit(expr->right);
  }

  switch (expr->type) {
    case EXPR_NUMBER:
      return expr->number > UINT32_MAX;
    case EXPR_VAR:
      return expr->size == 8;
    default:
      ASSERT(0);  // should not happen
  }
}

enum {
  NEVER,
  NORMAL,
  ALWAYS,
};

static bool evaluate_jump(__u32 type, uint32_t left, uint32_t right) {
  switch (type) {
    case BPF_JEQ:
      return left == right;
    case BPF_JGE:
      return left >= right;
    case BPF_JGT:
      return left > right;
    case BPF_JSET:
      return left & right;
    default:
      ASSERT(0);  // should not happen
  }
}

static int generate_cmp32(struct codegen_ctxt *ctxt, __u32 type,
                          struct expr_tree *expr, int tloc, int floc, int word,
                          int load) {
  ASSERT(ctxt != NULL);
  ASSERT(expr != NULL);

  int next, begin = CURRENT_LOC;
  struct expr_tree *left = expr->left;
  struct expr_tree *right = expr->right;

  if (is_const_value(left, word)) {
    if (is_const_value(right, word)) {
      return evaluate_jump(type, value_of(left, word), value_of(right, word))
                 ? tloc
                 : floc;
    } else {
      SWAP(left, right);
      if (type == BPF_JGT) {
        type = BPF_JGE;
        SWAP(tloc, floc);
      } else if (type == BPF_JGE) {
        type = BPF_JGT;
        SWAP(tloc, floc);
      }
    }
  }

  // Only right may be a const value at this point

  if ((type == BPF_JEQ || type == BPF_JGT) && left->type == EXPR_BIT_AND &&
      is_const_value(right, word) && value_of(right, word) == 0) {
    right = left->right;
    left = left->left;
    if (is_const_value(left, word)) {
      SWAP(left, right);
    }
    if (type == BPF_JEQ) {
      SWAP(tloc, floc);
    }
    type = BPF_JSET;
  }

  ASSERT(!is_const_value(left, word));

  /* Scratch slots above the ones reserved by the plan for loaded words. */
  const size_t base = ctxt->plan->num_slots;

  if (is_const_value(right, word)) {
    next = ADD_JUMP_K(type, value_of(right, word), tloc, floc);
    if (load == ALWAYS || (load != NEVER && next > begin)) {
      begin = next = generate_load(ctxt, left, word, base);
    }
  } else {
    next = ADD_JUMP_X(type, tloc, floc);
    if (load == ALWAYS || (load != NEVER && next > begin)) {
      bool use_stack = should_use_stack(left);
      if (use_stack) {
        ADD_INSTR(BPF_STMT(BPF_LDX | BPF_MEM, base));
        generate_load(ctxt, left, word, base + 1);
        ADD_INSTR(BPF_STMT(BPF_ST, base));
      } else {
        generate_load(ctxt, left, word, base);
        ADD_INSTR(BPF_STMT(BPF_MISC | BPF_TAX, 0));
      }
      begin = next = generate_load(ctxt, right, word, base);
    }
  }

  return next;
}

static int generate_inequality(struct codegen_ctxt *ctxt, __u32 type,
                               struct expr_tree *expr, int tloc, int floc) {
  int next = generate_cmp32(ctxt, type, expr, tloc, floc, LOW_WORD, NORMAL);
  int begin = CURRENT_LOC;
  if (is_64bit(expr)) {
    next = generate_cmp32(ctxt, BPF_JGE, expr, next, floc, HIGH_WORD, NEVER);
    next = generate_cmp32(ctxt, BPF_JGT, expr, tloc, next, HIGH_WORD,
                          next > begin ? ALWAYS : NORMAL);
  }
  return next;
}

static int generate_equality(struct codegen_ctxt *ctxt, struct expr_tree *expr,
                             int tloc, int floc) {
  // TODO maybe compare low words first as they're more likely to differ
  int next = generate_cmp32(ctxt, BPF_JEQ, expr, tloc, floc, LOW_WORD, NORMAL);
  if (is_64bit(expr)) {
    next = generate_cmp32(ctxt, BPF_JEQ, expr, next, floc, HIGH_WORD, NORMAL);
  }
  return next;
}

static int generate_expr(struct codegen_ctxt *ctxt, struct expr_tree *expr,
                         int tloc, int floc) {
  ASSERT(ctxt != NULL);
  ASSERT(expr != NULL);

  switch (expr->type) {
    case EXPR_AND:
      tloc = generate_expr(ctxt, expr->right, tloc, floc);
      return generate_expr(ctxt, expr->left, tloc, floc);
    case EXPR_OR:
      floc = generate_expr(ctxt, expr->right, tloc, floc);
      return generate_expr(ctxt, expr->left, tloc, floc);
    case EXPR_LE:
      SWAP(tloc, floc);
    // fall-through
    case EXPR_GT:
      return generate_inequality(ctxt, BPF_JGT, expr, tloc, floc);
    case EXPR_LT:
      SWAP(tloc, floc);
    // fall-through
    case EXPR_GE:
      return generate_inequality(ctxt, BPF_JGE, expr, tloc, floc);
    case EXPR_NEQ:
      SWAP(tloc, floc);
    // fall-through
    case EXPR_EQ:
      return generate_equality(ctxt, expr, tloc, floc);
    case EXPR_NOT:
      return generate_expr(ctxt, expr->child, floc, tloc);
    default:
      ASSERT(0);  // should not happen
  }
}

static int generate_action(struct codegen_ctxt *ctxt,
                           struct syscall_range_rule *rule) {
  ASSERT(ctxt != NULL);
  ASSERT(rule != NULL);

  if (rule->action != ACTION_CONDITIONAL) {
    return -rule->action;
  }

  struct expression_to_action *mapping;
  int last_loc = INVALID_LOCATION;
  TAILQ_FOREACH_REVERSE(mapping, &rule->expr_list, expression_to_action_list,
                        list) {
    if (last_loc == INVALID_LOCATION) {
      ASSERT(mapping->expr == NULL || mapping->expr->type == EXPR_TRUE);
      last_loc = -mapping->action;
    } else {
      ASSERT(mapping->expr != NULL);
      /*
       * The parser bounds expression depth at parse time; re-check it
       * here so that generation-time recursion is provably bounded too.
       */
      if (mapping->expr->depth > MAX_EXPRESSION_DEPTH) {
        append_error(ctxt->kafel_ctxt,
                     "Expression depth (%d) exceeds maximum supported depth "
                     "(%d)\n",
                     mapping->expr->depth, MAX_EXPRESSION_DEPTH);
        ctxt->failed = true;
        return 0;
      }
      struct expr_plan plan;
      if (!plan_expression(ctxt, mapping->expr, &plan)) {
        ctxt->failed = true;
        return 0;
      }
      ctxt->plan = &plan;
      last_loc = generate_expr(ctxt, mapping->expr, -mapping->action, last_loc);
      last_loc = emit_planned_loads(ctxt, &plan, last_loc);
      ctxt->plan = NULL;
    }
  }
  ASSERT(last_loc != INVALID_LOCATION);
  return last_loc;
}

static int generate_rules(struct codegen_ctxt *ctxt,
                          struct syscall_range_rules *rules) {
  ASSERT(ctxt != NULL);
  ASSERT(rules != NULL);
  ASSERT(rules->len != 0);

  struct {
    int level;
    int action;
    uint32_t nr;
  } buf[33];
  int num = 0;
  for (size_t i = rules->len; i > 0; --i) {
    struct syscall_range_rule *rule = &rules->data[i - 1];
    int action = generate_action(ctxt, rule);
    if (ctxt->failed) {
      return 0;
    }
    ASSERT(num == 0 || rule->last + 1 == buf[num - 1].nr);
    if (num > 0 && buf[num - 1].action == action) {
      buf[num - 1].nr = rule->first;
      continue;
    }
    while (num >= 2 && buf[num - 2].level == buf[num - 1].level) {
      --num;
      buf[num - 1].action = add_jump(ctxt, BPF_JGE, buf[num - 1].nr,
                                     buf[num - 1].action, buf[num].action);
      buf[num - 1].nr = buf[num].nr;
      ++buf[num - 1].level;
    }
    buf[num].level = 0;
    buf[num].nr = rule->first;
    buf[num].action = action;
    ++num;
  }
  ASSERT(num > 0);
  ASSERT(buf[num - 1].nr == 0);
  while (num >= 2) {
    --num;
    buf[num - 1].action = add_jump(ctxt, BPF_JGE, buf[num - 1].nr,
                                   buf[num - 1].action, buf[num].action);
    buf[num - 1].nr = buf[num].nr;
  }
  return buf[0].action;
}

static void reverse_instruction_buffer(struct codegen_ctxt *ctxt) {
  struct sock_filter *first = ctxt->buffer.data;
  struct sock_filter *last = first + (ctxt->buffer.len - 1);
  while (first < last) {
    SWAP(*first, *last);
    ++first, --last;
  }
}

/*
 * Generation-time safety proof for the final program.
 *
 * Verifies, on the final (execution-order) instruction stream, that
 * every scratch memory access stays within BPF_MEMWORDS, every data
 * load stays inside struct seccomp_data, and every jump lands on a
 * valid instruction.  Combined with the upfront expression plan this
 * guarantees stack and jump safety for anything the generator emits,
 * independently of how the expression was shaped at parse time.
 */
static bool validate_program(struct codegen_ctxt *ctxt,
                             struct kafel_ctxt *kafel_ctxt) {
  ASSERT(ctxt != NULL);
  ASSERT(kafel_ctxt != NULL);

  const struct sock_filter *insns = ctxt->buffer.data;
  const size_t len = ctxt->buffer.len;
  for (size_t pc = 0; pc < len; ++pc) {
    const struct sock_filter *insn = &insns[pc];
    const uint16_t code = insn->code;
    bool valid;
    switch (BPF_CLASS(code)) {
      case BPF_LD:
        switch (BPF_MODE(code)) {
          case BPF_ABS:
            valid = BPF_SIZE(code) == BPF_W &&
                    insn->k % sizeof(uint32_t) == 0 &&
                    (uint64_t)insn->k + sizeof(uint32_t) <=
                        sizeof(struct seccomp_data);
            break;
          case BPF_MEM:
            valid = insn->k < BPF_MEMWORDS;
            break;
          case BPF_IMM:
          case BPF_LEN:
            valid = true;
            break;
          default:
            valid = false;
            break;
        }
        break;
      case BPF_LDX:
        valid = BPF_MODE(code) == BPF_IMM || BPF_MODE(code) == BPF_LEN ||
                (BPF_MODE(code) == BPF_MEM && insn->k < BPF_MEMWORDS);
        break;
      case BPF_ST:
      case BPF_STX:
        valid = insn->k < BPF_MEMWORDS;
        break;
      case BPF_ALU:
        valid = BPF_SRC(code) == BPF_K || BPF_SRC(code) == BPF_X ||
                BPF_OP(code) == BPF_NEG;
        break;
      case BPF_JMP:
        switch (BPF_OP(code)) {
          case BPF_JA:
            valid = (uint64_t)pc + 1 + insn->k < len;
            break;
          case BPF_JEQ:
          case BPF_JGT:
          case BPF_JGE:
          case BPF_JSET:
            valid = (uint64_t)pc + 1 + insn->jt < len &&
                    (uint64_t)pc + 1 + insn->jf < len;
            break;
          default:
            valid = false;
            break;
        }
        break;
      case BPF_RET:
        valid = BPF_SRC(code) == BPF_K || BPF_SRC(code) == BPF_A;
        break;
      case BPF_MISC:
        valid = BPF_MISCOP(code) == BPF_TAX || BPF_MISCOP(code) == BPF_TXA;
        break;
      default:
        valid = false;
        break;
    }
    if (!valid) {
      append_error(kafel_ctxt,
                   "Internal error: generated BPF program failed safety "
                   "validation at instruction %zu (code=0x%02x, k=%u)\n",
                   pc, code, insn->k);
      return false;
    }
  }
  return true;
}

static int compile_policy_for_archs(struct codegen_ctxt *ctxt,
                                   struct kafel_ctxt *kafel_ctxt,
                                   uint32_t target_archs) {
  ASSERT(ctxt != NULL);
  ASSERT(kafel_ctxt != NULL);

  struct syscall_range_rules *rules = range_rules_create();
  while (target_archs) {
    uint32_t target_arch = target_archs & ~(target_archs-1);
    target_archs &= ~(target_arch);
    const struct syscall_list *syscall_list = syscalls_lookup(target_arch);
    ASSERT(syscall_list != NULL);
    mark_all_policies_unused(kafel_ctxt);
    add_policy_rules(rules, kafel_ctxt->main_policy, syscall_list);
  }
  normalize_rules(rules, kafel_ctxt->default_action);
  int begin = CURRENT_LOC;
  int next = generate_rules(ctxt, rules);
  range_rules_destroy(&rules);
  if (ctxt->failed) {
    return 0;
  }
  if (next > begin) {
    begin = next = ADD_INSTR(BPF_LOAD_SYSCALL);
  } else {
    next = -kafel_ctxt->default_action;
  }
  return next;
}

static int compile_policy_impl(struct codegen_ctxt *ctxt,
                               struct kafel_ctxt *kafel_ctxt,
                               struct sock_fprog *prog) {
  ASSERT(ctxt != NULL);
  ASSERT(kafel_ctxt != NULL);
  ASSERT(prog != NULL);

  ctxt->kafel_ctxt = kafel_ctxt;

  if (kafel_ctxt->main_policy == NULL) {
    kafel_ctxt->main_policy = policy_create("@main", NULL);
    register_policy(kafel_ctxt, kafel_ctxt->main_policy);
  }
  if (kafel_ctxt->default_action == 0) {
    kafel_ctxt->default_action = ACTION_KILL;
  }

  struct {
    uint32_t audit_arch;
    uint32_t target_archs;
  } archs[32];
  int archs_len = 0;

  uint32_t target_archs = kafel_ctxt->target_archs;
  if (target_archs == 0) {
    target_archs = KAFEL_DEFAULT_TARGET_ARCH;
  }
  while (target_archs) {
    uint32_t target_arch = target_archs & ~(target_archs-1);
    target_archs &= ~(target_arch);
    const struct syscall_list *syscall_list = syscalls_lookup(target_arch);
    bool found = false;
    for (int i = 0; i < archs_len; ++i) {
      if (archs[i].audit_arch == syscall_list->audit_arch) {
        archs[i].target_archs |= target_arch;
        found = true;
        break;
      }
    }
    if (!found) {
      archs[archs_len].audit_arch = syscall_list->audit_arch;
      archs[archs_len].target_archs = target_arch;
      ++archs_len;
    }
  }

  int begin = CURRENT_LOC;
  int next = -ACTION_KILL;

  for (int i = 0; i < archs_len; ++i) {
    /* __AUDIT_ARCH_LE (0x40000000) is set for little-endian architectures.
     * When absent, the target is big-endian and 64-bit argument word order
     * in seccomp_data must be swapped.
     */
    ctxt->target.is_big_endian = (archs[i].audit_arch & 0x40000000) == 0;
    int policy =
        compile_policy_for_archs(ctxt, kafel_ctxt, archs[i].target_archs);
    if (ctxt->failed) {
      return -1;
    }
    if (policy != -ACTION_KILL) {
      next = add_jump(ctxt, BPF_JEQ, archs[i].audit_arch, policy, next);
    }
  }

  if (next > begin) {
    begin = next = ADD_INSTR(BPF_LOAD_ARCH);
  }
  if (next < 0) {
    resolve_location(ctxt, next);
  }

  if (ctxt->max_stack_ptr >= BPF_MEMWORDS) {
    append_error(kafel_ctxt,
                 "Required stack size exceeds available BPF memory\n");
    return -1;
  }

  if (ctxt->buffer.len > USHRT_MAX) {
    append_error(
        kafel_ctxt,
        "Filter length exceeds maximum seccomp filter length: %zu > %d\n",
        ctxt->buffer.len, USHRT_MAX);
    return -1;
  }
  reverse_instruction_buffer(ctxt);
  if (!validate_program(ctxt, kafel_ctxt)) {
    return -1;
  }
  *prog = ((struct sock_fprog){.filter = ctxt->buffer.data,
                               .len = ctxt->buffer.len});
  ctxt->buffer.data = NULL;
  return 0;
}

int compile_policy(struct kafel_ctxt *kafel_ctxt, struct sock_fprog *prog) {
  struct codegen_ctxt *ctxt = context_create();
  int rv = compile_policy_impl(ctxt, kafel_ctxt, prog);
  context_destroy(&ctxt);
  return rv;
}
