/*
   Kafel - expression depth fixtures
   -----------------------------------------

   Copyright 2026 Google LLC

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

/*
 * Depth fixtures.
 *
 * The parser bounds expression depth at MAX_EXPRESSION_DEPTH; these
 * fixtures pin down the exact boundary and prove that generation-time
 * safety (BPF scratch memory budget, jump offset resolution over spans
 * longer than 255 instructions) holds for expressions at that boundary.
 */

#include <linux/unistd.h>
#include <stdio.h>
#include <string.h>

#include <kafel.h>

#include "runner/harness.h"
#include "runner/runner.h"

#define MAX_EXPR_DEPTH 200

/* Runs a single syscall spec through the interpreter only. */
static int check_spec(syscall_spec_t syscall_spec,
                      syscall_result_spec_t result_spec) {
  syscall_exec_spec_t specs[2] = {SYSCALL_EXEC_SPEC(syscall_spec, result_spec),
                                  SYSCALL_EXEC_SPEC_LAST};
  int previous_mode = test_set_syscalls_mode(KAFEL_TEST_SYSCALLS_INTERPRET);
  int rv = test_policy_enforcment_syscalls(specs);
  test_set_syscalls_mode(previous_mode);
  return rv;
}

#define CHECK_SPEC(...) CHECK_TEST_RET((check_spec(__VA_ARGS__)))

/* Builds a policy of the form
 * "ALLOW { read { fd <op> 0 <conn> fd <op> 1 ... }, exit } DEFAULT KILL"
 * with the given number of comparisons. */
static void build_chain_policy(char* buf, size_t size, int comparisons,
                               const char* op, const char* connector) {
  snprintf(buf, size, "ALLOW { read { fd %s 0", op);
  size_t off = strlen(buf);
  for (int i = 1; i < comparisons; ++i) {
    off += snprintf(buf + off, size - off, " %s fd %s %d", connector, op, i);
  }
  snprintf(buf + off, size - off, " }, exit } DEFAULT KILL");
}

TEST_CASE(depth_boundary_or_chain) {
  /* Exactly MAX_EXPRESSION_DEPTH: must compile.  The resulting program
   * spans far more than 255 instructions, so conditional jumps to the
   * rest of the chain only resolve through JA trampolines. */
  char policy[8192];
  build_chain_policy(policy, sizeof(policy), MAX_EXPR_DEPTH, "==", "||");
  TEST_POLICY(policy);
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 0), SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 150), SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 199), SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 200), SYSCALL_KILLED_SPEC());
}

TEST_CASE(depth_boundary_and_chain) {
  /* Same depth boundary on the && side: every comparison's true branch
   * chains into the next one across a >255 instruction span. */
  char policy[8192];
  build_chain_policy(policy, sizeof(policy), MAX_EXPR_DEPTH, "!=", "&&");
  TEST_POLICY(policy);
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 300), SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 0), SYSCALL_KILLED_SPEC());
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 150), SYSCALL_KILLED_SPEC());
}

TEST_CASE(depth_boundary_over_rejected) {
  /* One past the boundary: readable parse-time error. */
  char policy[8192];
  build_chain_policy(policy, sizeof(policy), MAX_EXPR_DEPTH + 1, "==", "||");
  TEST_COMPILE_ERROR(policy);
}

TEST_CASE(depth_not_chain) {
  /* MAX_EXPRESSION_DEPTH - 1 negations on top of a comparison reach the
   * depth boundary exactly; an odd count must invert the truth value. */
  char policy[1024];
  char* p = policy;
  p += sprintf(p, "ALLOW { read { ");
  for (int i = 0; i < MAX_EXPR_DEPTH - 1; ++i) {
    *p++ = '!';
  }
  sprintf(p, "(fd == 1) }, exit } DEFAULT KILL");
  TEST_POLICY(policy);
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 2), SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 1), SYSCALL_KILLED_SPEC());
}

TEST_CASE(depth_bitwise_nested) {
  /* Deep right-leaning bitwise nesting evaluates through the index
   * register and needs no scratch slots: depth alone must not trip the
   * generation-time memory budget. */
  char policy[2048];
  char* p = policy;
  p += sprintf(p, "ALLOW { read { fd");
  for (int i = 1; i < 100; ++i) {
    p += sprintf(p, " & (fd");
  }
  for (int i = 1; i < 100; ++i) {
    p += sprintf(p, ")");
  }
  sprintf(p, " == 0 }, exit } DEFAULT KILL");
  TEST_POLICY(policy);
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 0), SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(SYSCALL_SPEC1(__NR_read, 5), SYSCALL_KILLED_SPEC());
}

TEST_CASE(depth_left_leaning_mem_budget) {
  /* Left-leaning bitwise nesting needs one scratch slot per level; well
   * below the parse depth bound this already exceeds BPF_MEMWORDS and
   * must fail with a readable error instead of emitting unsafe code. */
  char policy[2048];
  char* p = policy;
  p += sprintf(p, "ALLOW { read { ");
  p += sprintf(p, "fd");
  for (int i = 1; i < 30; ++i) {
    p += sprintf(p, " & fd");
  }
  sprintf(p, " == 0 }, exit } DEFAULT KILL");
  TEST_COMPILE_ERROR(policy);
}
