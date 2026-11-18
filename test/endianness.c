/*
   Kafel - endianness fixtures
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
 * Multi-endianness fixtures.
 *
 * Policies are compiled for big-endian targets (mips64, m68k) and the
 * generated BPF is run through the userspace interpreter against a
 * seccomp_data buffer laid out the way a big-endian kernel would:
 * every 64-bit argument slot holds its high 32-bit word where the
 * big-endian BPF program expects it.  Because the interpreter reads
 * 32-bit words natively, emulating that layout only requires swapping
 * the two 32-bit halves of each 64-bit argument.
 */

#include <linux/audit.h>
#include <linux/seccomp.h>
#include <stdint.h>

#include <kafel.h>

#include "runner/harness.h"
#include "runner/runner.h"

static uint64_t be64_arg(uint64_t value) {
  return (value >> 32) | (value << 32);
}

static syscall_spec_t be_spec(uint32_t arch, int nr, uint64_t arg0) {
  syscall_spec_t spec = {
      .nr = nr,
      .arch = arch,
      .instruction_pointer = 0xf00f00f0deadbeefLL,
      .args = {be64_arg(arg0), 0, 0, 0, 0, 0},
  };
  return spec;
}

static syscall_spec_t le_spec(uint32_t arch, int nr, uint64_t arg0) {
  syscall_spec_t spec = {
      .nr = nr,
      .arch = arch,
      .instruction_pointer = 0xf00f00f0deadbeefLL,
      .args = {arg0, 0, 0, 0, 0, 0},
  };
  return spec;
}

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

#if defined(AUDIT_ARCH_MIPS64)
TEST_CASE(endianness_be64_eq) {
  TEST_POLICY_ARCHS(KAFEL_TARGET_ARCH_MIPS64,
                    "ALLOW { SYSCALL[5000](a) { a == 0x123456789abcdef0 }, "
                    "exit } DEFAULT KILL");
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x123456789abcdef0ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  /* Low word differs. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x123456789abcdef1ULL),
             SYSCALL_KILLED_SPEC());
  /* High word differs. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x023456789abcdef0ULL),
             SYSCALL_KILLED_SPEC());
}

TEST_CASE(endianness_be64_inequality) {
  TEST_POLICY_ARCHS(
      KAFEL_TARGET_ARCH_MIPS64,
      "ALLOW { SYSCALL[5000](a) { a > 0x1122334455667788 }, exit } "
      "DEFAULT KILL");
  /* Greater in the low word. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x1122334455667789ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  /* Equal. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x1122334455667788ULL),
             SYSCALL_KILLED_SPEC());
  /* Same high word, smaller low word. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x1122334400000000ULL),
             SYSCALL_KILLED_SPEC());
  /* Greater high word. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x2122334455667700ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  /* Smaller high word. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x0122334455667788ULL),
             SYSCALL_KILLED_SPEC());
}

TEST_CASE(endianness_be64_bitwise) {
  /* Exercises the JSET transform on the high word of a big-endian arg. */
  TEST_POLICY_ARCHS(KAFEL_TARGET_ARCH_MIPS64,
                    "ALLOW { SYSCALL[5000](a) { a & 0xff00000000000000 == 0 }, "
                    "exit } DEFAULT KILL");
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x0000000000000000ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x00ffffffffffffffULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x0100000000000000ULL),
             SYSCALL_KILLED_SPEC());
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x8000000000000000ULL),
             SYSCALL_KILLED_SPEC());

  /* Bitwise AND against a 64-bit mask. */
  TEST_POLICY_ARCHS(
      KAFEL_TARGET_ARCH_MIPS64,
      "ALLOW { SYSCALL[5000](a) { a & 0x1f0000001f == 0x1f0000001f }, exit } "
      "DEFAULT KILL");
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x1f0000001fULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0xff000000ffULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x1f00000000ULL),
             SYSCALL_KILLED_SPEC());
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5000, 0x000000001fULL),
             SYSCALL_KILLED_SPEC());
}

TEST_CASE(endianness_be64_32bit_arg) {
  /* fcntl on mips64: fd is a 32-bit argument (nr 5070). */
  TEST_POLICY_ARCHS(KAFEL_TARGET_ARCH_MIPS64,
                    "ALLOW { fcntl { fd == 0x1234 }, exit } DEFAULT KILL");
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5070, 0x1234),
             SYSCALL_EXECUTED_SPEC(0, 0));
  /* Garbage in the high word must not affect a 32-bit compare. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5070, 0xdeadbeef00001234ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5070, 0x1235), SYSCALL_KILLED_SPEC());

  /* A 64-bit constant forces comparing the whole 64-bit slot. */
  TEST_POLICY_ARCHS(KAFEL_TARGET_ARCH_MIPS64,
                    "ALLOW { fcntl { fd == 0x100001234 }, exit } DEFAULT KILL");
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5070, 0x100001234ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5070, 0x1234), SYSCALL_KILLED_SPEC());
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 5070, 0x100001235ULL),
             SYSCALL_KILLED_SPEC());
}
#endif /* AUDIT_ARCH_MIPS64 */

#if defined(AUDIT_ARCH_M68K)
TEST_CASE(endianness_be32_arch) {
  /* read on m68k: 32-bit big-endian target, fd is 32-bit (nr 3). */
  TEST_POLICY_ARCHS(KAFEL_TARGET_ARCH_M68K,
                    "ALLOW { read { fd == 1 }, exit } DEFAULT KILL");
  CHECK_SPEC(be_spec(AUDIT_ARCH_M68K, 3, 1), SYSCALL_EXECUTED_SPEC(0, 0));
  /* On big-endian the low word lives at offset +4; garbage elsewhere in
   * the slot must not leak into the compare. */
  CHECK_SPEC(be_spec(AUDIT_ARCH_M68K, 3, 0xffffffff00000001ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(be_spec(AUDIT_ARCH_M68K, 3, 2), SYSCALL_KILLED_SPEC());
  CHECK_SPEC(be_spec(AUDIT_ARCH_M68K, 3, 0x100000000ULL),
             SYSCALL_KILLED_SPEC());
}
#endif /* AUDIT_ARCH_M68K */

#if defined(AUDIT_ARCH_MIPS64) && defined(AUDIT_ARCH_X86_64)
TEST_CASE(endianness_multi_arch_same_truth) {
  /* One program, two targets with opposite endianness: the observable
   * truth values must be identical. */
  TEST_POLICY_ARCHS(
      KAFEL_TARGET_ARCH_X86_64 | KAFEL_TARGET_ARCH_MIPS64,
      "ALLOW { SYSCALL[6000](a) { a == 0x1111222233334444 }, exit } "
      "DEFAULT KILL");
  CHECK_SPEC(le_spec(AUDIT_ARCH_X86_64, 6000, 0x1111222233334444ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(le_spec(AUDIT_ARCH_X86_64, 6000, 0x1111222233334445ULL),
             SYSCALL_KILLED_SPEC());
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 6000, 0x1111222233334444ULL),
             SYSCALL_EXECUTED_SPEC(0, 0));
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 6000, 0x1111222233334445ULL),
             SYSCALL_KILLED_SPEC());
  CHECK_SPEC(be_spec(AUDIT_ARCH_MIPS64, 6000, 0x2111222233334444ULL),
             SYSCALL_KILLED_SPEC());
}
#endif /* AUDIT_ARCH_MIPS64 && AUDIT_ARCH_X86_64 */
