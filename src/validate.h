/*
   Kafel - shared numeric domain validation
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

#ifndef KAFEL_VALIDATE_H
#define KAFEL_VALIDATE_H

#include <stdbool.h>
#include <stdint.h>

#include "policy.h"
#include "syscall.h"

/*
 * Numeric error classification shared by the parser, range normalization
 * and action encoding. Every numeric rejection is explicitly classified as
 * either a value outside its domain (KAFEL_NUMERIC_OUT_OF_RANGE), a wrapped
 * or inverted range endpoint (KAFEL_NUMERIC_OVERFLOW) or an overlapping
 * endpoint (KAFEL_NUMERIC_OVERLAP).
 */
enum kafel_numeric_error {
  KAFEL_NUMERIC_OK = 0,
  KAFEL_NUMERIC_OUT_OF_RANGE,
  KAFEL_NUMERIC_OVERFLOW,
  KAFEL_NUMERIC_OVERLAP,
};

/* Action payloads (ERRNO/TRAP/TRACE data) are limited to 16 bits. */
#define KAFEL_ACTION_DATA_MAX 0xffffU

/*
 * Syscall numbers live in the uint32 domain [0, MAX_SYSCALL_NR]. Values in
 * [UINT64_MAX - INT32_MAX, UINT64_MAX] are the two's-complement shorthand
 * for [-2^31, -1] and map onto the top of the uint32 domain.
 */
#define KAFEL_SYSCALL_NR_NEGATIVE_MIN ((uint64_t)UINT64_MAX - INT32_MAX)

const char* kafel_numeric_error_desc(enum kafel_numeric_error error);

enum kafel_numeric_error kafel_validate_syscall_nr(uint64_t value,
                                                   uint32_t* out);
enum kafel_numeric_error kafel_validate_action_data(uint64_t value,
                                                    uint32_t* out);
enum kafel_numeric_error kafel_validate_range(uint32_t first, uint32_t last);

/* Wrap-safe adjacency check: is `first` the endpoint right after `last`? */
bool kafel_range_endpoints_adjacent(uint32_t last, uint32_t first);

/* Is `action` an encodable action (basic action or class with 16-bit data)? */
bool kafel_action_valid(int action);

#endif /* KAFEL_VALIDATE_H */
