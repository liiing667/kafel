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

#include "validate.h"

#include "common.h"

const char* kafel_numeric_error_desc(enum kafel_numeric_error error) {
  switch (error) {
    case KAFEL_NUMERIC_OK:
      return "ok";
    case KAFEL_NUMERIC_OUT_OF_RANGE:
      return "out of range";
    case KAFEL_NUMERIC_OVERFLOW:
      return "range endpoint overflow";
    case KAFEL_NUMERIC_OVERLAP:
      return "overlapping endpoint";
  }
  ASSERT(0);  // should not happen
}

enum kafel_numeric_error kafel_validate_syscall_nr(uint64_t value,
                                                   uint32_t* out) {
  ASSERT(out != NULL);

  if (value <= MAX_SYSCALL_NR) {
    *out = (uint32_t)value;
    return KAFEL_NUMERIC_OK;
  }
  if (value >= KAFEL_SYSCALL_NR_NEGATIVE_MIN) {
    /* Two's-complement shorthand for [-2^31, -1]; truncation is exact. */
    *out = (uint32_t)value;
    return KAFEL_NUMERIC_OK;
  }
  return KAFEL_NUMERIC_OUT_OF_RANGE;
}

enum kafel_numeric_error kafel_validate_action_data(uint64_t value,
                                                    uint32_t* out) {
  ASSERT(out != NULL);

  if (value > KAFEL_ACTION_DATA_MAX) {
    return KAFEL_NUMERIC_OUT_OF_RANGE;
  }
  *out = (uint32_t)value;
  return KAFEL_NUMERIC_OK;
}

enum kafel_numeric_error kafel_validate_range(uint32_t first, uint32_t last) {
  if (first > last) {
    return KAFEL_NUMERIC_OVERFLOW;
  }
  return KAFEL_NUMERIC_OK;
}

bool kafel_range_endpoints_adjacent(uint32_t last, uint32_t first) {
  /* last + 1 would wrap when last == MAX_SYSCALL_NR */
  return last < MAX_SYSCALL_NR && last + 1 == first;
}

bool kafel_action_valid(int action) {
  if (action >= ACTION_KILL && action <= ACTION_BASIC_MAX) {
    return true;
  }
  if (action < 0) {
    return false;
  }
  uint32_t action_class = (uint32_t)action & ~KAFEL_ACTION_DATA_MAX;
  return action_class == ACTION_TRAP || action_class == ACTION_ERRNO ||
         action_class == ACTION_TRACE;
}
