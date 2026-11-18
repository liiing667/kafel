/*
   Kafel - historical samples fixture
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
 * Historical samples fixture: every policy shipped under samples/ must
 * keep compiling, so that refactors of the expression pipeline never
 * silently drop support for previously valid inputs.
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kafel.h>

#include "runner/harness.h"
#include "runner/runner.h"

#define SAMPLES_DIR "../samples"

TEST_CASE(samples_compile) {
  DIR* dir = opendir(SAMPLES_DIR);
  if (dir == NULL) {
    test_fail_with_message("cannot open " SAMPLES_DIR);
    test_failed(__LINE__, __FILE__);
    return;
  }
  int count = 0;
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    const char* dot = strrchr(entry->d_name, '.');
    if (dot == NULL || strcmp(dot, ".policy") != 0) {
      continue;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", SAMPLES_DIR, entry->d_name);
    FILE* file = fopen(path, "r");
    if (file == NULL) {
      test_fail_with_message("cannot open %s", path);
      test_failed(__LINE__, __FILE__);
      break;
    }
    kafel_ctxt_t ctxt = kafel_ctxt_create();
    kafel_set_input_file(ctxt, file);
    struct sock_fprog prog;
    int rv = kafel_compile(ctxt, &prog);
    if (rv != 0) {
      test_fail_with_message("sample %s failed to compile: %s", path,
                             kafel_error_msg(ctxt));
      test_failed(__LINE__, __FILE__);
    } else {
      free(prog.filter);
      ++count;
    }
    kafel_ctxt_destroy(&ctxt);
    fclose(file);
  }
  closedir(dir);
  if (count == 0) {
    test_fail_with_message("no samples found in " SAMPLES_DIR);
    test_failed(__LINE__, __FILE__);
  }
}
