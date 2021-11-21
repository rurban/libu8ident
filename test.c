/* libu8ident - Follow unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/
#include <string.h>
#include <assert.h>
#include "u8ident.h"

uint8_t u8ident_get_script(uint32_t cp);

// check if the library can be used without init: script lookups, default checks
void test_scripts_no_init(void) {
  assert(u8ident_get_script(0x41) == 2);
  assert(u8ident_get_script(0x5a) == 2);
  assert(strcmp(u8ident_script_name(0), "Common") == 0);
  assert(strcmp(u8ident_script_name(1), "Inherited") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x2EB)), "Bopomofo") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x371)), "Greek") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x3132)), "Hangul") == 0);
}

// TODO check normalizations, mixed-script check, contexts, options, XID.

int main(void) {
  test_scripts_no_init();
  return 0;
}
