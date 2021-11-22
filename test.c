/* libu8ident - Follow unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "u8ident.h"

// private access
uint8_t u8ident_get_script(uint32_t cp);
bool u8ident_is_allowed(const uint32_t cp);
const char * u8ident_get_scx(const uint32_t cp);

// check if the library can be used without init: script lookups, default checks
void test_scripts_no_init(void) {
  assert(u8ident_get_script(0x41) == 2);
  assert(u8ident_get_script(0x5a) == 2);
  assert(strcmp(u8ident_script_name(0), "Common") == 0);
  assert(strcmp(u8ident_script_name(1), "Inherited") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x2EB)), "Bopomofo") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x371)), "Greek") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x3132)), "Hangul") == 0);
  assert(!u8ident_get_scx(0x3132));
  const char *scx = u8ident_get_scx(0x309A);
  assert(scx);
  assert(strlen(scx) == 2);
  assert(scx[0] == 0x11); // Hiragana
  assert(scx[1] == 0x12); // Katakana
  scx = u8ident_get_scx(0x30FC);
  assert(scx);
  assert(strlen(scx) == 2);
  assert(scx[0] == 0x11); // Hiragana
  assert(scx[1] == 0x12); // Katakana
  scx = u8ident_get_scx(0x064B);
  assert(scx);
  assert(strlen(scx) == 2);
  assert(scx[0] == 0x03);   // Arab
  assert(scx[1] == '\x99'); // Syrc, signed!
  assert(u8ident_is_allowed(0x27));
  assert(!u8ident_is_allowed(0x26));
  assert(u8ident_is_allowed(0x40e));
}

// TODO check normalizations, mixed-script check, contexts, options, XID.

int main(void) {
  test_scripts_no_init();
  return 0;
}
