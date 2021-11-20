#include <string.h>
#include <assert.h>
#include "u8ident.h"

uint8_t u8ident_get_script(uint32_t cp);

int main(void) {
  // check if the library can be used without init
  assert(u8ident_get_script(0x41) == 2);
  assert(u8ident_get_script(0x5a) == 2);
  assert(strcmp(u8ident_script_name(2), "Latin") == 0);
  return 0;
}
