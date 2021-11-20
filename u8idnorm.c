// See https://www.unicode.org/reports/tr15/tr15-51.html
#include "u8ident.h"
#include "u8id_private.h"

#include "hangul.h"
#include "un8ifcan.h"

int u8ident_may_normalize(const char* buf, int len) {
  return 1;
}

/* Returns a freshly allocated normalized string, in the option defined at `u8ident_init`. */
EXTERN uint8_t* u8ident_normalize(const char* buf, int len) {
  //
}

