/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/
#include "u8ident.h"
#include "u8id_private.h"

unsigned s_u8id_options = U8ID_NFKC | U8ID_PROFILE_4;
unsigned s_maxlen = 1024;

/* Initialize the library with a bitmask of options, which define the
   performed checks. Recommended is `U8ID_PROFILE_4` only. */
EXTERN int u8ident_init(enum u8id_options options) {
  s_u8id_options = (unsigned)options;
}

unsigned u8ident_options(void) {
  return s_u8id_options;
}

/* maxlength of an identifier. Default: 1024. Beware that such long identiers are
   not really identifiable anymore, and keep them under 80 or even
   less. Some filesystems do allow now 32K identifiers, which is a
   glaring security hole, waiting to be exploited. */
EXTERN void u8ident_set_maxlength(unsigned maxlen) {
  if (maxlen > 1)
    s_maxlen = maxlen;
}

unsigned u8ident_maxlength(void) {
  return s_maxlen;
}

/* Two variants to check if this identifier is valid. The second avoids
   allocating a fresh string from the parsed input.
   Return values:
    * 0   - valid without need to normalize.
    * 1   - valid with need to normalize.
    * 2   - warn about confusable (not yet implemented)
    * -1  - invalid character class
    * -2  - invalid script
    * -3  - invalid encoding
    * -4  - invalid because confusable (not yet implemented)
*/
EXTERN int u8ident_check(const uint8_t* string) {
  return 0; // NYI
}
EXTERN int u8ident_check_buf(const char* buf, int len) {
  return 0; // NYI
}

