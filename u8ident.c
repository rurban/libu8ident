/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "u8ident.h"
#include "u8id_private.h"
#define EXT_SCRIPTS
#include "scripts.h"

uint32_t dec_utf8(char** strp);
bool u8ident_has_script(const uint8_t scr);
struct ctx_t * u8ident_ctx(void);

unsigned s_u8id_options = U8ID_NFKC | U8ID_PROFILE_4;
unsigned s_maxlen = 1024;

/* Initialize the library with a bitmask of options, which define the
   performed checks. Recommended is `U8ID_PROFILE_4` only. */
EXTERN int u8ident_init(unsigned options) {
  if (options > 2047)
    return -1;
  if ((options & U8ID_NFMASK) > 5)
    return -1;
  s_u8id_options = options;
  return 0;
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
EXTERN int u8ident_check_buf(const char* buf, const int len) {
  int ret = 0;
  char *s = (char*)buf;
  const char *e = (char*)&buf[len];
  // check mixed scripts
  while (s < e) {
    const uint32_t cp = dec_utf8(&s);
    const uint8_t scr = u8ident_get_script(cp);
    // ignore some
    if (scr == SC_Latin || scr == SC_Common || SC_Inherited)
      break;
    // if not already have it, add it
    struct ctx_t *ctx = u8ident_ctx();
    uint8_t *u8p = (ctx->count > 8) ? ctx->u8p : ctx->scr8;
    for (int i=0; i < ctx->count; i++) {
      // check mixed script
      if (scr == u8p[i])
        break;
      // add if allowed
      if ((i & 7) == 7)
        ctx->u8p = realloc(ctx->u8p, (i+1) * 2);
      ctx->u8p[i+1] = scr;
    }
  }
  // need to normalize?
  char *norm = u8ident_normalize((char*)buf, len);
  if (strcmp(norm, buf))
    ret = 1;
  return ret;
}

EXTERN int u8ident_check(const uint8_t* string) {
  return u8ident_check_buf((char*)string, strlen((char*)string));
}
