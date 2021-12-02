/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "u8ident.h"
#include "u8id_private.h"
#include "u8idscr.h"

// defaults to U8ID_NFKC | U8ID_PROFILE_4
unsigned s_u8id_options = U8ID_NORM_DEFAULT | U8ID_PROFILE_DEFAULT;
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
EXTERN enum u8id_errors u8ident_check_buf(const char* buf, const int len, char** outnorm) {
  int ret = U8ID_EOK;
  char *s = (char*)buf;
  const char *e = (char*)&buf[len];
  // check mixed scripts
  while (s < e) {
    const uint32_t cp = dec_utf8(&s);
    if (unlikely(!cp)) {
      struct ctx_t *ctx = u8ident_ctx();
      ctx->last_cp = cp;
      return U8ID_ERR_ENCODING;
    }
    // when should we check for allowed?
    if (s_u8id_options & U8ID_CHECK_XID) {
      if (unlikely(!u8ident_is_allowed(cp))) {
	struct ctx_t *ctx = u8ident_ctx();
	ctx->last_cp = cp;
	return U8ID_ERR_CCLASS;
      }
    }
    // TODO check if normalize is needed (mark, ...)
    const uint8_t scr = u8ident_get_script(cp);
    // disallow Limited_Use if not already extra added
    if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT)) {
      struct ctx_t *ctx = u8ident_ctx();
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }
    // ignore some. they are never counted
    if (scr == SC_Latin || scr == SC_Common || scr == SC_Inherited)
      continue;
    // if not already have it, add it. EXCLUDED_SCRIPT must already exist
    struct ctx_t *ctx = u8ident_ctx();
    bool is_new = !u8ident_has_script_ctx(scr, ctx);
    // TODO check profile
    if (is_new) {
      // if excluded it must have been already manually added
      if (unlikely(scr >= FIRST_EXCLUDED_SCRIPT)) {
        ctx->last_cp = cp;
        return U8ID_ERR_SCRIPT;
      }
      // allowed is only one, unless it is an allowed combination
      if (ctx->count) {
        // check allowed CJK combinations
        if (scr == SC_Bopomofo) {
          if (unlikely(!ctx->has_han)) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          else
            goto ok;
        }
        else if (scr == SC_Han) {
          if (unlikely(!(ctx->is_chinese || ctx->is_japanese || ctx->is_korean))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          else
            goto ok;
        }
        else if (scr == SC_Katakana || scr == SC_Hiragana) {
          if (unlikely(!(ctx->is_japanese || ctx->has_han))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          else
            goto ok;
        }
        // and disallow all other combinations
        else { /* if (scr == SC_Greek && ctx->is_cyrillic)
                return U8ID_ERR_SCRIPTS;
                else if (scr == SC_Cyrillic && u8ident_has_script_ctx(SC_Greek, ctx)) */
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        }
      }
  ok:
      if (scr == SC_Han)
        ctx->has_han = 1;
      else if (scr == SC_Bopomofo)
        ctx->is_chinese = 1;
      else if (scr == SC_Katakana || scr == SC_Hiragana)
        ctx->is_japanese = 1;
      else if (scr == SC_Hangul)
        ctx->is_korean = 1;
      //else if (scr == SC_Cyrillic)
      //  ctx->is_cyrillic = 1;
      u8ident_add_script_ctx(scr, ctx);
    }
  }
  // need to normalize?
  char *norm = u8ident_normalize((char*)buf, len);
  if (strcmp(norm, buf))
    ret = U8ID_EOK_NORM;
  if (outnorm)
    *outnorm = norm;
  else
    free (norm);
  return ret;
}

EXTERN enum u8id_errors u8ident_check(const uint8_t* string, char** outnorm) {
  return u8ident_check_buf((char*)string, strlen((char*)string), outnorm);
}
