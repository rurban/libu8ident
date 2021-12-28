/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include "u8id_private.h"
#include <u8ident.h>
#include "u8idscr.h"
#ifdef HAVE_CROARING
#  include "u8idroar.h"
#endif

// defaults to U8ID_NFC | U8ID_PROFILE_4
unsigned s_u8id_options = U8ID_NORM_DEFAULT | U8ID_PROFILE_DEFAULT
#ifndef DISABLE_CHECK_XID
                          | U8ID_CHECK_XID
#endif
    ;
enum u8id_profile s_u8id_profile = U8ID_PROFILE_DEFAULT;
unsigned s_maxlen = 1024;

/* Initialize the library with a bitmask of options, which define the
   performed checks. Recommended is `U8ID_PROFILE_4` only. */
EXTERN int u8ident_init(unsigned options) {
  if (options > 8192 + 2048 + 512 + 256)
    return -1;
  if ((options & U8ID_NFMASK) > 5)
    return -1;
#if defined U8ID_NORM
  enum u8id_norm norm = options & U8ID_NFMASK;
  // only one is allowed, else fail
#  if U8ID_NORM == NFD
  if (!((norm != U8ID_NFD || norm != U8ID_FCD)))
    return -1;
#  endif
#  if U8ID_NORM == NFC
  if (!((norm == U8ID_NFD || norm == U8ID_FCD || norm == U8ID_NFC)))
    return -1;
#  endif
#  if U8ID_NORM == NFKC
  if (!((norm != U8ID_NFKD || norm != U8ID_NFKC)))
    return -1;
#  endif
#  if U8ID_NORM == NFKD
  if (norm != U8ID_NFKD)
    return -1;
#  endif
#  if U8ID_NORM == FCD
  if (norm != U8ID_FCD)
    return -1;
#  endif
#  if U8ID_NORM == FCC
  if (norm != U8ID_FCC)
    return -1;
#  endif
#endif
  s_u8id_profile = 0;
  for (unsigned i = U8ID_PROFILE_2; i <= U8ID_PROFILE_6; i *= 2) {
    if (options & i) {
      if (s_u8id_profile)
        return -1; // error. another profile already defined
      s_u8id_profile = i;
    }
  }
  if (!s_u8id_profile) {
    if (options & U8ID_PROFILE_C11_4)
      s_u8id_profile = 11;
    else if (options & U8ID_PROFILE_C11_6)
      s_u8id_profile = 12;
  }
  if (!s_u8id_profile)
    return -1; // error. no profile defined
  s_u8id_options = options;
#ifdef HAVE_CROARING
  if (u8ident_roar_init())
    return -1;
#endif
  return 0;
}

unsigned u8ident_options(void) { return s_u8id_options; }
unsigned u8ident_profile(void) {
#if defined U8ID_PROFILE_SAFEC11
  return 11;
#elif defined U8ID_PROFILE_C11STD
  return 12;
#else
  assert(s_u8id_profile >= U8ID_PROFILE_2 && s_u8id_profile <= U8ID_PROFILE_6);
  // 8>>4: 0, 16>>4: 1, 32>>4: 2, 64>>4: 4, 128>>4: 8
  static const uint8_t _profiles[] = {2, 3, 4, 0, 5, 0, 0, 0, 6};
  return (unsigned)_profiles[(unsigned)s_u8id_profile >> 4];
#endif
}

/* maxlength of an identifier. Default: 1024. Beware that such long identiers
   are not really identifiable anymore, and keep them under 80 or even less.
   Some filesystems do allow now 32K identifiers, which is a glaring security
   hole, waiting to be exploited. */
EXTERN void u8ident_set_maxlength(unsigned maxlen) {
  if (maxlen > 1)
    s_maxlen = maxlen;
}

unsigned u8ident_maxlength(void) { return s_maxlen; }

/* Two variants to check if this identifier is valid. The second avoids
   allocating a fresh string from the parsed input.
*/
EXTERN enum u8id_errors u8ident_check_buf(const char *buf, const int len,
                                          char **outnorm) {
  int ret = U8ID_EOK;
  char *s = (char *)buf;
  const char *e = (char *)&buf[len];
  bool need_normalize = false;
  // char scx[32]; // combination of all scx
  // scx[0] = '\0';
  //  check mixed scripts
  while (s < e) {
    const uint32_t cp = dec_utf8(&s);
    if (unlikely(!cp)) {
      struct ctx_t *ctx = u8ident_ctx();
      ctx->last_cp = cp;
      return U8ID_ERR_ENCODING; // not well-formed UTF-8
    }
#ifndef DISABLE_CHECK_XID
    // check for the Allowed IdentifierStatus (tr39)
    if
#  ifdef ENABLE_CHECK_XID
        (1)
#  else
        (s_u8id_options & U8ID_CHECK_XID)
#  endif
    {
      if (unlikely(!u8ident_is_allowed(cp))) {
        struct ctx_t *ctx = u8ident_ctx();
        ctx->last_cp = cp;
        return U8ID_ERR_XID;
      }
    }
#endif

#ifdef HAVE_CONFUS
    /* allow some latin confusables: 0 1 I ` | U+30, U+31, U+49, U+60, U+7C */
    /* what about: 0x00A0, 0x00AF, 0x00B4, 0x00B5, 0x00B8, 0x00D7, 0x00F6 */
    if (s_u8id_options & (U8ID_WARN_CONFUSABLE | U8ID_ERROR_CONFUSABLE) &&
        cp > 0x7C) {
      bool yes = u8ident_is_confusable(cp);
      if (yes) {
        if (s_u8id_options & U8ID_ERROR_CONFUSABLE)
          return U8ID_ERR_CONFUS;
        else if (s_u8id_options & U8ID_WARN_CONFUSABLE)
          ret = U8ID_EOK_WARN_CONFUS;
      }
    }
#endif

#if defined U8ID_PROFILE && (U8ID_PROFILE == 6 || U8ID_PROFILE == C11_6)
    continue; // skip all script checks
#elif defined U8ID_PROFILE && U8ID_PROFILE != 6 && U8ID_PROFILE != C11_6
#else
    if (s_u8id_profile == U8ID_PROFILE_6 || s_u8id_profile == U8ID_PROFILE_C11_6)
      continue;
#endif

    const uint8_t scr = u8ident_get_script(cp);
    // disallow Excluded
    if (unlikely(scr >= FIRST_EXCLUDED_SCRIPT &&
                 s_u8id_profile < U8ID_PROFILE_6)) {
      struct ctx_t *ctx = u8ident_ctx();
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }

    if (!need_normalize) {
      need_normalize = u8ident_maybe_normalized(cp);
    }

#if defined U8ID_PROFILE && U8ID_PROFILE == 5
    continue; // skip all mixed scripts checks
#elif defined U8ID_PROFILE && U8ID_PROFILE != 5
#else
    if (s_u8id_profile == U8ID_PROFILE_5)
      continue; // skip all mixed scripts checks
#endif
    bool is_new = false;
    struct ctx_t *ctx = u8ident_ctx();
    // check scx on Common or Inherited. keep list of possible scripts, and
    // reduce them
    if (scr == SC_Common || scr == SC_Inherited) {
      const char *this_scx = u8ident_get_scx(cp);
      if (this_scx) {
        char *x = (char *)this_scx;
        int n = 0;
        while (*x) {
          bool has = u8ident_has_script_ctx(*x, ctx);
          n += has ? 1 : 0;
          x++;
        }
        if (!n) { // We have SCX and none of the SCX occured yet. so
          // we have a new one.
          is_new = true; // we dont know which yet, but we can set is_new.
        }
      }
    }
    // ignore Latin. This is compatible with everything
    else if (scr == SC_Latin) {
      if (!u8ident_has_script_ctx(scr, ctx))
        u8ident_add_script_ctx(scr, ctx);
      continue;
    }

    // if not already have it, add it. EXCLUDED_SCRIPT must already exist
    if (!is_new && !(scr == SC_Common || scr == SC_Inherited))
      is_new = !u8ident_has_script_ctx(scr, ctx);
    if (is_new) {
      // if Limited Use it must have been already manually added
      if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT &&
                   s_u8id_profile < U8ID_PROFILE_5)) {
        ctx->last_cp = cp;
        return U8ID_ERR_SCRIPT;
      }
      // allowed is only one, unless it is an allowed combination
      if (ctx->count) {
#if !defined U8ID_PROFILE || U8ID_PROFILE != 2
        if (s_u8id_profile == U8ID_PROFILE_2)
#endif
        { // single script only
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        }
        // check allowed CJK combinations
        if (scr == SC_Bopomofo) {
          if (unlikely(!ctx->has_han)) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          } else
            goto ok;
        } else if (scr == SC_Han) {
          if (unlikely(
                  !(ctx->is_chinese || ctx->is_japanese || ctx->is_korean))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          } else
            goto ok;
        } else if (scr == SC_Katakana || scr == SC_Hiragana) {
          if (unlikely(!(ctx->is_japanese || ctx->has_han))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          } else
            goto ok;
        }
        // and disallow all other combinations
#if !defined U8ID_PROFILE || U8ID_PROFILE == 3
        else if (s_u8id_profile == U8ID_PROFILE_3) {
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        }
#endif
#if !defined U8ID_PROFILE || U8ID_PROFILE == C11_4
        else if (s_u8id_profile == U8ID_PROFILE_C11_4) {
          if (scr == SC_Greek) {
            assert(s_u8id_profile == U8ID_PROFILE_C11_4);
            goto ok;
          }
        }
#endif
        // PROFILE_4: allow adding any Recommended to Latin,
        // but not Greek nor Cyrillic.
        // the only remaining profile
#if !defined U8ID_PROFILE || U8ID_PROFILE == 4
        else if (scr == SC_Greek || scr == SC_Cyrillic) {
          assert(s_u8id_profile == U8ID_PROFILE_4);
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        } else {
          assert(s_u8id_profile == U8ID_PROFILE_4 || s_u8id_profile == U8ID_PROFILE_C11_4);
          // but not more than 2
          if (ctx->count >= 2) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
        }
#endif
      }
    ok:
      u8ident_add_script_ctx(scr, ctx);
    }
  }

#if defined U8ID_PROFILE && (U8ID_PROFILE == 6 || U8ID_PROFILE == C11_6)
  need_normalize = true;
#elif defined U8ID_PROFILE && U8ID_PROFILE != 6 && U8ID_PROFILE != C11_6
#else
  if (s_u8id_profile == U8ID_PROFILE_6 || s_u8id_profile == U8ID_PROFILE_C11_6)
    need_normalize = true;
#endif
  if (need_normalize) {
    char *norm = u8ident_normalize((char *)buf, len);
    if (!norm || strcmp(norm, buf))
      ret = U8ID_EOK_NORM | ret;
    if (outnorm)
      *outnorm = norm;
    else
      free(norm);
  }
  return ret;
}

EXTERN enum u8id_errors u8ident_check(const uint8_t *string, char **outnorm) {
  return u8ident_check_buf((char *)string, strlen((char *)string), outnorm);
}
