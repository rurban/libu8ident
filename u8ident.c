/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022 Reini Urban
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

// defaults to U8ID_PROFILE_4, U8ID_NFC, U8ID_TR31_ALLOWED
unsigned s_u8id_options = 0
#ifndef DISABLE_CHECK_XID
                          | U8ID_TR31_ALLOWED
#endif
    ;
enum u8id_norm s_u8id_norm = U8ID_NORM_DEFAULT;
enum u8id_profile s_u8id_profile = U8ID_PROFILE_DEFAULT;
unsigned s_maxlen = 1024;

/* Initialize the library with a profile, normalization and a bitmask of
   enum u8id_options, which define the performed checks. Recommended is
   `(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0)`.
*/
EXTERN int u8ident_init(enum u8id_profile profile, enum u8id_norm norm,
                        unsigned options) {
  u8ident_free(); // clear and reset the ctx
  if (options > 1023)
    return -1;
  if (profile < U8ID_PROFILE_1 || profile > U8ID_PROFILE_C23_4)
    return -1;
  if (norm > U8ID_FCC)
    return -1;
#if defined U8ID_NORM
    // only one is allowed, else fail
#  if U8ID_NORM == NFD
  if (norm != U8ID_NFD)
    return -1;
#  endif
#  if U8ID_NORM == NFC
  if (norm != U8ID_NFC)
    return -1;
#  endif
#  if U8ID_NORM == NFKC
  if (norm != U8ID_NFKC)
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
  s_u8id_norm = norm;

#if defined U8ID_PROFILE_SAFEC23
  s_u8id_profile = U8ID_PROFILE_C23_4;
#elif defined U8ID_PROFILE_C11STD
  s_u8id_profile = U8ID_PROFILE_C11_6;
#else
  s_u8id_profile = profile;
#endif

  s_u8id_options = options;
#ifdef HAVE_CROARING
  if (u8ident_roar_init())
    return -1;
#endif
  return 0;
}

enum u8id_norm u8ident_norm(void) { return s_u8id_norm; }
enum u8id_profile u8ident_profile(void) { return s_u8id_profile; }
enum u8id_options u8ident_tr31(void) {
  return (enum u8id_options)(s_u8id_options & 127);
}
unsigned u8ident_options(void) { return s_u8id_options; }

/* maxlength of an identifier. Default: 1024. Beware that such long identiers
   are not really identifiable anymore, and keep them under 80 or even less.
   Some filesystems do allow now 32K identifiers, which is a glaring security
   hole, waiting to be exploited. */
EXTERN void u8ident_set_maxlength(unsigned maxlen) {
  if (maxlen > 1)
    s_maxlen = maxlen;
}

unsigned u8ident_maxlength(void) { return s_maxlen; }

/* check if the script sc is in the SCX list */
bool in_SCX(const enum u8id_sc scr, const char *scx) {
  unsigned char *x = (unsigned char *)scx;
  while (*x) {
    if (*x == (unsigned char)scr)
      return true;
    x++;
  }
  return false;
}

/* Two variants to check if this identifier is valid. The second avoids
   allocating a fresh string from the parsed input.
*/
EXTERN enum u8id_errors u8ident_check_buf(const char *buf, const int len,
                                          char **outnorm) {
  int ret = U8ID_EOK;
  char *s = (char *)buf;
  const char *e = (char *)&buf[len];
  bool need_normalize = false;
  struct ctx_t *ctx = u8ident_ctx();
  enum u8id_sc basesc = SC_Unknown;
  // char *scx = NULL;
  // char scx[32]; // combination of all scx
  // scx[0] = '\0';
  //  check mixed scripts
  while (s < e) {
    const uint32_t cp = dec_utf8(&s);
    if (unlikely(!cp)) {
      ctx->last_cp = cp;
      return U8ID_ERR_ENCODING; // not well-formed UTF-8
    }
#ifndef DISABLE_CHECK_XID
    // check for the Allowed IdentifierStatus (tr39)
    if
#  ifdef ENABLE_CHECK_XID
        (1)
#  else
        (s_u8id_options & U8ID_TR31_XID)
#  endif
    {
      if (unlikely(!u8ident_is_allowed(cp))) {
        ctx->last_cp = cp;
        return U8ID_ERR_XID;
      }
    }
#endif
    if (unlikely(s_u8id_profile == U8ID_PROFILE_1 && cp > 127)) {
      ctx->last_cp = cp;
      return U8ID_ERR_XID;
    }
#ifdef HAVE_CONFUS
    /* allow some latin confusables: 0 1 I ` | U+30, U+31, U+49, U+60, U+7C */
    /* what about: 0x00A0, 0x00AF, 0x00B4, 0x00B5, 0x00B8, 0x00D7, 0x00F6 */
    if (unlikely(s_u8id_options &
                     (U8ID_WARN_CONFUSABLE | U8ID_ERROR_CONFUSABLE) &&
                 cp > 0x7C)) {
      bool yes = u8ident_is_confusable(cp);
      if (yes) {
        if (s_u8id_options & U8ID_ERROR_CONFUSABLE)
          return U8ID_ERR_CONFUS;
        else if (s_u8id_options & U8ID_WARN_CONFUSABLE)
          ret = U8ID_EOK_WARN_CONFUS;
      }
    }
#endif

    // profile 6 shortcuts: skip all script checks.
    // advance to normalize checks
#if defined U8ID_PROFILE && (U8ID_PROFILE == 6 || U8ID_PROFILE == C11_6)
    need_normalize = true;
    //if (scr != SC_Common && scr != SC_Inherited)
    //  basesc = scr;
    goto norm;
#elif defined U8ID_PROFILE && U8ID_PROFILE != 6 && U8ID_PROFILE != C11_6
#else
    if (s_u8id_profile == U8ID_PROFILE_6 ||
        s_u8id_profile == U8ID_PROFILE_C11_6) {
      need_normalize = true;
      //if (scr != SC_Common && scr != SC_Inherited)
      //  basesc = scr;
      goto norm;
    }
#endif

    const enum u8id_sc scr = (enum u8id_sc)u8ident_get_script(cp);
    // disallow Excluded
    if (unlikely(scr >= FIRST_EXCLUDED_SCRIPT &&
                 s_u8id_profile != U8ID_PROFILE_6 &&
                 s_u8id_profile != U8ID_PROFILE_C11_6)) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }
    // disallow bidi formatting
    if (unlikely(!ctx->is_rtl && u8ident_is_bidi(cp))) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }
    if (!need_normalize) {
      need_normalize = u8ident_maybe_normalized(cp);
    }

#if defined U8ID_PROFILE && U8ID_PROFILE == 5
    goto ok;
#elif defined U8ID_PROFILE && U8ID_PROFILE != 5
#else
    if (s_u8id_profile == U8ID_PROFILE_5)
      goto ok;
#endif
    bool is_new = false;
    // check scx on Common or Inherited.
    // TODO Keep list of possible scripts and reduce them.
    if (scr == SC_Common || scr == SC_Inherited) {
      // Almost everybody may mix with latin
      const bool has_latin = u8ident_has_script_ctx(SC_Latin, ctx);
      const struct scx *this_scx = u8ident_get_scx(cp);
      if (this_scx) {
        char *x = (char *)this_scx->scx;
        const enum u8id_gc gc = (const enum u8id_gc)this_scx->gc;
        int n = 0;
        if (ctx->count && (s_u8id_profile < 5 || s_u8id_profile == C23_4)) {
          // Special-case for runs: only after japanese.
          // This is the only context dependent Lm case.
          // All others are Combining Marks.
          if (!ctx->is_japanese &&
              ((cp >= 0x30FC && cp <= 0x30FE) || cp == 0xFF70)) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          if (!has_latin) { // 6 cases for Hira Kana
            if (strEQc(x, "\x11\x12") && !ctx->is_japanese) {
              ctx->last_cp = cp;
              return U8ID_ERR_SCRIPTS;
            }
            // any cfk, also 6 cases for Bopo Hang Hani Hira Kana
            if (strEQc(x, "\x06\x0e\x0f\x11\x12") && !ctx->is_japanese &&
                !ctx->has_han && !ctx->is_korean) {
              ctx->last_cp = cp;
              return U8ID_ERR_SCRIPTS;
            }
          }
        }
        // We have 2 Mc cases, and 30 Mn in SCX. No Me. More of them are in SC
        // though.
        if (gc == GC_Mn || gc == GC_Mc) {
          if (!ctx->count || basesc == SC_Unknown) {
            // Disallow combiners without any base char (which does have a
            // script) This catches only a mark as very first char. We check the
            // base char for runs at ok:
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (!in_SCX(basesc, this_scx->scx)) {
            // Check combiners against basesc
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          }
        }
        while (*x) {
          bool has = u8ident_has_script_ctx(*x, ctx);
          n += has ? 1 : 0;
          x++;
        }
        /* We have SCX and none of the SCX occured yet.
           So we have a new one.
           We dont know which yet, but we can set is_new. */
        if (!n) {
          is_new = true;
          // scx = (char *)this_scx->scx; // for errors
        }
      }
    }
    // ignore Latin. This is compatible with everything
    else if (scr == SC_Latin) {
      if (!u8ident_has_script_ctx(scr, ctx))
        u8ident_add_script_ctx(scr, ctx);
      basesc = scr;
      continue;
    }

    // if not already have it, add it. EXCLUDED_SCRIPT must already exist
    if (!is_new && !(scr == SC_Common || scr == SC_Inherited))
      is_new = !u8ident_has_script_ctx(scr, ctx);
    if (is_new) {
      // if Limited Use it must have been already manually added
      if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT &&
                   (s_u8id_profile < U8ID_PROFILE_5 ||
                    s_u8id_profile == U8ID_PROFILE_C23_4))) {
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
        } else if (scr == SC_Common || scr == SC_Inherited) {
          // may we now collapse it?
          goto ok;
        }
        // and disallow all other combinations
#if !defined U8ID_PROFILE || U8ID_PROFILE == 3
        else if (s_u8id_profile == U8ID_PROFILE_3) {
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        }
#endif
#if !defined U8ID_PROFILE || U8ID_PROFILE == C23_4
        else if (s_u8id_profile == U8ID_PROFILE_C23_4) {
          if (scr == SC_Greek) {
            assert(s_u8id_profile == U8ID_PROFILE_C23_4);
            goto ok;
          }
        }
#endif
        // PROFILE_4: allow adding any Recommended to Latin,
        // but not Greek nor Cyrillic.
        // the only remaining profile
#if !defined U8ID_PROFILE || U8ID_PROFILE == 4
        else if (scr == SC_Greek || scr == SC_Cyrillic) {
          assert(s_u8id_profile == U8ID_PROFILE_4 ||
                 s_u8id_profile == U8ID_PROFILE_C23_4);
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        } else {
          assert(s_u8id_profile == U8ID_PROFILE_4 ||
                 s_u8id_profile == U8ID_PROFILE_C23_4);
          // but not more than 2
          if (ctx->count >= 2) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
        }
#endif
      }
    ok:
      // check illegal runs.
      // A generic is_MARK(cp) would be too slow here. we rather should keep the
      // SCX, and check the marks there.
      if (scr == SC_Common || scr == SC_Inherited /*|| u8ident_is_MARK(cp)*/) {
        if (basesc == SC_Unknown) {
          // Only for Mark, not Lm.
          // Disallow combiners without any base char (which do have a script)
          ctx->last_cp = cp;
          return U8ID_ERR_COMBINE;
        } // SCX already checked above
      } else {
        basesc = scr;
      }
      u8ident_add_script_ctx(scr, ctx);
    }
  }

#if !defined U8ID_PROFILE || U8ID_PROFILE == 6 || U8ID_PROFILE == C11_6
norm:
#endif
  if (need_normalize) {
    char *norm = u8ident_normalize((char *)buf, len);
    if (!norm || strcmp(norm, buf)) {
      ctx->last_cp = 0;
      ret = U8ID_EOK_NORM | ret;
    }
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
