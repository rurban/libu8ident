/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   TODO: SAFEC23_4 without Greek-Latin confusables
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

// defaults to U8ID_PROFILE_4, U8ID_NFC, U8ID_TR31_XID
unsigned s_u8id_options = U8ID_TR31_DEFAULT;
enum u8id_norm s_u8id_norm = U8ID_NORM_DEFAULT;
enum u8id_profile s_u8id_profile = U8ID_PROFILE_DEFAULT;
unsigned s_maxlen = 1024;

LOCAL const char *u8ident_errstr(int errcode) {
  static const char *const _str[] = {
      "ERR_CONFUS",           // -6
      "ERR_COMBINE",          // -5
      "ERR_ENCODING",         // -4
      "ERR_SCRIPTS",          //-3
      "ERR_SCRIPT",           //-2
      "ERR_XID",              // -1
      "EOK",                  // 0
      "EOK_NORM",             // 1
      "EOK_WARN_CONFUS",      // 2
      "EOK_NORM_WARN_CONFUS", // 3
  };
  assert(errcode >= -6 && errcode <= 3);
  return _str[errcode + 6];
}

/* tr31 options:
  XID      - ID minus NFKC quirks.
  ID       - all letters, plus numbers, punctuation and marks. With exotic
  scripts. ALLOWED  - TR31 ID with only recommended scripts. Allowed
  IdentifierStatus. SAFEC23  - see c23++proposal XID minus exotic scripts,
  filtered by NFC and IdentifierType. C11      - the AltId ranges from the C11
  standard ALLUTF8  - all > 128, e.g. D, php, nim, crystal. ASCII    - only
  ASCII letters
*/
#ifndef DISABLE_CHECK_XID
static struct func_tr31_s tr31_funcs[] = {
    {isXID_start, isXID_cont},         {isID_start, isID_cont},
    {isALLOWED_start, isALLOWED_cont}, {isSAFEC23_start, isSAFEC23_cont},
    {isC11_start, isC11_cont},         {isALLUTF8_start, isALLUTF8_cont},
    {isASCII_start, isASCII_cont},
};
#endif

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

#ifdef ENABLE_CHECK_XID
  s_u8id_options = (options & ~U8ID_TR31_MASK) | U8ID_TR31_DEFAULT;
#else
  if (unlikely(s_u8id_profile == U8ID_PROFILE_1))
    s_u8id_options = (options & ~U8ID_TR31_MASK) | U8ID_TR31_ASCII;
  else
    s_u8id_options = options;
#endif

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
  enum u8id_sc scr;
  enum u8id_sc basesc = SC_Unknown;
  const unsigned xid_mask = s_u8id_options & U8ID_TR31_MASK;
  // default to XID (0)
  const enum xid_e xid = xid_mask > 64 ? xid_mask - 64 : XID;
  char *scx = NULL;
  assert(xid >= 0 && xid <= LAST_XID_E);
#ifndef DISABLE_CHECK_XID
#  if (defined(__GNUC__) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 460)
  _Static_assert(ARRAY_SIZE(tr31_funcs) == LAST_XID_E + 1,
                 "Invalid tr31_funcs[] size");
#  endif
#endif
  uint32_t cp = dec_utf8(&s);

#ifndef DISABLE_CHECK_XID
  func_tr31 *id_start = tr31_funcs[xid].start;
  func_tr31 *id_cont = tr31_funcs[xid].cont;
  // hardcoded TR31 funcs via static functions (inlinable)
  if
#  if !defined U8ID_TR31
      (unlikely(!(*id_start)(cp)))
#  elif U8ID_TR31 == ALLOWED
      (unlikely(!isALLOWED_start(cp)))
#  elif U8ID_TR31 == ASCII
      (unlikely(!isASCII_start(cp)))
#  elif U8ID_TR31 == SAFEC23
      (unlikely(!isSAFEC23_start(cp)))
#  elif U8ID_TR31 == C11
      (unlikely(!isC11_start(cp)))
#  elif U8ID_TR31 == XID
      (unlikely(!isXID_start(cp)))
#  elif U8ID_TR31 == ID
      (unlikely(!isID_start(cp)))
#  elif U8ID_TR31 == ALLUTF8
      (unlikely(!isALLUTF8_start(cp)))
#  else
      (unlikely(!(*id_start)(cp)))
#  endif
  {
    ctx->last_cp = cp;
    return U8ID_ERR_XID;
  }
#endif
  bool has_latin = u8ident_has_script_ctx(SC_Latin, ctx);

  do {

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
    // when we need TR31 checks.
    // advance to normalize checks
#if defined U8ID_PROFILE && (U8ID_PROFILE == 6 || U8ID_PROFILE == C11_6) &&    \
    defined(DISABLE_CHECK_XID)
    need_normalize = true;
    // if (scr != SC_Common && scr != SC_Inherited)
    //   basesc = scr;
    goto norm;
#elif defined U8ID_PROFILE && U8ID_PROFILE != 6 && U8ID_PROFILE != C11_6
#else
    if (s_u8id_profile == U8ID_PROFILE_6 ||
        s_u8id_profile == U8ID_PROFILE_C11_6) {
      need_normalize = true;
      if (!((s_u8id_options & U8ID_TR31_MASK) == U8ID_TR31_ALLOWED))
        goto norm;
      else {
        scr = (enum u8id_sc)u8ident_get_script(cp);
        goto ok;
      }
    }
#endif

    scr = (enum u8id_sc)u8ident_get_script(cp);
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

    bool is_new = false;
    // check scx on Common or Inherited.
    // TODO Keep list of possible scripts and reduce them.
    if (scr == SC_Common || scr == SC_Inherited) {
      // Almost everybody may mix with latin
      const struct scx *this_scx = u8ident_get_scx(cp);
      if (this_scx) {
        scx = (char *)this_scx->scx;
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
            if (strEQc(scx, "\x11\x12") && !ctx->is_japanese) {
              ctx->last_cp = cp;
              return U8ID_ERR_SCRIPTS;
            }
            // any cfk, also 6 cases for Bopo Hang Hani Hira Kana
            if (strEQc(scx, "\x06\x0e\x0f\x11\x12") && !ctx->is_japanese &&
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
        char *x = scx;
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

#if defined U8ID_PROFILE && U8ID_PROFILE == 5
    goto ok;
#elif defined U8ID_PROFILE && U8ID_PROFILE != 5
#else
    if (s_u8id_profile == U8ID_PROFILE_5)
      goto ok;
#endif

    // ignore Latin. This is compatible with everything
    if (likely(scr == SC_Latin)) {
      if (!u8ident_has_script_ctx(scr, ctx)) {
        has_latin = true;
        u8ident_add_script_ctx(scr, ctx);
      }
      basesc = scr;
      goto next;
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
          if (unlikely(!ctx->has_han && !has_latin)) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          } else
            goto ok;
        } else if (scr == SC_Han) {
          if (unlikely(!(ctx->is_chinese || ctx->is_japanese ||
                         ctx->is_korean || has_latin))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          } else
            goto ok;
        } else if (scr == SC_Katakana || scr == SC_Hiragana) {
          if (unlikely(!(ctx->is_japanese || ctx->has_han || has_latin))) {
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
          if (ctx->count >= 2 || scr == SC_Cyrillic) { // not more than 2
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          // some Greek may mix with Latin
          if (scr == SC_Greek && has_latin) {
            assert(s_u8id_profile == U8ID_PROFILE_C23_4);
            // only not confusables
            if (u8ident_is_greek_latin_confus(cp)) {
              ctx->last_cp = cp;
              return U8ID_ERR_SCRIPTS;
            }
            goto ok;
          }
        }
#endif
        // PROFILE_4: allow adding any Recommended to Latin,
        // but not Greek nor Cyrillic.
        // the only remaining profile
#if !defined U8ID_PROFILE || U8ID_PROFILE == 4
        else if (!has_latin || scr == SC_Greek || scr == SC_Cyrillic) {
          assert(s_u8id_profile == U8ID_PROFILE_4);
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        } else {
          assert(s_u8id_profile == U8ID_PROFILE_4);
          // but not Latin with more than 2
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
#if defined U8ID_PROFILE && (U8ID_PROFILE < 5 || U8ID_PROFILE == C11_4)
        // what with a Sm as first?
        if (basesc == SC_Unknown) {
          // Only for Mark, not Lm.
          // Disallow combiners without any base char (which do have a script)
          ctx->last_cp = cp;
          return U8ID_ERR_COMBINE;
        } // SCX already checked above
#endif
      } else {
        basesc = scr;
      }
      u8ident_add_script_ctx(scr, ctx);
      // not is new, but still a possible greek confusable
    } else if (s_u8id_profile == U8ID_PROFILE_C23_4 && scr == SC_Greek &&
               has_latin && u8ident_is_greek_latin_confus(cp)) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPTS;
    } else if (scr != SC_Common && scr != SC_Inherited) {
      basesc = scr;
    }

  next:
    cp = dec_utf8(&s);
#ifndef DISABLE_CHECK_XID
    if (likely(s <= e && cp != 0)) {
      // hardcode cont also? not yet
      if (unlikely(!(*id_cont)(cp) && !(*id_start)(cp))) {
        ctx->last_cp = cp;
        return U8ID_ERR_XID;
      }
      if (s == e && u8ident_is_MEDIAL(cp)) {
        ctx->last_cp = cp;
        return U8ID_ERR_XID;
      }
    }
#endif
  } while (s <= e);

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
