/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

  Classify and search for the script property
  https://www.unicode.org/reports/tr24/tr24-32.html Implement
  http://www.unicode.org/reports/tr39/#Mixed_Script_Detection
*/

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "u8id_private.h"
#include <u8ident.h>

#include "scripts.h"
#ifndef HAVE_CROARING
// optional. default: disabled
#  ifdef HAVE_CONFUS
#    include "confus.h"
#  endif
#else
#  include "u8idroar.h"
#endif

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

extern unsigned s_u8id_options;
// not yet thread-safe
struct ctx_t ctx[U8ID_CTX_TRESH] = {0}; // pre-allocate 5 contexts
static int i_ctx = 0;
struct ctx_t *ctxp = NULL; // if more than 5 contexts

/* Generates a new identifier document/context/directory, which
   initializes a new list of seen scripts. */
EXTERN int u8ident_new_ctx(void) {
  // thread-safety later
  int i = i_ctx + 1;
  i_ctx++;
  if (i == U8ID_CTX_TRESH) {
    ctxp = (struct ctx_t *)calloc(U8ID_CTX_TRESH, sizeof(struct ctx_t));
  } else if (i > U8ID_CTX_TRESH) {
    ctxp = (struct ctx_t *)realloc(ctxp, i * sizeof(struct ctx_t));
  } else {
    ctxp = &ctx[i];
  }
  memset(ctxp, 0, sizeof(struct ctx_t));
  return i_ctx;
}

/* Changes to the context previously generated with `u8ident_new_ctx`. */
EXTERN int u8ident_set_ctx(int i) {
  if (i >= 0 && i <= i_ctx) {
    i_ctx = i;
    return 0;
  } else
    return -1;
}

/* Changes to the context previously generated with `u8ident_new_ctx`. */
struct ctx_t *u8ident_ctx(void) {
  return (i_ctx < U8ID_CTX_TRESH) ? &ctx[i_ctx] : &ctxp[i_ctx];
}

// search in linear vector of scripts per ctx
bool u8ident_has_script_ctx(const uint8_t scr, const struct ctx_t *c) {
  if (!c->count)
    return false;
  const uint8_t *u8p = (c->count > 8) ? c->u8p : c->scr8;
  for (int i = 0; i < c->count; i++) {
    if (scr == u8p[i])
      return true;
  }
  return false;
}

bool u8ident_has_script(const uint8_t scr) {
  return u8ident_has_script_ctx(scr, u8ident_ctx());
}

int u8ident_add_script_ctx(const uint8_t scr, struct ctx_t *c) {
  if (scr < 2 || scr >= FIRST_LIMITED_USE_SCRIPT)
    return -1;
  int i = c->count;
  if (unlikely(i > 8 && (i & 7) == 7)) {
    c->u8p = realloc(c->u8p, i + 8);
    c->u8p[i] = scr;
  } else if (i == 9) {
    uint8_t *p = malloc(16);
    memcpy(p, c->scr8, 8);
    c->u8p = p;
    c->u8p[i] = scr;
  } else {
    if (i > 8) {
      if (!c->u8p) {
        c->u8p = calloc(16, 1);
        memcpy(c->u8p, c->scr8, 8);
      }
      c->u8p[i] = scr;
    } else {
      c->scr8[i] = scr;
    }
  }
  if (scr == SC_Han)
    c->has_han = 1;
  else if (scr == SC_Bopomofo)
    c->is_chinese = 1;
  else if (scr == SC_Katakana || scr == SC_Hiragana)
    c->is_japanese = 1;
  else if (scr == SC_Hangul)
    c->is_korean = 1;
  else if (scr == SC_Hebrew || scr == SC_Arabic)
    c->is_rtl = 1;
  c->count++;
  return 0;
}

static inline bool linear_search(const uint32_t cp,
                                 const struct range_bool *sc_list,
                                 const int len) {
  struct range_bool *s = (struct range_bool *)sc_list;
  for (int i = 0; i < len; i++) {
    assert(s->from <= s->to);
    if ((cp - s->from) <= (s->to - s->from))
      return true;
    if (cp <= s->to) // s is sorted. not found
      return false;
    s++;
  }
  return false;
}

static inline struct sc *binary_search(const uint32_t cp, const char *list,
                                       const size_t len, const size_t size) {
  int n = (int)len;
  const char *p = list;
  struct sc *pos;
  while (n > 0) {
    pos = (struct sc *)(p + size * (n / 2));
    // hack: with unsigned wrapping max-cp is always higher, so false
    // was: (cp >= pos->from && cp <= pos->to)
    if ((cp - pos->from) <= (pos->to - pos->from))
      return pos;
    else if (cp < pos->from)
      n /= 2;
    else {
      p = (char *)pos + size;
      n -= (n / 2) + 1;
    }
  }
  return NULL;
}

static inline uint8_t sc_search(const uint32_t cp, const struct sc *sc_list,
                                const size_t len) {
  const struct sc *sc =
      (struct sc *)binary_search(cp, (char *)sc_list, len, sizeof(*sc_list));
  return sc ? sc->scr : 255;
}

static inline bool range_bool_search(const uint32_t cp,
                                     const struct range_bool *list,
                                     const size_t len) {
  const char *r = (char *)binary_search(cp, (char *)list, len, sizeof(*list));
  return r ? true : false;
}

uint8_t u8ident_get_script(const uint32_t cp) {
#if defined DISABLE_CHECK_XID || defined ENABLE_CHECK_XID
  // faster check, as we have no NON-xid's
  return sc_search(cp, nonxid_script_list, ARRAY_SIZE(nonxid_script_list));
#else
  if (s_u8id_options & U8ID_CHECK_XID) // we already checked for allowed
    return sc_search(cp, nonxid_script_list, ARRAY_SIZE(nonxid_script_list));
  else
    return sc_search(cp, xid_script_list, ARRAY_SIZE(xid_script_list));
#endif
}

/* list of script indices */
const char *u8ident_get_scx(const uint32_t cp) {
  const struct scx *scx = (struct scx *)binary_search(
      cp, (char *)scx_list, ARRAY_SIZE(scx_list), sizeof(*scx_list));
  return scx ? scx->list : NULL;
}

bool u8ident_is_bidi(const uint32_t cp) {
  return linear_search(cp, bidi_list, ARRAY_SIZE(bidi_list));
}

#ifndef DISABLE_CHECK_XID
//#ifndef HAVE_CROARING
bool u8ident_is_allowed(const uint32_t cp) {
  return range_bool_search(cp, allowed_id_list, ARRAY_SIZE(allowed_id_list));
}
bool u8ident_is_ID_Start(const uint32_t cp) {
  return range_bool_search(cp, id_start_list, ARRAY_SIZE(id_start_list));
}
bool u8ident_is_ID_Cont(const uint32_t cp) {
  return range_bool_search(cp, id_cont_list, ARRAY_SIZE(id_cont_list));
}
bool u8ident_is_XID_Start(const uint32_t cp) {
  return range_bool_search(cp, xid_start_list, ARRAY_SIZE(xid_start_list));
}
bool u8ident_is_XID_Cont(const uint32_t cp) {
  return range_bool_search(cp, xid_cont_list, ARRAY_SIZE(xid_cont_list));
}
//#endif

// bitmask of u8id_idtypes
uint16_t u8ident_get_idtypes(const uint32_t cp) {
  const struct range_short *id = (struct range_short *)binary_search(
      cp, (char *)idtype_list, ARRAY_SIZE(idtype_list), sizeof(*idtype_list));
  return id ? id->types : 0;
}
#endif

#ifdef HAVE_CONFUS
#  ifndef HAVE_CROARING
static int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}

EXTERN bool u8ident_is_confusable(const uint32_t cp) {
  return bsearch(&cp, confusables, ARRAY_SIZE(confusables), 4, compar32) != NULL
             ? true
             : false;
}
#  endif
#endif

const char *u8ident_script_name(const int scr) {
  if (scr < 0 || scr > LAST_SCRIPT)
    return NULL;
  assert(scr >= 0 && scr <= LAST_SCRIPT);
  return all_scripts[scr];
}

/* returns the failing codepoint, which failed in the last check. */
uint32_t u8ident_failed_char(const int i) {
  if (i >= 0 && i <= i_ctx) {
    const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    return c->last_cp;
  } else {
    return 0;
  }
}
/* returns the constant script name, which failed in the last check. */
const char *u8ident_failed_script_name(const int i) {
  if (i >= 0 && i <= i_ctx) {
    const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    const uint32_t cp = c->last_cp;
    if (cp > 0)
      return u8ident_script_name(u8ident_get_script(cp));
  }
  return NULL;
}

/* Optionally adds a script to the context, if it's known or declared
   beforehand. Such as `use utf8 "Greek";` in cperl.
   0, 1, 2 are always included by default.
*/
EXTERN int u8ident_add_script(uint8_t scr) {
  return u8ident_add_script_ctx(scr, u8ident_ctx());
}

/* Deletes the context generated with `u8ident_new_ctx`. This is
   optional, all remaining contexts are deleted by `u8ident_free` */
EXTERN int u8ident_free_ctx(int i) {
  if (i_ctx < U8ID_CTX_TRESH)
    ctxp = &ctx[0];
  if (i >= 0 && i <= i_ctx) {
    if (ctxp[i].count > 8)
      free(ctxp[i].u8p);
    ctxp[i].count = 0;
    if (i > 0)
      i_ctx = i - 1; // switch to the previous context
    else
      i_ctx = 0; // deleting 0 will lead to a reset
    return 0;
  } else
    return -1;
}

/* End this library, cleaning up all internal structures. */
EXTERN void u8ident_free(void) {
  for (int i = 0; i <= i_ctx; i++) {
    u8ident_free_ctx(i);
  }
  if (i_ctx >= U8ID_CTX_TRESH) {
    free(ctxp);
  }
#ifdef HAVE_CROARING
  u8ident_roar_free();
#endif
}

/* Returns a fresh string of the list of the seen scripts in this
   context whenever a mixed script error occurs. Needed for the error message
   "Invalid script %s, already have %s", where the 2nd %s is returned by this
   function. The returned string needs to be freed by the user.

   Usage:

   if (u8id_check("wrongᴧᴫ") == U8ID_ERR_SCRIPTS) {
       const char *errstr = u8ident_existing_scripts(ctx);
       fprintf(stdout, "Invalid script %s, already have %s\n",
           u8ident_failed_script_name(ctx),
           u8ident_existing_scripts(ctx));
     free(errstr);
   }
*/
const char *u8ident_existing_scripts(const int i) {
  if (unlikely(i < 0 || i > i_ctx))
    return NULL;
  const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
  const uint8_t *u8p = (c->count > 8) ? c->u8p : c->scr8;
  int len = c->count * 12;
  char *res = malloc(len);
  *res = 0;
  for (int j = 0; j < c->count; j++) {
    const char *str = u8ident_script_name(u8p[j]);
    if (!str)
      return NULL;
    const int l = strlen(str);
    if (*res) {
      if (l + 3 > len) {
        len = l + 3;
        res = realloc(res, len);
      }
      strcat(res, ", ");
    } else { // first name
      if (l + 1 > len) {
        len = l + 1;
        res = realloc(res, len);
      }
    }
    strcat(res, str);
  }
  return res;
}

#if 0
// TODO. Generate either if-trees, or sorted lists of those.
static bool _is_MARK(const uint32_t cp) {
  (void)cp;
  return true;
}
static bool _is_DECOMPOSED_REST(const uint32_t cp) {
  return cp < 128 || (cp >> 11) > 2 ? false : true;
}

/*
  Check for the right-hand-side of the Decomposition_Mapping property,
  which means the codepoint can be normalized, if the sequence is
  decomposed (NFD or NFKD).
  This is equivalent to all 1963 C<\p{IsM}> Mark characters,
  plus the remaining 869 non-mark and non-hangul normalizables.
*/

bool u8ident_is_decomposed(const uint32_t cp, const uint8_t scr) {
  if (scr == SC_Hangul || _is_MARK(cp))
    return true;
  return _is_DECOMPOSED_REST(cp);
}
#endif

/* quickcheck these lists
  NFD_QC_N
  NFC_QC_N
  NFC_QC_M
  NFKD_QC_N
  NFKC_QC_N
  NFKC_QC_M
 */
bool u8ident_maybe_normalized(const uint32_t cp) {

#if U8ID_NORM == FCC || U8ID_NORM == FCD
  (void)cp;
#endif

#if !defined U8ID_NORM
  if ((s_u8id_options & U8ID_NFMASK) == U8ID_NFC)
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFC
  {
#  if defined HAVE_CROARING && defined USE_NORM_CROAR
    return u8ident_roar_maybe_nfc(cp);
#  else
    if (range_bool_search(cp, NFC_N_list, ARRAY_SIZE(NFC_N_list)))
      return true;
    return range_bool_search(cp, NFC_M_list, ARRAY_SIZE(NFC_M_list));
#  endif
  }
#endif

#if !defined U8ID_NORM
  if ((s_u8id_options & U8ID_NFMASK) == U8ID_NFKC)
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFKC
  {
#  if defined HAVE_CROARING && defined USE_NORM_CROAR
    return u8ident_roar_maybe_nfkc(cp);
#  else
    if (range_bool_search(cp, NFKC_N_list, ARRAY_SIZE(NFKC_N_list)))
      return true;
    return range_bool_search(cp, NFKC_M_list, ARRAY_SIZE(NFKC_M_list));
#  endif
  }
#endif

#if !defined U8ID_NORM
  if ((s_u8id_options & U8ID_NFMASK) == U8ID_NFD)
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFD
  {
#  if defined HAVE_CROARING && defined USE_NORM_CROAR
    return u8ident_roar_maybe_nfd(cp);
#  else
    return !range_bool_search(cp, NFD_N_list, ARRAY_SIZE(NFD_N_list));
#  endif
  }
#endif

#if !defined U8ID_NORM
  if ((s_u8id_options & U8ID_NFMASK) == U8ID_NFKD)
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFKD
  {
#  if defined HAVE_CROARING && defined USE_NORM_CROAR
    return u8ident_roar_maybe_nfkd(cp);
#  else
    return !range_bool_search(cp, NFKD_N_list, ARRAY_SIZE(NFKD_N_list));
#  endif
  }
#endif
  return true;
}

// See also the Table 3. Unicode Script Property Values and ISO 15924 Codes
// https://www.unicode.org/reports/tr24/tr24-32.html#Relation_To_ISO15924

/*
The unicode standard 13 defines 157 scripts, i.e. written language
families.

    perl -alne'/; (\w+) #/ && print $1' lib/unicore/Scripts.txt | \
        sort -u

We add some aliases for languages using multiple scripts:

   :Japanese => Katakana Hiragana Han
   :Korean   => Hangul Han
   :Hanb     => Han Bopomofo

These three aliases need not to be declared. They are allowed scripts
in the [Highly Restriction
Level](http://www.unicode.org/reports/tr39/#Restriction_Level_Detection) for
identifiers.

Certain scripts don't need to be declared.

We follow by default the **Moderately Restrictive Level** for identifiers.
I.e. All characters in each identifier must be from a single script,
or from any of the following combinations:

Latin + Han + Hiragana + Katakana; or equivalently: Latn + Jpan

Latin + Han + Bopomofo; or equivalently: Latn + Hanb

Latin + Han + Hangul; or equivalently: Latn + Kore

Allow Latin with other Recommended scripts except
Cyrillic and Greek. Cyrillic and Greek may not be used together for
identifiers in the same file.

http://www.unicode.org/reports/tr31/#Table_Recommended_Scripts

   Common Inherited Arabic Armenian Bengali Bopomofo Cyrillic
   Devanagari Ethiopic Georgian Greek Gujarati Gurmukhi Hangul Han Hebrew
   Hiragana Katakana Kannada Khmer Lao Latin Malayalam Myanmar Oriya
   Sinhala Tamil Telugu Thaana Thai Tibetan

So these scripts need always to be declared explicitly:

   Ahom Anatolian_Hieroglyphs Avestan Bassa_Vah Bhaiksuki
   Brahmi Buginese Buhid Carian Caucasian_Albanian Coptic Cuneiform
   Cypriot Deseret Dogra Duployan Egyptian_Hieroglyphs Elbasan Elymaic
   Glagolitic Gothic Grantha Gunjala_Gondi Hanunoo Hatran
   Imperial_Aramaic Inscriptional_Pahlavi Inscriptional_Parthian Kaithi
   Kharoshthi Khojki Khudawadi Linear_A Linear_B Lycian Lydian Mahajani
   Makasar Manichaean Marchen Masaram_Gondi Medefaidrin Mende_Kikakui
   Meroitic_Cursive Meroitic_Hieroglyphs Modi Mongolian Mro Multani
   Nabataean Nandinagari Nushu Ogham Old_Hungarian Old_Italic
   Old_North_Arabian Old_Permic Old_Persian Old_Sogdian
   Old_South_Arabian Old_Turkic Osmanya Pahawh_Hmong Palmyrene
   Pau_Cin_Hau Phags_Pa Phoenician Psalter_Pahlavi Rejang Runic
   Samaritan Sharada Shavian Siddham SignWriting Sogdian Sora_Sompeng
   Soyombo Tagalog Tagbanwa Takri Tangut Tirhuta Ugaritic Warang_Citi
   Zanabazar_Square

All Limited Use Scripts are disallowed:
http://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts

   Adlam Balinese Bamum Batak Canadian_Aboriginal Chakma Cham Cherokee
   Hanifi_Rohingya Javanese Kayah_Li Lepcha Limbu Lisu Mandaic
   Meetei_Mayek Miao New_Tai_Lue Newa Nko Nyiakeng_Puachue_Hmong Ol_Chiki
   Osage Saurashtra Sundanese Syloti_Nagri Syriac Tai_Le Tai_Tham
   Tai_Viet Tifinagh Vai Wancho Yi Unknown

Scripts: ignore Latin, Common and Inherited.

Beware that some Common codes need the scx also.
Using the Script property alone, for example, will not detect that the
U+30FC ( ー ) KATAKANA-HIRAGANA PROLONGED SOUND MARK (Script=Common)
should not be mixed with Latin. See [UTS39] and [UTS46].

*/
