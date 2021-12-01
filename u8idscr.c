/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

  Classify and search for the script property https://www.unicode.org/reports/tr24/tr24-32.html
  Implement http://www.unicode.org/reports/tr39/#Mixed_Script_Detection
*/

#include "u8ident.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "u8id_private.h"

#include "scripts.h"

extern unsigned s_u8id_options;
// not yet thread-safe
struct ctx_t ctx[U8ID_CTX_TRESH] = { 0 }; // pre-allocate 5 contexts
static int i_ctx = 0;
struct ctx_t *ctxp = NULL; // if more than 5 contexts

/* Generates a new identifier document/context/directory, which
   initializes a new list of seen scripts. */
EXTERN int u8ident_new_ctx(void) {
  // thread-safety later
  int i = i_ctx + 1;
  i_ctx++;
  if (i == U8ID_CTX_TRESH) {
    ctxp = (struct ctx_t *)calloc(U8ID_CTX_TRESH, sizeof (struct ctx_t));
  } else if (i > U8ID_CTX_TRESH) {
    ctxp = (struct ctx_t *)realloc(ctxp, i * sizeof (struct ctx_t));
  } else {
    ctxp = &ctx[i];
  }
  memset(ctxp, 0, sizeof( struct ctx_t ));
  return i_ctx;
}

/* Changes to the context previously generated with `u8ident_new_ctx`. */
EXTERN int u8ident_set_ctx(int i) {
  if (i >= 0 && i <= i_ctx) {
    i_ctx = i;
    return 0;
  }
  else
    return -1;
}

/* Changes to the context previously generated with `u8ident_new_ctx`. */
struct ctx_t * u8ident_ctx(void) {
  return (i_ctx < U8ID_CTX_TRESH) ? &ctx[i_ctx] : &ctxp[i_ctx];
}

bool u8ident_has_script(const uint8_t scr) {
  struct ctx_t *ctx = u8ident_ctx();
  uint8_t *u8p = (ctx->count > 8) ? ctx->u8p : ctx->scr8;
  for (int i=0; i < ctx->count; i++) {
    if (scr == u8p[i])
      return true;
  }
  return false;
}

// search in linear vector of scripts per ctx
bool u8ident_has_script_ctx(const uint8_t scr, const struct ctx_t *ctx) {
  const uint8_t *u8p = (ctx->count > 8) ? ctx->u8p : ctx->scr8;
  for (int i=0; i < ctx->count; i++) {
    if (scr == u8p[i])
      return true;
  }
  return false;
}
void u8ident_add_script_ctx(const uint8_t scr, struct ctx_t *ctx) {
  int i = ctx->count;
  uint8_t *u8p = (i > 7) ? ctx->u8p : ctx->scr8;
  if ((i & 7) == 7)
    ctx->u8p = realloc(ctx->u8p, (i+1) * 2);
  ctx->count++;
  u8p[i+1] = scr;
  return;
}

#if 0
static uint8_t sc_search_linear(const uint32_t cp, const struct sc *sc_list, const int len) {
  struct sc *s = (struct sc *)sc_list;
  // so far only linear search. TODO binary
  for (int i=0; i<len; i++) {
    assert(s->from <= s->to);
    if (cp >= s->from && cp <= s->to)
      return s->scr;
    if (cp <= s->to) // s is sorted. not found
      return 255;
    s++;
  }
  return 255;
}
#endif

static struct sc * binary_search(const uint32_t cp, const char *list, const size_t len, const size_t size) {
  int n = (int)len;
  const char *p = list;
  struct sc *pos;
  while (n > 0) {
    pos = (struct sc *)(p + size * (n / 2));
    if (cp >= pos->from && cp <= pos->to)
      return pos;
    else if (cp < pos->from)
      n /= 2;
    else {
      p = (char*)pos + size;
      n -= (n / 2) + 1;
    }
  }
  return NULL;
}

static inline uint8_t sc_search(const uint32_t cp, const struct sc *sc_list, const size_t len) {
  const struct sc* sc = (struct sc*)binary_search(cp, (char*)sc_list, len, sizeof(*sc_list));
  return sc ? sc->scr : 255;
}
static inline bool range_bool_search(const uint32_t cp, const struct range_bool *list, const size_t len) {
  const char* r = (char*)binary_search(cp, (char*)list, len, sizeof(*list));
  return r ? true : false;
}

uint8_t u8ident_get_script(const uint32_t cp) {
#ifndef DISABLE_CHECK_XID
  if (s_u8id_options & U8ID_CHECK_XID)
    return sc_search(cp, xid_script_list, sizeof(xid_script_list)/sizeof(*xid_script_list));
  else
#endif
    return sc_search(cp, nonxid_script_list, sizeof(nonxid_script_list)/sizeof(*nonxid_script_list));
}

/* list of script indices */
const char * u8ident_get_scx(const uint32_t cp) {
  const struct scx* scx = (struct scx*)binary_search(cp, (char*)scx_list,
                                           sizeof(scx_list)/sizeof(*scx_list), sizeof(*scx_list));
  return scx ? scx->list : NULL;
}

bool u8ident_is_allowed(const uint32_t cp) {
  return range_bool_search(cp, allowed_id_list, sizeof(allowed_id_list) / sizeof(*allowed_id_list));
}

// bitmask of u8id_idtypes
uint16_t u8ident_get_idtypes(const uint32_t cp) {
  const struct range_short* id = (struct range_short*)binary_search(cp, (char*)idtype_list,
                                           sizeof(idtype_list) / sizeof(*idtype_list), sizeof(*idtype_list));
  return id ? id->types : 0;
}

const char* u8ident_script_name(const int scr) {
  if (scr < 0 || scr > LAST_SCRIPT)
    return NULL;
  assert(scr >= 0 && scr <= LAST_SCRIPT);
  return all_scripts[scr];
}

/* returns the failing codepoint, which failed in the last check. */
uint32_t u8ident_failed_char(const int i) {
  if (i >= 0 && i <= i_ctx) {
    const struct ctx_t *ctx = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    return ctx->last_cp;
  } else {
    return 0;
  }
}
/* returns the constant script name, which failed in the last check. */
const char* u8ident_failed_script_name(const int i) {
  if (i >= 0 && i <= i_ctx) {
    const struct ctx_t *ctx = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    const uint32_t cp = ctx->last_cp;
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
  if (scr < 2 || scr >= FIRST_LIMITED_USE_SCRIPT)
    return -1;
  int i = i_ctx;
  int c = ctxp[i].count;
  if (c < 8) {
    ctxp[i].scr8[c] = scr;
  } else {
    if ((c & 7) == 7) // add a new word
      ctxp[i].u8p = realloc(ctxp[i].u8p, (c+1) * 2);
    ctxp[i].u8p[c] = scr;
  }
  ctxp[i].count++;
  return 0;
}

/* Deletes the context generated with `u8ident_new_ctx`. This is
   optional, all remaining contexts are deleted by `u8ident_delete` */
EXTERN int u8ident_delete_ctx(int i) {
  if (i >= 0 && i <= i_ctx) {
    if (ctxp[i].count > 8)
      free (ctxp[i].u8p);
    ctxp[i].count = 0;
    if (i > 0)
      i_ctx = i - 1; // switch to the previous context
    else
      i_ctx = 0; // deleting 0 will lead to a reset
    return 0;
  }
  else
    return -1;
}

/* End this library, cleaning up all internal structures. */
EXTERN void u8ident_delete(void) {
  for (int i=0; i<=i_ctx; i++) {
    u8ident_delete_ctx(i);
  }
  if (i_ctx >= U8ID_CTX_TRESH) {
    free (ctxp);
  }
}

/* Returns a fresh string of the list of the seen scripts in this
   context whenever a mixed script error occurs. Needed for the error message
   "Invalid script %s, already have %s", where the 2nd %s is returned by this function.
   The returned string needs to be freed by the user.
   Usage:
   if (u8id_check("wrongᴧᴫ") == U8ID_ERR_SCRIPTS) {
     const char *errstr = u8ident_existing_scripts(ctx);
     fprintf(stdout, "Invalid script %s, already have %s\n",
       u8ident_failed_script_name(ctx),
       u8ident_existing_scripts(ctx));
     free(errstr);
   }

*/
const char* u8ident_existing_scripts(const int i) {
  if (unlikely(i < 0 || i > i_ctx))
    return NULL;
  const struct ctx_t *ctx = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
  const uint8_t *u8p = (ctx->count > 8) ? ctx->u8p : ctx->scr8;
  int len = ctx->count * 12;
  char *res = malloc(len);
  *res = 0;
  for (int j=0; j < ctx->count; j++) {
    const char* str = u8ident_script_name(u8p[j]);
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
in the [Highly Restriction Level](http://www.unicode.org/reports/tr39/#Restriction_Level_Detection)
for identifiers.

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
