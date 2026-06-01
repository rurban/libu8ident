/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022, 2025, 2026 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   Amalgam: u8ident-tr39.c + u8idscr-tr39.c combined.
   Hardcoded for U8ID_PROFILE=TR39_4, U8ID_NORM=NFC, U8ID_TR31=TR39.
   No preprocessor conditionals in any function body.
*/

#undef HAVE_CONFIG_H

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <wchar.h>

#if __GNUC__ >= 4
#  define EXTERN __attribute__((visibility("default")))
#else
#  define EXTERN
#endif
#define LOCAL static

#include "u8ident_c.h"
#include "unitr39.h"

/* ===== Forward declarations ===== */
static const struct sc_tr39 *isTR39_start(const uint32_t cp);
static const struct sc_tr39 *isTR39_cont(const uint32_t cp);

/* ===== Globals ===== */
unsigned s_u8id_options = U8ID_TR31_DEFAULT;
enum u8id_norm s_u8id_norm = U8ID_NORM_DEFAULT;
enum u8id_profile s_u8id_profile = U8ID_PROFILE_DEFAULT;
unsigned s_maxlen = 1024;

/* ===== Context management ===== */
struct ctx_t ctx[U8ID_CTX_TRESH] = {0};
static u8id_ctx_t i_ctx = 0;
struct ctx_t *ctxp = NULL;

EXTERN u8id_ctx_t u8ident_new_ctx(void) {
  u8id_ctx_t i = i_ctx + 1;
  i_ctx++;
  if (i == U8ID_CTX_TRESH) {
    ctxp = (struct ctx_t *)calloc(U8ID_CTX_TRESH, sizeof(struct ctx_t));
  } else if (i > U8ID_CTX_TRESH) {
    struct ctx_t *tmp =
        (struct ctx_t *)realloc(ctxp, i * sizeof(struct ctx_t));
    if (tmp)
      ctxp = tmp;
  } else {
    ctxp = &ctx[i];
  }
  memset(ctxp, 0, sizeof(struct ctx_t));
  return i_ctx;
}

EXTERN int u8ident_set_ctx(u8id_ctx_t i) {
  if (i <= i_ctx) {
    i_ctx = i;
    return 0;
  } else
    return -1;
}

LOCAL struct ctx_t *u8ident_ctx(void) {
  return (i_ctx < U8ID_CTX_TRESH) ? &ctx[i_ctx] : &ctxp[i_ctx];
}

LOCAL bool u8ident_has_script_ctx(const uint8_t scr, const struct ctx_t *c) {
  if (!c->count)
    return false;
  const uint8_t *u8p = (c->count > 8) ? c->u8p : c->scr8;
  for (int i = 0; i < c->count; i++) {
    if (scr == u8p[i])
      return true;
  }
  return false;
}

LOCAL bool u8ident_has_script(const uint8_t scr) {
  return u8ident_has_script_ctx(scr, u8ident_ctx());
}

LOCAL int u8ident_add_script_ctx(const uint8_t scr, struct ctx_t *c) {
  if (scr < 2 || scr >= FIRST_LIMITED_USE_SCRIPT)
    return -1;
  int i = c->count;
  if (unlikely(i == 8)) {
    uint8_t *p = malloc(16);
    memcpy(p, c->scr8, 8);
    c->u8p = p;
    c->u8p[i] = scr;
  } else if (unlikely(i > 8 && (i & 7) == 7)) {
    c->u8p = realloc(c->u8p, i + 8);
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

/* ===== Search utilities ===== */

static inline bool linear_search(const uint32_t cp,
                                 const struct range_bool *sc_list,
                                 const int len) {
  struct range_bool *s = (struct range_bool *)sc_list;
  for (int i = 0; i < len; i++) {
    assert(s->from <= s->to);
    if ((cp - s->from) <= (s->to - s->from))
      return true;
    if (cp <= s->to)
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

static inline bool range_bool_search(const uint32_t cp,
                                     const struct range_bool *list,
                                     const size_t len) {
  return binary_search(cp, (char *)list, len, sizeof(*list)) ? true : false;
}

/* ===== Lookup functions ===== */

/* Search for TR39 XID entry, in start or cont lists */
LOCAL const struct sc_tr39 *u8ident_get_tr39(const uint32_t cp) {
  const struct sc_tr39 *sc = (const struct sc_tr39 *)binary_search(
      cp, (char *)tr39_start_list, ARRAY_SIZE(tr39_start_list),
      sizeof(*tr39_start_list));
  if (sc)
    return sc;
  else
    return (const struct sc_tr39 *)binary_search(cp, (char *)tr39_cont_list,
                                                 ARRAY_SIZE(tr39_cont_list),
                                                 sizeof(*tr39_cont_list));
}

EXTERN uint8_t u8ident_get_script(const uint32_t cp) {
  const struct sc_tr39 *sc = u8ident_get_tr39(cp);
  if (sc)
    return sc->sc;
  return SC_Unknown;
}

LOCAL bool u8ident_is_tr39_MEDIAL(uint32_t cp) {
  return range_bool_search(cp, tr39_medial_list, ARRAY_SIZE(tr39_medial_list));
}

LOCAL bool u8ident_is_bidi(const uint32_t cp) {
  return linear_search(cp, bidi_list, ARRAY_SIZE(bidi_list));
}

/* ===== XID classification functions ===== */

static const struct range_bool ascii_start_list[] = {
    {'$', '$'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}};
static const struct range_bool ascii_cont_list[] = {
    {'$', '$'},
    {'0', '9'},
};

LOCAL bool isASCII_start(const uint32_t cp) {
  return range_bool_search(cp, ascii_start_list, ARRAY_SIZE(ascii_start_list));
}
LOCAL bool isASCII_cont(const uint32_t cp) {
  return range_bool_search(cp, ascii_cont_list, ARRAY_SIZE(ascii_cont_list));
}
static const struct sc_tr39 *isTR39_start(const uint32_t cp) {
  return (const struct sc_tr39 *)binary_search(
      cp, (char *)tr39_start_list, ARRAY_SIZE(tr39_start_list),
      sizeof(*tr39_start_list));
}
static const struct sc_tr39 *isTR39_cont(const uint32_t cp) {
  return (const struct sc_tr39 *)binary_search(
      cp, (char *)tr39_cont_list, ARRAY_SIZE(tr39_cont_list),
      sizeof(*tr39_cont_list));
}

/* bool wrappers for func_tr31 table (which expects bool return) */
static bool isTR39_start_bool(const uint32_t cp) {
  return isTR39_start(cp) != NULL;
}
static bool isTR39_cont_bool(const uint32_t cp) {
  return isTR39_cont(cp) != NULL;
}

/* ===== Confusables ===== */

static inline int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}

bool u8ident_is_greek_latin_confus(const uint32_t cp) {
  return bsearch(&cp, greek_confus_list, ARRAY_SIZE(greek_confus_list), 4,
                 compar32) != NULL
             ? true
             : false;
}

/* ===== Script naming ===== */

EXTERN const char *u8ident_script_name(const int scr) {
  if (scr < 0 || scr > LAST_SCRIPT)
    return NULL;
  assert(scr >= 0 && scr <= LAST_SCRIPT);
  return all_scripts[scr];
}

EXTERN uint32_t u8ident_failed_char(const u8id_ctx_t i) {
  if (i <= i_ctx) {
    const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    return c->last_cp;
  } else {
    return 0;
  }
}

EXTERN const char *u8ident_failed_script_name(const u8id_ctx_t i) {
  if (i <= i_ctx) {
    const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    const uint32_t cp = c->last_cp;
    if (cp > 0)
      return u8ident_script_name(u8ident_get_script(cp));
  }
  return NULL;
}

EXTERN int u8ident_add_script(uint8_t scr) {
  return u8ident_add_script_ctx(scr, u8ident_ctx());
}

EXTERN int u8ident_free_ctx(u8id_ctx_t i) {
  if (i_ctx < U8ID_CTX_TRESH)
    ctxp = &ctx[0];
  if (i <= i_ctx) {
    if (ctxp[i].count > 8)
      free(ctxp[i].u8p);
    memset(&ctxp[i], 0, sizeof(u8id_ctx_t));
    if (i > 0)
      i_ctx = i - 1;
    else
      i_ctx = 0;
    return 0;
  } else
    return -1;
}

EXTERN void u8ident_free(void) {
  for (u8id_ctx_t i = 0; i <= i_ctx; i++) {
    u8ident_free_ctx(i);
  }
  if (i_ctx >= U8ID_CTX_TRESH) {
    free(ctxp);
  }
}

EXTERN const char *u8ident_existing_scripts(const u8id_ctx_t i) {
  if (unlikely(i > i_ctx))
    return NULL;
  const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
  const uint8_t *u8p = (c->count > 8) ? c->u8p : c->scr8;
  size_t len = c->count * 12;
  char *res = malloc(len);
  *res = 0;
  for (int j = 0; j < c->count; j++) {
    const char *str = u8ident_script_name(u8p[j]);
    if (!str) {
      free(res);
      return NULL;
    }
    const size_t l = strlen(str);
    if (*res) {
      if (l + 3 > len) {
        len = l + 3;
        res = realloc(res, len);
      }
      strcat(res, ", ");
    } else {
      if (l + 1 > len) {
        len = l + 1;
        res = realloc(res, len);
      }
    }
    strcat(res, str);
  }
  return res;
}

/* ===== Error strings ===== */

LOCAL const char *u8ident_errstr(int errcode) {
  static const char *const _str[] = {
      "ERR_CONFUS",           // -6
      "ERR_COMBINE",          // -5
      "ERR_ENCODING",         // -4
      "ERR_SCRIPTS",          // -3
      "ERR_SCRIPT",           // -2
      "ERR_XID",              // -1
      "EOK",                  // 0
      "EOK_NORM",             // 1
      "EOK_WARN_CONFUS",      // 2
      "EOK_NORM_WARN_CONFUS", // 3
  };
  assert(errcode >= -6 && errcode <= 3);
  return _str[errcode + 6];
}

/* ===== Init/config ===== */

EXTERN int u8ident_init(enum u8id_profile profile, enum u8id_norm norm,
                        unsigned options) {
  u8ident_free();
  if (options > 1023)
    return -1;
  if (profile < U8ID_PROFILE_1 || profile > U8ID_PROFILE_TR39_4)
    return -1;
  if (norm > U8ID_FCC)
    return -1;
  /* NFC only for this amalgam */
  if (norm != U8ID_NFC)
    return -1;
  s_u8id_norm = norm;
  s_u8id_profile = U8ID_PROFILE_TR39_4;
  s_u8id_options = (options & ~U8ID_TR31_MASK) | U8ID_TR31_DEFAULT;
  return 0;
}

enum u8id_norm u8ident_norm(void) { return s_u8id_norm; }
enum u8id_profile u8ident_profile(void) { return s_u8id_profile; }
enum u8id_options u8ident_tr31(void) {
  return (enum u8id_options)(s_u8id_options & 127);
}
unsigned u8ident_options(void) { return s_u8id_options; }

EXTERN void u8ident_set_maxlength(unsigned maxlen) {
  if (maxlen > 1)
    s_maxlen = maxlen;
}

unsigned u8ident_maxlength(void) { return s_maxlen; }

/* ===== SCX / NSM ===== */

bool in_SCX(const enum u8id_sc scr, const char *scx) {
  unsigned char *x = (unsigned char *)scx;
  while (*x) {
    if (*x == (unsigned char)scr)
      return true;
    x++;
  }
  return false;
}

bool nsm_check(const uint32_t base_cp, const uint32_t cp) {
  if (cp == 0x307 && (base_cp == 'i' || base_cp == 0x131 /* dotless i */
                      || base_cp == 0x237                 /* dotless j */
                      || base_cp == 0x25F     /* dotless j with stroke */
                      || base_cp == 0x284     /* dotless j with stroke and hook */
                      || base_cp == 0x1DA1    /* dotless j with stroke */
                      || base_cp == 0x10798   /* dotless i */
                      || base_cp == 0x1D6A4   /* dotless j */
                      || base_cp == 0x1D645)) /* dotless j */
    return false;

  for (unsigned i = 0; i < ARRAY_SIZE(nsm_letters); i++) {
    const struct nsm_ws *l = &nsm_letters[i];
    if (l->nsm > cp)
      break;
    if (l->nsm != cp)
      continue;
    if (wcschr(l->letters, (wchar_t)base_cp))
      return false;
  }
  return true;
}

/* ===== UTF-8 helpers ===== */

typedef struct {
  uint8_t mask;
  uint8_t lead;
  uint32_t beg;
  uint32_t end;
  int bits_stored;
} _utf_t;

static const _utf_t *utf[] = {
    // clang-format off
  [0] = &(_utf_t){0x3f/*0b00111111*/, 0x80/*0b10000000*/, 0,       0,        6},
  [1] = &(_utf_t){0x7f/*0b01111111*/, 0x00/*0b00000000*/, 0000,    0177,     7},
  [2] = &(_utf_t){0x1f/*0b00011111*/, 0xc0/*0b11000000*/, 0200,    03777,    5},
  [3] = &(_utf_t){0x0f/*0b00001111*/, 0xe0/*0b11100000*/, 04000,   0177777,  4},
  [4] = &(_utf_t){0x07/*0b00000111*/, 0xf0/*0b11110000*/, 0200000, 04177777, 3},
  &(_utf_t){0},
    // clang-format on
};

static int utf8_len(const unsigned char ch) {
  int len = 0;
  for (_utf_t **u = (_utf_t **)utf; *u; ++u) {
    if ((ch & ~(*u)->mask) == (*u)->lead)
      break;
    ++len;
  }
  return len;
}

LOCAL uint32_t dec_utf8(char **strp) {
  const unsigned char *str = (const unsigned char *)*strp;
  int bytes = utf8_len(*str);
  int shift;
  uint32_t cp;

  if (bytes > 4) {
    errno = EILSEQ;
    return 0;
  }
  shift = utf[0]->bits_stored * (bytes - 1);
  assert(shift >= 0);
  cp = (*str++ & utf[bytes]->mask) << shift;
  for (int i = 1; i < bytes; ++i, ++str) {
    shift -= utf[0]->bits_stored;
    assert(shift >= 0);
    cp |= (*str & utf[0]->mask) << shift;
  }
  *strp = (char *)str;
  return cp;
}

/* All TR39 codepoints are NFC-stable, so normalize is a trivial memcpy. */
EXTERN char *u8ident_normalize(const char *src, int srcsz) {
  char *dest = malloc(srcsz + 1);
  if (dest) {
    memcpy(dest, src, srcsz);
    dest[srcsz] = '\0';
  }
  return dest;
}

/* ===== u8ident_check_buf: core identifier checker ===== */

EXTERN enum u8id_errors u8ident_check_buf(const char *buf, const int bufsz,
                                          char **outnorm) {
  int ret = U8ID_EOK;
  char *s = (char *)buf;
  const char *e = (char *)&buf[bufsz];
  struct ctx_t *ctx = u8ident_ctx();
  enum u8id_sc scr;
  enum u8id_sc basesc = SC_Unknown;
  char *scx = NULL;
  uint32_t prev_cp = 0, base_cp = 0;
  int seq_mn = 0;
  uint32_t cp = dec_utf8(&s);

  (void)outnorm;

  /* Start character check via isTR39_start returning struct pointer */
  const struct sc_tr39 *tr39 = isTR39_start(cp);
  if (unlikely(!tr39)) {
    ctx->last_cp = cp;
    return U8ID_ERR_XID;
  }
  bool has_latin = u8ident_has_script_ctx(SC_Latin, ctx);

  do {
    scr = tr39->sc;

    /* disallow Limited Use scripts */
    if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT)) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }
    /* disallow bidi formatting */
    if (unlikely(!ctx->is_rtl && u8ident_is_bidi(cp))) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }

    bool is_new = false;

    /* check scx on Common or Inherited */
    if (scr == SC_Common || scr == SC_Inherited) {
      const struct sc_tr39 *this_scx = u8ident_get_tr39(cp);
      if (unlikely(this_scx && this_scx->scx)) {
        scx = (char *)this_scx->scx;
        const enum u8id_gc gc = (const enum u8id_gc)this_scx->gc;
        int n = 0;
        if (ctx->count) {
          /* Special-case for runs: only after japanese. */
          if (!ctx->is_japanese &&
              ((cp >= 0x30FC && cp <= 0x30FE) || cp == 0xFF70)) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          if (!has_latin) {
            if (strEQc(scx, "\x11\x12") && !ctx->is_japanese) {
              ctx->last_cp = cp;
              return U8ID_ERR_SCRIPTS;
            }
            if (strEQc(scx, "\x06\x0e\x0f\x11\x12") && !ctx->is_japanese &&
                !ctx->has_han && !ctx->is_korean) {
              ctx->last_cp = cp;
              return U8ID_ERR_SCRIPTS;
            }
          }
        }
        if (gc == GC_Mn || gc == GC_Mc) {
          if (!ctx->count || basesc == SC_Unknown) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (!in_SCX(basesc, this_scx->scx)) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (cp == prev_cp) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (gc == GC_Mn && ++seq_mn > 4) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (!nsm_check(base_cp, cp)) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          }
        } else {
          seq_mn = 0;
        }
        char *x = scx;
        while (*x) {
          bool has = u8ident_has_script_ctx(*x, ctx);
          n += has ? 1 : 0;
          x++;
        }
        if (!n)
          is_new = true;
      }
    } else {
      base_cp = cp;
    }

    /* ignore Latin - compatible with everything */
    if (likely(scr == SC_Latin)) {
      if (!u8ident_has_script_ctx(scr, ctx)) {
        has_latin = true;
        u8ident_add_script_ctx(scr, ctx);
      }
      basesc = scr;
      goto next;
    }

    /* if not already have it, add it */
    if (!is_new && !(scr == SC_Common || scr == SC_Inherited))
      is_new = !u8ident_has_script_ctx(scr, ctx);
    if (is_new) {
      /* if Limited Use it must have been already manually added */
      if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT)) {
        ctx->last_cp = cp;
        return U8ID_ERR_SCRIPT;
      }
      /* allowed is only one, unless it is an allowed combination */
      if (ctx->count) {
        /* check allowed CJK combinations */
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
          goto ok;
        }
        /* and disallow all other combinations (TR39_4) */
        else {
          if (ctx->count >= 2 || scr == SC_Cyrillic) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          /* some Greek may mix with Latin, only not confusables */
          if (scr == SC_Greek && has_latin) {
            if (u8ident_is_greek_latin_confus(cp)) {
              ctx->last_cp = cp;
              return U8ID_ERR_CONFUS;
            }
            goto ok;
          }
        }
      }
    ok:
      basesc = scr;
      if (!u8ident_has_script_ctx(scr, ctx))
        u8ident_add_script_ctx(scr, ctx);
    } else if (scr == SC_Greek && has_latin &&
               u8ident_is_greek_latin_confus(cp)) {
      /* not new, but still a possible greek confusable */
      ctx->last_cp = cp;
      return U8ID_ERR_CONFUS;
    } else if (scr != SC_Common && scr != SC_Inherited) {
      basesc = scr;
      base_cp = cp;
    } else {
      /* Check illegal runs using gc from the TR39 struct */
      const enum u8id_gc gc = tr39->gc;
      if (gc == GC_Mn || gc == GC_Me) {
        if (cp == prev_cp) {
          ctx->last_cp = cp;
          return U8ID_ERR_COMBINE;
        } else if (++seq_mn > 4) {
          ctx->last_cp = cp;
          return U8ID_ERR_COMBINE;
        } else if (!nsm_check(base_cp, cp)) {
          ctx->last_cp = cp;
          return U8ID_ERR_COMBINE;
        }
      }
      if (basesc == SC_Unknown &&
          (gc == GC_Mn || gc == GC_Me || gc == GC_Mc)) {
        ctx->last_cp = cp;
        return U8ID_ERR_COMBINE;
      }
    }

  next:
    prev_cp = cp;
    cp = dec_utf8(&s);
    if (likely(s <= e && cp != 0)) {
      tr39 = isTR39_cont(cp);
      if (unlikely(!tr39))
        tr39 = isTR39_start(cp);
      if (unlikely(!tr39)) {
        ctx->last_cp = cp;
        return U8ID_ERR_XID;
      }
      if (s == e && u8ident_is_tr39_MEDIAL(cp)) {
        ctx->last_cp = cp;
        return U8ID_ERR_XID;
      }
    }
  } while (s <= e);

  return ret;
}

EXTERN enum u8id_errors u8ident_check(const uint8_t *string, char **outnorm) {
  return u8ident_check_buf((char *)string, strlen((char *)string), outnorm);
}

/* The other primitive variant without mixed-scripts checks (stub). */
EXTERN enum u8id_errors u8ident_check_confusables(const char *buf,
                                                  const int bufsz) {
  (void)buf;
  (void)bufsz;
  fprintf(stderr,
          "Unsupported u8ident_check_confusables(), need --enable-confus\n");
  return -1;
}
