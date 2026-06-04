/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021,2022,2025 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   TR39 amalgam — single-file implementation for C compiler integration.
   No preprocessor conditionals.  Profile hardcoded to TR39_4.
 */
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <wchar.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Visibility and compiler hints (inlined from u8id_private.h) ---- */
#if defined _WIN32 || defined __CYGWIN__
#  define U8ID_EXTERN __declspec(dllexport)
#  define U8ID_LOCAL
#elif __GNUC__ >= 4
#  define U8ID_EXTERN __attribute__((visibility("default")))
#  define U8ID_LOCAL __attribute__((visibility("hidden")))
#else
#  define U8ID_EXTERN
#  define U8ID_LOCAL
#endif

#if __GNUC__ >= 3
#  define likely(expr)   __builtin_expect((long)((expr) != 0), 1)
#  define unlikely(expr) __builtin_expect((long)((expr) != 0), 0)
#  define INLINE static inline
#else
#  define likely(expr)   (expr)
#  define unlikely(expr) (expr)
#  define INLINE static
#endif

/* ---- Utility macros ---- */
#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)
#define strEQ(s1, s2) !strcmp((s1), (s2))
#define strEQc(s1, s2) !strcmp((s1), s2 "")

/* ---- Types and constants (inlined from u8id_private.h + u8ident.h) ---- */

#define U8ID_CTX_TRESH 5
#define U8ID_SCR_TRESH 8

struct ctx_t {
  uint8_t count;
  uint8_t has_han : 1;
  uint8_t is_japanese : 1;
  uint8_t is_chinese : 1;
  uint8_t is_korean : 1;
  uint8_t is_rtl : 1;
  uint32_t last_cp;
  union {
    uint64_t scr64;
    uint8_t scr8[U8ID_SCR_TRESH];
    uint8_t *u8p;
  };
};

typedef unsigned u8id_ctx_t;

enum u8id_norm {
  U8ID_NFC = 0,
  U8ID_NFD = 1,
  U8ID_NFKC = 2,
  U8ID_NFKD = 3,
  U8ID_FCD = 4,
  U8ID_FCC = 5
};

enum u8id_profile {
  U8ID_PROFILE_1 = 1,
  U8ID_PROFILE_2 = 2,
  U8ID_PROFILE_3 = 3,
  U8ID_PROFILE_4 = 4,
  U8ID_PROFILE_5 = 5,
  U8ID_PROFILE_6 = 6,
  U8ID_PROFILE_C11_6 = 7,
  U8ID_PROFILE_TR39_4 = 8,
};

enum u8id_options {
  U8ID_TR31_XID = 64,
  U8ID_TR31_ID = 65,
  U8ID_TR31_ALLOWED = 66,
  U8ID_TR31_TR39 = 67,
  U8ID_TR31_C23 = 68,
  U8ID_TR31_C11 = 69,
  U8ID_TR31_ALLUTF8 = 70,
  U8ID_TR31_ASCII = 71,
  U8ID_FOLDCASE = 128,
  U8ID_WARN_CONFUSABLE = 256,
  U8ID_ERROR_CONFUSABLE = 512,
};
#define U8ID_TR31_MASK 127

enum u8id_errors {
  U8ID_EOK = 0,
  U8ID_EOK_NORM = 1,
  U8ID_EOK_WARN_CONFUS = 2,
  U8ID_EOK_NORM_WARN_CONFUS = 3,
  U8ID_ERR_XID = -1,
  U8ID_ERR_SCRIPT = -2,
  U8ID_ERR_SCRIPTS = -3,
  U8ID_ERR_ENCODING = -4,
  U8ID_ERR_COMBINE = -5,
  U8ID_ERR_CONFUS = -6,
};

#define U8ID_NORM_DEFAULT U8ID_NFC
#define U8ID_PROFILE_DEFAULT U8ID_PROFILE_TR39_4
#define U8ID_TR31_DEFAULT U8ID_TR31_TR39

/* ---- Data headers with definitions (no EXTERN_SCRIPTS = define U8ID_LOCAL arrays) ---- */
#include "unitr39.h"

/* ---- Global state ---- */

unsigned s_u8id_options = U8ID_TR31_ALLOWED;
enum u8id_norm s_u8id_norm = U8ID_NFC;
enum u8id_profile s_u8id_profile = U8ID_PROFILE_TR39_4;
unsigned s_maxlen = 1024;

U8ID_LOCAL const char *u8ident_errstr(int errcode) {
  static const char *const _str[] = {
      "ERR_CONFUS",      "ERR_COMBINE",          "ERR_ENCODING",
      "ERR_SCRIPTS",     "ERR_SCRIPT",           "ERR_XID",
      "EOK",             "EOK_NORM",             "EOK_WARN_CONFUS",
      "EOK_NORM_WARN_CONFUS",
  };
  assert(errcode >= -6 && errcode <= 3);
  return _str[errcode + 6];
}

/* ---- Context management ---- */

struct ctx_t ctx[U8ID_CTX_TRESH] = {{0}};
static u8id_ctx_t i_ctx = 0;
struct ctx_t *ctxp = NULL;

/* Generates a new identifier document/context/directory, which
   initializes a new list of seen scripts. */
U8ID_EXTERN u8id_ctx_t u8ident_new_ctx(void) {
  // thread-safety later
  u8id_ctx_t i = ++i_ctx;
  if (i == U8ID_CTX_TRESH) {
    ctxp = (struct ctx_t *)calloc(U8ID_CTX_TRESH + 1, sizeof(struct ctx_t));
    if (!ctxp) {
      fprintf(stderr, "u8ident: out of memory\n"); abort();
    }
    // extra work, just for debugging. we never access these
    memcpy(ctxp, &ctx, U8ID_CTX_TRESH * sizeof(struct ctx_t));
  } else if (i > U8ID_CTX_TRESH) {
    struct ctx_t *p = (struct ctx_t *)realloc(ctxp, (i + 1) * sizeof(struct ctx_t));
    if (!p) {
      fprintf(stderr, "u8ident: out of memory\n"); abort();
    }
    ctxp = p;
    memset(&ctxp[i], 0, sizeof(struct ctx_t));
  } else {
    ctxp = &ctx[i];
  }
  return i_ctx;
}

/* Changes to the context previously generated with `u8ident_new_ctx`. */
U8ID_EXTERN int u8ident_set_ctx(u8id_ctx_t i) {
  if (i <= i_ctx) {
    i_ctx = i;
    return 0;
  } else
    return -1;
}

/* Changes to the context previously generated with `u8ident_new_ctx`. */
U8ID_LOCAL struct ctx_t *u8ident_ctx(void) {
  return (i_ctx < U8ID_CTX_TRESH) ? &ctx[i_ctx] : &ctxp[i_ctx];
}

// search in linear vector of scripts per ctx
U8ID_LOCAL bool u8ident_has_script_ctx(const uint8_t scr, const struct ctx_t *c) {
  if (!c->count)
    return false;
  const uint8_t *u8p = (c->count > 8) ? c->u8p : c->scr8;
  for (int i = 0; i < c->count; i++) {
    if (scr == u8p[i])
      return true;
  }
  return false;
}

U8ID_LOCAL bool u8ident_has_script(const uint8_t scr) {
  return u8ident_has_script_ctx(scr, u8ident_ctx());
}

U8ID_LOCAL int u8ident_add_script_ctx(const uint8_t scr, struct ctx_t *c) {
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

static inline void *binary_search(const uint32_t cp, const char *list,
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

// hybrid search: linear or binary
static inline uint8_t sc_search(const uint32_t cp, const struct sc *sc_list,
                                const size_t len) {
  if (cp < 255) { // 14 ranges a 9 byte (126 byte, i.e cache loads)
    struct sc *s = (struct sc *)sc_list;
    for (size_t i = 0; i < len; i++) {
      if ((cp - s->from) <= (s->to - s->from)) // faster in-between trick
        return s->scr;
      if (cp <= s->to) // s is sorted. not found
        return 255;
      s++;
    }
    return 255;
  } else {
    const struct sc *sc =
        (struct sc *)binary_search(cp, (char *)sc_list, len, sizeof(*sc_list));
    return sc ? sc->scr : 255;
  }
}

static inline bool range_bool_search(const uint32_t cp,
                                     const struct range_bool *list,
                                     const size_t len) {
  return binary_search(cp, (char *)list, len, sizeof(*list)) ? true : false;
}

U8ID_EXTERN uint8_t u8ident_get_script(const uint32_t cp) {
  // faster check, as we have no NON-xid's
  return sc_search(cp, nonxid_script_list, ARRAY_SIZE(nonxid_script_list));
}

/* Search for list of script indices */
U8ID_LOCAL const struct scx *u8ident_get_scx(const uint32_t cp) {
  return (const struct scx *)binary_search(
      cp, (char *)scx_list, ARRAY_SIZE(scx_list), sizeof(*scx_list));
}

U8ID_LOCAL bool isTR39_start(const uint32_t cp) {
  return binary_search(cp, (char *)tr39_start_list, ARRAY_SIZE(tr39_start_list),
                       sizeof(*tr39_start_list))
             ? true
             : false;
}
U8ID_LOCAL bool isTR39_cont(const uint32_t cp) {
  return binary_search(cp, (char *)tr39_cont_list, ARRAY_SIZE(tr39_cont_list),
                       sizeof(*tr39_cont_list))
             ? true
             : false;
}

/* ---- TR39 lookup ---- */
/* Internal: struct-pointer versions used by check_buf */
static const struct sc_tr39 *isTR39_start_p(const uint32_t cp) {
  return (const struct sc_tr39 *)binary_search(
      cp, (char *)tr39_start_list, ARRAY_SIZE(tr39_start_list),
      sizeof(*tr39_start_list));
}

static const struct sc_tr39 *isTR39_cont_p(const uint32_t cp) {
  return (const struct sc_tr39 *)binary_search(
      cp, (char *)tr39_cont_list, ARRAY_SIZE(tr39_cont_list),
      sizeof(*tr39_cont_list));
}

U8ID_LOCAL const struct sc_tr39 *u8ident_get_tr39(const uint32_t cp) {
  const struct sc_tr39 *sc = isTR39_start_p(cp);
  return sc ? sc : isTR39_cont_p(cp);
}


// bitmask of u8id_idtypes
U8ID_LOCAL uint16_t u8ident_get_idtypes(const uint32_t cp) {
  const struct range_short *id = (struct range_short *)binary_search(
      cp, (char *)idtype_list, ARRAY_SIZE(idtype_list), sizeof(*idtype_list));
  return id ? id->types : 0;
}

static inline int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}

U8ID_EXTERN bool u8ident_is_greek_latin_confus(const uint32_t cp) {
  return bsearch(&cp, greek_confus_list, ARRAY_SIZE(greek_confus_list),
                 sizeof(*greek_confus_list), compar32) != NULL;
}


U8ID_EXTERN const char *u8ident_script_name(const int scr) {
  if (scr < 0 || scr > LAST_SCRIPT)
    return NULL;
  assert(scr >= 0 && scr <= LAST_SCRIPT);
  return all_scripts[scr];
}

/* returns the failing codepoint, which failed in the last check. */
U8ID_EXTERN uint32_t u8ident_failed_char(const u8id_ctx_t i) {
  if (i <= i_ctx) {
    const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    return c->last_cp;
  } else {
    return 0;
  }
}
/* returns the constant script name, which failed in the last check. */
U8ID_EXTERN const char *u8ident_failed_script_name(const u8id_ctx_t i) {
  if (i <= i_ctx) {
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
U8ID_EXTERN int u8ident_add_script(uint8_t scr) {
  return u8ident_add_script_ctx(scr, u8ident_ctx());
}

/* Deletes the context generated with `u8ident_new_ctx`. This is
   optional, all remaining contexts are deleted by `u8ident_free` */
U8ID_EXTERN int u8ident_free_ctx(u8id_ctx_t i) {
  if (i_ctx < U8ID_CTX_TRESH)
    ctxp = &ctx[0];
  if (i <= i_ctx) {
    if (ctxp[i].count > 8)
      free(ctxp[i].u8p);
    memset(&ctxp[i], 0, sizeof(u8id_ctx_t));
    if (i > 0)
      i_ctx = i - 1; // switch to the previous context
    else
      i_ctx = 0; // deleting 0 will lead to a reset
    return 0;
  } else
    return -1;
}

/* End this library, cleaning up all internal structures. */
U8ID_EXTERN void u8ident_free(void) {
  for (u8id_ctx_t i = 0; i <= i_ctx; i++) {
    u8ident_free_ctx(i);
  }
  if (i_ctx >= U8ID_CTX_TRESH) {
    free(ctxp);
  }
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
U8ID_EXTERN const char *u8ident_existing_scripts(const u8id_ctx_t i) {
  if (unlikely(i > i_ctx))
    return NULL;
  const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
  const uint8_t *u8p = (c->count > 8) ? c->u8p : c->scr8;
  /* First pass: compute exact allocation size. */
  size_t len = 1; /* NUL terminator */
  for (int j = 0; j < c->count; j++) {
    const char *str = u8ident_script_name(u8p[j]);
    if (!str)
      return NULL;
    if (j > 0)
      len += 2; /* ", " separator */
    len += strlen(str);
  }
  char *res = malloc(len);
  if (!res)
    return NULL;
  /* Second pass: write into the exact-sized buffer. */
  char *p = res;
  for (int j = 0; j < c->count; j++) {
    const char *str = u8ident_script_name(u8p[j]);
    if (j > 0) {
      memcpy(p, ", ", 2);
      p += 2;
    }
    const size_t l = strlen(str);
    memcpy(p, str, l);
    p += l;
  }
  *p = '\0';
  return res;
}


/* ---- tr31 function table ---- */

/* ---- tr31 options ---- */

U8ID_LOCAL enum u8id_options u8ident_tr31(void) {
  return U8ID_TR31_DEFAULT;
}

/* ---- Initialization  (hardcoded TR39_4) ---- */

U8ID_EXTERN int u8ident_init(enum u8id_profile profile, enum u8id_norm norm,
                        unsigned options) {
  if (options > 1023)
    return -1;
  if (profile < U8ID_PROFILE_1 || profile > U8ID_PROFILE_TR39_4)
    return -1;
  if (norm > U8ID_FCC)
    return -1;
  u8ident_free();
  s_u8id_norm = U8ID_NFC;
  s_u8id_profile = U8ID_PROFILE_TR39_4;
  s_u8id_options = (options & ~127) | U8ID_TR31_ALLOWED;
  return 0;
}

enum u8id_norm u8ident_norm(void) { return s_u8id_norm; }
enum u8id_profile u8ident_profile(void) { return s_u8id_profile; }
unsigned u8ident_options(void) { return s_u8id_options; }

U8ID_EXTERN void u8ident_set_maxlength(unsigned maxlen) {
  if (maxlen > 1)
    s_maxlen = maxlen;
}
unsigned u8ident_maxlength(void) { return s_maxlen; }

/* ---- Helper: check if script is in SCX byte-string ---- */

static bool in_SCX(const enum u8id_sc scr, const char *scx) {
  unsigned char *x = (unsigned char *)scx;
  while (*x) {
    if (*x == (unsigned char)scr)
      return true;
    x++;
  }
  return false;
}

/* ---- NSM check (non-spacing mark sequences to forbid) ---- */

static bool nsm_check(const uint32_t base_cp, const uint32_t cp) {
  if (cp == 0x307 && (base_cp == 'i' || base_cp == 0x131 ||
                       base_cp == 0x237 || base_cp == 0x25F ||
                       base_cp == 0x284 || base_cp == 0x1DA1 ||
                       base_cp == 0x10798 || base_cp == 0x1D6A4 ||
                       base_cp == 0x1D645))
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

/* ---- UTF-8 helpers ---- */

typedef struct {
  uint8_t mask;
  uint8_t lead;
  uint32_t beg;
  uint32_t end;
  int bits_stored;
} _utf_t;

static const _utf_t *utf[] = {
    [0] = &(_utf_t){0x3f, 0x80, 0,       0,        6},
    [1] = &(_utf_t){0x7f, 0x00, 0000,    0177,     7},
    [2] = &(_utf_t){0x1f, 0xc0, 0200,    03777,    5},
    [3] = &(_utf_t){0x0f, 0xe0, 04000,   0177777,  4},
    [4] = &(_utf_t){0x07, 0xf0, 0200000, 04177777, 3},
    &(_utf_t){0},
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

U8ID_LOCAL uint32_t dec_utf8(char **strp) {
  const unsigned char *str = (const unsigned char *)*strp;
  int bytes = utf8_len(*str);
  int shift;
  uint32_t cp;
  if (bytes > 4) {
    errno = EILSEQ;
    return 0;
  }
  shift = utf[0]->bits_stored * (bytes - 1);
  cp = (*str++ & utf[bytes]->mask) << shift;
  for (int i = 1; i < bytes; ++i, ++str) {
    shift -= utf[0]->bits_stored;
    cp |= (*str & utf[0]->mask) << shift;
  }
  *strp = (char *)str;
  return cp;
}

/* ---- Core: check_buf (no #if, uses struct pointers) ---- */
/* FXIME: update from unifdef u8ident.c */

U8ID_EXTERN enum u8id_errors u8ident_check_buf(const char *buf, const int bufsz,
                                          char **outnorm) {
  char *s = (char *)buf;
  const char *e = (char *)&buf[bufsz];
  struct ctx_t *ctx = u8ident_ctx();
  enum u8id_errors ret = U8ID_EOK;
  (void)outnorm;

  uint32_t prev_cp = 0, base_cp = 0;
  int seq_mn = 0;
  enum u8id_sc basesc = SC_Unknown;
  bool has_latin = u8ident_has_script_ctx(SC_Latin, ctx);

  uint32_t cp = dec_utf8(&s);
  const struct sc_tr39 *tr39 = isTR39_start_p(cp);
  if (unlikely(!tr39)) {
    ctx->last_cp = cp;
    return U8ID_ERR_XID;
  }

  do {
    enum u8id_sc scr = tr39->sc;
    bool is_new = false;
    char *scx = NULL;

    /* Latin always compatible */
    if (likely(scr == SC_Latin)) {
      if (!u8ident_has_script_ctx(SC_Latin, ctx)) {
        has_latin = true;
        u8ident_add_script_ctx(SC_Latin, ctx);
      }
      basesc = scr;
      goto next_cp;
    }

    /* Disallow Limited Use scripts */
    if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT)) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }
    /* Disallow bidi formatting */
    if (unlikely(!ctx->is_rtl && u8ident_is_bidi(cp))) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }

    /* Common/Inherited SCX handling */
    if (scr == SC_Common || scr == SC_Inherited) {
      tr39 = u8ident_get_tr39(cp);
      if (tr39 && tr39->scx) {
        scx = (char *)tr39->scx;
        const enum u8id_gc gc = tr39->gc;
        int n = 0;
        if (ctx->count) {
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
          } else if (!in_SCX(basesc, tr39->scx)) {
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
          n += u8ident_has_script_ctx(*x, ctx) ? 1 : 0;
          x++;
        }
        if (!n)
          is_new = true;
      }
    } else {
      base_cp = cp;
    }

    /* New script detection */
    if (!is_new && !(scr == SC_Common || scr == SC_Inherited))
      is_new = !u8ident_has_script_ctx(scr, ctx);

    if (is_new) {
      if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT)) {
        ctx->last_cp = cp;
        return U8ID_ERR_SCRIPT;
      }
      if (ctx->count) {
        if (scr == SC_Bopomofo) {
          if (unlikely(!ctx->has_han && !has_latin)) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          goto add_ok;
        } else if (scr == SC_Han) {
          if (unlikely(!(ctx->is_chinese || ctx->is_japanese ||
                         ctx->is_korean || has_latin))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          goto add_ok;
        } else if (scr == SC_Katakana || scr == SC_Hiragana) {
          if (unlikely(!(ctx->is_japanese || ctx->has_han || has_latin))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          goto add_ok;
        } else if (scr == SC_Common || scr == SC_Inherited) {
          goto add_ok;
        }
        /* TR39_4: max 2 scripts, no Cyrillic */
        if (ctx->count >= 2 || scr == SC_Cyrillic) {
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        }
        /* Greek confusable check */
        if (scr == SC_Greek && has_latin) {
          if (u8ident_is_greek_latin_confus(cp)) {
            ctx->last_cp = cp;
            return U8ID_ERR_CONFUS;
          }
          goto add_ok;
        }
      }
add_ok:
      basesc = scr;
      if (!u8ident_has_script_ctx(scr, ctx))
        u8ident_add_script_ctx(scr, ctx);
    } else if (scr != SC_Common && scr != SC_Inherited) {
      basesc = scr;
      base_cp = cp;
    } else {
      /* Existing Common/Inherited without SCX */
      if (scr == SC_Greek && has_latin &&
          u8ident_is_greek_latin_confus(cp)) {
        ctx->last_cp = cp;
        return U8ID_ERR_CONFUS;
      }
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

next_cp:
    prev_cp = cp;
    cp = dec_utf8(&s);
    if (likely(s <= e && cp != 0)) {
      tr39 = isTR39_cont_p(cp);
      if (unlikely(!tr39))
        tr39 = isTR39_start_p(cp);
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

/* ---- String wrapper ---- */

U8ID_EXTERN enum u8id_errors u8ident_check(const uint8_t *string, char **outnorm) {
  return u8ident_check_buf((char *)string, strlen((char *)string), outnorm);
}
