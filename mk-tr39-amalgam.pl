#!/usr/bin/perl
# mk-tr39-amalgam.pl — regenerate self-contained u8ident-tr39.c
# Usage: perl mk-tr39-amalgam.pl [srcdir]
# Requires: unifdef in $PATH or $UNIFDEF env var.
#
# The amalgam is structured as:
#   1. Fixed preamble (license, standard includes, inline types + enums,
#      unitr39.h, inlined data arrays, global state, errstr)
#   2. Generated from u8idscr.c via unifdef + filtering (only TR39-relevant
#      functions; skips everything that references XID/ID/ALLOWED/etc lists)
#   3. Fixed tail (TR39-specific init, utf8 helpers, check_buf, stubs)

use strict;
use warnings;

my $srcdir = $ARGV[0] // '.';
my $UNIFDEF = $ENV{UNIFDEF} // 'unifdef';

# Flags mirror Makefile.am U8IFDEF, plus -UNO_UNITR39 so unifdef collapses
# the #ifndef NO_UNITR39 guards and we get the TR39-enabled code paths.
my @flags = qw(
    -DU8ID_TR31=3 -DU8ID_PROFILE_TR39 -DU8ID_NORM=0
    -UHAVE_CROARING -UHAVE_CONFUS
    -DENABLE_CHECK_XID -UDISABLE_CHECK_XID
    -UDEBUG -UPERF_TEST -UDISABLE_U8ID_TR31
    -DU8ID_PROFILE=8 -UHAVE_CONFIG_H -UNO_UNITR39
);

# ── 1. Fixed preamble ─────────────────────────────────────────────────────────

print <<'PREAMBLE';
/* libu8ident_c - TR39-limited unicode security guidelines for C/C++ identifiers.
   Copyright 2021,2022,2025,2026 Reini Urban
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

/* ---- Data (unitr39.h is self-contained; remaining data inlined below) ---- */
#include "unitr39.h"

PREAMBLE

# ── Inline data arrays needed by the tail (from scripts.h, mark.h) ───────

sub extract_array {
    my ($file, $name) = @_;
    open my $fh, '<', "$srcdir/$file" or die "$file: $!";
    local $/;
    my $text = <$fh>;
    # Match: [LOCAL] const type name[] = { ... };
    $text =~ /(?:(?:LOCAL|U8ID_LOCAL)\s+)?(const\s+\S+\s+\Q$name\E\[\]\s*=\s*\{.+?\};)/s
        or die "Could not find $name in $file";
    return $1;
}

sub inline_array {
    my ($file, $name) = @_;
    my $def = extract_array($file, $name);
    # Strip LOCAL prefix if present
    $def =~ s/^(?:LOCAL|U8ID_LOCAL)\s+//;
    print "$def\n\n";
}

print "/* ---- Inlined data from scripts.h, mark.h ---- */\n\n";
inline_array('scripts.h', 'bidi_list');
inline_array('scripts.h', 'greek_confus_list');
inline_array('scripts.h', 'nonxid_script_list');
inline_array('scripts.h', 'scx_list');
inline_array('scripts.h', 'all_scripts');
inline_array('mark.h',   'nsm_letters');

print <<'PREAMBLE2';
/* ---- Global state ---- */

unsigned s_u8id_options = U8ID_TR31_ALLOWED;
enum u8id_norm s_u8id_norm = U8ID_NFC;
enum u8id_profile s_u8id_profile = U8ID_PROFILE_TR39_4;
unsigned s_maxlen = 1024;

LOCAL const char *u8ident_errstr(int errcode) {
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

PREAMBLE2
    u8ident_is_MEDIAL
    u8ident_get_tr39
);

my $in_body    = 0;  # 1 once we're past the file header
my @skip_stack = (); # non-empty while inside a function we are skipping
my $depth      = 0;  # brace depth inside the skipped function
my $tr39cont   = 0;  # state: 0=before, 1=in isTR39_cont, 2=just closed it

for my $line (@src) {

    # ── Advance past the file header (license, includes, global state) ──────
    # Skip until we reach the docstring comment before u8ident_new_ctx.
    # Print the trigger line itself so it appears in the output, then
    # continue processing normally.
    unless ($in_body) {
        if ($line =~ /^\/\* Generates a new identifier/) {
            $in_body = 1;
            print $line;   # emit the first line of the docstring
        }
        next;
    }

    # ── Stop before normalization helpers and trailing comment block ─────────
    last if $line =~ /^\/\* quickcheck these lists/;
    last if $line =~ /^LOCAL bool u8ident_maybe_normalized\b/;
    last if $line =~ m{^// See also the Table 3};

    # ── Enter skip mode when we hit a function we don't want ─────────────────
    if (!@skip_stack) {
        for my $fn (keys %skip_fn) {
            if ($line =~ /\b\Q$fn\E\b/ && $line =~ /\(/) {
                push @skip_stack, $fn;
                $depth = ($line =~ tr/\{//) - ($line =~ tr/\}//);
                last;
            }
        }
        next if @skip_stack;
    }

    # ── While in skip mode, track braces ─────────────────────────────────────
    if (@skip_stack) {
        $depth += ($line =~ tr/\{//);
        $depth -= ($line =~ tr/\}//);
        if ($depth <= 0) { pop @skip_stack; $depth = 0; }
        next;
    }

    # ── Track isTR39_cont to inject pointer wrappers after it ────────────────
    if ($tr39cont == 0 && $line =~ /^LOCAL bool isTR39_cont\b/) {
        $tr39cont = 1;
    } elsif ($tr39cont == 1 && $line =~ /^\}/) {
        $tr39cont = 2;
    }

    print $line;

    # ── Inject isTR39_start_p / isTR39_cont_p immediately after isTR39_cont ──
    if ($tr39cont == 2) {
        $tr39cont = 3;  # emit once only
        print <<'TR39_PTRS';

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

TR39_PTRS
    }
}

# ── 3. Fixed TR39 tail (init, check_buf, stubs) ───────────────────────────────
# Update this section when the core TR39 algorithm changes in u8ident.c.

print <<'TAIL';

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

TAIL
