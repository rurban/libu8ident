/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021,2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "u8id_private.h"
#include "u8ident.h"
#include "u8idscr.h"
#ifdef HAVE_CROARING
#  include "u8idroar.h"
#endif
#define EXTERN_SCRIPTS
#include "unitr39.h"
#include "medial.h"
#undef EXTERN_SCRIPTS
#ifdef HAVE_CONFUS
#  ifndef HAVE_CROARING
#    define EXTERN_SCRIPTS
#  endif
#  include "confus.h"
#endif

static char buf[128]; // for hex display

// private access
unsigned u8ident_options(void);
enum u8id_profile u8ident_profile(void);
char *enc_utf8(char *dest, size_t *lenp, const uint32_t cp);

static inline bool is_profile_6(void) {
  return u8ident_profile() == 6 || u8ident_profile() == C11_6;
}
//static inline bool is_profile_4(void) {
//  return u8ident_profile() == 4 || u8ident_profile() == TR39_4;
//}

// check if the library can be used without init: script lookups, default checks
void test_scripts_no_init(void) {
#ifdef HAVE_CROARING
  // well, this needs an init
  assert(!u8ident_roar_init());
#endif
  assert(u8ident_get_script(0x41) == 2);
  assert(u8ident_get_script(0x5a) == 2);
  assert(strcmp(u8ident_script_name(0), "Common") == 0);
  assert(strcmp(u8ident_script_name(1), "Inherited") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x2EB)), "Bopomofo") ==
         0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x371)), "Greek") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x3132)), "Hangul") ==
         0);
  assert(!u8ident_get_scx(0x3132));
  const struct scx *scx = u8ident_get_scx(0x309A);
  assert(scx);
  assert(scx->gc == GC_Mn);
  assert(strlen(scx->scx) == 2);
  assert(scx->scx[0] == 0x11); // Hiragana
  assert(scx->scx[1] == 0x12); // Katakana
  scx = u8ident_get_scx(0x30FC);
  assert(scx);
  assert(scx->gc == GC_Lm);
  assert(strlen(scx->scx) == 2);
  assert(scx->scx[0] == 0x11); // Hiragana
  assert(scx->scx[1] == 0x12); // Katakana
  scx = u8ident_get_scx(0x064B);
  assert(scx);
  assert(scx->gc == GC_Mn);
  assert(strlen(scx->scx) == 2);
  assert(scx->scx[0] == 0x03);   // Arab
  assert(strcmp(u8ident_script_name((uint8_t)scx->scx[0]), "Arabic") == 0);
  assert(strcmp(u8ident_script_name((uint8_t)scx->scx[1]), "Syriac") == 0);
#ifndef DISABLE_CHECK_XID
  assert(!isID_start('0'));
  assert(!isXID_start('0'));
  assert(!isALLOWED_start('0'));
  assert(!isC11_start('0'));
#if !defined U8ID_NORM || U8ID_NORM == NFC
  assert(!isC23_start('0'));
#endif
  assert(!isTR39_start('0'));
  assert(!isALLUTF8_start('0'));
  assert(!isASCII_start('0'));
  assert(isID_cont('0'));
  assert(isXID_cont('0'));
  assert(isALLOWED_cont('0'));
  assert(isC11_cont('0'));
#if !defined U8ID_NORM || U8ID_NORM == NFC
  assert(isC23_cont('0'));
#endif
  assert(isTR39_cont('0'));
  assert(isALLUTF8_cont('0'));
  assert(isASCII_cont('0'));

  assert(!isID_start('$'));
  assert(!isXID_start('$'));
  assert(!isID_cont('$'));
  assert(!isXID_cont('$'));
  assert(!isALLOWED_start('$'));
  assert(!isALLOWED_cont('$'));
  // GH #25: It is implementation-defined if $ is allowed in identifiers
#ifdef ALLOW_DOLLAR /* default */
  assert(isC11_start('$'));
  assert(isTR39_start('$'));
  assert(isC23_start('$'));
  assert(isC11_cont('$'));
  assert(isTR39_cont('$'));
  assert(isC23_cont('$'));
#else
  assert(!isC11_start('$'));
  assert(!isTR39_start('$'));
  assert(!isC23_start('$'));
  assert(!isC11_cont('$'));
  assert(!isTR39_cont('$'));
  assert(!isC23_cont('$'));
#endif

  assert(isALLOWED_cont(0x27));  // '
  assert(!isALLOWED_cont(0x26)); // &
  assert(isALLOWED_cont(0x40e)); // Ў
#if !defined U8ID_NORM || U8ID_NORM == NFC
  assert(isC23_cont(0x311)); // ̑
#endif
  
  assert(u8ident_get_idtypes(0x102E2) == (U8ID_Obsolete | U8ID_Not_XID));
#endif
  // check that no list elements can be merged
#if !defined DISABLE_CHECK_XID && !defined ENABLE_CHECK_XID
  for (size_t i = 0; i < ARRAY_SIZE(xid_script_list) - 1; i++) {
    const struct sc *r = &xid_script_list[i];
    const struct sc *n = &xid_script_list[i + 1];
    assert(r->from <= r->to);
    assert(r->to <= n->from);
    if (r->to + 1 >= n->from) {
      if (r->scr == n->scr)
        printf("ERROR U+%X .. U+%X both with SC %d\n", r->to, n->from, r->scr);
      assert(r->scr != n->scr); // can not be merged
    }
    // if (r->to + 1 != n->from) {
    //   printf("  Unknown at U+%X .. U+%X Zzzz\n", r->to + 1, n->from - 1);
    // }
  }
#endif
  for (size_t i = 0; i < ARRAY_SIZE(nonxid_script_list) - 1; i++) {
    const struct sc *r = &nonxid_script_list[i];
    const struct sc *n = &nonxid_script_list[i + 1];
    assert(r->from <= r->to);
    assert(r->to <= n->from);
    if (r->to + 1 >= n->from) {
      if (r->scr == n->scr)
        printf("ERROR U+%X .. U+%X both with SC %d\n", r->to, n->from, r->scr);
      assert(r->scr != n->scr); // can not be merged
    }
  }
#ifndef DISABLE_CHECK_XID
  for (size_t i = 0; i < ARRAY_SIZE(allowed_id_list) - 1; i++) {
    const struct range_bool *r = &allowed_id_list[i];
    const struct range_bool *n = &allowed_id_list[i + 1];
    assert(r->from <= r->to);
    assert(r->to + 1 < n->from); // can not be merged
  }
  for (size_t i = 0; i < ARRAY_SIZE(idtype_list) - 1; i++) {
    const struct range_short *r = &idtype_list[i];
    const struct range_short *n = &idtype_list[i + 1];
    assert(r->from <= r->to);
    assert(r->to <= n->from);
    if (r->to + 1 >= n->from)
      assert(r->types != n->types); // can not be merged
  }
#endif
}

static int sign(int i) { return (i < 0) ? -1 : (i == 0) ? 0 : 1; }
static char *xstr(const char *s) {
  unsigned i;
  memset(buf, 0, sizeof(buf));
  for (i = 0; i < strlen(s); i++) {
    snprintf(&buf[i * 2], 128 - (i * 2), "%02x", (unsigned char)s[i]);
  }
  // buf[i] = 0;
  return buf;
}
#define CHECK_RET(ret, wanted, ctx)                                            \
  do {                                                                         \
    check_ret(ret, wanted, ctx);                                               \
    assert(ret == wanted);                                                     \
  } while (0)

static void check_ret(int ret, enum u8id_errors wanted, int ctx) {
  if (ret != wanted) {
    if (ret == U8ID_EOK_NORM) {
      printf("ERROR %s in profile %u, expected %s.\n", // print hexstr diff?
             u8ident_errstr(ret), u8ident_profile(), u8ident_errstr(wanted));
      return;
    }
    const char *scripts = u8ident_existing_scripts(ctx);
    if (ret)
      printf("ERROR %s U+%X %s in profile %u, expected %s. Have scripts: %s\n",
             u8ident_failed_script_name(ctx), u8ident_failed_char(ctx),
             u8ident_errstr(ret), u8ident_profile(), u8ident_errstr(wanted),
             scripts);
    else
      printf("ERROR %s in profile %u, expected %s. Have scripts: %s\n",
             u8ident_errstr(ret), u8ident_profile(), u8ident_errstr(wanted),
             scripts);
    free((void *)scripts);
  }
}

// check if a script is detected and added properly
void test_script(void) {
  int ctx = u8ident_new_ctx();
  // first in a range 0x0388 .. 0x03E1
  assert(strEQc(u8ident_script_name(u8ident_get_script(0x388)), "Greek"));
  // middle
  assert(strEQc(u8ident_script_name(u8ident_get_script(0x3BB)), "Greek"));
  // last
  assert(strEQc(u8ident_script_name(u8ident_get_script(0x3E1)), "Greek"));
  // Δ Greek is currently not latin-greek confusable
  int ret = u8ident_check((const uint8_t *)"Δ2", NULL);
  CHECK_RET(ret, U8ID_EOK, ctx); // Greek only
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  const char *s = u8ident_existing_scripts(ctx);
  assert(strcmp(s, "Greek") == 0);
  free((char *)s);
#endif

  ret = u8ident_check((const uint8_t *)"aΔ", NULL); // Latin + Greek
  CHECK_RET(ret, U8ID_EOK, ctx);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  s = u8ident_existing_scripts(ctx);
  assert(strEQc(s, "Greek, Latin"));
  free((char *)s);
#endif
  assert(u8ident_free_ctx(ctx) == 0);
}

struct norms_t {
  const char *id;
  const char *norm;
  const int result;
};

static void testnorm(const char *name, const struct norms_t *testids) {
  struct norms_t *p;
  for (p = (struct norms_t *)testids; p->id; p++) {
    char *norm = u8ident_normalize(p->id, strlen(p->id));
    assert(norm);
    if (strcmp(p->norm, norm) != 0) {
      printf("%s[%ld]: %s [%s] != ", name, (long)(p - testids), p->norm,
             xstr(p->norm));
      printf("%s [%s]\n", norm, xstr(norm));
    }
    if (sign(strcmp(p->id, norm)) != sign(p->result))
      printf("%s[%ld]: %s [%s] => %d\n", name, (long)(p - testids), p->id,
             xstr(p->id), strcmp(p->id, norm));
    if (strcmp(name, "FCD")) {
      assert(strcmp(norm, p->norm) == 0);
      assert(sign(strcmp(p->id, norm)) == sign(p->result));
    }
    free(norm);
  }
}

/*
  all differences: unichars -a '\pL' 'NFC ne NFKC'

  sub wstr($) {
    join('',map{sprintf'\x%02x',$_} unpack 'W*', encode_utf8 $_[0]);
  }
  ./mktest-norm.pl
  Café [\x43\x61\x66\x65\xcc\x81]:
  NFC:  Café [\x43\x61\x66\xc3\xa9]
  NFKC: Café [\x43\x61\x66\xc3\xa9]
  FCC:  Café [\x43\x61\x66\xc3\xa9]
  NFD:  Café [\x43\x61\x66\x65\xcc\x81]
  NFKD: Café [\x43\x61\x66\x65\xcc\x81]
  FCD:  Café [\x43\x61\x66\x65\xcc\x81]

  Café [\x43\x61\x66\xc3\xa9]:
  NFC:  Café [\x43\x61\x66\xc3\xa9]
  NFKC: Café [\x43\x61\x66\xc3\xa9]
  FCC:  Café [\x43\x61\x66\xc3\xa9]
  NFD:  Café [\x43\x61\x66\x65\xcc\x81]
  NFKD: Café [\x43\x61\x66\x65\xcc\x81]
  FCD:  Café [\x43\x61\x66\xc3\xa9]

  ᾇ [\xe1\xbe\x87]:
  NFC:  ᾇ [\xe1\xbe\x87]
  NFKC: ᾇ [\xe1\xbe\x87]
  FCC:  ᾇ [\xe1\xbe\x87]
  NFD:  ᾇ [\xce\xb1\xcc\x94\xcd\x82\xcd\x85]
  NFKD: ᾇ [\xce\xb1\xcc\x94\xcd\x82\xcd\x85]
  FCD:  ᾇ [\xe1\xbe\x87]

  ᾇ [\xce\xb1\xcc\x94\xcd\x82\xcd\x85]:
  NFC:  ᾇ [\xe1\xbe\x87]
  NFKC: ᾇ [\xe1\xbe\x87]
  FCC:  ᾇ [\xe1\xbe\x87]
  NFD:  ᾇ [\xce\xb1\xcc\x94\xcd\x82\xcd\x85]
  NFKD: ᾇ [\xce\xb1\xcc\x94\xcd\x82\xcd\x85]
  FCD:  ᾇ [\xce\xb1\xcc\x94\xcd\x82\xcd\x85]

  ǅŀ [\xc7\x85\xc5\x80]: \x{1c5}\x{140}
  NFC:  ǅŀ [\xc7\x85\xc5\x80]
  NFKC: Džl· [\x44\xc5\xbe\x6c\xc2\xb7]
  FCC:  ǅŀ [\xc7\x85\xc5\x80]
  NFD:  ǅŀ [\xc7\x85\xc5\x80]
  NFKD: Džl· [\x44\x7a\xcc\x8c\x6c\xc2\xb7]
  FCD:  ǅŀ [\xc7\x85\xc5\x80]

  Džl· [\x44\xc5\xbe\x6c\xc2\xb7]:
  NFC:  Džl· [\x44\xc5\xbe\x6c\xc2\xb7]
  NFKC: Džl· [\x44\xc5\xbe\x6c\xc2\xb7]
  FCC:  Džl· [\x44\xc5\xbe\x6c\xc2\xb7]
  NFD:  Džl· [\x44\x7a\xcc\x8c\x6c\xc2\xb7]
  NFKD: Džl· [\x44\x7a\xcc\x8c\x6c\xc2\xb7]
  FCD:  Džl· [\x44\xc5\xbe\x6c\xc2\xb7]
*/
#if !defined U8ID_NORM || U8ID_NORM == NFKC
void test_norm_nfkc(void) {
  const struct norms_t testids[] = {
      // clang-format off
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Caf" "\xc3\xa9", -1}, // U+301 => U+E9
    {"Caf" "\xc3\xa9", "Caf" "\xc3\xa9", 0},   // U+E9  => U+E9
    // Greek Small Letter Alpha with Dasia and Perispomeni and Ypogegrammeni
    {"\xce\xb1" "\xcc\x94" "\xcd\x85" "\xcd\x82", "\xe1\xbe\x87", -19}, // ᾇ => U+1f87 with reorder
    {"\xc7\x85\xc5\x80", "\x44\xc5\xbe\x6c\xc2\xb7", 1}, // ǅŀ
    {NULL, NULL, 0},
      // clang-format on
  };
  assert(!u8ident_init(U8ID_PROFILE_4, U8ID_NFKC, 0));
  testnorm("NFKC", testids);

  char *norm = NULL;
  int ret = u8ident_check((const uint8_t *)"Cafe\xcc\x81", &norm);
  if (u8ident_tr31() != U8ID_TR31_TR39 &&
      u8ident_tr31() != U8ID_TR31_C23) { // which demand NFC already
    CHECK_RET(ret, U8ID_EOK_NORM, 0);
    assert(strEQc(norm, "Caf\xc3\xa9"));
    free(norm);
  }
}
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFC
void test_norm_nfc(void) {
  const struct norms_t testids[] = {
      // clang-format off
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Caf" "\xc3\xa9", -1}, // U+301 => U+E9
    {"Caf" "\xc3\xa9", "Caf" "\xc3\xa9", 0},   // U+E9  => U+E9
    {"\xce\xb1" "\xcc\x94" "\xcd\x85" "\xcd\x82", "\xe1\xbe\x87", -19}, // => U+1f87 with reorder
    {"\x44\x7a\xcc\x8c\x6c\xc2\xb7", "\x44\xc5\xbe\x6c\xc2\xb7", -75}, // ǅŀ
    {NULL, NULL, 0},
      // clang-format on
  };
  assert(!u8ident_init(U8ID_PROFILE_4, U8ID_NFC, 0));
  testnorm("NFC", testids);

  // which demands NFC already, so fails on XID earlier
  if (u8ident_tr31() != U8ID_TR31_TR39 && u8ident_tr31() != U8ID_TR31_C23) {
    char *norm = NULL;
    int ret = u8ident_check((const uint8_t *)"Cafe\xcc\x81", &norm);
    CHECK_RET(ret, U8ID_EOK_NORM, 0);
    assert(strEQc(norm, "Caf\xc3\xa9"));
    free(norm);
  }
}
#endif
#if !defined U8ID_NORM || U8ID_NORM == FCC
void test_norm_fcc(void) {
  const struct norms_t testids[] = {
      // clang-format off
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Caf" "\xc3\xa9", -1}, // U+301 => U+E9
    {"Caf" "\xc3\xa9",  "Caf" "\xc3\xa9", 0},  // U+E9  => U+E9
    {"\xce\xb1\xcc\x94\xcd\x82\xcd\x85", "\xe1\xbe\x87", -19},   // U+1f87
    {"\xc7\x85\xc5\x80", "\xc7\x85\xc5\x80", 0}, // ǅŀ
    {NULL, NULL, 0},
      // clang-format on
  };
  assert(!u8ident_init(U8ID_PROFILE_4, U8ID_FCC, 0));
  testnorm("FCC", testids);
}
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFKD
void test_norm_nfkd(void) {
  const struct norms_t testids[] = {
      // clang-format off
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Cafe" "\xcc\x81", 0},  // U+301 => U+301
    {"Caf" "\xc3\xa9",  "Cafe" "\xcc\x81", 94},  // U+E9  => U+301
    {"\xe1\xbe\x87", "\xce\xb1\xcc\x94\xcd\x82\xcd\x85", 19}, // U+1f87 => exc: α U+03B1 U+0314 U+0342 U+0345
    {"\xc7\x85\xc5\x80", "\x44\x7a\xcc\x8c\x6c\xc2\xb7", 1}, // ǅŀ
    {"\x44\xc5\xbe\x6c\xc2\xb7", "\x44\x7a\xcc\x8c\x6c\xc2\xb7", 1}, // ǅŀ
    {NULL, NULL, 0},
      // clang-format on
  };
  assert(!u8ident_init(U8ID_PROFILE_4, U8ID_NFKD, 0));
  testnorm("NFKD", testids);

  char *norm = NULL;
  int ret = u8ident_check((const uint8_t *)"Caf\xc3\xa9", &norm);
  CHECK_RET(ret, U8ID_EOK_NORM, 0);
  assert(strEQc(norm, "Cafe\xcc\x81"));
  free(norm);
}
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFD
void test_norm_nfd(void) {
  const struct norms_t testids[] = {
      // clang-format off
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Cafe" "\xcc\x81", 0},  // U+301 => U+301
    {"Caf" "\xc3\xa9",  "Cafe" "\xcc\x81", 94}, // U+E9  => U+301
    {"\xe1\xbe\x87", "\xce\xb1\xcc\x94\xcd\x82\xcd\x85", 19},   // U+1f87 => exc: α U+03B1 U+0314 U+0342 U+0345
    {"\xc7\x85\xc5\x80", "\xc7\x85\xc5\x80", 0}, // ǅŀ
    {"\x44\xc5\xbe\x6c\xc2\xb7", "\x44\x7a\xcc\x8c\x6c\xc2\xb7", 1}, // ǅŀ
    {NULL, NULL, 0},
      // clang-format on
  };
  assert(!u8ident_init(U8ID_PROFILE_4, U8ID_NFD, 0));
  testnorm("NFD", testids);

  char *norm = NULL;
  int ret = u8ident_check((const uint8_t *)"Caf\xc3\xa9", &norm);
  CHECK_RET(ret, U8ID_EOK_NORM, 0);
  assert(strEQc(norm, "Cafe\xcc\x81"));
  free(norm);
}
#endif
#if !defined U8ID_NORM || U8ID_NORM == FCD
void test_norm_fcd(void) {
  const struct norms_t testids[] = {
      // clang-format off
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Cafe" "\xcc\x81", 0}, // U+301 => U+301
    {"Caf" "\xc3\xa9",  "Caf" "\xc3\xa9", 0},  // U+E9  => U+E9
    {"\xe1\xbe\x87", "\xe1\xbe\x87", 0},       // U+1f87
    {"\xce\xb1\xcc\x94\xcd\x82\xcd\x85", "\xce\xb1\xcc\x94\xcd\x82\xcd\x85", 0},   // U+1f87
    {"\xc7\x85\xc5\x80", "\xc7\x85\xc5\x80", 0}, // ǅŀ
    {NULL, NULL, 0},
      // clang-format on
  };
  assert(!u8ident_init(U8ID_PROFILE_4, U8ID_FCD, 0));
  testnorm("FCD", testids);
  u8ident_free();
}
#endif

// latin plus greek or cyrillic is disallowed with profile 4
// only CFK or any Recommended script. No ctx here so Latin is first, and
// Bengali 2nd/ https://www.unicode.org/reports/tr39/#Mixed_Script_Detection
void test_mixed_scripts(int xid_check) {
  int ret;
  // printf("test_mixed_scripts(%d)\n", xid_check);
  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, xid_check);
  int xid = u8ident_tr31();
  ret = u8ident_check((const uint8_t *)"abcd", NULL);
  CHECK_RET(ret, U8ID_EOK, 0); // Latin only

  ret = u8ident_check((const uint8_t *)"aঅ", NULL); // Latin + Bengali U+985
#if !defined U8ID_PROFILE || U8ID_PROFILE > 3
  if (xid == U8ID_TR31_ASCII)
    CHECK_RET(ret, U8ID_ERR_XID, 0);
  else
    CHECK_RET(ret, U8ID_EOK, 0);
#else
  // 2 single script, 3 +CFK.
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#endif
  u8ident_free();

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, xid_check);
  // Latin + U+386 Greek
  ret = u8ident_check((const uint8_t *)"a\xce\x86", NULL);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0); // c26 allows greek
#elif !defined U8ID_NORM || U8ID_NORM == NFKC || U8ID_NORM == NFC ||           \
    U8ID_NORM == FCC
  CHECK_RET(ret, U8ID_EOK, 0);
#else
  CHECK_RET(ret, U8ID_EOK_NORM, 0); // U+386
#endif

  ret = u8ident_check((const uint8_t *)"Cafe\xcc\x81", NULL);
  if (xid == U8ID_TR31_TR39 && !is_profile_6())
    CHECK_RET(ret, U8ID_ERR_XID, 0);
  // C23 cannot check XID alone with NFC_M, but fails NORM later.
  else if (xid == U8ID_TR31_C23 && !is_profile_6())
    CHECK_RET(ret, U8ID_EOK_NORM, 0);
  else {
#if !defined U8ID_NORM || U8ID_NORM == NFKC || U8ID_NORM == NFC ||             \
    U8ID_NORM == FCC
    CHECK_RET(ret, U8ID_EOK_NORM, 0); // U+301
#else
    CHECK_RET(ret, U8ID_EOK, 0); // U+301
#endif
  }

  ret = u8ident_check((const uint8_t *)"\xc3\xb7", NULL);
#ifdef DISABLE_CHECK_XID
  CHECK_RET(ret, U8ID_EOK, 0);
#else
  if (xid != U8ID_TR31_ALLUTF8) {
    CHECK_RET(ret, U8ID_ERR_XID, 0); // division sign U+F7 Sm forbidden as XID
    ret = u8ident_check((const uint8_t *)"\xc6\x80", NULL);
    // small letter b with stroke U+180 is in xid, but not allowed
    if (xid == U8ID_TR31_ALLOWED) {
      CHECK_RET(ret, U8ID_ERR_XID, 0);
      ret = u8ident_check((const uint8_t *)"\xe1\xac\x85", NULL);
      CHECK_RET(ret, U8ID_ERR_XID, 0); // Balinese U+1B05 is limited
    } else {
      CHECK_RET(ret, U8ID_EOK, 0);
      ret = u8ident_check((const uint8_t *)"\xe1\xac\x85", NULL);
      // Balinese U+1B05 is limited. so TR39 should fail earlier
      if (u8ident_tr31() == U8ID_TR31_TR39)
        CHECK_RET(ret, U8ID_ERR_XID, 0);
      else if (!is_profile_6())
        CHECK_RET(ret, U8ID_ERR_SCRIPT, 0);
      else
        CHECK_RET(ret, U8ID_EOK, 0);
    }
  } else {
    // division sign U+F7 Math_Symbol allowed without XID check.
    CHECK_RET(ret, U8ID_EOK, 0); // FIXME COMBINE
    ret = u8ident_check((const uint8_t *)"\xc6\x80", NULL);
    CHECK_RET(ret, U8ID_EOK, 0); // small letter b with stroke U+180
    ret = u8ident_check((const uint8_t *)"\xe1\xac\x85", NULL);
    if (!is_profile_6())
      CHECK_RET(ret, U8ID_ERR_SCRIPT, 0); // U+1B05 Balinese is limited
    else
      CHECK_RET(ret, U8ID_EOK, 0);
  }
#endif

#if U8ID_UNICODE_MAJOR < 15
  // GREEK SMALL LETTER LAMDA did have no LATIN counter-part then (it has now)
  ret = u8ident_check((const uint8_t *)"abcλ", NULL); // Greek
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0);
#endif
  u8ident_free();

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, xid_check);
  ret = u8ident_check((const uint8_t *)"abcλѝ", NULL); // Greek + Cyrillic
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5 || U8ID_PROFILE == TR39_4
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#elif !defined U8ID_NORM || U8ID_NORM == NFKC || U8ID_NORM == NFC ||           \
    U8ID_NORM == FCC
  CHECK_RET(ret, U8ID_EOK, 0);
#else
  CHECK_RET(ret, U8ID_EOK_NORM, 0);
#endif
  u8ident_free();

#else // new UNICODE 16 confusables

  // Now confusable LATIN SMALL LETTER LAMBDA → GREEK SMALL LETTER LAMDA
  ret = u8ident_check((const uint8_t *)"abcΔ", NULL); // Greek
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0);
#endif
  u8ident_free();

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, xid_check);
  ret = u8ident_check((const uint8_t *)"abcΔѝ", NULL); // Greek + Cyrillic
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5 || U8ID_PROFILE == TR39_4
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#elif !defined U8ID_NORM || U8ID_NORM == NFKC || U8ID_NORM == NFC ||           \
    U8ID_NORM == FCC
  CHECK_RET(ret, U8ID_EOK, 0);
#else
  CHECK_RET(ret, U8ID_EOK_NORM, 0);
#endif
  u8ident_free();

#endif // new UNICODE 16 confusables

  // U+386 Greek, U+985 Bengali. 37B confusable with latin
  ret = u8ident_check((const uint8_t *)"Άঅ", NULL);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#elif U8ID_PROFILE == TR39_4 && U8ID_UNICODE_MAJOR < 16
  CHECK_RET(ret, U8ID_ERR_CONFUS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0); // multi-scripts allowed in 5 and 6
#endif

  // han + hangul is allowed, ditto hangul + han
  // han + katakana is allowed, ditto katakana + han
  // hiragana + katakana is allowed, ditto katakana + hiragana, ...
  u8ident_free();
}

// check if mixed scripts per ctx work
void test_mixed_scripts_with_ctx(void) {
  int ctx = u8ident_new_ctx(); // new ctx 1 (no Latin)
  // U+37B Greek confusable,  but not Allowed anymore. Replaced by U+386
  int ret = u8ident_check((const uint8_t *)"Ά", NULL);
  CHECK_RET(ret, U8ID_EOK, ctx); // Greek alone
  assert(u8ident_free_ctx(ctx) == 0);

  assert(!u8ident_init(u8ident_profile(), u8ident_norm(), u8ident_options()));
  int tr31 = u8ident_tr31();
  ctx = u8ident_new_ctx();
  assert(ctx == 1);
  // U+45D, replaced by U+45C
  ret = u8ident_check((const uint8_t *)"ќ", NULL); // Cyrillic alone
  // NFD to U+438,U+300 (d0b8cc800a)
#if U8ID_NORM == NFD || U8ID_NORM == NFKD || U8ID_NORM == FCD
  CHECK_RET(ret, U8ID_EOK_NORM, ctx);
#else
  CHECK_RET(ret, U8ID_EOK, ctx);
#endif
  assert(u8ident_free_ctx(ctx) == 0);

  // back to old empty ctx 0
  ret = u8ident_check((const uint8_t *)"aηώ", NULL);
  // TR39_4 allows Greek (not confusable)
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0); // Latin + Greek disallowed in 2-4
#elif U8ID_NORM == NFKD || U8ID_NORM == NFD || U8ID_NORM == FCD
  CHECK_RET(ret, U8ID_EOK_NORM, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0); // Latin + Greek
                               // assert(ret >= 0); // Latin + Greek
#endif

  ctx = u8ident_new_ctx(); // new ctx
  ret = u8ident_check((const uint8_t *)"\u0710", NULL);
  if (tr31 != U8ID_TR31_ALLOWED && tr31 != U8ID_TR31_TR39) {
#if !defined U8ID_PROFILE || U8ID_PROFILE < 6 || U8ID_PROFILE == TR39_4
    CHECK_RET(ret, U8ID_ERR_SCRIPT, ctx); // U+0710 Syriac is limited use
#else
    CHECK_RET(ret, U8ID_EOK, ctx); // 6 allows even these
#endif
  }
  assert(u8ident_free_ctx(ctx) == 0);
  u8ident_free();

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0);
  ctx = u8ident_new_ctx(); // new ctx
  // check legal and illegal 0x30FC runs. KATAKANA-HIRAGANA PROLONGED SOUND MARK
  ret = u8ident_check((const uint8_t *)"\u30fa\u30fc", NULL);
#if U8ID_NORM == NFD || U8ID_NORM == NFKD || U8ID_NORM == FCD
  CHECK_RET(ret, U8ID_EOK_NORM, ctx);
#else
  CHECK_RET(ret, U8ID_EOK, ctx);
#endif
  assert(u8ident_free_ctx(ctx) == 0);
  u8ident_free();

  // disallow Latin + 0x30FC
  ret = u8ident_check((const uint8_t *)"a\u30fc", NULL);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5 || U8ID_PROFILE == TR39_4
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0);
#endif
  u8ident_free();

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0);
  // Allow Latin plus other Japanese Lm VERTICAL KANA REPEAT MARK
  ret = u8ident_check((const uint8_t *)"a\u3031", NULL);
  if (tr31 == U8ID_TR31_ALLOWED) {
    // 3031 Lm is not in TR31_ALLOWED, just XID
    CHECK_RET(ret, U8ID_ERR_XID, 0);
  } else {
#if defined U8ID_PROFILE && U8ID_PROFILE < 3
    CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
    CHECK_RET(ret, U8ID_EOK, 0);
#endif
  }
  u8ident_free();

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0);
  ret = u8ident_check((const uint8_t *)"أحرارًا", NULL);
  // huh? 6 norms, but 5 not?
  if (is_profile_6())
    CHECK_RET(ret, U8ID_EOK_NORM, 0);
  else if (tr31 == U8ID_TR31_TR39)
    CHECK_RET(ret, U8ID_ERR_XID, 0);
  else {
#if U8ID_NORM == NFD || U8ID_NORM == NFKD || U8ID_NORM == FCD
    CHECK_RET(ret, U8ID_EOK_NORM, 0);
#else
    CHECK_RET(ret, U8ID_EOK, 0);
#endif
  }
  u8ident_free();
}

// Test invalid encodings (Combining marks)
void test_combine() {
  int ret;
  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0);
  int tr31 = u8ident_tr31();
  // these have safe XIDs, disallowing combiners
  if (tr31 == U8ID_TR31_ALLOWED || tr31 == U8ID_TR31_TR39 || tr31 == U8ID_TR31_C23)
    return;
  if (is_profile_6()) // this bypasses combiner checks
    return;

  // Disallow Latin plus Japanese Mn
  ret = u8ident_check((const uint8_t *)"a\u3099", NULL);
  CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

  // Disallow Latin plus Vedic Mn (in SCX)
  ret = u8ident_check((const uint8_t *)"a\u1cd0", NULL);
  CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

  // Disallow Latin plus Deva Mn (now also in SCX)
  ret = u8ident_check((const uint8_t *)"a\u1cd1", NULL);
  CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

#ifndef DISABLE_CHECK_XID
  int prof = u8ident_profile();
  if (prof != 5) {
    // Disallow equal combiners (Inherited, Recommended, Mn)
    ret = u8ident_check((const uint8_t *)"a\u0300\u0300", NULL);
    CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

    // Disallow more then 4 combiners (Inherited, Recommended, Mn)
    ret = u8ident_check((const uint8_t *)"a\u0300\u0301\u0302\u0303\u0304", NULL);
    CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

    // Special cases DOT ABOVE:
    // Disallow i with DOT ABOVE
    ret = u8ident_check((const uint8_t *)"i\u0307", NULL);
    CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

    // Disallow DOTLESS I with DOT ABOVE
    ret = u8ident_check((const uint8_t *)"ı\u0307", NULL);
    CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

    // Regular nsm_letters[] cases:
    // Disallow Ä with DIAERESIS
    ret = u8ident_check((const uint8_t *)"Ä\u0308", NULL);
    CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

    // Disallow Å with RING ABOVE
    ret = u8ident_check((const uint8_t *)"Å\u030a", NULL);
    CHECK_RET(ret, U8ID_ERR_COMBINE, 0);

#if !defined U8ID_PROFILE || U8ID_PROFILE == 8
    // U8ID_TR31_TR39 disallows combiners at all
    u8ident_init(U8ID_PROFILE_TR39_4, U8ID_NORM_DEFAULT, 0);
    // \UXXXXXXXXX letter support
    u8ident_add_script(SC_Yezidi); // EXCLUDED_SCRIPT only addable with profile 6
    ret = u8ident_check((const uint8_t *)"\U00010EB0\u0307", NULL);
    CHECK_RET(ret, U8ID_ERR_COMBINE, 0); // FIXME
#endif
  }
#endif

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0);
  // But ignore spacing marks Mc (Devanagari)
  ret = u8ident_check((const uint8_t *)"\u0904\u0903\u0903", NULL);
  //CHECK_RET(ret, U8ID_EOK or EOK_NORM, 0);
  assert(ret >= 0);
  ret = u8ident_check((const uint8_t *)"\u0904\u0903\u093b\u093e\u093b\u093e", NULL);
  //CHECK_RET(ret, U8ID_EOK or EOK_NORM, 0);
  assert(ret >= 0);

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0);
  // Disallow Latin plus Cyrillic Mn. not in SCX, so ERR_SCRIPTS
  ret = u8ident_check((const uint8_t *)"a\u2dfa", NULL);
  if (u8ident_profile() == 5)
    CHECK_RET(ret, U8ID_EOK, 0);
  else
    CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);  
  u8ident_free();

  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0);
  // Arabic-only combiners
  // "\xd8\xa3\xd8\xad\xd8\xb1\xd8\xa7\xd8\xb1\xd9\x8b\xd8\xa7" from
  // texts/arabic-1.txt
  ret = u8ident_check((const uint8_t *)"أحرارًا", NULL);
#if U8ID_NORM == NFD || U8ID_NORM == NFKD || U8ID_NORM == FCD
  CHECK_RET(ret, U8ID_EOK_NORM, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0);
#endif
  u8ident_free();
}

void test_init(void) {
  // wrong inits
  assert(u8ident_init(0, 0, 0)); // missing profile
  assert(u8ident_init(0, 0, 6));
  assert(u8ident_init(2048, 0, 0));
  assert(u8ident_init(0, 0, U8ID_TR31_ALLOWED)); // missing PROFILE
  assert(!u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT,
                       U8ID_TR31_ALLOWED));
  assert(u8ident_init(U8ID_PROFILE_DEFAULT, 8, 0)); // wrong norm
  assert(u8ident_init(1, 0, 2048));
  u8ident_free();
}

void test_scx_singles(void) {
  // check scripts of all scx singles, if really only Common and Inherited. (Yes
  // with UCD 14.0)
  int c = u8ident_new_ctx();
  struct ctx_t *ctx = u8ident_ctx();
  // uint8_t oldscr = 0;
  for (size_t i = 0; i < ARRAY_SIZE(scx_list); i++) {
    if (scx_list[i].scx && strlen(scx_list[i].scx) == 1) {
#ifdef PRINT_SCX_SINGLES
      uint8_t scrx = (uint8_t)scx_list[i].scx[0];
#endif
      for (uint32_t j = scx_list[i].from; j <= scx_list[i].from; j++) {
        uint8_t scr = u8ident_get_script(j);
        if (!u8ident_has_script_ctx(scr, ctx)) {
          u8ident_add_script_ctx(scr, ctx);
          // oldscr = 0;
        }
        // if (scr != oldscr)
#ifdef PRINT_SCX_SINGLES
        printf("SCX single: U+%X %s => %s\n", (unsigned)j,
               u8ident_script_name(scr), u8ident_script_name(scrx));
#endif
        // oldscr = scr;
        if (scx_list[i].from == scx_list[i].to)
          break;
      }
    }
  }
  for (uint8_t scr = 0; scr <= LAST_SCRIPT; scr++) {
    if (u8ident_has_script_ctx(scr, ctx)) {
      printf("SC: %s\n", u8ident_script_name(scr));
      assert(scr == SC_Common || scr == SC_Inherited);
    }
  }
  u8ident_free_ctx(c);
}

void test_gc(void) {
  // check consecutive and alternating GC ranges
  assert(gc_list[0].from == 0);
  for (size_t i = 1; i < ARRAY_SIZE(gc_list); i++) {
    assert(gc_list[i - 1].to != gc_list[i].from);
    assert(gc_list[i - 1].gc != gc_list[i].gc);
  }
}

void test_medial(void) {
  // check consecutive medial ranges
  for (size_t i = 1; i < ARRAY_SIZE(medial_list); i++) {
    assert(medial_list[i - 1].to != medial_list[i].from);
  }

#ifndef DISABLE_CHECK_XID
  if (u8ident_tr31() == U8ID_TR31_ALLOWED)
    return; // FB8A FB91 are all disallowed
  const enum u8id_norm norm = u8ident_norm();
  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, U8ID_TR31_ID);
  // medial at end
  int ret = u8ident_check((const uint8_t *)"\u06A2\uFB8A\uFB91", NULL);
  if (!is_profile_6())
    CHECK_RET(ret, U8ID_ERR_XID, 0);
  else if (norm == U8ID_NFKC || norm == U8ID_NFKD)
    CHECK_RET(ret, U8ID_EOK_NORM, 0);
  else
    CHECK_RET(ret, U8ID_EOK, 0);
  if (u8ident_tr31() == U8ID_TR31_TR39 || u8ident_tr31() == U8ID_TR31_C23)
    return; // FB8A is disallowed
  // medial at medial
  ret = u8ident_check((const uint8_t *)"\u06A2\uFB8A\uFB91\uFB51", NULL);
  if (norm == U8ID_NFKC || norm == U8ID_NFKD)
    CHECK_RET(ret, U8ID_EOK_NORM, 0);
  else
    CHECK_RET(ret, U8ID_EOK, 0);
  // medial at start
  ret = u8ident_check((const uint8_t *)"\uFB91\uFB51", NULL);
  // which tr31 is not broken and detects medial at start? Only TR39 so far.
  // unicode bug filed for UCD versions 1-14. v15 might have it fixed.
  if (u8ident_tr31() == U8ID_TR31_TR39)
    CHECK_RET(ret, U8ID_ERR_XID, 0);
  else if (norm == U8ID_NFKC || norm == U8ID_NFKD)
    CHECK_RET(ret, U8ID_EOK_NORM, 0);
  else
    CHECK_RET(ret, U8ID_EOK, 0);
  u8ident_free();
#endif
}

void test_tr39(void) {
  // check consecutive and alternating scripts and tr39 ranges
  // assert(tr39_start_list[0].from == 0);
  for (size_t i = 1; i < ARRAY_SIZE(tr39_start_list); i++) {
    if (tr39_start_list[i - 1].to >= tr39_start_list[i].from)
      printf("[%lu].to U+%X >= [%lu].from U+%X\n", i - 1,
             tr39_start_list[i - 1].to, i, tr39_start_list[i].from);
    assert(tr39_start_list[i - 1].to < tr39_start_list[i].from);
    if (tr39_start_list[i - 1].sc == tr39_start_list[i].sc) {
      if (tr39_start_list[i - 1].to >= tr39_start_list[i].from)
        printf("[%lu].to U+%X >= [%lu].from U+%X\n", i - 1,
               tr39_start_list[i - 1].to, i, tr39_start_list[i].from);
      assert(tr39_start_list[i - 1].to < tr39_start_list[i].from);
    }
    if (tr39_start_list[i - 1].gc == tr39_start_list[i].gc)
      assert(tr39_start_list[i - 1].to < tr39_start_list[i].from);
  }
  for (size_t i = 1; i < ARRAY_SIZE(tr39_cont_list); i++) {
    if (tr39_cont_list[i - 1].to >= tr39_cont_list[i].from)
      printf("[%lu].to U+%X >= [%lu].from U+%X\n", i - 1,
             tr39_cont_list[i - 1].to, i, tr39_cont_list[i].from);
    assert(tr39_cont_list[i - 1].to < tr39_cont_list[i].from);
    if (tr39_cont_list[i - 1].sc == tr39_cont_list[i].sc)
      assert(tr39_cont_list[i - 1].to + 1 < tr39_cont_list[i].from);
    if (tr39_cont_list[i - 1].gc == tr39_cont_list[i].gc)
      assert(tr39_cont_list[i - 1].to + 1 < tr39_cont_list[i].from);
  }
}

void test_greek(void) {
  // check consecutive greek_confus_list
  for (size_t i = 1; i < ARRAY_SIZE(greek_confus_list); i++) {
    assert(greek_confus_list[i - 1] < greek_confus_list[i]);
  }
  // check mixed script c26_4 logic
  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, U8ID_TR31_ID);
  int ret = u8ident_check((const uint8_t *)"a", NULL);
  // allow some greek with latin
  if (u8ident_profile() == TR39_4) {
    ret = u8ident_check((const uint8_t *)"θ", NULL); // U+38B not confus
    CHECK_RET(ret, U8ID_EOK, 0);
    ret = u8ident_check((const uint8_t *)"Α", NULL); // U+391 confus
    CHECK_RET(ret, U8ID_ERR_CONFUS, 0);
  } else if (u8ident_profile() < 5) {
    ret = u8ident_check((const uint8_t *)"θ", NULL);
    CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
    ret = u8ident_check((const uint8_t *)"Α", NULL);
    CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
  } else {
    ret = u8ident_check((const uint8_t *)"θ", NULL);
    CHECK_RET(ret, U8ID_EOK, 0);
    ret = u8ident_check((const uint8_t *)"Α", NULL);
    CHECK_RET(ret, U8ID_EOK, 0);
  }
  u8ident_free();
}

void test_add_scripts(void) {
  int c = u8ident_new_ctx();
  struct ctx_t *ctx = u8ident_ctx();
  for (uint8_t i = 2; i < FIRST_LIMITED_USE_SCRIPT; i++) {
    assert(u8ident_add_script(i) == U8ID_EOK);
    assert(u8ident_has_script(i));
    assert(u8ident_has_script_ctx(i, ctx));
  }
  u8ident_free_ctx(c);
}

#ifdef HAVE_CONFUS
static int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}

void test_confus(void) {
  int ret;
#  ifdef HAVE_CROARING
  u8ident_roar_init();
#  endif
  // test for equality of both variants
  for (size_t i = 0; i < ARRAY_SIZE(confusables); i++) {
    const uint32_t cp = confusables[i];
    assert(u8ident_is_confusable(cp));
    uint32_t *x = (uint32_t *)bsearch(&cp, confusables, ARRAY_SIZE(confusables), 4, compar32);
    assert(x);
    assert(*x == cp);
  }
  //
  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, U8ID_WARN_CONFUSABLE);
  if (u8ident_tr31() != U8ID_TR31_TR39 && u8ident_tr31() != U8ID_TR31_C23) {
    ret = u8ident_check((const uint8_t *)"Cafe\xcc\x81", NULL);
    assert(!(ret & U8ID_EOK_WARN_CONFUS));
  }

  u8ident_add_script(SC_Coptic);
  ret = u8ident_check((const uint8_t *)"\u01a6", NULL); // Ʀ
#  if !defined ENABLE_CHECK_XID
  if (!(ret & U8ID_EOK_WARN_CONFUS))
    printf("ERROR \"ͮ\" U+1A6 not detected as confusable");
  assert(ret == U8ID_EOK_WARN_CONFUS);
#  endif

  for (size_t i = 0; i < ARRAY_SIZE(confusables); i++) {
    size_t len;
    const uint32_t cp = confusables[i];
    if (cp > 0x7C) { // skip the latin confusables: 0 1 I ` |
      ret = u8ident_check((const uint8_t *)enc_utf8(buf, &len, cp), NULL);
      if (ret == U8ID_EOK || ret == U8ID_EOK_NORM) {
        printf("ERROR U+%X not detected as confusable, but %s\n", cp,
               u8ident_errstr(ret));
      }
      assert(ret == U8ID_EOK_WARN_CONFUS || ret < 0 ||
             ret == U8ID_EOK_NORM_WARN_CONFUS);
    }
  }
#  ifdef HAVE_CROARING
  u8ident_roar_free();
#  endif
}

void test_htable(void) {
  struct htable *htab = new_htab(16);
  assert(!find_htab(htab, "0"));
  add_htab(htab, "0", "1");
  assert(find_htab(htab, "0"));
  assert(!find_htab(htab, "1"));

  for (int i=1; i<1000; i++) {
    char s[14];
    snprintf(s, 13, "%u", i);
    add_htab(htab, s, "x");
    assert(find_htab(htab, s));
  }

  free_htab(htab);
  free(htab);
}

void test_confusables(void) {
  // requires generic or NFC
#if !defined U8ID_NORM || U8ID_NORM == NFC
  int ret = u8ident_check_confusables("check", sizeof("check") - 1);
  assert(ret == 0);
  // Cyrillic c U+441, һ U+4bb, е U+435
  ret = u8ident_check_confusables("сһесk", sizeof("сһесk") - 1);
  assert(ret == U8ID_ERR_CONFUS);
  // Latin c, Cyrillic һ U+4bb, е U+435
  ret = u8ident_check_confusables("cһесk", sizeof("cһесk") - 1);
  assert(ret == U8ID_ERR_CONFUS);
#endif
}

#endif

int main(int argc, char **argv) {
  int i = 1;
  const int norm = (argc > i && strEQc(argv[i], "norm") && i++);
  const int profile = (argc > i && strEQc(argv[i], "profile") && i++);
#ifndef DISABLE_CHECK_XID
  const int xid = (argc > i && strEQc(argv[i], "xid") && i++);
#endif
  const int scx = (argc > i && strEQc(argv[i], "scx") && i++);
  const int combine = (argc > i && strEQc(argv[i], "combine") && i++);
  
  if (argc == 1) {
    test_scripts_no_init();
    test_init();
    test_gc();
    test_medial();
    test_tr39();
    test_greek();
    test_script();
  }
  if (combine) {
    test_combine();
    return 0;
  }

#ifdef HAVE_CONFUS
  if (argc > i && strEQc(argv[i], "htable")) {
    test_htable();
    u8ident_free();
    return 0;
  }
  if (argc > i && strEQc(argv[i], "confusables")) {
    test_confusables();
    u8ident_free();
    return 0;
  }
#endif

  if (norm || argc == 1) {
#if !defined U8ID_NORM || U8ID_NORM == NFKC
    test_norm_nfkc();
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFC
    test_norm_nfc();
#endif
#if !defined U8ID_NORM || U8ID_NORM == FCC
    test_norm_fcc();
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFKD
    test_norm_nfkd();
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFD
    test_norm_nfd();
#endif
#if !defined U8ID_NORM || U8ID_NORM == FCD
    test_norm_fcd();
#endif
    if (norm)
      return 0;
  }
#ifndef ENABLE_CHECK_XID
  if (profile || argc == 1) {
    test_mixed_scripts(0);
  }
#endif
#ifndef DISABLE_CHECK_XID
  if (profile || xid || argc == 1) {
    test_mixed_scripts(U8ID_TR31_DEFAULT);
    test_medial();
  }
#endif

#if U8ID_NORM != FCD && U8ID_NORM != FCC
  test_mixed_scripts_with_ctx();
  test_combine();
#endif

  if (scx || argc == 1) {
    test_scx_singles();
    test_add_scripts();
  }

#ifdef HAVE_CONFUS
  test_confus();
  test_htable();
  test_confusables();
#endif

  u8ident_free();
  return 0;
}
