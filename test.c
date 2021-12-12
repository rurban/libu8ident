/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "u8id_private.h"
#include "u8ident.h"
#include "u8idscr.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)
static char buf[128]; // for hex display

// private access
unsigned u8ident_options(void);
unsigned u8ident_profile(void);

static const char *errstr(int errcode) {
  static const char *const _str[] = {
      "ERR_CONFUS",      // -5
      "ERR_ENCODING",    // -4
      "ERR_SCRIPTS",     //-3
      "ERR_SCRIPT",      //-2
      "ERR_XID",         // -1
      "EOK",             // 0
      "EOK_NORM",        // 1
      "EOK_WARN_CONFUS", // 2
  };
  assert(errcode >= -5 && errcode <= 2);
  return _str[errcode + 5];
}

// check if the library can be used without init: script lookups, default checks
void test_scripts_no_init(void) {
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
  const char *scx = u8ident_get_scx(0x309A);
  assert(scx);
  assert(strlen(scx) == 2);
  assert(scx[0] == 0x11); // Hiragana
  assert(scx[1] == 0x12); // Katakana
  scx = u8ident_get_scx(0x30FC);
  assert(scx);
  assert(strlen(scx) == 2);
  assert(scx[0] == 0x11); // Hiragana
  assert(scx[1] == 0x12); // Katakana
  scx = u8ident_get_scx(0x064B);
  assert(scx);
  assert(strlen(scx) == 2);
  assert(scx[0] == 0x03);   // Arab
  assert(scx[1] == '\x99'); // Syrc, signed!
#ifndef DISABLE_CHECK_XID
  assert(u8ident_is_allowed(0x27));
  assert(!u8ident_is_allowed(0x26));
  assert(u8ident_is_allowed(0x40e));
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
  testnorm("NFKC", testids);
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
  assert(!u8ident_init(U8ID_NFC | U8ID_PROFILE_4));
  testnorm("NFC", testids);
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
  assert(!u8ident_init(U8ID_FCC | U8ID_PROFILE_4));
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
  assert(!u8ident_init(U8ID_NFKD | U8ID_PROFILE_4));
  testnorm("NFKD", testids);
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
  assert(!u8ident_init(U8ID_NFD | U8ID_PROFILE_4));
  testnorm("NFD", testids);
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
  assert(!u8ident_init(U8ID_FCD | U8ID_PROFILE_4));
  testnorm("FCD", testids);
}
#endif

#define CHECK_RET(ret, wanted, ctx)  \
  check_ret(ret, wanted, ctx); assert(ret == wanted)

static void check_ret(int ret, enum u8id_errors wanted, int ctx) {
  if (ret != wanted) {
    const char *scripts = u8ident_existing_scripts(ctx);
    if (ret) {
      printf("ERROR %s U+%X %s in profile %u, expected %s. Have scripts: %s\n",
             u8ident_failed_script_name(ctx), u8ident_failed_char(ctx),
             errstr(ret), u8ident_profile(), errstr(wanted), scripts);
    } else {
      printf("ERROR %s in profile %u, expected %s. Have scripts: %s\n",
             errstr(ret), u8ident_profile(), errstr(wanted), scripts);
    }
    free((void*)scripts);
  }
}

// latin plus greek or cyrillic is disallowed with profile 4
// only CFK or any Recommended script. No ctx here so Latin is first, and Bengali 2nd/
// https://www.unicode.org/reports/tr39/#Mixed_Script_Detection
void test_mixed_scripts(int xid_check) {
  int ret;
  u8ident_init(U8ID_DEFAULT_OPTS | xid_check);
  ret = u8ident_check((const uint8_t *)"abcd", NULL);
  CHECK_RET(ret, U8ID_EOK, 0); // Latin only

  ret = u8ident_check((const uint8_t *)"aঅ", NULL); // Latin + Bengali U+985
#if defined U8ID_PROFILE && U8ID_PROFILE < 4
  // 2 single script, 3 +CFK.
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0);
#endif

  // Latin + U+386 Greek
  ret = u8ident_check((const uint8_t *)"a\xce\x86", NULL);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0);
#endif

  ret = u8ident_check((const uint8_t *)"Cafe\xcc\x81", NULL);
  CHECK_RET(ret, U8ID_EOK_NORM, 0); // U+301

  ret = u8ident_check((const uint8_t *)"\xc3\xb7", NULL);
  if (u8ident_options() & U8ID_CHECK_XID) {
    CHECK_RET(ret, U8ID_ERR_XID, 0); // division sign U+F7 forbidden as XID
    ret= u8ident_check((const uint8_t *)"\xc6\x80", NULL);
    CHECK_RET(ret, U8ID_ERR_XID, 0); // small letter b with stroke U+180 is not allowed
    ret = u8ident_check((const uint8_t *)"\xe1\xac\x85", NULL);
    CHECK_RET(ret, U8ID_ERR_XID, 0); // Balinese U+1B05 is limited
  } else {
    CHECK_RET(ret, U8ID_EOK, 0); // division sign U+F7 allowed without XID check
    ret= u8ident_check((const uint8_t *)"\xc6\x80", NULL);
    CHECK_RET(ret, U8ID_EOK, 0); // small letter b with stroke U+180
    ret = u8ident_check((const uint8_t *)"\xe1\xac\x85", NULL);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 6
    CHECK_RET(ret, U8ID_ERR_SCRIPT, 0); // U+1B05 Balinese is limited
#else
    CHECK_RET(ret, U8ID_EOK, 0);
#endif
  }

  ret = u8ident_check((const uint8_t *)"abcͻ", NULL); // Greek
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0);
#endif
  ret = u8ident_check((const uint8_t *)"abcͻѝ", NULL); // Greek + Cyrillic
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0);
#endif
  // U+37B Greek, U+985 Bengali
  ret = u8ident_check((const uint8_t *)"ͻঅ", NULL);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0);
#else
  CHECK_RET(ret, U8ID_EOK, 0); // multi-scripts allowed in 5 and 6
#endif

  // han + hangul is allowed, ditto hangul + han
  // han + katakana is allowed, ditto katakana + han
  // hiragana + katakana is allowed, ditto katakana + hiragana, ...
}

// check if mixed scripts per ctx work
void test_mixed_scripts_with_ctx(void) {
  int ctx = u8ident_new_ctx(); // new ctx 1 (no Latin)
  // U+37B Greek
  int ret = u8ident_check((const uint8_t *)"ͻ", NULL);
  CHECK_RET(ret, U8ID_EOK, ctx); // Greek alone
  assert(u8ident_delete_ctx(ctx) == 0);

  assert(!u8ident_init(u8ident_options()));
  ctx = u8ident_new_ctx();
  assert(ctx == 1);
  ret = u8ident_check((const uint8_t *)"ѝ", NULL);
  CHECK_RET(ret, U8ID_EOK, ctx); // Cyrillic alone
  assert(u8ident_delete_ctx(ctx) == 0);

  // back to old ctx 0 (which has latin already)
  ret = u8ident_check((const uint8_t *)"abͻώ", NULL);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 5
  CHECK_RET(ret, U8ID_ERR_SCRIPTS, 0); // Latin + Greek disallowed in 2-4
#else
  CHECK_RET(ret, U8ID_EOK, 0); // Latin + Greek
  //assert(ret >= 0); // Latin + Greek
#endif

  ctx = u8ident_new_ctx(); // new ctx
  ret = u8ident_check((const uint8_t *)"\xf0\x91\x8c\x81", NULL);
#if !defined U8ID_PROFILE || U8ID_PROFILE < 6
  CHECK_RET(ret, U8ID_ERR_SCRIPT, 0); // U+11301 Grantha is excluded
#else
  CHECK_RET(ret, U8ID_EOK, 0); // 6 allows even these
#endif
  assert(u8ident_delete_ctx(ctx) == 0);
}

void test_init(void) {
  // wrong inits
  assert(u8ident_init(0)); // missing profile
  assert(u8ident_init(6));
  assert(u8ident_init(2048));
  assert(u8ident_init(U8ID_CHECK_XID)); // missing PROFILE
  assert(
      !u8ident_init(U8ID_NORM_DEFAULT | U8ID_CHECK_XID | U8ID_PROFILE_DEFAULT));
  assert(u8ident_init(U8ID_FCC));                        // missing PROFILE
  assert(u8ident_init(U8ID_PROFILE_2 | U8ID_PROFILE_4)); // multiple profiles
  assert(u8ident_init(2048));
}

void test_scx_singles(void) {
  // check scripts of all scx singles, if really only Common and Inherited. (Yes
  // with UCD 14.0) Ideally we would have none, they would all be merged into the
  // sc_list, splitting it up.
  int c = u8ident_new_ctx();
  struct ctx_t *ctx = u8ident_ctx();
  // uint8_t oldscr = 0;
  for (size_t i = 0; i < ARRAY_SIZE(scx_list); i++) {
    if (scx_list[i].list && strlen(scx_list[i].list) == 1) {
      uint8_t scrx = (uint8_t)scx_list[i].list[0];
      for (uint32_t j = scx_list[i].from; j <= scx_list[i].from; j++) {
        uint8_t scr = u8ident_get_script(j);
        if (!u8ident_has_script_ctx(scr, ctx)) {
          u8ident_add_script_ctx(scr, ctx);
          // oldscr = 0;
        }
        // if (scr != oldscr)
        printf("SCX single: U+%X %s => %s\n", (unsigned)j,
               u8ident_script_name(scr), u8ident_script_name(scrx));
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
  u8ident_delete_ctx(c);
}

void test_add_scripts(void) {
  int c = u8ident_new_ctx();
  struct ctx_t *ctx = u8ident_ctx();
  for (uint8_t i=2; i<FIRST_LIMITED_USE_SCRIPT; i++) {
    assert(u8ident_add_script(i) == U8ID_EOK);
    assert(u8ident_has_script(i));
    assert(u8ident_has_script_ctx(i, ctx));
  }
  u8ident_delete_ctx(c);
}

int main(int argc, char **argv) {
  const int norm = (argc > 1 && !strcmp(argv[1], "norm"));
  const int profile = (argc > 1 && !strcmp(argv[1], "profile"));
#ifndef DISABLE_CHECK_XID
  const int xid = (argc > 1 && !strcmp(argv[1], "xid"));
#endif
  const int scx = (argc > 1 && !strcmp(argv[1], "scx"));

  if (argc == 1) {
    test_scripts_no_init();
    test_init();
  }
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
    test_mixed_scripts(U8ID_CHECK_XID);
  } else
#endif
#ifdef ENABLE_CHECK_XID
    test_mixed_scripts(U8ID_CHECK_XID);
#endif

  test_mixed_scripts_with_ctx();
  if (scx) {
    test_scx_singles();
    test_add_scripts();
  }
  u8ident_delete();
  return 0;
}
