/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "u8ident.h"
#define EXT_SCRIPTS
#include "scripts.h"

#define ARRAY_SIZE(x) sizeof(x)/sizeof(*x)
static char buf[128]; // for hex display

// private access
unsigned u8ident_options(void);
uint8_t u8ident_get_script(uint32_t cp);
bool u8ident_is_allowed(const uint32_t cp);
const char * u8ident_get_scx(const uint32_t cp);
uint16_t u8ident_get_idtypes(const uint32_t cp);

// check if the library can be used without init: script lookups, default checks
void test_scripts_no_init(void) {
  assert(u8ident_get_script(0x41) == 2);
  assert(u8ident_get_script(0x5a) == 2);
  assert(strcmp(u8ident_script_name(0), "Common") == 0);
  assert(strcmp(u8ident_script_name(1), "Inherited") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x2EB)), "Bopomofo") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x371)), "Greek") == 0);
  assert(strcmp(u8ident_script_name(u8ident_get_script(0x3132)), "Hangul") == 0);
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
  assert(u8ident_is_allowed(0x27));
  assert(!u8ident_is_allowed(0x26));
  assert(u8ident_is_allowed(0x40e));
  assert(u8ident_get_idtypes(0x102E2) == (U8ID_Obsolete | U8ID_Not_XID));

  // check that no list elements can be merged
#ifndef DISABLE_CHECK_XID
  for (size_t i=0; i < ARRAY_SIZE(xid_script_list) - 1; i++) {
    const struct sc* r = &xid_script_list[i];
    const struct sc* n = &xid_script_list[i+1];
    assert(r->from <= r->to);
    assert(r->to <= n->from);
    if (r->to + 1 >= n->from)
      assert(r->scr != n->scr);  // can not be merged
  }
#endif
  for (size_t i=0; i < ARRAY_SIZE(nonxid_script_list) - 1; i++) {
    const struct sc* r = &nonxid_script_list[i];
    const struct sc* n = &nonxid_script_list[i+1];
    assert(r->from <= r->to);
    assert(r->to <= n->from);
    if (r->to + 1 >= n->from)
      assert(r->scr != n->scr);  // can not be merged
  }
  for (size_t i=0; i < ARRAY_SIZE(allowed_id_list) - 1; i++) {
    const struct range_bool* r = &allowed_id_list[i];
    const struct range_bool* n = &allowed_id_list[i+1];
    assert(r->from <= r->to);
    assert(r->to + 1 < n->from);  // can not be merged
  }
  for (size_t i=0; i < ARRAY_SIZE(idtype_list) - 1; i++) {
    const struct range_short* r = &idtype_list[i];
    const struct range_short* n = &idtype_list[i+1];
    assert(r->from <= r->to);
    assert(r->to <= n->from);
    if (r->to + 1 >= n->from)
      assert(r->types != n->types);  // can not be merged
  }
}

static int sign(int i) {
  return (i < 0) ? -1 : (i == 0) ? 0 : 1;
}
static char* xstr(const char *s) {
  unsigned i;
  memset(buf, 0, sizeof(buf));
  for (i=0; i<strlen(s); i++) {
    snprintf(&buf[i*2], 128-(i*2), "%02x", (unsigned char)s[i]);
  }
  //buf[i] = 0;
  return buf;
}

struct norms_t {
  const char *id;
  const char *norm;
  const int result;
};

static void testnorm(const char* name, const struct norms_t *testids) {
  struct norms_t *p;
  for (p = (struct norms_t*)testids; p->id; p++) {
    char *norm = u8ident_normalize(p->id, strlen(p->id));
    assert(norm);
    if (strcmp(p->norm, norm) != 0) {
      printf("%s[%ld]: %s [%s] != ", name, p - testids,
             p->norm, xstr(p->norm));
      printf("%s [%s]\n", norm, xstr(norm));
    }
    if (sign(strcmp(p->id, norm)) != sign(p->result))
      printf("%s[%ld]: %s [%s] => %d\n", name, p - testids,
             p->id, xstr(p->id), strcmp(p->id, norm));
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
void test_norm_nfkc(void) {
  const struct norms_t testids[] = {
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Caf" "\xc3\xa9", -1}, // U+301 => U+E9
    {"Caf" "\xc3\xa9", "Caf" "\xc3\xa9", 0},   // U+E9  => U+E9
    // Greek Small Letter Alpha with Dasia and Perispomeni and Ypogegrammeni
    {"\xce\xb1" "\xcc\x94" "\xcd\x85" "\xcd\x82", "\xe1\xbe\x87", -19}, // ᾇ => U+1f87 with reorder
    {"\xc7\x85\xc5\x80", "\x44\xc5\xbe\x6c\xc2\xb7", 1}, // ǅŀ
    {NULL, NULL, 0},
  };
  testnorm("NFKC", testids);
}
void test_norm_nfc(void) {
  const struct norms_t testids[] = {
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Caf" "\xc3\xa9", -1}, // U+301 => U+E9
    {"Caf" "\xc3\xa9", "Caf" "\xc3\xa9", 0},   // U+E9  => U+E9
    {"\xce\xb1" "\xcc\x94" "\xcd\x85" "\xcd\x82", "\xe1\xbe\x87", -19}, // => U+1f87 with reorder
    {"\x44\x7a\xcc\x8c\x6c\xc2\xb7", "\x44\xc5\xbe\x6c\xc2\xb7", -75}, // ǅŀ
    {NULL, NULL, 0},
  };
  u8ident_init(U8ID_NFC | U8ID_PROFILE_4);
  testnorm("NFC", testids);
}
void test_norm_fcc(void) {
  const struct norms_t testids[] = {
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Caf" "\xc3\xa9", -1}, // U+301 => U+E9
    {"Caf" "\xc3\xa9",  "Caf" "\xc3\xa9", 0},  // U+E9  => U+E9
    {"\xce\xb1\xcc\x94\xcd\x82\xcd\x85", "\xe1\xbe\x87", -19},   // U+1f87
    {"\xc7\x85\xc5\x80", "\xc7\x85\xc5\x80", 0}, // ǅŀ
    {NULL, NULL, 0},
  };
  u8ident_init(U8ID_FCC | U8ID_PROFILE_4);
  testnorm("FCC", testids);
}
void test_norm_nfkd(void) {
  const struct norms_t testids[] = {
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Cafe" "\xcc\x81", 0},  // U+301 => U+301
    {"Caf" "\xc3\xa9",  "Cafe" "\xcc\x81", 94},  // U+E9  => U+301
    {"\xe1\xbe\x87", "\xce\xb1\xcc\x94\xcd\x82\xcd\x85", 19}, // U+1f87 => exc: α U+03B1 U+0314 U+0342 U+0345
    {"\xc7\x85\xc5\x80", "\x44\x7a\xcc\x8c\x6c\xc2\xb7", 1}, // ǅŀ
    {"\x44\xc5\xbe\x6c\xc2\xb7", "\x44\x7a\xcc\x8c\x6c\xc2\xb7", 1}, // ǅŀ
    {NULL, NULL, 0},
  };
  u8ident_init(U8ID_NFKD | U8ID_PROFILE_4);
  testnorm("NFKD", testids);
}
void test_norm_nfd(void) {
  const struct norms_t testids[] = {
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Cafe" "\xcc\x81", 0},  // U+301 => U+301
    {"Caf" "\xc3\xa9",  "Cafe" "\xcc\x81", 94}, // U+E9  => U+301
    {"\xe1\xbe\x87", "\xce\xb1\xcc\x94\xcd\x82\xcd\x85", 19},   // U+1f87 => exc: α U+03B1 U+0314 U+0342 U+0345
    {"\xc7\x85\xc5\x80", "\xc7\x85\xc5\x80", 0}, // ǅŀ
    {"\x44\xc5\xbe\x6c\xc2\xb7", "\x44\x7a\xcc\x8c\x6c\xc2\xb7", 1}, // ǅŀ
    {NULL, NULL, 0},
  };
  u8ident_init(U8ID_NFD | U8ID_PROFILE_4);
  testnorm("NFD", testids);
}
void test_norm_fcd(void) {
  const struct norms_t testids[] = {
    {"abcd", "abcd", 0},
    {"Cafe" "\xcc\x81", "Cafe" "\xcc\x81", 0}, // U+301 => U+301
    {"Caf" "\xc3\xa9",  "Caf" "\xc3\xa9", 0},  // U+E9  => U+E9 TODO
    {"\xe1\xbe\x87", "\xe1\xbe\x87", 0},       // U+1f87 TODO
    {"\xce\xb1\xcc\x94\xcd\x82\xcd\x85", "\xce\xb1\xcc\x94\xcd\x82\xcd\x85", 0},   // U+1f87
    {"\xc7\x85\xc5\x80", "\xc7\x85\xc5\x80", 0}, // ǅŀ
    {NULL, NULL, 0},
  };
  u8ident_init(U8ID_FCD | U8ID_PROFILE_4);
  testnorm("FCD", testids);
}

// TODO mixed-script check, contexts, options, XID.

// latin plus just greek is allowed, but not greek + cyrillic. and so on
void test_mixed_scripts(int xid_check) {
  u8ident_init(U8ID_DEFAULT_OPTS | xid_check);
  assert(u8ident_check((const uint8_t*)"abcd", NULL) == U8ID_EOK);
  assert(u8ident_check((const uint8_t*)"abc\xce\x86", NULL) == U8ID_EOK); // Latin + Greek ok
  assert(u8ident_check((const uint8_t*)"Cafe\xcc\x81", NULL) == U8ID_EOK_NORM);

  int err = u8ident_check((const uint8_t*)"\xc3\xb7", NULL);
  if (u8ident_options() & U8ID_CHECK_XID) {
      assert(err == U8ID_ERR_CCLASS); // division sign U+F7 forbidden as XID
      //printf("ERROR U+F7 is not allowed\n");
      assert(u8ident_check((const uint8_t*)"\xc6\x80", NULL) == U8ID_ERR_CCLASS); // small letter b with stroke
      //printf("ERROR U+180 is not allowed\n");
      if (u8ident_check((const uint8_t*)"\xe1\xac\x85", NULL) != U8ID_ERR_CCLASS) // U+1B05
	  printf("ERROR Balinese is limited\n");
  }
  else {
     assert(err == U8ID_EOK); // division sign U+F7 allowed without XID check
     assert(u8ident_check((const uint8_t*)"\xc6\x80", NULL) == U8ID_EOK); // U+180
     //printf("U+1B05: %d\n", u8ident_check((const uint8_t*)"\xe1\xac\x85", NULL));
     assert(u8ident_check((const uint8_t*)"\xe1\xac\x85", NULL) == U8ID_ERR_SCRIPT); // U+1B05 is limited
  }
  // TODO check with profiles 2-6
  if (u8ident_check((const uint8_t*)"\xf0\x91\x8c\x81", NULL) != U8ID_ERR_SCRIPT) // U+11301 Grantha
    printf("ERROR Grantha is excluded\n");
  if (u8ident_check((const uint8_t*)"abcͻѝ", NULL) != U8ID_ERR_SCRIPTS)
    printf("ERROR Greek plus Cyrillic\n");
  if (u8ident_check((const uint8_t*)"ͻঅ", NULL) != U8ID_ERR_SCRIPTS)
    printf("ERROR Greek plus Bengali\n");
  // han + hangul is allowed, ditto hangul + han
  // han + katakana is allowed, ditto katakana + han
  // hiragana + katakana is allowed, ditto katakana + hiragana, ...
}

// check if mixed scripts per ctx work
void test_mixed_scripts_with_ctx(void) {
  assert(u8ident_check((const uint8_t*)"abcͻ", NULL) == U8ID_EOK); // Greek
  u8ident_init(U8ID_DEFAULT_OPTS);
  int ctx = u8ident_new_ctx(); // new ctx 1
  assert(ctx == 1);
  assert(u8ident_check((const uint8_t*)"abcѝ", NULL) == U8ID_EOK);  // Cyrillic
  assert(u8ident_delete_ctx(ctx) == 0);
  // back to ctx 0
  assert(u8ident_check((const uint8_t*)"abͻώ", NULL) == U8ID_EOK); // next Greek
}

int main(void) {
  test_scripts_no_init();
  test_norm_nfkc();
  test_norm_nfc();
  test_norm_fcc();
  test_norm_nfkd();
  test_norm_nfd();
  test_norm_fcd();
  test_mixed_scripts(0);
  test_mixed_scripts(U8ID_CHECK_XID);
  test_mixed_scripts_with_ctx();
  return 0;
}
