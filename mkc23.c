/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   Create and test a secure variant of C11 identifiers, the SAFEC23 profile:
   * TR39#5.2 Mixed-Scripts Moderately Restrictive (4), but allow Greek scripts (hence C23_4),
   * Disallow all Limited_Use and Excluded scripts,
   * Only allow TR 39#1 Recommended, Inclusion, Technical Identifier Type properties,
   * Demand NFC normalization. Reject all composable sequences as ill-formed.
   * Reject illegal mark sequences (Lm, Mn, Mc) with mixed-scripts (SCX) as ill-formed.

   See c11.md and c23++proposal.md

   TODO:
   List of Lm chars in the resulting list, for c23++proposal 7.3
   Number of Identifier_Type filtering (before, after).
   Number of Script filtering (before, after)
   Number of NFC filtering (before, after)
*/
#include "u8id_private.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif
#if defined HAVE_DIRENT_H && !defined _MSC_VER
#  include <dirent.h>
#endif
#ifdef _MSC_VER
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#include "u8ident.h"
#include "u8idscr.h"
#undef EXT_SCRIPTS
#include "unic11.h"
#include "mark.h"

// private use:
char *enc_utf8(char *dest, size_t *lenp, const uint32_t cp);

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
static inline bool range_bool_search(const uint32_t cp,
                                     const struct range_bool *list,
                                     const size_t len) {
  return binary_search(cp, (char *)list, len, sizeof(*list)) ? true : false;
}

static inline bool isMARK(uint32_t cp) {
  return range_bool_search(cp, mark_list, ARRAY_SIZE(mark_list));
}

static inline bool isSkipIdtype(uint32_t cp) {
  struct range_short *s = (struct range_short *)binary_search(
      cp, (char *)idtype_list, ARRAY_SIZE(idtype_list), sizeof(*idtype_list));
  if (s)
    return s->types & (U8ID_Limited_Use | U8ID_Obsolete | U8ID_Uncommon_Use);
  else
    return false;
}

// uint8_t[10FFFF/8]
#define BITGET(b, i) (b[i >> 3] & (1 << (7 - (i & 7)))) != 0
#define BITSET(b, i) b[i >> 3] |= (1 << (7 - (i & 7)))
#define BITCLR(b, i) b[i >> 3] &= ~(1 << (7 - (i & 7)))

struct stats {
  unsigned ranges, singles, codepoints;
} stats;

void emit_ranges(FILE *f, size_t start, uint8_t *u, bool with_sc) {
  unsigned from = start;
  bool on = BITGET(u, from);
  uint8_t s = u8ident_get_script(start);
  uint8_t s1 = s;
  for (unsigned i = start; i < 0x10ffff; i++) {
    if (BITGET(u, i)) {
      if (!on) { // now on, and was off
        from = i;
	s = u8ident_get_script(from);
        on = true;
      }
      if (with_sc && i > start)
	s1 = u8ident_get_script(i);
      // when the script property changed, or when its now off, but was on
      bool sc_changed = with_sc ? s1 != s : false;
      if (sc_changed) {
	fprintf(stderr, "U+%X: %u -> %u\n", i, s, s1);
	goto changed;
      }
    } else { // now off. emit the range
      if (on) {
      changed:
        if (from <= i - 1) {
          char tmp[32];
          size_t len;
          enc_utf8(tmp, &len, from);
	  s = u8ident_get_script(from);
	  fprintf(f, "    {0x%X, 0x%X", from, i - 1);
	  if (with_sc)
	    fprintf(f, ", %u", s);
	  fprintf(f, "}, // %s%s %s",
		  u8ident_script_name(s),
		  s >= FIRST_LIMITED_USE_SCRIPT ? " (Limited)"
		  : s >= FIRST_EXCLUDED_SCRIPT  ? " (Excluded)"
		  : "",
		  tmp);
          if (from == i - 1) {
            stats.singles++;
            fprintf(f, "\n");
          } else {
            stats.ranges++;
            enc_utf8(tmp, &len, i - 1);
            fprintf(f, "..%s\n", tmp);
          }
          stats.codepoints += (i - from - 1);
        }
        from = i;
	if (with_sc)
	  s = u8ident_get_script(from);
        on = false;
      }
    }
  }
}

/* Show all insecure scripts in the C11 permitted range.
   C11/C++11 accepted all, ignoring all unicode security recommendations for identifiers.
 */
static void gen_c11_all(void) {
  //uint8_t o = 0, s;
  const char* header = "c11-all.h";
  uint8_t u[0x10ffff >> 3];
  memset(u, 0, sizeof(u));
  memset(&stats, 0, sizeof(stats));
  for (size_t i = 0; i < ARRAY_SIZE(c11_start_list); i++) {
    struct range_bool r = c11_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      BITSET(u, cp);
    }
  }
  FILE *f = fopen(header, "w");
  fputs("/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */\n"
        "/* libu8ident - Check unicode security guidelines for identifiers.\n"
        "   Copyright 2021, 2022 Reini Urban\n"
        "   SPDX-License-Identifier: Apache-2.0\n"
        "\n"
        "   generated by mkc23 from unic11.h.\n"
        "   UNICODE version 14.0\n"
        "*/\n",
        f);
  fputs("const struct range_bool c11_start_list[] = {\n"
        "    {'$', '$'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'},\n"
        "    {0x00A8, 0x00A8},   {0x00AA, 0x00AA},\n"
        "    {0x00AD, 0x00AD},   {0x00AF, 0x00AF},   {0x00B2, 0x00B5},\n"
        "    {0x00B7, 0x00BA},   {0x00BC, 0x00BE},   {0x00C0, 0x00D6},\n"
        "    {0x00D8, 0x00F6},   {0x00F8, 0x00FF},\n"
        "    // {0x0100, 0x02FF}, // Latin, 2B0-2FF: Modifiers (2EA Bopomofo)\n",
        f);
  emit_ranges(f, 0xff, u, false);
  fputs("};", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "c11_start_list",
         stats.ranges, stats.singles, stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);

  memset(u, 0, sizeof(u));
  memset(&stats, 0, sizeof(stats));
  for (size_t i = 0; i < ARRAY_SIZE(c11_cont_list); i++) {
    struct range_bool r = c11_cont_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      BITSET(u, cp);
    }
  }
  fputs("const struct range_bool c11_cont_list[] = {\n"
        "    {'$', '$'},\n"
        "    {'0', '9'},\n", f);
  emit_ranges(f, 0xff, u, false);
  fputs("};", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "c11_cont_list",
         stats.ranges, stats.singles, stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fclose(f);
  memset(&stats, 0, sizeof(stats));
  printf("%s created\n", header);
}

  // XID, only recommended scripts and IdTypes, mandate NFC (no MARK)
static void gen_c23_safe(void) {
  const char* header = "c23-safe.h";
  FILE *f = fopen(header, "w");
  int nfc = 0;
  static uint8_t u[0x10ffff >> 3];
  char tmp[32];
  memset(u, 0, sizeof(u));
  memset(&stats, 0, sizeof(stats));
  fprintf(stderr, "Split some ranges with different scripts:\n");
  for (size_t i = 0; i < ARRAY_SIZE(xid_start_list); i++) {
    struct range_bool r = xid_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      uint8_t s = u8ident_get_script(cp);
      if (s < FIRST_EXCLUDED_SCRIPT && !isMARK(cp)) {
	size_t len;
	if (enc_utf8(tmp, &len, cp)) {
	  char *norm = u8ident_normalize(tmp, sizeof(tmp));
	  if (!strEQ(tmp, norm)) {
	    nfc++;
	    continue; // skip
	  }
	}
        BITSET(u, cp);
      }
    }
  }
  fputs("/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */\n"
        "/* libu8ident - Check unicode security guidelines for identifiers.\n"
        "   Copyright 2021, 2022 Reini Urban\n"
        "   SPDX-License-Identifier: Apache-2.0\n"
        "\n"
        "   generated by mkc23, do not modify.\n"
        "   UNICODE version 14.0\n" // FIXME dynamic version
        "   Filtered XID_Start/Continue with allowed scripts, "
         "!Limited_Use,!Obsolete,!Uncommon_Use and NFC\n"
        "   TODO: new struct with SC,SCX and GC(if Lm,Mn,Me) properties.\n"
        "*/\n"
        "\n"
        "struct sc_c23 {\n"
        "    uint32_t from;\n"
        "    uint32_t to;\n"
        "    enum u8id_sc sc;\n"
        "    enum u8id_gc gc;\n"
        "    const char *scx; // maxsize Beng Deva Dogr Gong Gonm Gran Gujr Guru Knda Limb Mahj Mlym Nand Orya Sind Sinh Sylo Takr Taml Telu Tirh\n"
        "};\n"
        "\n", f);
  fputs("// Filtering allowed scripts, XID_Start, Skipped Ids and NFC\n", f);
  fputs("const struct sc_c23 safec23_start_list[] = {\n"
        "    {'$', '$', SC_Latin, GC_Sc, NULL},\n"  // 24
	"    {'A', 'Z', SC_Latin, GC_Lu, NULL},\n"  // 41-5a
        "    {'_', '_', SC_Latin, GC_Pc, NULL},\n"  // 5f
        "    {'a', 'z', SC_Latin, GC_Ll, NULL},\n", // 61-7a
        f);
  emit_ranges(f, 0x7a, u, true);
  fputs("};\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "safec23_start_list",
         stats.ranges, stats.singles, stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);

  memset(&stats, 0, sizeof(stats));
  static uint8_t c[0x10ffff >> 3];
  memset(c, 0, sizeof(c));
  for (size_t i = 0; i < ARRAY_SIZE(xid_cont_list); i++) {
    struct range_bool r = xid_cont_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      if (BITGET(u, cp))
	continue;
      uint8_t s = u8ident_get_script(cp);
      if (s < FIRST_EXCLUDED_SCRIPT && !isMARK(cp) && !isSkipIdtype(cp)) {
	size_t len;
	if (enc_utf8(tmp, &len, cp)) {
	  char *norm = u8ident_normalize(tmp, sizeof(tmp));
	  if (!strEQ(tmp, norm)) {
	    nfc++;
	    continue; // skip
	  }
	}
        BITSET(c, cp);
      }
    }
  }
  fputs("\n// Filtering allowed scripts, XID_Continue,!XID_Start, Skipped Ids, NFC and !MARK\n", f);
  fputs("const struct sc safec23_cont_list[] = {\n", f);
  emit_ranges(f, 0x23, c, true);
  fputs("};\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "safec23_cont_list",
         stats.ranges, stats.singles, stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  memset(&stats, 0, sizeof(stats));

  // now more scripts
  fputs("\n\n//---------------------------------------------------\n", f);
  fputs("\n// Only excluded scripts, XID_Start,!Obsolete,!Uncommon_Use, NFC and !MARK\n", f);
  memset(u, 0, sizeof(u));
  for (size_t i = 0; i < ARRAY_SIZE(xid_start_list); i++) {
    struct range_bool r = xid_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      uint8_t s = u8ident_get_script(cp);
      if (s >= FIRST_EXCLUDED_SCRIPT && s < FIRST_LIMITED_USE_SCRIPT &&
          !isMARK(cp) && !isSkipIdtype(cp)) {
        size_t len;
        if (enc_utf8(tmp, &len, cp)) {
	  char *norm = u8ident_normalize(tmp, sizeof(tmp));
	  if (!strEQ(tmp, norm)) {
	    continue; // skip
	  }
	}
        BITSET(u, cp);
      }
    }
  }
  fputs("const struct sc safec23_excl_start_list[] = {\n", f);
  emit_ranges(f, 0x7a, u, true);
  fputs("};\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "safec23_excl_start_list",
         stats.ranges, stats.singles, stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  memset(&stats, 0, sizeof(stats));

  fputs("\n// Only excluded scripts, XID_Continue,!XID_Start, Skipped Ids, NFC and !MARK\n", f);
  memset(c, 0, sizeof(c));
  for (size_t i = 0; i < ARRAY_SIZE(xid_cont_list); i++) {
    struct range_bool r = xid_cont_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      if (BITGET(u, cp))
	continue;
      uint8_t s = u8ident_get_script(cp);
      if (s >= FIRST_EXCLUDED_SCRIPT && s < FIRST_LIMITED_USE_SCRIPT &&
          !isMARK(cp) && !isSkipIdtype(cp)) {
        size_t len;
        if (enc_utf8(tmp, &len, cp)) {
	  char *norm = u8ident_normalize(tmp, sizeof(tmp));
	  if (!strEQ(tmp, norm)) {
	    continue; // skip
	  }
	}
        BITSET(c, cp);
      }
    }
  }
  fputs("const struct range_bool safec23_excl_cont_list[] = {\n", f);
  emit_ranges(f, 0x23, c, true);
  fputs("};\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "safec23_excl_cont_list",
         stats.ranges, stats.singles, stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fclose(f);
  memset(&stats, 0, sizeof(stats));
  fprintf(stderr, "%d codepoints not NFC safe\n", nfc);
  printf("%s created\n", header);
}

int main(/*int argc, char **argv*/) {
  u8ident_init(U8ID_PROFILE_C23_4, U8ID_NFC, 0);

  gen_c11_all();
  gen_c23_safe();

  u8ident_free();
  return 0;
}
