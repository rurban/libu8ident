/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   Create and test a secure variant of C11 identifiers, the SAFEC23 profile:
   * TR39#5.2 Mixed-Scripts Moderately Restrictive (4), but allow Greek scripts
   (hence C23_4),
   * Disallow all Limited_Use and Excluded scripts,
   * Only allow TR 39#1 Recommended, Inclusion, Technical Identifier Type
   properties,
   * Demand NFC normalization. Reject all composable sequences as ill-formed.
   * Reject illegal mark sequences (Lm, Mn, Mc) with mixed-scripts (SCX) as
   ill-formed.

   See doc/c11.md and doc/P2528R0.md

   TODO:
   List of Lm chars in the resulting list, for P2528R0 7.3
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
#define EXTERN_SCRIPTS
#include "unic11.h"

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

/* TR 39#1 Recommended, Inclusion, Technical Identifier Type properties */
static inline bool isSkipIdtype(const uint32_t cp) {
  struct range_short *s = (struct range_short *)binary_search(
      cp, (char *)idtype_list, ARRAY_SIZE(idtype_list), sizeof(*idtype_list));
  if (s)
    return s->types & (U8ID_Limited_Use | U8ID_Default_Ignorable |
                       U8ID_Deprecated | U8ID_Exclusion | U8ID_Not_NFKC |
                       U8ID_Not_XID | U8ID_Obsolete | U8ID_Uncommon_Use);
  else
    return false;
}

// allow U8ID_Exclusion for the _excl_ lists
static inline bool isExcludedIdtype(const uint32_t cp) {
  struct range_short *s = (struct range_short *)binary_search(
      cp, (char *)idtype_list, ARRAY_SIZE(idtype_list), sizeof(*idtype_list));
  if (s)
    return s->types &
           (U8ID_Limited_Use | U8ID_Default_Ignorable | U8ID_Deprecated |
            U8ID_Not_NFKC | U8ID_Not_XID | U8ID_Obsolete | U8ID_Uncommon_Use);
  else
    return false;
}

// disallow 0xFF00-0xFFEF, homoglyph with LATIN A-Z
static inline bool isHalfwidthOrFullwidth(const uint32_t cp) {
  return (cp >= 0xFF00 && cp <= 0xFFEF);
}

// uint8_t[10FFFF/8]
#define BITGET(b, i) (b[i >> 3] & (1 << (7 - (i & 7)))) != 0
#define BITSET(b, i) b[i >> 3] |= (1 << (7 - (i & 7)))
#define BITCLR(b, i) b[i >> 3] &= ~(1 << (7 - (i & 7)))

struct stats {
  unsigned ranges, singles, codepoints;
} stats;

static char *cquote_new(const char *s) {
  long l = (strlen(s) * 4) + 1;
  char *ret = malloc(l);
  uint8_t *p = (uint8_t *)s;
  char *r = ret;
  while (*p) {
    assert(l > 0);
    snprintf(r, l, "\\x%02x", *p);
    p++;
    r += 4;
    l -= 4;
  }
  *r = '\0'; // terminate to avoid calloc
  return ret;
}

// Only record major changes, like Lm => Mn or Mn => Lu.
// if only a minor GC changed write it to outgc.
static unsigned first_major_gc_change(const uint32_t from, const uint32_t to,
                                      char *outgc) {
  if (from == to)
    return 0U;
  const enum u8id_gc gc1 = u8ident_get_gc(from);
  for (uint32_t i = from + 1; i <= to; i++) {
    const enum u8id_gc gc2 = u8ident_get_gc(i);
    if (gc1 != gc2) {
      const char *gcs1 = u8ident_gc_name(gc1);
      const char *gcs2 = u8ident_gc_name(gc2);
      if (gcs1 && gcs2 && *gcs1 == *gcs2) {
        *outgc = *gcs1;
        continue;
        // Only if one of the names is M do a major split. S and L are
        // compatible
      } else if (gcs1 && gcs2 && *gcs1 != 'M' && *gcs2 != 'M') {
        *outgc = 'V';
        continue;
      } else {
        return i;
      }
    }
  }
  return 0;
}

static unsigned first_scx_change(const uint32_t from, const uint32_t to) {
  if (from == to)
    return 0U;
  const struct scx *s1 = u8ident_get_scx(from);
  for (uint32_t i = from + 1; i <= to; i++) {
    const struct scx *s2 = u8ident_get_scx(i);
    // if both are NULL or both are defined and equal, it's equal.
    if (!((!s1 && !s2) || ((s1 && s2) && strEQ(s1->scx, s2->scx))))
      return i;
  }
  return 0;
}

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
        fprintf(stderr, "U+%X: SC %u -> %u\n", i, s, s1);
        goto changed;
      }
    } else { // now off. emit the range
      if (on) {
      changed:
        if (from <= i - 1) {
          char tmp[32];
          size_t len;
          unsigned to = i - 1;
          enc_utf8(tmp, &len, from);
          s = u8ident_get_script(from);
          if (with_sc) {
            unsigned gc_split, scx_split;
            enum u8id_gc gc = u8ident_get_gc(from);
            char *gcname = (char *)u8ident_gc_name(gc);
            struct scx *this_scx = (struct scx *)u8ident_get_scx(from);
            char mgcname[3]; // a copy because the original is read-only
            char minor[1];   // if a change is not major, but only minor
            *minor = '\0';
            strcpy(mgcname, gcname);
            if ((gc_split = first_major_gc_change(from, to, minor))) {
              // This is thanksfully dead code for now
              fprintf(f, "    // SPLIT on GC\n");
              fprintf(f, "    {0x%X, 0x%X", from, gc_split - 1);
              if (this_scx) {
                char *scx = cquote_new(this_scx->scx);
                fprintf(f, ", SC_%s, GC_%s, \"%s\"},", u8ident_script_name(s),
                        gcname, scx);
                fprintf(f, "  //");
                for (size_t i = 0; i < strlen(this_scx->scx); i++) {
                  fprintf(f, "%s%s", i ? "," : "",
                          u8ident_script_name((uint8_t)this_scx->scx[i]));
                }
                free(scx);
              } else {
                fprintf(f, ", SC_%s, GC_%s, NULL},", u8ident_script_name(s),
                        gcname);
              }
              fprintf(stderr, "U+%X: split GC %s -> %s at U+%X\n", from, gcname,
                      u8ident_gc_name(u8ident_get_gc(gc_split)), gc_split);
              if (from == gc_split - 1) {
                stats.singles++;
              } else {
                stats.ranges++;
              }
              stats.codepoints += (gc_split - from - 1);
              from = gc_split;
              gc = u8ident_get_gc(from);
              gcname = (char *)u8ident_gc_name(gc);
              this_scx = (struct scx *)u8ident_get_scx(from);
            } else {
              if (*minor) {
                mgcname[0] = *minor;
                mgcname[1] = '\0'; // we cannot represent L& as enum, so use
                                   // just GC_L or GC_V
                fprintf(stderr, "U+%X: minor GC %s -> %s\n", from, gcname,
                        mgcname);
              }
            }
            if ((scx_split = first_scx_change(from, to))) {
              fprintf(stderr, "U+%X: split SCX changed at U+%X\n", from,
                      scx_split);
              fprintf(f, "    // SPLIT on SCX (prev to U+%X)\n", to);
              fprintf(f, "    {0x%X, 0x%X", from, scx_split - 1);
              if (this_scx) {
                char *scx = cquote_new(this_scx->scx);
                fprintf(f, ", SC_%s, GC_%s, \"%s\"}, //",
                        u8ident_script_name(s), mgcname, scx);
                for (size_t i = 0; i < strlen(this_scx->scx); i++) {
                  fprintf(f, "%s%s", i ? "," : "",
                          u8ident_script_name((uint8_t)this_scx->scx[i]));
                }
                free(scx);
              } else {
                fprintf(f, ", SC_%s, GC_%s, NULL},", u8ident_script_name(s),
                        mgcname);
              }
              fprintf(f, " // %s %s",
                      s >= FIRST_LIMITED_USE_SCRIPT ? " (Limited)"
                      : s >= FIRST_EXCLUDED_SCRIPT  ? " (Excluded)"
                                                    : "",
                      tmp);
              if (from == scx_split - 1) {
                stats.singles++;
                fprintf(f, "\n");
              } else {
                stats.ranges++;
                enc_utf8(tmp, &len, scx_split - 1);
                fprintf(f, "..%s\n", tmp);
              }
              stats.codepoints += (scx_split - from - 1);
              from = scx_split;
              this_scx = (struct scx *)u8ident_get_scx(from);
              enc_utf8(tmp, &len, from);
            }
            fprintf(f, "    {0x%X, 0x%X", from, to);
            if (this_scx) {
              char *scx = cquote_new(this_scx->scx);
              fprintf(f, ", SC_%s, GC_%s, \"%s\"}, //", u8ident_script_name(s),
                      mgcname, scx);
              for (size_t i = 0; i < strlen(this_scx->scx); i++) {
                fprintf(f, "%s%s", i ? "," : "",
                        u8ident_script_name((uint8_t)this_scx->scx[i]));
              }
              free(scx);
            } else
              fprintf(f, ", SC_%s, GC_%s, NULL},", u8ident_script_name(s),
                      mgcname);
            fprintf(f, " // %s %s",
                    s >= FIRST_LIMITED_USE_SCRIPT ? " (Limited)"
                    : s >= FIRST_EXCLUDED_SCRIPT  ? " (Excluded)"
                                                  : "",
                    tmp);
          } else {
            fprintf(f, "    {0x%X, 0x%X", from, to);
            fprintf(f, "}, // %s%s %s", u8ident_script_name(s),
                    s >= FIRST_LIMITED_USE_SCRIPT ? " (Limited)"
                    : s >= FIRST_EXCLUDED_SCRIPT  ? " (Excluded)"
                                                  : "",
                    tmp);
          }
          if (from == to) {
            stats.singles++;
            fprintf(f, "\n");
          } else {
            stats.ranges++;
            enc_utf8(tmp, &len, to);
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
   C11/C++11 accepted all, ignoring all unicode security recommendations for
   identifiers.
 */
static void gen_c11_all(void) {
  // uint8_t o = 0, s;
  const char *header = "c11-all.h";
  uint8_t u[0x10ffff >> 3];
  memset(u, 0, sizeof(u));
  memset(&stats, 0, sizeof(stats));
  for (size_t i = 0; i < ARRAY_SIZE(c11_start_list); i++) {
    struct range_bool r = c11_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      BITSET(u, cp);
    }
  }
#ifdef HAVE_SYS_STAT_H
  chmod(header, 0644);
#endif
  FILE *f = fopen(header, "w");
  fprintf(f,
          "/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */\n"
          "/* libu8ident - Check unicode security guidelines for identifiers.\n"
          "   Copyright 2021, 2022 Reini Urban\n"
          "   SPDX-License-Identifier: Apache-2.0\n"
          "\n"
          "   Generated by mkc23 from unic11.h.\n"
          "   UNICODE version %d.%d\n"
          "*/\n",
          U8ID_UNICODE_MAJOR, U8ID_UNICODE_MINOR);
  fputs(
      "static const struct range_bool c11_start_list[] = {\n"
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
  fputs("static const struct range_bool c11_cont_list[] = {\n"
        "    {'$', '$'},\n"
        "    {'0', '9'},\n",
        f);
  emit_ranges(f, 0xff, u, false);
  fputs("};", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "c11_cont_list",
         stats.ranges, stats.singles, stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fclose(f);
#ifdef HAVE_SYS_STAT_H
  chmod(header, 0444);
#endif
  memset(&stats, 0, sizeof(stats));
  printf("%s created\n", header);
}

// XID, only recommended scripts and IdTypes, mandate NFC (no MARK)
static void gen_c23_safe(void) {
  const char *header = "unic23.h";
#ifdef HAVE_SYS_STAT_H
  chmod(header, 0644);
#endif
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
      if (s < FIRST_EXCLUDED_SCRIPT && !u8ident_is_MARK(cp) &&
          !isHalfwidthOrFullwidth(cp) && !u8ident_is_MEDIAL(cp)) {
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
  fprintf(
      f,
      "/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */\n"
      "/* libu8ident - Check unicode security guidelines for identifiers.\n"
      "   Copyright 2022 Reini Urban\n"
      "   SPDX-License-Identifier: Apache-2.0\n"
      "\n"
      "   Generated by mkc23, do not modify.\n"
      "   UNICODE version %d.%d\n"
      "   Filtered XID_Start/Continue with allowed scripts, safe IDTypes and "
      "NFC\n"
      "*/\n"
      "\n"
      "struct sc_c23 {\n"
      "    uint32_t from;\n"
      "    uint32_t to;\n"
      "    enum u8id_sc sc;\n"
      "    enum u8id_gc gc;\n"
      "    // maxsize: Beng Deva Dogr Gong Gonm Gran Gujr Guru Knda Limb\n"
      "    //          Mahj Mlym Nand Orya Sind Sinh Sylo Takr Taml Telu Tirh\n"
      "    const char *scx;\n"
      "};\n"
      "\n",
      U8ID_UNICODE_MAJOR, U8ID_UNICODE_MINOR);
  fputs("// Filtering allowed scripts, XID_Start, Skipped Ids, !MEDIAL and "
        "NFC.\n",
        f);
  fputs("// Ranges split on GC and SCX changes\n", f);
  fputs("#ifndef EXTERN_SCRIPTS\n", f);
  fputs("const struct sc_c23 safec23_start_list[] = {\n"
        "    {'$', '$', SC_Latin, GC_Sc, NULL},\n"  // 24
        "    {'A', 'Z', SC_Latin, GC_Lu, NULL},\n"  // 41-5a
        "    {'_', '_', SC_Latin, GC_Pc, NULL},\n"  // 5f
        "    {'a', 'z', SC_Latin, GC_Ll, NULL},\n", // 61-7a
        f);
  emit_ranges(f, 0x7b, u, true);
  fputs("};\n", f);
  fputs("#else\n", f);
  fprintf(f, "extern const struct sc_c23 safec23_start_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
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
      if (s < FIRST_EXCLUDED_SCRIPT && !u8ident_is_MARK(cp) &&
          !isSkipIdtype(cp) && !isHalfwidthOrFullwidth(cp)) {
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
  // plus we move the medial positions here, which were originally in start.
  // A TR31 XID oversight
  for (size_t i = 0; i < ARRAY_SIZE(xid_start_list); i++) {
    struct range_bool r = xid_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      if (BITGET(c, cp))
        continue;
      uint8_t s = u8ident_get_script(cp);
      if (s < FIRST_EXCLUDED_SCRIPT && u8ident_is_MEDIAL(cp) &&
          !u8ident_is_MARK(cp) && !isHalfwidthOrFullwidth(cp)) {
        BITSET(c, cp);
      }
    }
  }

  fputs(
      "\n// Filtering allowed scripts, XID_Continue,!XID_Start, safe IDTypes, "
      "NFC\n"
      "// MEDIAL from XID_Start and !MARK. Split on GC and SCX\n",
      f);
  fputs("#ifndef EXTERN_SCRIPTS\n", f);
  fputs("const struct sc_c23 safec23_cont_list[] = {\n", f);
  emit_ranges(f, 0x23, c, true);
  fputs("};\n", f);
  fputs("#else\n", f);
  fprintf(f, "extern const struct sc_c23 safec23_cont_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "safec23_cont_list",
         stats.ranges, stats.singles, stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  memset(&stats, 0, sizeof(stats));

  // now more scripts
  fputs("\n\n//---------------------------------------------------\n", f);
  fputs("\n// Only excluded scripts, XID_Start, more IDTypes, NFC, !MEDIAL "
        "and !MARK\n",
        f);
  memset(u, 0, sizeof(u));
  for (size_t i = 0; i < ARRAY_SIZE(xid_start_list); i++) {
    struct range_bool r = xid_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      uint8_t s = u8ident_get_script(cp);
      if (s >= FIRST_EXCLUDED_SCRIPT && s < FIRST_LIMITED_USE_SCRIPT &&
          !u8ident_is_MARK(cp) && !isExcludedIdtype(cp) &&
          !isHalfwidthOrFullwidth(cp) && !u8ident_is_MEDIAL(cp)) {
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
  fputs("#ifndef EXTERN_SCRIPTS\n", f);
  fputs("const struct sc_c23 safec23_excl_start_list[] = {\n", f);
  emit_ranges(f, 0x7a, u, true);
  fputs("};\n", f);
  fputs("#else\n", f);
  fprintf(f, "extern const struct sc_c23 safec23_excl_start_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n",
         "safec23_excl_start_list", stats.ranges, stats.singles,
         stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  memset(&stats, 0, sizeof(stats));

  fputs(
      "\n// Only excluded scripts, XID_Continue,!XID_Start, more IDTypes, NFC "
      "and !MARK\n",
      f);
  memset(c, 0, sizeof(c));
  for (size_t i = 0; i < ARRAY_SIZE(xid_cont_list); i++) {
    struct range_bool r = xid_cont_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      if (BITGET(u, cp))
        continue;
      uint8_t s = u8ident_get_script(cp);
      if (s >= FIRST_EXCLUDED_SCRIPT && s < FIRST_LIMITED_USE_SCRIPT &&
          !u8ident_is_MARK(cp) && !isExcludedIdtype(cp) &&
          !isHalfwidthOrFullwidth(cp)) {
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
  // plus we move the medial positions here, which were originally in start.
  // A TR31 XID oversight
  for (size_t i = 0; i < ARRAY_SIZE(xid_start_list); i++) {
    struct range_bool r = xid_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      if (BITGET(c, cp))
        continue;
      uint8_t s = u8ident_get_script(cp);
      if (s >= FIRST_EXCLUDED_SCRIPT && s < FIRST_LIMITED_USE_SCRIPT &&
          u8ident_is_MEDIAL(cp) && !u8ident_is_MARK(cp) &&
          !isExcludedIdtype(cp) && !isHalfwidthOrFullwidth(cp)) {
        BITSET(c, cp);
      }
    }
  }

  fputs("#ifndef EXTERN_SCRIPTS\n", f);
  fputs("const struct sc_c23 safec23_excl_cont_list[] = {\n", f);
  emit_ranges(f, 0x23, c, true);
  fputs("};\n", f);
  fputs("#else\n", f);
  fprintf(f, "extern const struct sc_c23 safec23_excl_cont_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n",
         "safec23_excl_cont_list", stats.ranges, stats.singles,
         stats.codepoints);
  fprintf(f, "// %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fclose(f);
#ifdef HAVE_SYS_STAT_H
  chmod(header, 0444);
#endif
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
