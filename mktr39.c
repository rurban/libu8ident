/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022, 2025 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   Create and test a secure variant of C11 identifiers, the TR39 profile:
   * TR39#5.2 Mixed-Scripts Moderately Restrictive (4), but allow Greek scripts
     (hence TR39_4),
   * Disallow all Limited_Use and Excluded scripts,
   * Only allow TR 39#1 Recommended, Inclusion, and not-confusable Technical
     Identifier Type properties,
     Forbid confusables in Technical, such as ǃ U+1C3 "LATIN LETTER ALVEOLAR
   CLICK" ǀ U+1C0 "LATIN LETTER DENTAL CLICK" and ǁ U+1C1 "LATIN LETTER LATERAL
   CLICK"
   * Demand NFC normalization. Reject all composable sequences as ill-formed.
   * Reject illegal mark sequences (Lm, Mn, Mc) with mixed-scripts (SCX) as
     ill-formed.

   See doc/c11.md and doc/D2528R1.md

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

// Local SCX data, parsed directly from ScriptExtensions.txt and
// PropertyValueAliases.txt.  This avoids depending on scripts.h scx_list.
#define MAX_LOCAL_SCX 512
#define MAX_SCX_SCRIPTS 16

static struct {
  char short_name[32];
  char long_name[64];
} pva_map[256];
static int pva_count = 0;

static struct local_scx {
  uint32_t from;
  uint32_t to;
  char scx[MAX_SCX_SCRIPTS + 1];
} local_scx_list[MAX_LOCAL_SCX];
static int local_scx_count = 0;

static void read_pva(void) {
  FILE *fp = fopen("PropertyValueAliases.txt", "r");
  if (!fp) {
    fprintf(stderr, "Cannot open PropertyValueAliases.txt\n");
    return;
  }
  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    char short_name[32], long_name[64];
    if (sscanf(line, "sc ; %31s ; %63s", short_name, long_name) == 2) {
      strcpy(pva_map[pva_count].short_name, short_name);
      strcpy(pva_map[pva_count].long_name, long_name);
      pva_count++;
    }
  }
  fclose(fp);
}

static const char *pva_lookup(const char *short_name) {
  for (int i = 0; i < pva_count; i++) {
    if (strcmp(pva_map[i].short_name, short_name) == 0)
      return pva_map[i].long_name;
  }
  return short_name;
}

static int script_name_to_enum(const char *name) {
  if (!name)
    return -1;
  for (int i = 0; i <= LAST_SCRIPT; i++) {
    if (!all_scripts[i])
      continue;
    if (strcmp(all_scripts[i], name) == 0)
      return i;
  }
  return -1;
}

static void read_scx(void) {
  fprintf(stderr, "read_scx: starting\n");
  FILE *fp = fopen("ScriptExtensions.txt", "r");
  if (!fp) {
    fprintf(stderr, "Cannot open ScriptExtensions.txt\n");
    return;
  }
  char line[512];
  uint32_t prev_to = 0;
  const char *prev_scx_str = NULL;
  while (fgets(line, sizeof(line), fp)) {
    if (line[0] == '#' || line[0] == '\n')
      continue;
    if (strncmp(line, "# @", 3) == 0)
      continue;
    char *p = line;
    char *endptr;
    uint32_t from = strtoul(p, &endptr, 16);
    if (endptr == p)
      continue;
    p = endptr;
    uint32_t to = from;
    if (*p == '.' && p[1] == '.') {
      p += 2;
      to = strtoul(p, &endptr, 16);
      p = endptr;
    }
    while (*p == ' ' || *p == '\t')
      p++;
    if (*p != ';')
      continue;
    p++;
    while (*p == ' ' || *p == '\t')
      p++;
    char *scripts_start = p;
    char *hash = strchr(p, '#');
    if (!hash)
      continue;
    *hash = '\0';

    // UCD bug workaround for 0x0345
    if (from == 0x0345) {
      from = 0x342;
      prev_to = 0x341;
    }

    char scx_bytes[MAX_SCX_SCRIPTS + 1] = {0};
    int scx_len = 0;
    char *saveptr;
    char *tok = strtok_r(scripts_start, " \t\r\n", &saveptr);
    while (tok && scx_len < MAX_SCX_SCRIPTS) {
      int sc_enum = script_name_to_enum(tok);
      if (sc_enum < 0) {
        const char *long_name = pva_lookup(tok);
        sc_enum = script_name_to_enum(long_name);
      }
      if (sc_enum < 0) {
        fprintf(stderr, "Unknown script %s at U+%04X\n", tok, from);
      } else {
        scx_bytes[scx_len++] = (char)sc_enum;
      }
      tok = strtok_r(NULL, " \t\r\n", &saveptr);
    }
    scx_bytes[scx_len] = '\0';

    // Merge with previous range if contiguous and same scx
    if (prev_to + 1 == from && prev_scx_str && strEQ(prev_scx_str, scx_bytes) &&
        local_scx_count > 0) {
      local_scx_list[local_scx_count - 1].to = to;
    } else {
      if (local_scx_count >= MAX_LOCAL_SCX) {
        fprintf(stderr, "Too many SCX ranges\n");
        break;
      }
      local_scx_list[local_scx_count].from = from;
      local_scx_list[local_scx_count].to = to;
      memcpy(local_scx_list[local_scx_count].scx, scx_bytes, scx_len + 1);
      local_scx_count++;
    }
    prev_to = to;
    prev_scx_str = local_scx_list[local_scx_count - 1].scx;
  }
  fprintf(stderr, "read_scx: loaded %d ranges\n", local_scx_count);
  for (int j = 0; j < local_scx_count; j++) {
    fprintf(stderr, "  scx[%d]: 0x%04X-0x%04X\n", j, local_scx_list[j].from, local_scx_list[j].to);
  }
  fclose(fp);
}

static const struct local_scx *local_get_scx(const uint32_t cp) {
  int n = local_scx_count;
  const char *p = (char *)local_scx_list;
  const size_t size = sizeof(local_scx_list[0]);
  while (n > 0) {
    const struct local_scx *pos = (const struct local_scx *)(p + size * (n / 2));
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

// disallow Arabic Presentation Forms-A and B
static inline bool isArabicPresentationForm(const uint32_t cp) {
  return (cp >= 0xFB50 && cp <= 0xFDFF) || (cp >= 0xFE70 && cp <= 0xFEFF);
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
  const struct local_scx *s1 = local_get_scx(from);
  for (uint32_t i = from + 1; i <= to; i++) {
    const struct local_scx *s2 = local_get_scx(i);
    // if both are NULL or both are defined and equal, it's equal.
    if (!((!s1 && !s2) || ((s1 && s2) && strEQ(s1->scx, s2->scx))))
      return i;
  }
  return 0;
}

void emit_ranges(FILE *f, size_t start, uint8_t *u, bool with_sc) {
  unsigned from = (unsigned)start;
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
            struct local_scx *this_scx = (struct local_scx *)local_get_scx(from);
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
              this_scx = (struct local_scx *)local_get_scx(from);
            } else {
              if (*minor) {
                mgcname[0] = *minor;
                mgcname[1] = '\0'; // we cannot represent L& as enum, so use
                                   // just GC_L or GC_V
                fprintf(stderr, "U+%X: minor GC %s -> %s\n", from, gcname,
                        mgcname);
              }
            }
            while ((scx_split = first_scx_change(from, to))) {
              fprintf(stderr, "U+%X: split SCX changed at U+%X (s1=%p, s2=%p)\n", from,
                      scx_split, (void*)local_get_scx(from), (void*)local_get_scx(scx_split));
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
              this_scx = (struct local_scx *)local_get_scx(from);
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
  uint8_t u[0x110000 >> 3];
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
          "   Copyright 2021,2022,2025 Reini Urban\n"
          "   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later\n"
          "\n"
          "   Generated by mktr29 from unic11.h. Do not modify. Modify "
          "mktr39.c instead..\n"
          "   UNICODE version %d.%d\n"
          "*/\n",
          U8ID_UNICODE_MAJOR, U8ID_UNICODE_MINOR);
  fputs(
      "#include \"config.h\"\n"
      "static const struct range_bool c11_start_list[] = {\n"
      "#ifdef ALLOW_DOLLAR\n"
      "    {'$', '$'},\n"
      "#endif\n"
      "    {'A', 'Z'}, {'_', '_'}, {'a', 'z'},\n"
      "    {0x00A8, 0x00A8},   {0x00AA, 0x00AA},\n"
      "    {0x00AD, 0x00AD},   {0x00AF, 0x00AF},   {0x00B2, 0x00B5},\n"
      "    {0x00B7, 0x00BA},   {0x00BC, 0x00BE},   {0x00C0, 0x00D6},\n"
      "    {0x00D8, 0x00F6},   {0x00F8, 0x00FF},\n"
      "    // {0x0100, 0x02FF}, // Latin, 2B0-2FF: Modifiers (2EA Bopomofo)\n",
      f);
  emit_ranges(f, 0xff, u, false);
  fprintf(f, "}; // %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "c11_start_list",
         stats.ranges, stats.singles, stats.codepoints);

  memset(u, 0, sizeof(u));
  memset(&stats, 0, sizeof(stats));
  for (size_t i = 0; i < ARRAY_SIZE(c11_cont_list); i++) {
    struct range_bool r = c11_cont_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      BITSET(u, cp);
    }
  }
  fputs("static const struct range_bool c11_cont_list[] = {\n"
        "#ifdef ALLOW_DOLLAR\n"
        "    {'$', '$'},\n"
        "#endif\n"
        "    {'0', '9'},\n",
        f);
  emit_ranges(f, 0xff, u, false);
  fprintf(f, "}; // %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "c11_cont_list",
         stats.ranges, stats.singles, stats.codepoints);
  fclose(f);
#ifdef HAVE_SYS_STAT_H
  chmod(header, 0444);
#endif
  memset(&stats, 0, sizeof(stats));
  printf("%s created\n", header);
}

// XID, only recommended scripts and IdTypes, mandate NFC (no MARK)
static void gen_unitr39(void) {
  const char *header = "unitr39.h";
#ifdef HAVE_SYS_STAT_H
  chmod(header, 0644);
#endif
  FILE *f = fopen(header, "w");
  int nfc = 0;
  static uint8_t u[0x110000 >> 3];
  char tmp[32];
  memset(u, 0, sizeof(u));
  memset(&stats, 0, sizeof(stats));
  fprintf(stderr, "Split some ranges with different scripts:\n");
  for (size_t i = 0; i < ARRAY_SIZE(xid_start_list); i++) {
    struct range_bool r = xid_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      uint8_t s = u8ident_get_script(cp);
      enum u8id_gc gc = u8ident_get_gc(cp);
      if (s < FIRST_EXCLUDED_SCRIPT && !u8ident_is_MARK(cp) && gc != GC_Mc &&
          !isSkipIdtype(cp) && !isHalfwidthOrFullwidth(cp) &&
          !isArabicPresentationForm(cp) && !u8ident_is_MEDIAL(cp)) {
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
      "   Copyright 2022,2025 Reini Urban\n"
      "   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later\n"
      "\n"
      "   Generated by mktr29, do not modify. Modify mktr39.c instead.\n"
      "   UNICODE version %d.%d\n"
      "   Filtered XID_Start/Continue with allowed scripts, safe IDTypes and "
      "NFC\n"
      "*/\n"
      "\n"
      "#include \"config.h\"\n"
      "struct sc_tr39 {\n"
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
  fputs("const struct sc_tr39 tr39_start_list[] = {\n"
        "#ifdef ALLOW_DOLLAR\n"
        "    {'$', '$', SC_Latin, GC_Sc, NULL},\n" // 24
        "#endif\n"
        "    {'A', 'Z', SC_Latin, GC_Lu, NULL},\n"  // 41-5a
        "    {'_', '_', SC_Latin, GC_Pc, NULL},\n"  // 5f
        "    {'a', 'z', SC_Latin, GC_Ll, NULL},\n", // 61-7a
        f);
  emit_ranges(f, 0x7b, u, true);
  fprintf(f, "}; // %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fputs("#else\n", f);
  fprintf(f, "extern const struct sc_tr39 tr39_start_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "tr39_start_list",
         stats.ranges, stats.singles, stats.codepoints);

  memset(&stats, 0, sizeof(stats));
  static uint8_t c[0x10ffff >> 3];
  memset(c, 0, sizeof(c));
  for (size_t i = 0; i < ARRAY_SIZE(xid_cont_list); i++) {
    struct range_bool r = xid_cont_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      if (BITGET(u, cp))
        continue;
      uint8_t s = u8ident_get_script(cp);
      enum u8id_gc gc = u8ident_get_gc(cp);
      if (s < FIRST_EXCLUDED_SCRIPT && !u8ident_is_MARK(cp) && gc != GC_Mc &&
          !isSkipIdtype(cp) && !isArabicPresentationForm(cp) &&
          !isHalfwidthOrFullwidth(cp)) {
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
      enum u8id_gc gc = u8ident_get_gc(cp);
      if (s < FIRST_EXCLUDED_SCRIPT && u8ident_is_MEDIAL(cp) &&
          !u8ident_is_MARK(cp) && gc != GC_Mc && !isHalfwidthOrFullwidth(cp) &&
          !isArabicPresentationForm(cp)) {
        BITSET(c, cp);
      }
    }
  }
  // Clear the unused catalan B7 MIDDLE DOT, another TR39 bug.
  // This should have an Uncommon_Use Type, not Inclusion.
  // https://en.wikipedia.org/wiki/Catalan_orthography#Punt_volat_(middot)
  BITCLR(c, 0xB7);

  fputs(
      "\n// Filtering allowed scripts, XID_Continue,!XID_Start, safe IDTypes, "
      "NFC\n"
      "// MEDIAL from XID_Start and !MARK. Split on GC and SCX\n",
      f);
  fputs("#ifndef EXTERN_SCRIPTS\n", f);
  fputs("const struct sc_tr39 tr39_cont_list[] = {\n", f);
  emit_ranges(f, 0x23, c, true);
  fprintf(f, "}; // %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fputs("#else\n", f);
  fprintf(f, "extern const struct sc_tr39 tr39_cont_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "tr39_cont_list",
         stats.ranges, stats.singles, stats.codepoints);
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
      enum u8id_gc gc = u8ident_get_gc(cp);
      if (s >= FIRST_EXCLUDED_SCRIPT && s < FIRST_LIMITED_USE_SCRIPT &&
          !u8ident_is_MARK(cp) && gc != GC_Mc && !isExcludedIdtype(cp) &&
          !isHalfwidthOrFullwidth(cp) && !isArabicPresentationForm(cp) &&
          !u8ident_is_MEDIAL(cp)) {
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
  fputs("const struct sc_tr39 tr39_excl_start_list[] = {\n", f);
  emit_ranges(f, 0x7a, u, true);
  fprintf(f, "}; // %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fputs("#else\n", f);
  fprintf(f, "extern const struct sc_tr39 tr39_excl_start_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n",
         "tr39_excl_start_list", stats.ranges, stats.singles, stats.codepoints);
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
      enum u8id_gc gc = u8ident_get_gc(cp);
      if (s >= FIRST_EXCLUDED_SCRIPT && s < FIRST_LIMITED_USE_SCRIPT &&
          !u8ident_is_MARK(cp) && gc != GC_Mc && !isExcludedIdtype(cp) &&
          !isHalfwidthOrFullwidth(cp) && !isArabicPresentationForm(cp)) {
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
      enum u8id_gc gc = u8ident_get_gc(cp);
      if (s >= FIRST_EXCLUDED_SCRIPT && s < FIRST_LIMITED_USE_SCRIPT &&
          u8ident_is_MEDIAL(cp) && !u8ident_is_MARK(cp) && gc != GC_Mc &&
          !isExcludedIdtype(cp) && !isHalfwidthOrFullwidth(cp) &&
          !isArabicPresentationForm(cp)) {
        BITSET(c, cp);
      }
    }
  }

  fputs("#ifndef EXTERN_SCRIPTS\n", f);
  fputs("const struct sc_tr39 tr39_excl_cont_list[] = {\n", f);
  emit_ranges(f, 0x23, c, true);
  fprintf(f, "}; // %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fputs("#else\n", f);
  fprintf(f, "extern const struct sc_tr39 tr39_excl_cont_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "tr39_excl_cont_list",
         stats.ranges, stats.singles, stats.codepoints);
  memset(&stats, 0, sizeof(stats));

  // get tr39_medial. Empty for v14
  memset(c, 0, sizeof(c));
  for (size_t i = 0; i < ARRAY_SIZE(xid_start_list); i++) {
    struct range_bool r = xid_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      if (BITGET(c, cp))
        continue;
      if (u8ident_is_MEDIAL(cp)) {
        uint8_t s = u8ident_get_script(cp);
        enum u8id_gc gc = u8ident_get_gc(cp);
        if (s < FIRST_LIMITED_USE_SCRIPT && !u8ident_is_MARK(cp) &&
            gc != GC_Mc && !isExcludedIdtype(cp) &&
            !isHalfwidthOrFullwidth(cp)) {
          BITSET(c, cp);
        }
      }
    }
  }
  for (size_t i = 0; i < ARRAY_SIZE(xid_cont_list); i++) {
    struct range_bool r = xid_cont_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      if (BITGET(c, cp))
        continue;
      if (u8ident_is_MEDIAL(cp)) {
        uint8_t s = u8ident_get_script(cp);
        enum u8id_gc gc = u8ident_get_gc(cp);
        if (s < FIRST_LIMITED_USE_SCRIPT && !u8ident_is_MARK(cp) &&
            gc != GC_Mc && !isExcludedIdtype(cp) &&
            !isArabicPresentationForm(cp) && !isHalfwidthOrFullwidth(cp)) {
          BITSET(c, cp);
        }
      }
    }
  }
  BITCLR(c, 0xB7);

  //fputs("\n// Currently empty MEDIAL list for tr39.\n", f);
  fputs("// tr39_start/cont + MEDIAL\n", f);
  //fputs("#if 0\n", f);
  fputs("#ifndef EXTERN_SCRIPTS\n", f);
  fputs("const struct range_bool tr39_medial_list[] = {\n", f);
  emit_ranges(f, 0x27, c, false);
  fprintf(f, "}; // %u ranges, %u singles, %u codepoints\n", stats.ranges,
          stats.singles, stats.codepoints);
  fputs("#else\n", f);
  fprintf(f, "extern const struct range_bool tr39_medial_list[%u];\n",
          stats.ranges + stats.singles);
  fputs("#endif\n", f);
  //fputs("#endif\n", f);
  printf("%s:\n  %u ranges, %u singles, %u codepoints\n", "tr39_medial_list",
         stats.ranges, stats.singles, stats.codepoints);

  fclose(f);
#ifdef HAVE_SYS_STAT_H
  chmod(header, 0444);
#endif
  memset(&stats, 0, sizeof(stats));
  fprintf(stderr, "%d codepoints not NFC safe\n", nfc);
  printf("%s created\n", header);
}

int main(/*int argc, char **argv*/) {
  u8ident_init(U8ID_PROFILE_TR39_4, U8ID_NFC, 0);

  gen_c11_all();
  read_pva();
  read_scx();
  gen_unitr39();

  u8ident_free();
  return 0;
}
