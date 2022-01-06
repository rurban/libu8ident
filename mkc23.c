/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   Create and test a secure variant of C11 identifiers, the SAFEC23 profile:
   * Moderately Restrictive (4), but allow Greek scripts,
   * Disallow all Limited_Use and Excluded scripts,
   * Demand NFC normalization.
   See c11.md and c23++proposal.md
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
#ifdef HAVE_LIBGEN_H
#  include <libgen.h>
#endif

#include "u8ident.h"
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
#  include "uniwbrk.h"
#endif
#ifdef HAVE_CROARING
#  include "roaring.h"
static roaring_bitmap_t *rmark = NULL;
#endif
#include "u8idscr.h"
#undef EXT_SCRIPTS
#include "unic11.h"
#include "mark.h"

// private access
unsigned u8ident_options(void);
unsigned u8ident_profile(void);
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

static inline bool isC11_start(uint32_t cp) {
  return range_bool_search(cp, c11_start_list, ARRAY_SIZE(c11_start_list));
}

static inline bool isC11_cont(uint32_t cp) {
  return range_bool_search(cp, c11_cont_list, ARRAY_SIZE(c11_cont_list));
}

static inline bool isMARK(uint32_t cp) {
#ifdef HAVE_CROARING
  return roaring_bitmap_contains(rmark, cp);
#else
  return range_bool_search(cp, mark_list, ARRAY_SIZE(mark_list));
#endif
}

static const char *errstr(int errcode) {
  static const char *const _str[] = {
      "ERR_CONFUS",           // -5
      "ERR_ENCODING",         // -4
      "ERR_SCRIPTS",          //-3
      "ERR_SCRIPT",           //-2
      "ERR_XID",              // -1
      "EOK",                  // 0
      "EOK_NORM",             // 1
      "EOK_WARN_CONFUS",      // 2
      "EOK_NORM_WARN_CONFUS", // 3
  };
  assert(errcode >= -5 && errcode <= 3);
  return _str[errcode + 5];
}

int testdir(const char *dir, const char *fname) {
  char path[256];
  static char line[1024] = {0};
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
  static char brks[1024] = {0};
#endif
  static char word[128] = {0};
  if (!dir) {
    strncpy(path, fname, sizeof(path) - 1);
  } else {
    strncpy(path, dir, sizeof(path) - 1);
    path[255] = '\0';
    strncat(path, "/", sizeof(path) - 1);
    path[255] = '\0';
    strncat(path, fname, sizeof(path) - 1);
    path[255] = '\0';
  }

  FILE *f = fopen(path, "r");
  if (!f) {
    perror("fopen");
    fprintf(stderr, "texts/%s\n", fname);
    return -1;
  }

  printf("-- texts/%s\n", fname);
  int ctx = u8ident_new_ctx();
  // while (fscanf(f, " %1023s", word) == 1)
  //  Check now also against libunistring: u8_wordbreaks
  while (fgets(line, 1023, f)) {
    char *s = &line[0];
    bool prev_isword = false;
    char *wp = &word[0];
    *word = '\0';
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
    u8_wordbreaks(s, strlen(s), brks);
#endif
    while (*s) {
      char *olds = s;
      uint32_t cp = dec_utf8(&s);
      if (!cp) {
        printf("ERROR %s illegal UTF-8\n", olds);
        exit(1);
      }

      // unicode #29 word-break, but simplified:
      // must not split at continuations (Combining marks). e.g. for
      // texts/arabic-1.txt
      const bool iscont = isC11_cont(cp);
      bool isword = prev_isword ? (isC11_start(cp) || iscont) : isC11_start(cp);
      char force_break = (prev_isword != isword && !iscont);
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
      if (force_break != brks[s - olds])
        fprintf(stderr, "WARN: %sbreak at U+%X \n", force_break ? "" : "no ",
                cp);
      force_break = brks[s - olds];
#endif
      // first, or changed from non-word to word, and is no mark (continuation)
      if (olds == &line[0] || force_break) {
        prev_isword = isword;
        if (isword) {
          int l = s - olds;
          if (l == 1) {
            *wp++ = *olds;
          } else {
            memcpy(wp, olds, l);
            wp += l;
          }
          continue; // started new word
        } else {    // word-end: fall-through to word check
          *wp = '\0';
        }
      } else { // no change. in word or non-word
        if (isword) {
          int l = s - olds;
          if (l == 1) {
            *wp++ = *olds;
          } else {
            memcpy(wp, olds, l);
            wp += l;
          }
        }
        if (*s != '\n')
          continue;
      }
      // bad case "\xd8\xa8\xd8\xb1\xd9\x88\xd8\xad" "بروح" Arabic
      if (!*wp && *word && force_break) { // non-empty word-end
        int ret = u8ident_check((uint8_t *)word, NULL);
        const char *scripts = u8ident_existing_scripts(ctx);
        printf("%s: %s (%s", word, errstr(ret), scripts);
        if (ret < 0) {
          const uint32_t cp = u8ident_failed_char(ctx);
          const uint8_t scr = u8ident_get_script(cp);
          if (scr != SC_Unknown)
            printf(" + U+%X %s)!\n", cp, u8ident_script_name(scr));
          else
            printf(" + U+%X)!\n", cp);
        } else
          printf(")\n");
        free((char *)scripts);
        *word = '\0';
        wp = &word[0];
      }
    }
  }

  u8ident_free_ctx(ctx);
  fclose(f);
  return 0;
}

int cmp_str(const void *a, const void *b) {
  return strcmp(*(const char **)a, *(const char **)b);
}

// uint8_t[10FFFF/8]
#define BITGET(b, i) (b[i >> 3] & (1 << (7 - (i & 7)))) != 0
#define BITSET(b, i) b[i >> 3] |= (1 << (7 - (i & 7)))
#define BITCLR(b, i) b[i >> 3] &= ~(1 << (7 - (i & 7)))

void emit_ranges(FILE *f, size_t start, uint8_t *u) {
  unsigned from = start;
  bool on = BITGET(u, from);
  for (unsigned i = start; i < 0x10ffff; i++) {
    if (BITGET(u, i)) {
      if (!on) { // on, and was off
        from = i;
        on = true;
      }
    } else if (on) { // off, but was on
      if (from <= i - 1) {
        const uint8_t s = u8ident_get_script(from);
        fprintf(f, "    {0x%X, 0x%X}, // %s%s\n", from, i - 1,
                u8ident_script_name(s),
                s >= FIRST_LIMITED_USE_SCRIPT ? " (Limited)"
                : s >= FIRST_EXCLUDED_SCRIPT  ? " (Excluded)"
                                              : "");
      }
      from = i;
      on = false;
    }
  }
}

/* Show all insecure scripts in the C11 permitted range.
   C11/C++11 accepted all, ignoring all unicode security recommendations.
 */
static void gen_c11_all(void) {
  uint8_t o = 0, s;
  uint8_t u[0x10ffff >> 3];
  memset(u, 0, sizeof(u));
  for (size_t i = 0; i < ARRAY_SIZE(c11_start_list); i++) {
    struct range_bool r = c11_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      BITSET(u, cp);
      s = u8ident_get_script(cp);
      if (s != o && s > SC_Latin && s < SC_Unknown) {
        if (cp == r.from)
          printf("    {0x%X, 0x%X}, // %s%s\n", cp, r.to,
                 u8ident_script_name(s),
                 s >= FIRST_LIMITED_USE_SCRIPT ? " (Limited)"
                 : s >= FIRST_EXCLUDED_SCRIPT  ? " (Excluded)"
                                               : "");
        else
          printf("                      // %X: %s%s\n", cp,
                 u8ident_script_name(s),
                 s >= FIRST_LIMITED_USE_SCRIPT ? " (Limited)"
                 : s >= FIRST_EXCLUDED_SCRIPT  ? " (Excluded)"
                                               : "");
        o = s;
      }
    }
  }
  FILE *f = fopen("c11-all.h", "w");
  fputs("/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */\n"
        "/* libu8ident - Check unicode security guidelines for identifiers.\n"
        "   Copyright 2021, 2022 Reini Urban\n"
        "   SPDX-License-Identifier: Apache-2.0\n"
        "\n"
        "   generated by text-c11 from unic11.h.\n"
        "   UNICODE version 14.0\n"
        "*/\n",
        f);
  fputs("const struct range_bool c11_start_list[] = {\n"
        "    {'$', '$'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'},\n"
        "    {0x00A8, 0x00A8},   {0x00AA, 0x00AA},\n"
        "    {0x00AD, 0x00AD},   {0x00AF, 0x00AF},   {0x00B2, 0x00B5},\n"
        "    {0x00B7, 0x00BA},   {0x00BC, 0x00BE},   {0x00C0, 0x00D6},\n"
        "    {0x00D8, 0x00F6},   {0x00F8, 0x00FF},\n"
        "    // {0x0100, 0x02FF}, // Latin, 2B0-2FF: Modifiers (2EA Bopomofo)",
        f);
  emit_ranges(f, 0x100, u);
  fputs("};", f);
  fclose(f);
}

static void gen_c23_safe(void) {
  FILE *f = fopen("c23-safe.h", "w");
  static uint8_t u[0x10ffff >> 3];
  memset(u, 0, sizeof(u));
  for (size_t i = 0; i < ARRAY_SIZE(c11_start_list); i++) {
    struct range_bool r = c11_start_list[i];
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      uint8_t s = u8ident_get_script(cp);
      if (s < FIRST_EXCLUDED_SCRIPT && u8ident_is_allowed(cp)) {
        BITSET(u, cp);
      }
    }
  }
  fputs("/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */\n"
        "/* libu8ident - Check unicode security guidelines for identifiers.\n"
        "   Copyright 2021, 2022 Reini Urban\n"
        "   SPDX-License-Identifier: Apache-2.0\n"
        "\n"
        "   generated by text-c11, do not modify.\n"
        "   UNICODE version 14.0\n"
        "*/\n",
        f);
  fputs("// Filtering allowed scripts and IdentifierStatus\n", f);
  fputs("const struct range_bool safec23_start_list[] = {\n"
        "    {'_', '_'},         {'a', 'z'},         {'A', 'Z'},\n"
        "    {'$', '$'},         {0x00A8, 0x00A8},   {0x00AA, 0x00AA},\n"
        "    {0x00AD, 0x00AD},   {0x00AF, 0x00AF},   {0x00B2, 0x00B5},\n"
        "    {0x00B7, 0x00BA},   {0x00BC, 0x00BE},   {0x00C0, 0x00D6},\n"
        "    {0x00D8, 0x00F6},   {0x00F8, 0x00FF},\n"
        "    // {0x0100, 0x02FF}, // Latin, 2B0-2FF: Modifiers (2EA Bopomofo)",
        f);
  emit_ranges(f, 0x100, u);
  fputs("};", f);
  fclose(f);
}

#if 0
/* Generate a filtered range without Limited and Excluded scripts.
   TODO Also skip the LTR, RTL symbols for non-Arabic, and word joiners on non-CFK scripts.
   WIP See gen_c23_safe() for the simplier variant.
 */
static void print_valid_scripts(void) {
  uint8_t o = 0, s;
  uint8_t u[0x10ffff >> 3];
  puts("\nconst struct range_bool safec11_start_list[] = {\n"
       "    {'_', '_'},         {'a', 'z'},         {'A', 'Z'},\n"
       "    {'$', '$'},         {0x00A8, 0x00A8},   {0x00AA, 0x00AA},\n"
       "    {0x00AD, 0x00AD},   {0x00AF, 0x00AF},   {0x00B2, 0x00B5},\n"
       "    {0x00B7, 0x00BA},   {0x00BC, 0x00BE},   {0x00C0, 0x00D6},\n"
       "    {0x00D8, 0x00F6},   {0x00F8, 0x00FF},\n"
       "    // {0x0100, 0x02FF}, // Latin, 2B0-2FF: Modifiers (also Bopomofo)");
  // keep the first 13 ranges
  for (size_t i = 14; i < ARRAY_SIZE(c11_start_list); i++) {
    struct range_bool r = c11_start_list[i];
    struct range_bool r1;
    r1.from = r.from;
    r1.to = r.to;
    for (uint32_t cp = r.from; cp <= r.to; cp++) {
      s = u8ident_get_script(cp);
      bool good = u8ident_is_allowed(cp);
      if (s < FIRST_EXCLUDED_SCRIPT && good) {
        BITSET(u,cp);
      }
      // split into permitted and forbidden ranges
      if (s != o) {
        if (s >= FIRST_EXCLUDED_SCRIPT || !good) { // split
          // bad, print the range before
          r1.to = cp - 1;
          if (r1.from <= r1.to)
            printf("    {0x%X, 0x%X}, // %s\n", r1.from, r1.to, u8ident_script_name(o));
          if (s < SC_Unknown) {
            printf("    // skipped 0x%X %s%s%s\n", cp, good ? "" : "IdRestr ", u8ident_script_name(s),
                   s >= FIRST_LIMITED_USE_SCRIPT ? " (Limited)" :
                   s >= FIRST_EXCLUDED_SCRIPT ? " (Excluded)" : "");
          }
          r1.from = cp + 1;
        } else { // allowed again
          r1.to = cp;
          //if (r1.from >= r1.to)
          //  printf("    {0x%X, 0x%X}, // %s\n", r1.from, r1.to, u8ident_script_name(o));
        }
        o = s;
      } else if (s >= FIRST_EXCLUDED_SCRIPT || !good) { // invalid
        r1.from = cp + 1;
      }
    }
    // print rest
    if (r1.from <= r1.to) {
      printf("    {0x%X, 0x%X}, // %s\n", r1.from, r1.to, u8ident_script_name(s));
      r1.from = r1.to + 1;
    }
  }
  puts("};");
}
#endif

int main(int argc, char **argv) {
  char *dirname = "texts";
#ifdef HAVE_SYS_STAT_H
  struct stat st;
#endif
  u8ident_init(U8ID_PROFILE_C23_4, U8ID_NFC, 0);
#ifdef HAVE_CROARING
  rmark = roaring_bitmap_portable_deserialize_safe((char *)mark_croar_bin,
                                                   mark_croar_bin_len);
#endif

#if !defined _WIN32 && defined HAVE_SYS_STAT_H
  // TODO Windows via GetFileAttributes as DirExists
  if (argc > 1 && stat(argv[1], &st) == 0) {
    testdir(NULL, argv[1]);
    u8ident_free();
#  ifdef HAVE_CROARING
    roaring_bitmap_free(rmark);
#  endif
    return 0;
  }
#endif

  gen_c11_all();
  gen_c23_safe();
  // print_valid_scripts();

  if (getenv("U8IDTEST_TEXTS")) {
    dirname = getenv("U8IDTEST_TEXTS");
  }
  DIR *dir = opendir(dirname);
  if (!dir) {
    perror("opendir");
    exit(1);
  }

#ifdef HAVE_DIRENT_H
  struct dirent *d;
  int s = 0;
  // sort the names on unix, to compare against the result
  while ((d = readdir(dir))) {
    size_t l = strlen(d->d_name);
    if (l > 2 && strcmp(&d->d_name[l - 2], ".c") == 0) {
      s++;
    }
  }
  rewinddir(dir);
  const char **files = calloc(s, sizeof(char *));
  int i = 0;
  while ((d = readdir(dir))) {
    size_t l = strlen(d->d_name);
    if (l > 2 && strcmp(&d->d_name[l - 2], ".c") == 0) {
      assert(i < s);
      files[i] = malloc(strlen(d->d_name) + 1);
      strcpy((char *)files[i], d->d_name);
      i++;
    }
  }
  qsort(files, s, sizeof(char *), cmp_str);
#endif

  for (i = 0; i < s; i++) {
    // printf("%s\n", files[i]);
    testdir(dirname, files[i]);
  }
  closedir(dir);
  for (i = 0; i < s; i++)
    free((void *)files[i]);
  free(files);
  u8ident_free();
#ifdef HAVE_CROARING
  roaring_bitmap_free(rmark);
#endif
  return 0;
}
