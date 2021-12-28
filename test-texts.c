/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   check some files, wordbreak them to valid identifiers in some common scripts.
*/
#include "u8id_private.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef _WIN32
#include <direct.h>
#endif
#include <libgen.h>

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
#include "mark.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

// private access
unsigned u8ident_options(void);
unsigned u8ident_profile(void);
char *enc_utf8(char *dest, size_t *lenp, const uint32_t cp);

#ifndef HAVE_CROARING
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
  const char *r = (char *)binary_search(cp, (char *)list, len, sizeof(*list));
  return r ? true : false;
}
#endif

bool isMARK(uint32_t cp) {
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
  //while (fscanf(f, " %1023s", word) == 1)
  // Check now also against libunistring: u8_wordbreaks
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
      // must not split at continuations (Combining marks). e.g. for texts/arabic-1.txt
      bool isword = u8ident_is_allowed(cp);
      bool ismark = isMARK(cp);
      char force_break = (prev_isword != isword && !ismark);
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
      if (force_break != brks[s - olds])
        fprintf(stderr, "WARN: %sbreak at U+%X \n", force_break ? "" : "no ", cp);
      force_break = brks[s - olds];
#endif
      // first, or changed from non-word to word, and is no mark (continuation)
      if (olds == &line[0] || force_break) {
        prev_isword = isword;
        if (isword) {
          int l = s - olds;
          if (l == 1) {
            *wp++ = *olds;
          }
          else {
            memcpy(wp, olds, l);
            wp += l;
          }
          continue; // started new word
        } else { // word-end: fall-through to word check
          *wp = '\0';
        }
      } else { // no change. in word or non-word
        if (isword) {
          int l = s - olds;
          if (l == 1) {
            *wp++ = *olds;
          }
          else {
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
          uint32_t cp = u8ident_failed_char(ctx);
          printf(" + U+%X %s)!\n", cp, u8ident_script_name(u8ident_get_script(cp)));
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

int main(int argc, char **argv) {
  char *dirname = "texts";
#ifdef HAVE_SYS_STAT_H
  struct stat st;
#endif
  u8ident_init(U8ID_DEFAULT_OPTS);
#ifdef HAVE_CROARING
  rmark = roaring_bitmap_portable_deserialize_safe((char *)mark_croar_bin,
						   mark_croar_bin_len);
#endif

#ifndef _WIN32
  if (argc > 1 && stat(argv[1], &st) == 0) {
    testdir(NULL, argv[1]);
    u8ident_free();
#ifdef HAVE_CROARING
    roaring_bitmap_free (rmark);
#endif
    return 0;
  }
#endif

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
  // sort the names, to compare against the result
  while ((d = readdir(dir))) {
    size_t l = strlen(d->d_name);
    if (l > 4 && strcmp(&d->d_name[l - 4], ".txt") == 0) {
      s++;
    }
  }
  rewinddir(dir);
  const char **files = calloc(s, sizeof(char *));
  int i = 0;
  while ((d = readdir(dir))) {
    size_t l = strlen(d->d_name);
    if (l > 4 && strcmp(&d->d_name[l - 4], ".txt") == 0) {
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
  roaring_bitmap_free (rmark);
#endif
  return 0;
}
