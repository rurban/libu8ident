/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   read some files with words/valid identifiers in some common scripts.
*/
#include "u8id_private.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "u8ident.h"
#include "mark.h"
#ifdef HAVE_CROARING
#  include "roaring.c"
static roaring_bitmap_t *rmark = NULL;
#endif
#include "u8idscr.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)
// static char buf[128]; // for hex display

// private access
unsigned u8ident_options(void);
unsigned u8ident_profile(void);
char *enc_utf8(char *dest, size_t *lenp, const uint32_t cp);

#ifndef HAVE_CROARING
static int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}
#endif

bool isMARK(uint32_t cp) {
#ifdef HAVE_CROARING
  return roaring_bitmap_contains(rmark, cp);
#else
  return bsearch(&cp, mark_list, ARRAY_SIZE(mark_list), 4, compar32) != NULL
             ? true
             : false;
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
    fprintf(stderr, "%s\n", path);
    return -1;
  }

  printf("-- %s\n", path);
  int ctx = u8ident_new_ctx();
  //while (fscanf(f, " %1023s", word) == 1)
  // TODO Check also against libunistring: u8_wordbreaks
  while (fgets(line, 1023, f)) {
    char *s = &line[0];
    bool prev_isword = false;
    char *wp = &word[0];
    *word = '\0';
    while (*s) {
      char *olds = s;
      uint32_t cp = dec_utf8(&s);
      if (!cp) {
        printf("ERROR %s illegal UTF-8\n", olds);
        exit(1);
      }
      // unicode #29 word-break, but simplified:
      // need to check for continuations (MARK). e.g. for texts/arabic-1.txt
      bool isword = u8ident_is_allowed(cp);
      bool ismark = isMARK(cp);
      // first, or changed from non-word to word, and is no mark (continuation)
      if (olds == &line[0] || (prev_isword != isword && !ismark)) {
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
      // FIXME: "\xd8\xa8\xd8\xb1\xd9\x88\xd8\xad" "بروح" Arabic
      if (!*wp && *word && !ismark) { // non-empty word-end
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
  struct stat st;
  u8ident_init(U8ID_DEFAULT_OPTS);
#ifdef HAVE_CROARING
  rmark = roaring_bitmap_portable_deserialize_safe((char *)mark_croar_bin,
						   mark_croar_bin_len);
#endif
  
  if (argc > 1 && stat(argv[1], &st) == 0) {
    testdir(NULL, argv[1]);
    u8ident_free();
#ifdef HAVE_CROARING
    roaring_bitmap_free (rmark);
#endif
    return 0;
  }

  if (getenv("U8IDTEST_TEXTS")) {
    dirname = getenv("U8IDTEST_TEXTS");
  }
  DIR *dir = opendir(dirname);
  if (!dir) {
    perror("opendir");
    exit(1);
  }

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
