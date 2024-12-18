/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   Check some files, wordbreak them to valid identifiers in some common scripts.
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
#include "u8idscr.h"
//#undef EXTERN_SCRIPTS
#include "unic11.h"

int verbose = 0;
// private access
unsigned u8ident_options(void);
enum u8id_profile u8ident_profile(void);
char *enc_utf8(char *dest, size_t *lenp, const uint32_t cp);

#ifdef HAVE_SYS_STAT_H
static int file_exists(const char *path) {
  struct stat st;
  return (stat(path, &st) == 0) && (st.st_mode & S_IFDIR) != S_IFDIR;
}
#elif defined _MSC_VER
static int file_exists(const char *path) {
  const uint16_t dwAttrib = GetFileAttributes(path);
  return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}
#endif

int testdir(const char *dir, const char *fname) {
  char path[256];
  static char line[1024] = {0};
  unsigned ln = 0;
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
    ln++;
    *word = '\0';
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
    u8_wordbreaks((uint8_t *)s, strlen(s), brks);
#endif
    while (*s) {
      char *olds = s;
      uint32_t cp = dec_utf8(&s);
      if (!cp) {
        printf("ERROR %s illegal UTF-8 at line %u, col %lu\n", olds, ln,
               s - olds);
        exit(1);
      }

      // unicode #29 word-break, but simplified:
      // must not split at continuations (Combining marks). e.g. for
      // texts/arabic-1.txt
      const bool iscont = isXID_cont(cp);
      bool isword = prev_isword ? (isXID_start(cp) || iscont) : isXID_start(cp);
      char force_break = (prev_isword != isword && !iscont);
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
      if (force_break != brks[s - olds] && verbose)
        /* break at: if libunistring found a break, but we not.
           no break at: if we found a break, but libunistring not. */
        fprintf(stderr, "WARN: %sbreak at U+%X, line %u, col %lu\n",
                force_break ? "" : "no ", cp, ln, s - olds);
        // don't rely in the CI on an optional lib
        // force_break = brks[s - olds];
#endif
      // first, or changed from non-word to word, and is no mark (continuation)
      if (olds == &line[0] || force_break) {
        prev_isword = isword;
        if (isword) {
          int l = s - olds;
          if (l == 1) {
            *wp++ = *olds;
          } else if (wp + l < &word[128]) {
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
          } else if (wp + l < &word[128]) {
            memcpy(wp, olds, l);
            wp += l;
          }
        }
        if (*s != '\n')
          continue;
      }
      // bad case "\xd8\xa8\xd8\xb1\xd9\x88\xd8\xad" "بروح" Arabic
      // also bad case "أحرارًا" Arabic at pos 12 (missing basesc)
      if (!*wp && *word && force_break) { // non-empty word-end
        int ret = u8ident_check((uint8_t *)word, NULL);
        const char *scripts = u8ident_existing_scripts(ctx);
        printf("%s: %s (%s", word, u8ident_errstr(ret), scripts);
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

int main(int argc, char **argv) {
  int i = 1;
  char *dirname = "texts";
  u8ident_init(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, U8ID_TR31_XID);

  if (getenv("U8IDTEST_TEXTS"))
    dirname = getenv("U8IDTEST_TEXTS");
  else if (argc > 1 && strEQc(argv[1], "-v")) {
    verbose++;
    i++;
  }

#if !defined _MSC_VER && defined HAVE_SYS_STAT_H
  if (argc > i && file_exists(argv[i])) {
    while (argc > i && file_exists(argv[i])) {
      testdir(NULL, argv[i++]);
    }
    u8ident_free();
    return 0;
  }
  if (argc > i && !file_exists(argv[i])) {
    dirname = argv[i];
  }
#endif

#if defined HAVE_DIRENT_H && !defined _MSC_VER
  DIR *dir = opendir(dirname);
  if (!dir) {
    perror("opendir");
    exit(1);
  }
#elif defined _MSC_VER
  WIN32_FIND_DATA FindFileData;
  HANDLE hdir;
#endif

  const char *const exts[] = {".txt", ".c"};
  for (size_t j = 0; j < ARRAY_SIZE(exts); j++) {
    const char *ext = exts[j];
    int s = 0;
    size_t lext = strlen(ext);

#if defined HAVE_DIRENT_H && !defined _MSC_VER
    struct dirent *d;
#  define NEXT_FILE (d = readdir(dir))
#  define CUR_FILE d->d_name
#elif defined _MSC_VER
    hdir = FindFirstFile(dirname, &FindFileData);
    if (hdir == INVALID_HANDLE_VALUE)
      continue;
#  define NEXT_FILE FindNextFile(hdir, &FindFileData)
#  define CUR_FILE FindFileData.cFileName
#endif

    // sort the names, to compare against the result
    while (NEXT_FILE) {
      size_t l = strlen(CUR_FILE);
      if (l > lext && '.' != CUR_FILE[0] && strEQ(&CUR_FILE[l - lext], ext)) {
        s++;
      }
    }

#if defined HAVE_DIRENT_H && !defined _MSC_VER
    rewinddir(dir);
#elif defined _MSC_VER
    FindClose(hdir);
    hdir = FindFirstFile(dirname, &FindFileData);
#endif

    const char **files = calloc(s, sizeof(char *));
    int i = 0;
    while (NEXT_FILE) {
      size_t l = strlen(CUR_FILE);
      if (l > lext && '.' != CUR_FILE[0] && strEQ(&CUR_FILE[l - lext], ext)) {
        if (i >= s)
          break;
        assert(i < s);
        files[i] = malloc(l + 1);
        strcpy((char *)files[i], CUR_FILE);
        i++;
      }
    }
    if (s)
      qsort(files, s, sizeof(char *), cmp_str);
    for (i = 0; i < s; i++) {
      // printf("%s\n", files[i]);
      testdir(dirname, files[i]);
    }
    for (int i = 0; i < s; i++)
      free((void *)files[i]);
    free(files);
  }
#if defined HAVE_DIRENT_H && !defined _MSC_VER
  closedir(dir);
#elif defined _MSC_VER
  FindClose(hdir);
#endif

  u8ident_free();
  return 0;
}
