/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   Parts of the chibicc tokenizer.c was used:
   Copyright 2020 Rui Ueyama
   SPDX-License-Identifier: MIT

   Language agnostic unicode linter for unsafe utf-8 identifiers.
   Detects not recommended scripts, mixed scripts and missing normalizations.
   Knows about C, C++, py, pl, rb, p6, js, ...
*/
#include "u8id_private.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <getopt.h>
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif
#ifdef _WIN32
#  include <fileapi.h>
#  include <direct.h>
#endif

#include "u8ident.h"
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
#  include "uniwbrk.h"
#endif
#include "u8idscr.h"
#undef EXT_SCRIPTS
#include "unic11.h"
#include "mark.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)
#define strEQ(s1,s2) !strcmp ((s1), (s2))
#define strEQc(s1,s2) !strcmp ((s1), s2 "")

int verbose = 0;
int quiet = 0;
int recursive = 0;

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
  const char *r = (char *)binary_search(cp, (char *)list, len, sizeof(*list));
  return r ? true : false;
}

static inline bool isC11_start(uint32_t cp) {
  return range_bool_search(cp, c11_start_list, ARRAY_SIZE(c11_start_list));
}

static inline bool isC11_cont(uint32_t cp) {
  return range_bool_search(cp, c11_cont_list, ARRAY_SIZE(c11_cont_list));
}

static inline bool isMARK(uint32_t cp) {
  return range_bool_search(cp, mark_list, ARRAY_SIZE(mark_list));
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

#ifdef HAVE_SYS_STAT_H
static int file_exists(const char *path) {
  struct stat st;
  return (stat(path, &st) == 0) && (st.st_mode & S_IFDIR) != S_IFDIR;
}
static int dir_exists(const char *dir, const char *fname) {
  struct stat st;
  char path[256];
  strncpy(path, dir, sizeof(path) - 1);
  path[255] = '\0';
  strncat(path, "/", sizeof(path) - 1);
  path[255] = '\0';
  strncat(path, fname, sizeof(path) - 1);
  path[255] = '\0';
  return (stat(path, &st) == 0) && (st.st_mode & S_IFDIR) == S_IFDIR;
}
#elif defined _WIN32
static int file_exists(const char *path) {
  const uint16_t dwAttrib = GetFileAttributes(path);
  return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}
static int dir_exists(const char *dir, const char *fname) {
  char path[256];
  strncpy(path, dir, sizeof(path) - 1);
  path[255] = '\0';
  strncat(path, "/", sizeof(path) - 1);
  path[255] = '\0';
  strncat(path, fname, sizeof(path) - 1);
  path[255] = '\0';
  const uint16_t dwAttrib = GetFileAttributes(path);
  return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
          (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
#endif

static void version(void) {
  puts("u8idlint " PACKAGE_VERSION);
}
static void usage(void) {
  version();
  puts("Usage: u8idlint [OPTIONS] [dirs or files]...");
  puts("OPTIONS:");
  puts(" -n|--normalize=nfc,nfkc,nfd,nfkc   default: nfc");
  puts(" -p|--profile=2,3,4,5,6,c11_4,c11_6 default: 4");
  puts(" -e|--ext=.c                        only this file extension");
  puts(" -r|--recursive");
  puts(" -v|--verbose");
  puts(" -q|--quiet");
  puts(" --help\n");
  puts("u8idlint checks all words in UTF-8 source files for");
  puts("violations against various unicode security guidelines for identifiers.");
  //puts("For special known file extensions it applies rules to parse identifiers,");
  //puts("macro names and #include names, and handles them stricter than comments or strings.");
  puts("\nSEE ALSO:");
  puts("  u8ident.3");
  puts("\nAUTHOR:");
  puts("  Reini Urban <rurban@cpan.org>");
  exit(0);
}

int testfile(const char *dir, const char *fname) {
  int err = 0;
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
    fprintf(stderr, "%s/%s\n", dir, fname);
    return -1;
  }

  if (!quiet)
    printf("-- %s/%s\n", dir, fname);
  int ctx = u8ident_new_ctx();
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
        err |= ret;
        if (ret < 0) {
          if (quiet)
            printf("-- %s/%s\n", dir, fname);
          printf("%s: %s (%s", word, errstr(ret), scripts);
          uint32_t cp = u8ident_failed_char(ctx);
          printf(" + U+%X %s)!\n", cp,
                 u8ident_script_name(u8ident_get_script(cp)));
        } else if (verbose && !quiet) {
          printf("%s: %s (%s)\n", word, errstr(ret), scripts);
        }
        free((char *)scripts);
        *word = '\0';
        wp = &word[0];
      }
    }
  }

  u8ident_free_ctx(ctx);
  fclose(f);
  return err;
}

 static int process_dir(const char *dirname, const char *ext);

static int process_dir(const char *dirname, const char *ext) {
  int ret = 0;
#ifdef HAVE_DIRENT_H
  DIR *dir = opendir(dirname);
  if (!dir) {
    perror("opendir");
    exit(1);
  }
  struct dirent *d = readdir(dir);
  if (!d)
    goto done;
#  define NEXT_FILE (d = readdir(dir))
#  define CUR_FILE d->d_name
#elif defined _WIN32
  WIN32_FIND_DATA FindFileData;
  HANDLE hdir = FindFirstFile(dirname, &FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) {
    perror("FindFirstFile");
    goto done;
  }
#  define NEXT_FILE FindNextFile(hdir, &FindFileData)
#  define CUR_FILE FindFileData.cFileName
#endif
  do {
    const char *const exts[] = {
        ".c",    ".C",   ".h",      ".H",   ".inc", ".inl", ".cpp",
        ".cxx",  ".hpp", ".py",     ".pl",  ".p6",  ".rb",  ".php",
        ".js",   ".ts",  ".erl",    ".f",   ".for", ".ftn", ".f77",
        ".f90",  ".f95", ".f03",    ".f08", ".f15", ".lhs", ".ml",
        ".lisp", ".lsp", ".cl",     ".el",  ".rs",  ".tcl", ".SCM",
        ".SM",   ".sch", ".scheme", ".scm", ".sm",  ".rkt",
    };
    const size_t l = strlen(CUR_FILE);
    if (ext) {
      size_t le = strlen(ext);
      if (l > le && strEQ(&CUR_FILE[l - le], ext)) {
        ret |= testfile(dirname, CUR_FILE);
      }
    } else {
      // check if it's a programming language source file
      for (unsigned i = 0; i < ARRAY_SIZE(exts); i++) {
        const char *e = exts[i];
        size_t le = strlen(e);
        if (l > le && strEQ(&CUR_FILE[l - le], e)) {
          ret |= testfile(dirname, CUR_FILE);
        }
      }
    }
    if (recursive && '.' != CUR_FILE[0] && dir_exists(dirname, CUR_FILE)) {
      char path[256];
      strncpy(path, dirname, sizeof(path) - 1);
      path[255] = '\0';
      strncat(path, "/", sizeof(path) - 1);
      path[255] = '\0';
      strncat(path, CUR_FILE, sizeof(path) - 1);
      path[255] = '\0';
      process_dir(path, ext);
    }
  } while (NEXT_FILE);
done:
#ifdef HAVE_DIRENT_H
  closedir(dir);
#elif defined _WIN32
  FindClose(hdir);
#endif
  return ret;
}

int main(int argc, char **argv) {
  int i = 1;
  int ret = 0;
  char *dirname = ".";
  char *ext = NULL;
  int c;
  unsigned u8idopts = U8ID_PROFILE_C11_4;
#ifdef HAVE_GETOPT_LONG
  int option_index = 0;
  static struct option long_options[]
      = { { "normalization", 1, 0, 'n' },
          { "profile", 1, 0, 'p' },
          { "ext", 1, 0, 'e' },
          { "recursive", 0, 0, 'r' },
          { "help", 0, 0, 0 },
          { "version", 0, 0, 0 },
          { "quiet", 0, &quiet, 'q' },
          { "verbose", 0, &verbose, 'v' },
          { NULL, 0, NULL, 0 } };
#endif

  if (argc > 1 && strEQc(argv[1], "--help"))
    usage();
  if (argc > 1 && strEQc(argv[1], "--version")) {
    version();
    exit(0);
  }
  while
#ifdef HAVE_GETOPT_LONG
      ((c = getopt_long (argc, argv, "p:n:e:rhvq", long_options, &option_index))
       != -1)
#else
      ((c = getopt (argc, argv, "p:n:e:rhvq")) != -1)
#endif
  {
    if (c == -1)
      break;
    switch (c)
      {
      case 'n':
        if (strEQc(optarg, "nfkc"))
          u8idopts |= U8ID_NFKC;
        else if (strEQc(optarg, "nfc"))
          u8idopts |= U8ID_NFC;
        else if (strEQc(optarg, "nfkd"))
          u8idopts |= U8ID_NFKD;
        else if (strEQc(optarg, "nfd"))
          u8idopts |= U8ID_NFD;
        else {
          fprintf(stderr, "Invalid --normalize %s\n", optarg);
          exit(1);
        }
        break;
      case 'p':
        if (strEQc(optarg, "2"))
          u8idopts |= U8ID_PROFILE_2;
        else if (strEQc(optarg, "3"))
          u8idopts |= U8ID_PROFILE_3;
        else if (strEQc(optarg, "4"))
          u8idopts |= U8ID_PROFILE_4;
        else if (strEQc(optarg, "5"))
          u8idopts |= U8ID_PROFILE_5;
        else if (strEQc(optarg, "6"))
          u8idopts |= U8ID_PROFILE_6;
        else if (strEQc(optarg, "c11_4"))
          u8idopts |= U8ID_PROFILE_C11_4;
        else if (strEQc(optarg, "c11_6"))
          u8idopts |= U8ID_PROFILE_C11_6;
        else {
          fprintf(stderr, "Invalid --profile %s\n", optarg);
          exit(1);
        }
        break;
      case 'e':
        ext = optarg;
        break;
      case ':': // missing arg
        break;
      case 'v':
        verbose++;
        break;
      case 'q':
        quiet++;
        break;
      case 'r':
        recursive++;
        break;
      case 'h':
        usage();
        break;
#ifdef HAVE_GETOPT_LONG
      case 0:
        /* This option sets a flag */
        if (strEQc (long_options[option_index].name, "verbose"))
          verbose++;
        else if (strEQc (long_options[option_index].name, "quiet"))
          quiet++;
        else if (strEQc (long_options[option_index].name, "recursive"))
          recursive++;
        else if (strEQc (long_options[option_index].name, "help"))
          usage();
        else if (strEQc (long_options[option_index].name, "version")) {
          version();
          exit(0);
        }
        break;
#endif
      }
  }
  i = optind;

  u8ident_init(u8idopts);
  if (i == argc) // no dir/file args
    ret |= process_dir(dirname, ext);
  while (i < argc) {
    if (file_exists(argv[i])) {
      ret |= testfile(".", argv[i]);
      u8ident_free();
      return ret;
    }
    if (dir_exists(".", argv[i])) {
      dirname = argv[i];
    }
    ret |= process_dir(dirname, ext);
    i++;
  }
  u8ident_free();
  return ret;
}
