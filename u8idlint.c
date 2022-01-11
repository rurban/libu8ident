/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022 Reini Urban
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
#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#if defined HAVE_DIRENT_H && !defined _MSC_VER
#  include <dirent.h>
#endif
#ifdef _MSC_VER
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <direct.h>
#endif

#include "u8ident.h"
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
#  include "uniwbrk.h"
#endif
#include "u8idscr.h"
#undef EXT_SCRIPTS
#include "unic11.h"
#include "unic23.h"
//#include "mark.h"

int verbose = 0;
int quiet = 0;
int recursive = 0;
enum xid_e xid = ALLOWED;
enum u8id_norm norm = U8ID_NFC;
enum u8id_profile profile = U8ID_PROFILE_C23_4;
unsigned u8idopts = 0;

// private access
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

const struct range_bool ascii_start_list[] = {
    {'$', '$'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}};
const struct range_bool ascii_cont_list[] = {
    {'$', '$'},
    {'0', '9'},
};

typedef bool func_xid(uint32_t cp);

static bool isASCII_start(uint32_t cp) {
  return range_bool_search(cp, ascii_start_list, ARRAY_SIZE(ascii_start_list));
}
static bool isASCII_cont(uint32_t cp) {
  return range_bool_search(cp, ascii_cont_list, ARRAY_SIZE(ascii_cont_list));
}
// Note: This includes 0..9 already
static bool isALLOWED_start(uint32_t cp) {
  return range_bool_search(cp, allowed_id_list, ARRAY_SIZE(allowed_id_list));
}
static bool isALLOWED_cont(uint32_t cp) {
  return range_bool_search(cp, allowed_id_list, ARRAY_SIZE(allowed_id_list));
}
static bool isSAFEC23_start(uint32_t cp) {
  return binary_search(cp, (char *)safec23_start_list,
                       ARRAY_SIZE(safec23_start_list),
                       sizeof(*safec23_start_list))
      ? true : false;
}
static bool isSAFEC23_cont(uint32_t cp) {
  return binary_search(cp, (char *)safec23_cont_list,
                       ARRAY_SIZE(safec23_cont_list),
                       sizeof(*safec23_cont_list))
      ? true : false;
}
static bool isID_start(uint32_t cp) { return u8ident_is_ID_Start(cp); }
static bool isID_cont(uint32_t cp) { return u8ident_is_ID_Cont(cp); }
static bool isXID_start(uint32_t cp) { return u8ident_is_XID_Start(cp); }
static bool isXID_cont(uint32_t cp) { return u8ident_is_XID_Cont(cp); }
static bool isC11_start(uint32_t cp) {
  return range_bool_search(cp, c11_start_list, ARRAY_SIZE(c11_start_list));
}
static bool isC11_cont(uint32_t cp) {
  return range_bool_search(cp, c11_cont_list, ARRAY_SIZE(c11_cont_list));
}
static bool isALLUTF8_start(uint32_t cp) {
  return isASCII_start(cp) || cp > 127;
}
static bool isALLUTF8_cont(uint32_t cp) { return isASCII_cont(cp) || cp > 127; }
struct func_xid_s {
  func_xid *start;
  func_xid *cont;
};

/* tokenizers:
  ASCII,   // only ASCII letters
  ALLOWED, // TR31 ID with only recommended scripts. Allowed IdentifierStatus.
  SAFEC23, // see c23++proposal
  ID,  // all letters, plus numbers, punctuation and marks. With exotic scripts.
  XID, // ID plus NFKC quirks.
  C11, // the AltId ranges from the C11 standard
  ALLUTF8, // all > 128, e.g. D, php, nim, crystal
*/
static struct func_start_s id_funcs[] = {
    // clang-format disable
    {isASCII_start, isASCII_cont},
    {isALLOWED_start, isALLOWED_cont},
    {isSAFEC23_start, isSAFEC23_cont},
    {isID_start, isID_cont},
    {isXID_start, isXID_cont},
    {isC11_start, isC11_cont},
    {isALLUTF8_start, isALLUTF8_cont},
    // clang-format enable
};

static const char *errstr(int errcode) {
  static const char *const _str[] = {
      "ERR_CONFUS",           // -6
      "ERR_COMBINE",          // -5
      "ERR_ENCODING",         // -4
      "ERR_SCRIPTS",          //-3
      "ERR_SCRIPT",           //-2
      "ERR_XID",              // -1
      "EOK",                  // 0
      "EOK_NORM",             // 1
      "EOK_WARN_CONFUS",      // 2
      "EOK_NORM_WARN_CONFUS", // 3
  };
  assert(errcode >= -6 && errcode <= 3);
  return _str[errcode + 6];
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
#elif defined _MSC_VER
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

static void version(void) { puts("u8idlint " PACKAGE_VERSION); }
static void usage(int exitcode) {
  version();
#ifndef HAVE_GETOPT_H
  puts("Usage: u8idlint [dirs or files]...");
#else
  puts("Usage: u8idlint [OPTIONS] [dirs or files]...");
  puts("OPTIONS:");
  puts(" -n|--normalize=nfc,nfkc,nfd,nfkc            default: nfc");
  puts("  set to nfkd by default for python");
  puts(" -p|--profile=1,2,3,4,5,6,c23_4,c11_6        default: c23_4");
  puts("  TR39 unicode security profile for identifiers:");
  puts("    1      ASCII. sets xid ascii.");
  puts("    2      Single script");
  puts("    3      Highly Restrictive");
  puts("    4      Moderately Restrictive");
  puts("    5      Minimally Restrictive");
  puts("    6      Unrestricted");
  puts("    c11_6  C11STD. Sets xid c11.");
  puts("    c23_4  SAFEC23 (i.e. 4 with Greek). Sets xid safec23.");
  puts(" -x|--xid=ascii,allowed,safec23,id,xid,c11,allutf8     default: allowed");
  puts("  TR31 set of identifiers:"); // sorted from most secure to least secure
  puts("    ascii     only ASCII letters, punctuations. plus numbers");
  puts("    allowed   tr31 with only recommended scripts, IdentifierStatus");
  puts("    safec23   allowed but different Identifer_Type and NFC");
  puts("    id        all letters. plus numbers, punctuations and combining "
       "marks");
  puts("    xid       stable id subset, no NFKC quirks");
  puts("    c11       some AltId unicode ranges from C11");
  puts("    allutf8   allow all >128. e.g. php, nim, crystal");
  // see below for recognized extensions
  puts(" -e|--ext=.c                        only this file extension");
  puts(" -r|--recursive");
  puts(" -v|--verbose");
  puts(" -q|--quiet");
  puts(" --help\n");
#endif
  puts("u8idlint checks all words in UTF-8 source files for");
  puts("violations against various unicode security guidelines for "
       "identifiers.");
  // puts("For special known file extensions it applies rules to parse
  // identifiers,"); puts("macro names and #include names, and handles them
  // stricter than comments or strings.");
  puts("It adds a special BIDI warning on bidi formatting chars and when the "
       "document");
  puts("is not in Hebrew nor Arabic.");
  puts("\nSEE ALSO:");
  puts("  u8ident.3");
  puts("\nAUTHOR:");
  puts("  Reini Urban <rurban@cpan.org>");
  exit(exitcode);
}

void printfile(const char *dir, const char *fname) {
  if (strEQc(dir, "."))
    printf("%s\n", fname);
  else
    printf("%s/%s\n", dir, fname);
}

int testfile(const char *dir, const char *fname) {
  int err = 0;
  char path[256];
  static char line[1024] = {0};
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
  static char brks[1024] = {0};
#endif
  static char _word[1024] = {0};
  char *word;
  unsigned maxlen = u8ident_maxlength();
  if (maxlen > 1024) {
    word = calloc(maxlen, 1);
  } else {
    word = &_word[0];
  }
  assert(xid <= ALLUTF8);
#if (defined(__GNUC__) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 460)
  _Static_assert(ARRAY_SIZE(id_funcs) == ALLUTF8 + 1, "Invalid id_funcs size");
#endif
  func_start *id_start = id_funcs[xid].start;
  func_start *id_cont = id_funcs[xid].cont;
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
    if (maxlen > 1024)
      free(word);
    return -1;
  }

  if (!quiet) {
    printfile(dir, fname);
  }
  int c = u8ident_new_ctx();
  while (fgets(line, 1023, f)) {
    char *s = &line[0];
    bool prev_isword = false;
    char *wp = &word[0];
    bool skip = false;
    *word = '\0';
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
    u8_wordbreaks(s, strlen(s), brks);
#endif
    while (*s) {
      char *olds = s;
      uint32_t cp = dec_utf8(&s);
      if (!cp) {
        printf("ERROR %s illegal UTF-8\n", olds);
        if (maxlen > 1024)
          free(word);
        exit(1);
      }
      // unicode #29 word-break, but simplified:
      // must not split at continuations (Combining marks). e.g. for
      // texts/arabic-1.txt
      bool iscont = (*id_cont)(cp);
      bool isword = prev_isword ? ((*id_start)(cp) || iscont) : (*id_start)(cp);
      char force_break = (prev_isword != isword && !iscont);
      if (wp - word + (s - olds) > (signed)maxlen) {
        force_break = true;
        skip = true;
      }
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
      if (force_break != brks[s - olds])
        fprintf(stderr, "WARN: %sbreak at U+%X \n", force_break ? "" : "no ",
                cp);
      force_break = brks[s - olds];
#endif
      // first, or changed from non-word to word, and is no mark (continuation)
      if ((olds == &line[0] || force_break) && !skip) {
        prev_isword = isword;
        if (isword) {
          int l = s - olds;
          if (l == 1) {
            *wp++ = *olds;
          } else if (wp + l < &word[maxlen - 1]) {
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
          } else if (wp + l < &word[maxlen - 1]) {
            memcpy(wp, olds, l);
            wp += l;
          }
        } else {
          // check at least for bidi chars
          if (u8ident_is_bidi(cp)) {
            struct ctx_t *cx = u8ident_ctx();
            if (!cx->is_rtl) {
              const char *scripts = u8ident_existing_scripts(c);
              if (quiet)
                printfile(dir, fname);
              printf(
                  "  %s: %s (%s", olds,
                  (profile == U8ID_PROFILE_6 || profile == U8ID_PROFILE_C11_6)
                      ? "WARN_BIDI"
                      : "ERR_BIDI",
                  scripts);
              printf(" + U+%X)!\n", cp);
              free((char *)scripts);
            }
          }
        }
        if (*s != '\n')
          continue;
      }
      // bad case "\xd8\xa8\xd8\xb1\xd9\x88\xd8\xad" "بروح" Arabic
      if (!*wp && *word && force_break) { // non-empty word-end
        int ret = u8ident_check((uint8_t *)word, NULL);
        const char *scripts = u8ident_existing_scripts(c);
        err |= ret;
        if (ret < 0) {
          if (quiet)
            printfile(dir, fname);
          printf("  %s: %s (%s", word, errstr(ret), scripts);
          const uint32_t cp = u8ident_failed_char(c);
          const uint8_t scr = u8ident_get_script(cp);
          if (scr != SC_Unknown)
            printf(" + U+%X %s)!\n", cp, u8ident_script_name(scr));
          else
            printf(" + U+%X)!\n", cp);
        } else if (verbose && !quiet) {
          printf("  %s: %s (%s)\n", word, errstr(ret), scripts);
        }
        // maybe also warn on skip. overly long words
        free((char *)scripts);
        *word = '\0';
        wp = &word[0];
        skip = false;
      }
    }
  }

  if (maxlen > 1024)
    free(word);
  u8ident_free_ctx(c);
  fclose(f);
  return err;
}

static int process_dir(const char *dirname, const char *ext);

static int process_dir(const char *dirname, const char *ext) {
  int ret = 0;
#if defined HAVE_DIRENT_H && !defined _MSC_VER
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
#elif defined _MSC_VER
  WIN32_FIND_DATA FindFileData;
  HANDLE hdir = FindFirstFile(dirname, &FindFileData);
  if (hdir == INVALID_HANDLE_VALUE) {
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
#if defined HAVE_DIRENT_H && !defined _MSC_VER
  closedir(dir);
#elif defined _MSC_VER
  FindClose(hdir);
#endif
  return ret;
}

int main(int argc, char **argv) {
  int i = 1;
  int ret = 0;
  char *dirname = ".";
  char *ext = NULL;
  // if the --xid option was given, to set profile defaults
  bool opt_xid = false;
  // if the --profile option was given, to set xid defaults
  bool opt_profile = false;
  xid = ALLOWED;

#ifdef HAVE_GETOPT_LONG
  int option_index = 0;
  static struct option long_options[] = {
      {"normalization", 1, 0, 'n'}, // *nfc*,nfd,nfkc,nfkd
      {"profile", 1, 0, 'p'},       // 1,2,3,*4*,5,6,c23_4,c11_6
      {"xid", 1, 0, 'x'},           // ascii,*allowed*,id,xid,c11,allutf8
      {"ext", 1, 0, 'e'},
      {"recursive", 0, 0, 'r'},
      {"help", 0, 0, 0},
      {"version", 0, 0, 0},
      {"quiet", 0, &quiet, 'q'},
      {"verbose", 0, &verbose, 'v'},
      {NULL, 0, NULL, 0}};
#endif

  if (argc > 1 && strEQc(argv[1], "--help"))
    usage(0);
  if (argc > 1 && strEQc(argv[1], "--version")) {
    version();
    exit(0);
  }
#ifdef HAVE_GETOPT_H
  int c;
  while
#  ifdef HAVE_GETOPT_LONG
      ((c = getopt_long(argc, argv, "p:n:x:e:rhvq", long_options,
                        &option_index)) != -1)
#  else
      ((c = getopt(argc, argv, "p:n:x:e:rhvq")) != -1)
#  endif
  {
    if (c == -1)
      break;
    switch (c) {
    case 'n':
      if (strEQc(optarg, "nfkc"))
        norm = U8ID_NFKC;
      else if (strEQc(optarg, "nfc"))
        norm = U8ID_NFC;
      else if (strEQc(optarg, "nfkd"))
        norm = U8ID_NFKD;
      else if (strEQc(optarg, "nfd"))
        norm = U8ID_NFD;
      else {
        fprintf(stderr, "Invalid --normalize %s\n", optarg);
        usage(1);
      }
      break;
    case 'p':
      opt_profile = true;
      if (strEQc(optarg, "1")) { // ASCII only
        profile = U8ID_PROFILE_1;
        if (!opt_xid)
          opt_xid = ASCII;
      } else if (strEQc(optarg, "2")) // single script
        profile = U8ID_PROFILE_2;
      else if (strEQc(optarg, "3"))
        profile = U8ID_PROFILE_3;
      else if (strEQc(optarg, "4"))
        profile = U8ID_PROFILE_4;
      else if (strEQc(optarg, "5"))
        profile = U8ID_PROFILE_5;
      else if (strEQc(optarg, "6"))
        profile = U8ID_PROFILE_6;
      else if (strEQc(optarg, "c23_4")) {
        profile = U8ID_PROFILE_C23_4;
        if (!opt_xid) {
          xid = SAFEC23;
          u8idopts |= U8ID_TR31_SAFEC23;
        }
      } else if (strEQc(optarg, "c11_6")) {
        profile = U8ID_PROFILE_C11_6;
        if (!opt_xid)
          xid = C11;
      } else {
        fprintf(stderr, "Invalid --profile %s\n", optarg);
	usage(1);
      }
      break;
    case 'x': // ascii,allowed,id,xid,c11,allutf8
      opt_xid = true;
      if (strEQc(optarg, "ascii")) {
        xid = ASCII;
        if (!opt_profile)
          profile = U8ID_PROFILE_1;
      } else if (strEQc(optarg, "allowed")) {
        xid = ALLOWED;
        u8idopts |= U8ID_TR31_ALLOWED;
      } else if (strEQc(optarg, "safec23")) {
        xid = SAFEC23;
        u8idopts |= U8ID_TR31_SAFEC23;
      } else if (strEQc(optarg, "id")) {
        xid = ID;
        u8idopts |= U8ID_TR31_ID;
      }
      else if (strEQc(optarg, "xid")) {
        xid = XID;
        u8idopts |= U8ID_TR31_XID;
      }
      else if (strEQc(optarg, "c11")) {
        xid = C11;
        u8idopts |= U8ID_TR31_C11;
      }
      else if (strEQc(optarg, "allutf8")) {
        xid = ALLUTF8;
        u8idopts |= U8ID_TR31_ALLUTF8;
      }
      else {
        fprintf(stderr, "Invalid --xid %s\n", optarg);
        usage(1);
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
      usage(0);
      break;
#  ifdef HAVE_GETOPT_LONG
    case 0:
      /* This option sets a flag */
      if (strEQc(long_options[option_index].name, "verbose"))
        verbose++;
      else if (strEQc(long_options[option_index].name, "quiet"))
        quiet++;
      else if (strEQc(long_options[option_index].name, "recursive"))
        recursive++;
      else if (strEQc(long_options[option_index].name, "help"))
        usage(0);
      else if (strEQc(long_options[option_index].name, "version")) {
        version();
        exit(0);
      }
      break;
#  endif
    }
  }
  i = optind;
#else
  (void)opt_profile;
  (void)opt_xid;
  i = 1;
  if (argc > i && (strEQc(argv[i], "--recursive") || strEQc(argv[i], "-r"))) {
    recursive++;
    i++;
  }
  if (argc > i + 1 && (strEQc(argv[i], "--ext") || strEQc(argv[i], "-e"))) {
    ext = argv[i + 1];
    i += 2;
  }
#endif

  u8ident_init(profile, norm, u8idopts);
  if (i == argc) // no dir/file args
    ret |= process_dir(dirname, ext);
  while (i < argc) {
    if (file_exists(argv[i])) {
      ret |= testfile(".", argv[i]);
    } else if (dir_exists(".", argv[i])) {
      dirname = argv[i];
    } else {
      fprintf(stderr, "Invalid arg %s\n", argv[i]);
      usage(1);
    }
    i++;
  }
  u8ident_free();
  return ret;
}
