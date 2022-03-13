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
#define EXTERN_SCRIPTS
#include "unic11.h"
#include "unic26.h"
//#include "mark.h"

int verbose = 0;
int quiet = 0;
int recursive = 0;
enum xid_e xid = SAFEC26;
enum u8id_norm norm = U8ID_NFC;
enum u8id_profile profile = U8ID_PROFILE_C26_4;
unsigned u8idopts = 0;
// if the --xid option was given, to set profile defaults
bool opt_xid = false;
// if the --profile option was given, to set xid defaults
bool opt_profile = false;

static const struct ext_xid {
  const char *const ext;
  const enum xid_e xid;
} exts[] = {
    // tr31 defaults per extension
    {".zig", ASCII},
    {".j", ASCII},
    {".c", C11},
    {".C", C11},
    {".h", C11},
    {".H", C11},
    {".inc", C11},
    {".inl", C11},
    {".cpp", C11},
    {".cxx", C11},
    {".hpp", C11},
    {".cs", XID}, // -p5
    {".fs", XID}, // -p5
    {".py", XID}, // -p5
    {".pl", XID}, // -p5
    {".p6", XID}, // -p5
    {".rb", XID},
    {".erl", XID},
    {".f", XID},
    {".for", XID},
    {".ftn", XID},
    {".f77", XID},
    {".f90", XID},
    {".f95", XID},
    {".f03", XID},
    {".f08", XID},
    {".f15", XID},
    {".lhs", XID},
    {".jl", XID}, // -p5
    {".ml", XID},
    {".rs", XID}, // -p4
    {".tcl", XID},
    {".ada", ID},
    {".go", ID},
    {".js", ID}, // -p5
    {".ts", ID},
    {".cr", ALLUTF8}, // Crystal
    {".d", ALLUTF8},
    {".factor", ALLUTF8},
    {".fs", ALLUTF8}, // Forth
    {".nim", ALLUTF8},
    {".lua", ALLUTF8},
    {".php", ALLUTF8},
    /* TODO LISP ids */
    {".lisp", ALLUTF8},
    {".lsp", ALLUTF8},
    {".cl", ALLUTF8},
    {".el", ALLUTF8},
    {".SCM", ALLUTF8},
    {".SM", ALLUTF8},
    {".sch", ALLUTF8},
    {".scheme", ALLUTF8},
    {".scm", ALLUTF8},
    {".sm", ALLUTF8},
    {".rkt", ALLUTF8},
};

// clang-format off
/* tr31 options:
  XID      - ID minus NFKC quirks.
  ID       - all letters, plus numbers, punctuation and marks. With exotic
             scripts.
  ALLOWED  - TR31 ID with only recommended scripts. Allowed IdentifierStatus.
  SAFEC26  - see c26++proposal XID minus exotic scripts, filtered by NFC and
             IdentifierType.
  C23      - XID plus NFC requirement.
  C11      - the AltId ranges from the C11 standard
  ALLUTF8  - all > 128, e.g. D, php, nim, crystal.
  ASCII    - only ASCII letters
*/
// clang-format on
static struct func_tr31_s tr31_funcs[] = {
    {isXID_start, isXID_cont},         {isID_start, isID_cont},
    {isALLOWED_start, isALLOWED_cont}, {isSAFEC26_start, isSAFEC26_cont},
    {isC23_start, isC23_cont},         {isC11_start, isC11_cont},
    {isALLUTF8_start, isALLUTF8_cont}, {isASCII_start, isASCII_cont},
};

static enum u8id_options xid_opts(const enum xid_e xid) {
  assert(xid >= 0 && xid <= LAST_XID_E);
  return xid + 64;
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
  strncat(path, "/", sizeof(path) - strlen(path) - 1);
  path[255] = '\0';
  strncat(path, fname, sizeof(path) - strlen(path) - 1);
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
  strncat(path, "/", sizeof(path) - strlen(path) - 1);
  path[255] = '\0';
  strncat(path, fname, sizeof(path) - strlen(path) - 1);
  path[255] = '\0';
  const uint16_t dwAttrib = GetFileAttributes(path);
  return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
          (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
#endif

// return the tr31 option for the filename extension
static unsigned extension_xid(const char *fname) {
  const size_t l = strlen(fname);
  for (unsigned i = 0; i < ARRAY_SIZE(exts); i++) {
    const char *e = exts[i].ext;
    size_t le = strlen(e);
    if (l > le && strEQ(&fname[l - le], e)) {
      return exts[i].xid;
    }
  }
  return 0;
}

static void version(void) { puts("u8idlint " PACKAGE_VERSION); }
static void usage(int exitcode) {
  version();
#ifndef HAVE_GETOPT_H
  puts("Usage: u8idlint [dirs or files]...");
#else
  puts("Usage: u8idlint [OPTIONS] [dirs or files]...");
  puts("OPTIONS:");
  puts(" -n|--norm=nfc,nfkc,nfd,nfkc            default: nfc");
  puts("  set to nfkd by default for python");
  puts(" -p|--profile=1,2,3,4,5,6,c26_4,c11_6        default: c26_4");
  puts("  TR39 unicode mixed-script security profile for identifiers:");
  puts("    1      ASCII. Sets xid ascii.");
  puts("    2      Single script");
  puts("    3      Highly Restrictive");
  puts("    4      Moderately Restrictive");
  puts("    5      Minimally Restrictive");
  puts("    6      Unrestricted");
  puts("    c11_6  C11STD. Sets xid c11.");
  puts("    c26_4  SAFEC26 (i.e. 4 with Greek). Sets xid safec26.");
  puts(" -x|--xid=ascii,allowed,safec26,id,xid,c11,c23,allutf8   default: "
       "allowed");
  puts("  TR31 set of identifiers:"); // sorted from most secure to least secure
  puts("    ascii     only ASCII letters, punctuations. plus numbers");
  puts("    allowed   tr31 with only recommended scripts, IdentifierStatus");
  puts("    safec26   allowed but different Identifier_Type and NFC");
  puts("    id        all letters. plus numbers, punctuations and combining "
       "marks");
  puts("    xid       stable id subset, no NFKC quirks");
  puts("    c23       xid with NFC requirement from C23");
  puts("    c11       some AltId unicode ranges from C11");
  puts("    allutf8   allow all >128. e.g. php, nim, crystal");
  // see above for recognized extensions
  puts(" -e|--ext=.c                        only this file extension");
  puts(" -r|--recursive");
  puts(" -v|--verbose");
  puts(" -q|--quiet");
  puts(" --help\n");
#endif
  puts("u8idlint checks all words in UTF-8 source files for");
  puts("violations against various unicode security guidelines for "
       "identifiers.");
  puts("For special known file extensions it uses its default xid to parse "
       "identifiers.");
  puts("(i.e. *.c uses C11)");
  // puts("macro names and #include names, and handles them stricter than
  // comments or strings.");
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

void printfile_line(const char *dir, const char *fname, size_t line) {
  if (strEQc(dir, "."))
    printf("%s:%u\n", fname, (unsigned)line);
  else
    printf("%s/%s:%u\n", dir, fname, (unsigned)line);
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
  bool need_free = false;
  size_t ln = 0;

  if (maxlen > 1024) {
    word = calloc(maxlen, 1);
  } else {
    word = &_word[0];
  }
  if (!opt_xid) {
    unsigned rest_opts = u8ident_options();
    enum xid_e _xid = extension_xid(fname);
    if (_xid) {
      xid = _xid;
      // do wordchecks according to the tr31. the profile is 4 by default for
      // all
      u8ident_init(u8ident_profile(), u8ident_norm(),
                   xid_opts(xid) | (rest_opts & ~127));
      need_free = true;
    }
  }
  assert(xid <= LAST_XID_E);
#if (defined(__GNUC__) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 460)
  _Static_assert(ARRAY_SIZE(tr31_funcs) == LAST_XID_E + 1,
                 "Invalid tr31_funcs[] size");
#endif
  // do wordbreaks according to the tr31
  func_tr31 *id_start = tr31_funcs[xid].start;
  func_tr31 *id_cont = tr31_funcs[xid].cont;
  if (!dir) {
    strncpy(path, fname, sizeof(path) - 1);
  } else {
    strncpy(path, dir, sizeof(path) - 1);
    path[255] = '\0';
    strncat(path, "/", sizeof(path) - strlen(path) - 1);
    path[255] = '\0';
    strncat(path, fname, sizeof(path) - strlen(path) - 1);
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
    ln++;
    *word = '\0';
#if defined HAVE_UNIWBRK_H && defined HAVE_LIBUNISTRING
    u8_wordbreaks((uint8_t *)s, strlen(s), brks);
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
      if (verbose > 1 && force_break != brks[s - olds])
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
                printfile_line(dir, fname, ln);
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
            printfile_line(dir, fname, ln);
          printf("  %s: %s (%s", word, u8ident_errstr(ret), scripts);
          const uint32_t cp = u8ident_failed_char(c);
          const uint8_t scr = u8ident_get_script(cp);
          if (scr != SC_Unknown)
            printf(" + U+%X %s)!\n", cp, u8ident_script_name(scr));
          else
            printf(" + U+%X)!\n", cp);
        } else if (verbose && !quiet) {
          printf("  %s: %s (%s)\n", word, u8ident_errstr(ret), scripts);
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
  if (need_free)
    u8ident_free();
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
    const size_t l = strlen(CUR_FILE);
    if (ext) {
      // TODO support comma-seperated list of exts
      size_t le = strlen(ext);
      if (l > le && strEQ(&CUR_FILE[l - le], ext)) {
        ret |= testfile(dirname, CUR_FILE);
      }
    } else {
      // check if it's a programming language source file
      for (unsigned i = 0; i < ARRAY_SIZE(exts); i++) {
        const char *e = exts[i].ext;
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
      strncat(path, "/", sizeof(path) - strlen(path) - 1);
      path[255] = '\0';
      strncat(path, CUR_FILE, sizeof(path) - strlen(path) - 1);
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

static void option_xid(const char *optarg) {
  if (strEQc(optarg, "ascii") || strEQc(optarg, "ASCII"))
    xid = ASCII;
  else if (strEQc(optarg, "allowed") || strEQc(optarg, "ALLOWED") ||
           strEQc(optarg, "tr39"))
    xid = ALLOWED;
  else if (strEQc(optarg, "safec26") || strEQc(optarg, "SAFEC26") ||
           strEQc(optarg, "safec23") || strEQc(optarg, "SAFEC23") ||
           strEQc(optarg, "c26") || strEQc(optarg, "c23"))
    xid = SAFEC26;
  else if (strEQc(optarg, "id") || strEQc(optarg, "ID"))
    xid = ID;
  else if (strEQc(optarg, "xid") || strEQc(optarg, "XID"))
    xid = XID;
  else if (strEQc(optarg, "c23") || strEQc(optarg, "C23"))
    xid = C23;
  else if (strEQc(optarg, "c11") || strEQc(optarg, "C11"))
    xid = C11;
  else if (strEQc(optarg, "allutf8") || strEQc(optarg, "ALLUTF8"))
    xid = ALLUTF8;
  else {
    fprintf(stderr, "Invalid --xid %s\n", optarg);
    usage(1);
  }
  if (u8idopts & U8ID_TR31_MASK) { // already set
    fprintf(stderr, "TR31 options already set\n");
    u8idopts &= ~U8ID_TR31_MASK; // clear it
  }
  u8idopts |= xid_opts(xid);
}

static void option_profile(const char *optarg) {
  if (strEQc(optarg, "1")) // ASCII only
    profile = U8ID_PROFILE_1;
  else if (strEQc(optarg, "2")) // single script
    profile = U8ID_PROFILE_2;
  else if (strEQc(optarg, "3"))
    profile = U8ID_PROFILE_3;
  else if (strEQc(optarg, "4"))
    profile = U8ID_PROFILE_4;
  else if (strEQc(optarg, "5"))
    profile = U8ID_PROFILE_5;
  else if (strEQc(optarg, "6"))
    profile = U8ID_PROFILE_6;
  else if (strEQc(optarg, "c26_4") || strEQc(optarg, "C26_4") ||
           strEQc(optarg, "c23_4") || strEQc(optarg, "C23_4") ||
           strEQc(optarg, "SAFEC23") || strEQc(optarg, "SAFEC26")) {
    profile = U8ID_PROFILE_C26_4;
  } else if (strEQc(optarg, "c11_6") || strEQc(optarg, "C11_6") ||
             strEQc(optarg, "C11")) {
    profile = U8ID_PROFILE_C11_6;
  } else {
    fprintf(stderr, "Invalid --profile %s\n", optarg);
    usage(1);
  }
}

// norm is global, but...
static enum u8id_norm option_norm(const char *optarg) {
  if (strEQc(optarg, "nfkc") || strEQc(optarg, "NFKC"))
    return U8ID_NFKC;
  else if (strEQc(optarg, "nfc") || strEQc(optarg, "NFC"))
    return U8ID_NFC;
  else if (strEQc(optarg, "nfkd") || strEQc(optarg, "NFKD"))
    return U8ID_NFKD;
  else if (strEQc(optarg, "nfd") || strEQc(optarg, "NFD"))
    return U8ID_NFD;
  else {
    fprintf(stderr, "Invalid --norm %s\n", optarg);
    usage(1);
  }
  return 0;
}

int main(int argc, char **argv) {
  int i = 1;
  int ret = 0;
  char *dirname = ".";
  char *ext = NULL;
  xid = ALLOWED;

#ifdef HAVE_GETOPT_LONG
  int option_index = 0;
  static struct option long_options[] = {
      {"norm", 1, 0, 'n'},    // *nfc*,nfd,nfkc,nfkd
      {"profile", 1, 0, 'p'}, // 1,2,3,*4*,5,6,c26_4,c11_6
      {"xid", 1, 0, 'x'},     // ascii,allowed,id,*xid*,safec26,c11,c23,allutf8
      {"ext", 1, 0, 'e'},        {"recursive", 0, 0, 'r'},
      {"help", 0, 0, 0},         {"version", 0, 0, 0},
      {"quiet", 0, &quiet, 'q'}, {"verbose", 0, &verbose, 'v'},
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
      norm = option_norm(optarg);
      break;
    case 'p':
      opt_profile = true;
      option_profile(optarg);
      if (profile == U8ID_PROFILE_1 && !opt_xid)
        opt_xid = ASCII;
      if (profile == U8ID_PROFILE_C26_4 && !opt_xid) {
        xid = SAFEC26;
        u8idopts |= U8ID_TR31_SAFEC26;
      }
      if (profile == U8ID_PROFILE_C11_6 && !opt_xid) {
        xid = C11;
        u8idopts |= U8ID_TR31_C11;
      }
      break;
    case 'x': // ascii,allowed,id,xid,safec26,c11,allutf8
      opt_xid = true;
      option_xid(optarg);
      if (xid == ASCII && !opt_profile)
        profile = U8ID_PROFILE_1;
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
  i = 1;
  while (i < argc) {
    if (argc > i && (strEQc(argv[i], "--recursive") || strEQc(argv[i], "-r"))) {
      recursive++;
      i++;
    }
    if (argc > i && (strEQc(argv[i], "--verbose") || strEQc(argv[i], "-v"))) {
      verbose++;
      i++;
    }
    if (argc > i && (strEQc(argv[i], "--quiet") || strEQc(argv[i], "-q"))) {
      quiet++;
      i++;
    }
    if (argc > i + 1 && (strEQc(argv[i], "--ext") || strEQc(argv[i], "-e"))) {
      // TODO support comma-seperated list of exts
      ext = argv[i + 1];
      i += 2;
    }
    if (argc > i + 1 && (strEQc(argv[i], "--xid") || strEQc(argv[i], "-x"))) {
      opt_xid = true;
      option_xid(argv[i + 1]);
      if (xid == ASCII && !opt_profile)
        profile = U8ID_PROFILE_1;
      i += 2;
    }
    if (argc > i + 1 && (strEQc(argv[i], "--norm") || strEQc(argv[i], "-n"))) {
      option_norm(argv[i + 1]);
      i += 2;
    }
    if (argc > i + 1 &&
        (strEQc(argv[i], "--profile") || strEQc(argv[i], "-p"))) {
      opt_profile = true;
      option_profile(argv[i] + 1);
      if (profile == U8ID_PROFILE_1 && !opt_xid)
        opt_xid = ASCII;
      if (profile == U8ID_PROFILE_C26_4 && !opt_xid) {
        xid = SAFEC26;
        u8idopts |= U8ID_TR31_SAFEC26;
      }
      if (profile == U8ID_PROFILE_C11_6 && !opt_xid) {
        xid = C11;
        u8idopts |= U8ID_TR31_C11;
      }
      i += 2;
    }
  }
#endif

  u8ident_init(profile, norm, u8idopts);
  if (i == argc) // no dir/file args
    ret |= process_dir(dirname, ext);
  while (i < argc) {
    if (file_exists(argv[i])) {
      ret |= testfile(".", argv[i]);
    } else if (dir_exists(".", argv[i])) {
      ret |= process_dir(argv[i], ext);
    } else {
      fprintf(stderr, "Invalid arg %s\n", argv[i]);
      usage(1);
    }
    i++;
  }
  u8ident_free();
  return ret;
}

// c-basic-offset: 2
