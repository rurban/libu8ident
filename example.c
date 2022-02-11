/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   Contrary to the tests and helpers, provide a test binary to link
   against the public methods and lib only.
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include "u8ident.h"

static void version(void) { puts("libu8ident example"); }
static void usage(int exitcode) {
  version();
  puts("Usage: example [--help|--version]");
  puts("\nSEE ALSO:");
  puts("  u8idlint.1");
  puts("\nAUTHOR:");
  puts("  Reini Urban <rurban@cpan.org>");
  exit(exitcode);
}

int main(int argc, char **argv) {
  unsigned linenr = 0U;
  enum u8id_options xid = U8ID_TR31_XID;
  enum u8id_norm norm = U8ID_NFC;
  enum u8id_profile profile = U8ID_PROFILE_C26_4;
  unsigned u8idopts = (unsigned)xid;

  char path[256] = {0};
  static char line[1024] = {0};

  if (argc > 1 && !strcmp(argv[1], "--help"))
    usage(0);
  if (argc > 1 && !strcmp(argv[1], "--version")) {
    version();
    exit(0);
  }
  u8ident_init(profile, norm, u8idopts);
  if (getenv("U8IDTEST_TEXTS")) {
    strncpy(path, getenv("U8IDTEST_TEXTS"), 255);
#ifdef _WIN32
    path[255] = '\0'; // only windows does not terminate
#endif
  }
  if (argc > 1) {
    strncpy(path, argv[1], 255);
#ifdef _WIN32
    path[255] = '\0'; // only windows does not terminate
#endif
  } else {
    if (*path)
      strncat(path, "/myanmar-1.txt", 255);
    else
      strncpy(path, "texts/myanmar-1.txt", 255);
  }

  FILE *f = fopen(path, "r");
  if (!f) {
    perror("fopen");
    fprintf(stderr, "%s\n", path);
    return -1;
  }
  printf("u8ident_check %s\n", path);

  while (fgets(line, 1023, f)) {
    linenr++;
    // split on whitespace
    char *s = &line[0];
    while (*s) {
      // we really should split on identifier boundaries, as in a real parser.
      // but this is just a simple example. So we get lots of unneeded XID
      // errors.
      char word[256];
      char *norm = NULL;
      char *p = strchr(s, ' ');
      ptrdiff_t len = p ? (ptrdiff_t)(p - s) : (ptrdiff_t)strlen(s);
      if (len && s[len - 1] == '\n')
        len--;
      if (!len)
        break;
      int ret = u8ident_check_buf(s, len, NULL);
      switch (ret) {
      case U8ID_EOK_NORM:
        if (len < 256) {
          strncpy(word, s, len);
          word[len] = '\0';
          u8ident_check((uint8_t *)word, &norm);
          printf("\"%s\".%u: NFC => \"%s\"\n", word, linenr, norm);
          free(norm);
        } else {
          printf("\"%.*s\".%u: NFC ...\n", (int)len, s, linenr);
        }
        break;
      case U8ID_ERR_XID:
        printf("\"%.*s\".%u: Wrong XID U+%X\n", (int)len, s, linenr,
               u8ident_failed_char(0));
        break;
      case U8ID_ERR_COMBINE:
        printf("\"%.*s\".%u: Wrong Combining Mark U+%X\n", (int)len, s, linenr,
               u8ident_failed_char(0));
        break;
      case U8ID_ERR_SCRIPT:
      case U8ID_ERR_SCRIPTS: {
        uint32_t cp = u8ident_failed_char(0);
        const char *scr = u8ident_failed_script_name(0);
        const char *scripts = u8ident_existing_scripts(0);
        printf("\"%.*s\".%u: Wrong SCRIPT %s for U+%X, have %s\n", (int)len, s,
               linenr, scr, cp, scripts);
        free((char*)scripts);
        break;
      }
      default:
        break;
      }
      if (p)
        s = p + 1;
      else
        break;
    }
  }
  fclose(f);

  u8ident_free();
  return 0;
}
