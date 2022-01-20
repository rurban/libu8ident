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
  enum u8id_options xid = U8ID_TR31_SAFEC23;
  enum u8id_norm norm = U8ID_NFC;
  enum u8id_profile profile = U8ID_PROFILE_C23_4;
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
    strncpy(path, argv[2], 255);
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
      char *p = strchr(s, ' ');
      ptrdiff_t len = p ? (ptrdiff_t)(p - s) : (ptrdiff_t)strlen(s);
      if (len && s[len - 1] == '\n')
        len--;
      if (!len)
        break;
      int ret = u8ident_check_buf(s, len, NULL);
      if (ret < 0) {
        printf("\"%.*s\".%u: %d\n", (int)len, s, linenr, ret);
      }
      if (p)
        s = p + 1;
      else
        break;
    }
  }

  u8ident_free();
  return 0;
}
