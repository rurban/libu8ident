/* libu8ident_c — Example for the TR39 amalgam library.
   Copyright 2025 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   Demonstrates the minimal API: init, check, diagnostics, cleanup.
   Build: cc -o example_c example_c.c -lu8ident_c
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "u8ident_c.h"

static void version(void) { puts("libu8ident_c example"); }

static void usage(int exitcode) {
  version();
  puts("Usage: example_c [--help|--version] [file ...]");
  puts("\nChecks identifiers from files or stdin for TR39 validity.");
  puts("TR39 (UTS#39 / P2528R1) enforces Recommended scripts only,");
  puts("Greek-Latin confusable detection, NFC stability, and");
  puts("combining-mark sequence limits.");
  puts("\nSEE ALSO: u8idlint(1)");
  exit(exitcode);
}

static void check_line(const char *line) {
  /* Trim trailing newline */
  size_t len = strlen(line);
  while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
    len--;

  char buf[1024];
  memcpy(buf, line, len);
  buf[len] = '\0';

  enum u8id_errors r = u8ident_check_buf(buf, (int)len, NULL);
  if (r == U8ID_EOK) {
    printf("OK    %s\n", buf);
    return;
  }

  u8id_ctx_t ctx = u8ident_new_ctx();
  printf("%-5s %s  (U+%04X: %s)\n",
         r == U8ID_ERR_CONFUS  ? "CONFUS" :
         r == U8ID_ERR_COMBINE ? "COMBINE" :
         r == U8ID_ERR_SCRIPTS ? "SCRIPTS" :
         r == U8ID_ERR_SCRIPT  ? "SCRIPT" :
         r == U8ID_ERR_XID     ? "XID" :
         r == U8ID_ERR_ENCODING ? "ENCODING" : "UNKNOWN",
         buf,
         u8ident_failed_char(ctx),
         u8ident_failed_script_name(ctx)
             ? u8ident_failed_script_name(ctx)
             : "");
  /* Show existing scripts on mixed-script errors */
  if (r == U8ID_ERR_SCRIPTS) {
    const char *scripts = u8ident_existing_scripts(ctx);
    if (scripts) {
      printf("      already have: %s\n", scripts);
      free((void *)scripts);
    }
  }
  u8ident_free_ctx(ctx);
}

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--help"))
    usage(0);
  if (argc > 1 && !strcmp(argv[1], "--version")) {
    version();
    return 0;
  }

  /* In libu8ident_c, profile and norm are hardcoded to TR39_4 / NFC.
     The arguments are validated but ignored. */
  u8ident_init(U8ID_PROFILE_TR39_4, U8ID_NFC, 0);

  if (argc > 1) {
    /* Each file: read whitespace-delimited words, one per line */
    for (int i = 1; i < argc; i++) {
      FILE *f = fopen(argv[i], "r");
      if (!f) {
        perror(argv[i]);
        continue;
      }
      printf("=== %s ===\n", argv[i]);
      char line[1024];
      while (fgets(line, sizeof(line), f))
        check_line(line);
      fclose(f);
    }
  } else {
    /* Read identifiers from stdin, one per line */
    puts("Enter identifiers (one per line, Ctrl-D to exit):");
    char line[1024];
    while (fgets(line, sizeof(line), stdin))
      check_line(line);
  }

  u8ident_free();
  return 0;
}
