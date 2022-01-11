/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/

#include <stdint.h>
#include <stdbool.h>

#define U8IDENT_VERSION_MAJOR 0
#define U8IDENT_VERSION_MINOR 0
#define U8IDENT_UNICODE_VERSION 14

enum u8id_norm {
  U8ID_NFC = 0,  // the default, shorter canonical composed normalization
  U8ID_NFD = 1,  // the longer, canonical decomposed normalization, as in the
                 // previous Apple HPFS filesystem
  U8ID_NFKC = 2, // the compatibility composed normalization, as in Python 3
  U8ID_NFKD = 3, // the longer compatibility decomposed normalization
  U8ID_FCD = 4,  // the faster variants
  U8ID_FCC = 5
};
enum u8id_profile {
  U8ID_PROFILE_1 = 1,     // ASCII only
  U8ID_PROFILE_2 = 2,     // Single Script only
  U8ID_PROFILE_3 = 3,     // Highly Restrictive
  U8ID_PROFILE_4 = 4,     // Moderately Restrictive
  U8ID_PROFILE_5 = 5,     // Minimally Restrictive
  U8ID_PROFILE_6 = 6,     // Unrestricted
  U8ID_PROFILE_C11_6 = 7, // The C11 std
  // PROFILE_4 + Greek with only Allowed ID's ("SAFEC23")
  U8ID_PROFILE_C23_4 = 8,
};
enum u8id_options {
  //  Note: The parser/tokenizer should do that. Without, the checker can be
  //  faster.
  //  Can be disallowed with --u8id-tr31=NONE, hardcoded with --u8id-tr31=.
  U8ID_TR31_XID = 64, // ID without NFKC quirks, labelled stable, the default
  U8ID_TR31_ID = 65,  // all letters, plus numbers, punctuation and marks. With
                      // exotic scripts.
  U8ID_TR31_ALLOWED =
      66, // TR39 ID with only recommended scripts. Allowed IdentifierStatus.
  U8ID_TR31_SAFEC23 =
      67, // practical XID with TR39 security measures. see c23++proposal
  U8ID_TR31_C11 =
      68, // the stable insecure AltId ranges from the C11 standard, Annex D
  U8ID_TR31_ALLUTF8 = 69, // allow all > 128, e.g. D, php, nim, crystal
  U8ID_TR31_ASCII = 70, // only ASCII letters (as e.g. zig, j. older compilers)
  // room for more tr31 profiles

  U8ID_FOLDCASE = 128,
  U8ID_WARN_CONFUSABLE = 256,  // requires -DHAVE_CONFUS
  U8ID_ERROR_CONFUSABLE = 512, // requires -DHAVE_CONFUS
};
#define U8ID_TR31_MASK 127
typedef unsigned u8id_ctx_t;

#ifndef U8ID_NORM_DEFAULT
#  define U8ID_NORM_DEFAULT U8ID_NFC
#endif
#ifndef U8ID_PROFILE_DEFAULT
#  define U8ID_PROFILE_DEFAULT U8ID_PROFILE_4
#endif

#ifndef _U8ID_PRIVATE_H
// from outside the dll
#  if defined _WIN32 || defined __CYGWIN__
#    define EXTERN __declspec(dllimport)
#  else
#    define EXTERN extern
#  endif
//#  define LOCAL
#else
// inside the dll
#  if defined _WIN32 || defined __CYGWIN__
#    define EXTERN __declspec(dllexport)
#    define LOCAL __attribute__((visibility("hidden")))
#  elif __GNUC__ >= 4
#    define EXTERN __attribute__((visibility("default")))
#    define LOCAL __attribute__((visibility("hidden")))
#  else
#    define EXTERN
#    define LOCAL
#  endif
#endif

/* Initialize the library with a tr39 profile, normalization and bitmask of
   options, which define more performed checks. Recommended is
   `(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0)`. return -1 on error, 0 if
   options are valid.
*/
EXTERN int u8ident_init(enum u8id_profile, enum u8id_norm, unsigned options);

/* maxlength of an identifier. Default: 1024. Beware that such longs
   identifiers, are not really identifiable anymore, and keep them under 80 or
   even less. Some filesystems do allow now 32K identifiers, which is a glaring
   security hole, waiting to be exploited */
EXTERN void u8ident_set_maxlength(unsigned maxlen);

/* Generates a new identifier document/context/directory, which
   initializes a new list of seen scripts. Contexts are optional, by
   default all checks are done in the same context 0. With compilers
   and interpreters a context is a source file, with filesystems a directory,
   with usernames you may choose if you need to support different languages at
   once.
   I cannot think of any such usage, so better avoid contexts with usernames to
   avoid mixups. */
EXTERN u8id_ctx_t u8ident_new_ctx(void);

/* Changes to the context previously generated with `u8ident_new_ctx`. */
EXTERN int u8ident_set_ctx(u8id_ctx_t ctx);

/* Optionally adds a script to the context, if it's known or declared
   beforehand. Such as `use utf8 "Greek";` in cperl.

   All http://www.unicode.org/reports/tr31/#Table_Recommended_Scripts
   need not to be declared beforehand.

   Common Inherited Arabic Armenian Bengali Bopomofo Cyrillic
   Devanagari Ethiopic Georgian Greek Gujarati Gurmukhi Hangul Han Hebrew
   Hiragana Katakana Kannada Khmer Lao Latin Malayalam Myanmar Oriya
   Sinhala Tamil Telugu Thaana Thai Tibetan

   All http://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts need
   to be or are disallowed by profile:

   Adlam Balinese Bamum Batak Canadian_Aboriginal Chakma Cham Cherokee
   Hanifi_Rohingya Javanese Kayah_Li Lepcha Limbu Lisu Mandaic
   Meetei_Mayek Miao New_Tai_Lue Newa Nko Nyiakeng_Puachue_Hmong Ol_Chiki
   Osage Saurashtra Sundanese Syloti_Nagri Syriac Tai_Le Tai_Tham
   Tai_Viet Tifinagh Vai Wancho Yi Unknown

   All others need to be added with u8ident_add_script_name().
*/
EXTERN int u8ident_add_script_name(const char *name);
EXTERN int u8ident_add_script(uint8_t script);

EXTERN uint8_t u8ident_get_script(const uint32_t cp);
EXTERN const char *u8ident_script_name(const int scr);

/* Deletes the context generated with `u8ident_new_ctx`. This is
   optional, all remaining contexts are deleted by `u8ident_free` */
EXTERN int u8ident_free_ctx(u8id_ctx_t ctx);

/* End this library, cleaning up all internal structures. */
EXTERN void u8ident_free(void);

/* Returns a freshly allocated normalized string, in the option defined at
   `u8ident_init`. Defaults to U8ID_NFC. */
EXTERN char *u8ident_normalize(const char *buf, int len);

/*
  Lookup if the codepoint is a confusable. Only with --enable-confus
  -DHAVE_CONFUS.  With --with-croaring -DHAVE_CROARING this is
  twice as fast, and needs half the size.
*/
EXTERN bool u8ident_is_confusable(const uint32_t cp);

enum u8id_errors {
  U8ID_EOK = 0,
  U8ID_EOK_NORM = 1,
  U8ID_EOK_WARN_CONFUS = 2,
  U8ID_EOK_NORM_WARN_CONFUS = 3,
  U8ID_ERR_XID = -1,
  U8ID_ERR_SCRIPT = -2,
  U8ID_ERR_SCRIPTS = -3,
  U8ID_ERR_ENCODING = -4,
  U8ID_ERR_COMBINE = -5,
  U8ID_ERR_CONFUS = -6,
};

/* Two variants to check if this identifier is valid. u8ident_check_buf avoids
   allocating a fresh string from the parsed input. buf must not be
   zero-terminated.

   Return values (enum u8id_errors):
    * 0   - valid without need to normalize.
    * 1   - valid with need to normalize.
    * 2   - warn about confusable
    * 3   - warn about confusable and need to normalize
    * -1  - invalid xid, disallowed via IdentifierStatus.txt
    * -2  - invalid script
    * -3  - invalid mixed scripts
    * -4  - invalid encoding
    * -5  - invalid because confusable (not yet implemented)
    outnorm is set to a fresh normalized string if valid.

  Note that in the check we explicitly allow the Latin confusables: 0 1 I `
  i.e. U+30, U+31, U+49, U+60
*/
EXTERN enum u8id_errors u8ident_check(const uint8_t *string, char **outnorm);
EXTERN enum u8id_errors u8ident_check_buf(const char *buf, int len,
                                          char **outnorm);

/* returns the failing codepoint, which failed in the last check. */
EXTERN uint32_t u8ident_failed_char(const u8id_ctx_t ctx);
/* returns the constant script name, which failed in the last check. */
EXTERN const char *u8ident_failed_script_name(const u8id_ctx_t ctx);

/* Returns a fresh string of the list of the seen scripts in this
   context whenever a mixed script error occurs. Needed for the error message
   "Invalid script %s, already have %s", where the 2nd %s is returned by this
   function. The returned string needs to be freed by the user.

   Usage:

   if (u8id_check("wrongᴧᴫ") == U8ID_ERR_SCRIPTS) {
       const char *scripts = u8ident_existing_scripts(ctx);
       fprintf(stdout, "Invalid script %s for U+%X, already have %s.\n",
           u8ident_failed_script_name(ctx), u8ident_failed_char(ctx),
           scripts);
       free(scripts);
   }
*/
EXTERN const char *u8ident_existing_scripts(const u8id_ctx_t ctx);
