/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0
*/

#include <stdint.h>

#define U8IDENT_VERSION_MAJOR 0
#define U8IDENT_VERSION_MINOR 0
#define U8IDENT_UNICODE_VERSION 14

enum u8id_norm {
  U8ID_NFKC = 0,  // by the default the compatibility composed normalization, as in Python 3
  U8ID_NFD  = 1,  // the longer, decomposed normalization, as in the previous Apple HPFS filesystem
  U8ID_NFC  = 2,  // the shorter composed normalization
  U8ID_NFKD = 3,  // the longer compatibility decomposed normalization
  U8ID_FCD  = 4,  // the faster variants
  U8ID_FCC  = 5
};
enum u8id_profile {
  U8ID_PROFILE_2 = 8,  // Single Script only
  U8ID_PROFILE_3 = 16, // Highly Restrictive
  U8ID_PROFILE_4 = 32, // Moderately Restrictive
  U8ID_PROFILE_5 = 64, // Minimally Restrictive
  U8ID_PROFILE_6 = 128 // Unrestricted
};
enum u8id_options {
  U8ID_DEFAULT_OPTS = U8ID_NFKC + U8ID_PROFILE_4,
  U8ID_CHECK_XID    = 256, // Optional, check for the allowed tr39 IdentifierStatus.
                           // Note: The parser should do that. Without, the checker can be faster.
  U8ID_WARN_CONFUSABLE  = 512,  // not yet implemented
  U8ID_ERROR_CONFUSABLE = 1024, //       -"-
};
#define U8ID_NFMASK   7
#define U8ID_PROFMASK 255

/* Initialize the library with a bitmask of options, which define the
   performed checks. Recommended is `U8ID_PROFILE_4` only.
   return -1 on error, 0 if options are valid.
*/
int u8ident_init(unsigned options);

/* maxlength of an identifier. Default: 1024. Beware that such longs identiers, are
   not really identifiable anymore, and keep them under 80 or even
   less. Some filesystems do allow now 32K identifiers, which is a
   glaring security hole, waiting to be exploited */
void u8ident_set_maxlength(unsigned maxlen);


/* Generates a new identifier document/context/directory, which
initializes a new list of seen scripts. Contexts are optional, by
default all checks are done in the same context 0. With compilers
and interpreters a context is a source file, with filesystems a directory,
with usernames you may choose if you need to support different languages at once.
I cannot think of any such usage, so better avoid contexts with usernames to avoid mixups. */
int u8ident_new_ctx(void);

/* Changes to the context previously generated with `u8ident_new_ctx`. */
int u8ident_set_ctx(int ctx);

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
int u8ident_add_script_name(const char *name);
int u8ident_add_script(uint8_t script);

uint8_t u8ident_get_script(const uint32_t cp);
const char* u8ident_script_name(const int scr);

/* Deletes the context generated with `u8ident_new_ctx`. This is
   optional, all remaining contexts are deleted by `u8ident_delete` */
int u8ident_delete_ctx(int);

/* End this library, cleaning up all internal structures. */
void u8ident_delete(void);

/* Returns a freshly allocated normalized string, in the option defined at `u8ident_init`.
   Defaults to U8ID_NFKC. */
char* u8ident_normalize(const char* buf, int len);

enum u8id_errors {
  U8ID_EOK = 0,
  U8ID_EOK_NORM = 1,
  U8ID_EOK_WARN_CONFUS = 2,
  U8ID_ERR_CCLASS = -1,
  U8ID_ERR_SCRIPT = -2,
  U8ID_ERR_SCRIPTS = -3,
  U8ID_ERR_ENCODING = -4,
  U8ID_ERR_CONFUS = -5,
};

/* Two variants to check if this identifier is valid. The second avoids
   allocating a fresh string from the parsed input. buf must not be
   zero-terminated.
   Return values:
    * 0   - valid without need to normalize.
    * 1   - valid with need to normalize.
    * 2   - warn about confusable (not yet implemented)
    * -1  - invalid character class. disallowed via IdentifierStatus.txt
    * -2  - invalid script
    * -3  - invalid mixed scripts
    * -4  - invalid encoding
    * -5  - invalid because confusable (not yet implemented)
    outnorm is set to a fresh normalized string if valid.
*/
enum u8id_errors u8ident_check(const uint8_t* string, char** outnorm);
enum u8id_errors u8ident_check_buf(const char* buf, int len, char** outnorm);

/* returns the failing codepoint, which failed in the last check. */
uint32_t u8ident_failed_char(const int ctx);
/* returns the constant script name, which failed in the last check. */
const char* u8ident_failed_script_name(const int ctx);

/* Returns a fresh string of the list of the seen scripts in this
   context whenever a mixed script error occurs. Needed for the error message
   "Invalid script %s, already have %s", where the 2nd %s is returned by this function.
   The returned string needs to be freed by the user.
   Usage:
   if (u8id_check("wrongᴧᴫ") == U8ID_ERR_SCRIPTS) {
     const char *errstr = u8ident_existing_scripts(ctx);
     fprintf(stdout, "Invalid script %s, already have %s\n",
       u8ident_failed_script_name(ctx),
       u8ident_existing_scripts(ctx));
     free(errstr);
   }
*/
const char* u8ident_existing_scripts(int ctx);
