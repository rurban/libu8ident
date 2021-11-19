/* libu8ident - Follow unicode security guidelines for identifiers
   Copyright 2014, 2021 Reini Urban
   Apache LICENSE
*/

#include <stdint.h>

enum u8id_options {
  U8ID_NFD  = 0, // the default decomposed, longer normalization
  U8ID_NFKC = 1, // as in Python 3
  U8ID_NFC  = 2, // the shorter composed normalization, as in the previous Apple HPFS filesystem

  U8ID_PROFILE_2 = 4,  // Single Script only
  U8ID_PROFILE_3 = 8,  // Highly Restrictive
  U8ID_PROFILE_4 = 16, // Moderately Restrictive
  U8ID_PROFILE_5 = 32, // Minimally Restrictive
  U8ID_PROFILE_6 = 64, // Unrestricted
};

/* Initialize the library with a bitmask of options, which define the
   performed checks. Recommended is `U8ID_PROFILE_4` only. */
int u8ident_init(enum u8id_options);

/* maxlength of an identifier. Default: 1024. Beware that such longs identiers, are
   not really identifiable anymore, and keep them under 80 or even
   less. Some filesystems do allow now 32K identifiers, which is a
   glaring security hole, waiting to be exploited */
int u8ident_set_maxlength(int maxlen);


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
   beforehand. Such as `use utf8 "Greek";` in cperl. */
int u8ident_add_script(uint8_t script);

/* Deletes the context generated with `u8ident_new_ctx`. This is
   optional, all remaining contexts are deleted by `u8ident_delete` */
int u8ident_delete_ctx(int);

/* End this library, cleaning up all internal structures. */
void u8ident_delete(void);


/* Two variants to check if this identifier is valid. The second avoids
   allocating a fresh string from the parsed input.
   Return values:
    * 0  - valid without need to normalize.
    * -1 - valid with need to normalize.
    * 1  - invalid character class
    * 2  - invalid script
    * 3  - invalid encoding
    * (4  - invalid because confusable, not yet implemented)
*/
int u8ident_check(const uint8_t* string);
int u8ident_check_buf(const char* buf, int len);

/* Returns a freshly allocated normalized string, in the option defined at `u8ident_init`. */
uint8_t* u8ident_normalize(const char* buf, int len);

/* Returns a string for the combinations of the seen scripts in this
   context whenever a mixed script error occurs.  The default string may
   be overridden by defining this function, otherwise the english message
   "Invalid script %s, already have %s" with the latest script and
   previous scripts is returned. The returned string needs to be freed by the user. */
// weak
const char* u8ident_script_error(int ctx);
