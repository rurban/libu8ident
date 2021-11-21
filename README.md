libu8ident - Follow unicode security guidelines for identifiers
===============================================================

without adding the full Unicode database.

This library does the unicode identifier security checks needed for
all the compilers, interpreters, filesystems and login systems, which
do support for whatever reason unicode identifiers ("names"), and wish
to avoid the various unicode security loopholes, like bidi- or
homoglyph attacks, mixed scripts, confusables, and support normalized
storage. For the UTF-8 encoding only, wchar_t users are rare.

Supporting the various Unicode security profiles for identifiers can
be small, performant and easy.  Still everybody (roughly 98 out of
100) are vulnerable to unicode identifier attacks. Since I implemented
proper unicode security in cperl in 2016, the 2nd language after Java
which did so, I publish this little library so that others can follow.

Remember, the meaning of identifiers is to be **identifiable**. A user
should not confuse one identifier with another. Only a program, IDE or
library can properly check unicode identifiers, humans certainly not.
Leaving such checks to a linter is not recommended. (_The C 20 Standard is wrong._)

Valid characters
----------------

Each identifer must start with *XID_Start* and continue with *XID_Continue*
characters. As perl regex:

     / (?[ ( \p{Word} & \p{XID_Start} ) + [_] ])
       (?[ ( \p{Word} & \p{XID_Continue} ) ]) * /x

This is normally done by a parser, to the library you just pass the len or
null-terminated identifier.  Optionally we can check for proper
`XID_Start`/`XID_Continue` properties also. But this may not use the
optimization `-DDISABLE_CHECK_XID`. 

With the `U8ID_CHECK_XID` option we check for valid UTF-8 encoding, and valid
XID properties of each character.

Normalization
-------------

All utf8 identifiers and literals are parsed and stored as normalized
NFKC variants, which prevents from various TR39 and TR36 unicode
confusable and spoofing security problems.  Normalization is similar
to Perl 6 and Python 3, but Perl 6 normalized to their own NFG format
and Python 3 normalizes to the NFKC format. See
http://www.unicode.org/reports/tr36/ and http://www.unicode.org/reports/tr39.
Optionally we also support the NFK and NFD formats.

Mixed Scripts
-------------

Many mixed scripts combinations in unicode identifiers for a certain
context (such as a document or directory) are forbidden, but they can
be declared via a special API.  The 'Common', 'Latin' and 'Inherited'
scripts are always allowed and don't need to be declared. 
With some Common and Inherited the SCX Extended scripts needs to be checked.
Also the following combinations are allowed without any declaration: Latin +
Hangul + Han (:Korean), Latin + Katakana + Hiregana (::Japanese) and
Latin + Han + Bopomofo (:Hanb).  And some more recommended and
aspirational scripts, which are not excluded, except Cyrillic and
Greek.

The first allowed undeclared unicode script for an identifier is the
only allowed one. This qualifies as single-script.  More scripts lead
to parsers errors.
See http://www.unicode.org/reports/tr36/#Mixed_Script_Spoofing and
http://www.unicode.org/reports/tr31/.

I.e. you may still declare those scripts as valid, but they are not
automatically allowed, similar to the need to declare mixed scripts.


General Security Profiles
-------------------------

Certain combinations of mixed scripts are defined with a user-defined security
profile, the Restriction Levels 1-5.

1. **ASCII-Only**

All characters in the string are in the ASCII range. You dont need this library
for that use-case.
        
2. **Single Script**

* The string qualifies as ASCII-Only, or
* The string is single-script, according to the definition in
  [Mixed Scripts](http://www.unicode.org/reports/tr39/#Mixed_Script_Detection).

3. **Highly Restrictive**

* The string qualifies as Single Script, or
* The string is covered by any of the following sets of scripts,
  according to the definition in Mixed Scripts:

  * Latin + Han + Hiragana + Katakana; or equivalently: Latn + Jpan
  * Latin + Han + Bopomofo; or equivalently: Latn + Hanb
  * Latin + Han + Hangul; or equivalently: Latn + Kore

4. **Moderately Restrictive**

* The string qualifies as Highly Restrictive, or
* The string is covered by Latin and any one other Recommended script, except
  Cyrillic, Greek.
        
5. **Minimally Restrictive**

* There are no restrictions on the set of scripts that cover the string.
* The only restrictions are the identifier well-formedness criteria
  and Identifier Profile, allowing arbitrary mixtures of scripts such
  as Ωmega, Teχ, HλLF-LIFE, Toys-Я-Us.
        
6. **Unrestricted**

* There are no restrictions on the script coverage of the string.
* The only restrictions are the criteria on identifier
  well-formedness. Characters may be outside of the Identifier
  Profile.
* This level is primarily for use in detection APIs, providing return
  value indicating that the string does not match any of the levels
  1-5.

Recommended is Level 4, the *Moderately Restrictive level*.


API
---

**u8id_options** is an enum of the following bits:

    U8ID_NFKC = 0  // by the default the compatibility composed normalization, as in Python 3
    U8ID_NFD  = 1  // the longer, decomposed normalization, as in the previous Apple HPFS filesystem
    U8ID_NFC  = 2  // the shorter composed normalization

    U8ID_PROFILE_2 = 4  // Single Script only
    U8ID_PROFILE_3 = 8  // Highly Restrictive
    U8ID_PROFILE_4 = 16 // Moderately Restrictive
    U8ID_PROFILE_5 = 32 // Minimally Restrictive
    U8ID_PROFILE_6 = 64 // Unrestricted

    U8ID_FOLDCASE = 128, // optional for case-insensitive idents. case-folded when normalized.
    U8ID_CHECK_XID = 256,// optional, the parser should do that. Without, the script checker
                         // can be much smaller.
    U8ID_WARN_CONFUSABLE  = 512,  // not yet implemented
    U8ID_ERROR_CONFUSABLE = 1024, //       -"-

`int u8ident_init (u8id_options)`

Initialize the library with a bitmask of options, which define the
performed checks. Recommended is `U8ID_PROFILE_4` only.

`int u8ident_set_maxlength (int maxlen)`

of an identifier. Default: 1024. Beware that such longs identiers are
not really identifiable anymore, and keep them under 80 or even
less. Some filesystems do allow now 32K identifiers, which is a
glaring security hole, waiting to be exploited.

`int u8ident_new_ctx ()`

Generates a new identifier document/context/directory, which
initializes a new list of seen scripts. Contexts are optional. By
default all checks are done in the same context 0. With compilers
and interpreters a context is a source file, with filesystems a directory,
with usernames you may choose if you need to support different languages at once.
I cannot think of any such usage, so better avoid contexts with usernames to avoid mixups.

`int u8ident_set_ctx (int ctx)`

Changes to the context generated with `u8ident_new_ctx`.

`int u8ident_add_script_name(const char *name)`
`int u8ident_add_script (uint8_t script)`

Adds the script to the context, if it's known or declared
beforehand. Such as `use utf8 "Greek";` in cperl.

`int u8ident_delete_ctx (int)`

Deletes the context generated with `u8ident_new_ctx`. This is
optional, all remaining contexts are deleted by `u8ident_delete`.

`int u8ident_delete ()`

End this library, cleaning up all internal structures.

`uint8_t u8ident_get_script (const uint32_t cp)`

Lookup the script property for a codepoint.

`const char* u8ident_script_name (const int scr)`

Lookup the long script name for the internal script byte/index.

`int u8ident_check (const u8* string)`

`int u8ident_check_buf (const char* buf, int len)`

Two variants to check if this identifier is valid. The second avoids
allocating a fresh string from the parsed input.

Return values:

  * 0  - valid without need to normalize.
  * 1   - valid with need to normalize.
  * 2   - warn about confusable (_not yet implemented_)
  * -1  - invalid script
  * -2  - invalid character class (only with `U8ID_CHECK_XID`)
  * -3  - invalid UTF-8 encoding (only with `U8ID_CHECK_XID`)
  * -4  - invalid because confusable (_not yet implemented_)

`char * u8ident_normalize (const char* buf, int len)`

Returns a freshly allocated normalized string, with the options defined at
`u8ident_init`.

`weak const char* u8ident_script_error (int ctx)`

Returns a string for the combinations of the seen scripts in this context
whenever a mixed script error occurs.  The default string may be overridden by
defining this function, otherwise the english message "Invalid script %s,
already have %s" with the latest script and previous scripts is returned. The
returned string needs to be freed by the user.

Internals
---------

Each context keeps a list of all seen unique scripts, which are represented as a
byte.  4-8 bytes are kept in a word, so you rarely need to allocate room for the
scripts.

The normalization tables need to be updated every year with the new Unicode
database.  This is generated from the current UCD via the current perl, every
April/May.  Stored are small 3-way tables for the canonical decomposition (NFD)
of each utf-8 character.  With `U8ID_NFC` also the canonical composition (NFC)
tables and the reorder logic.  With `U8ID_NFKC` even the larger compatibility
composition tables and the reorder logic.

The NFC strings are always shorter, but need a 2nd table set (2x memory) and 3x
longer lookup times. If compiled with `--disable-nfc` the library is smaller and
faster, but the resulting identifiers maybe a bit longer. The NFD table is very
sparse, only 3 of 17 initial planes are needed.  Some rare overlong entries (296
codepoints with > 5 byte of UTF-8) are searched in an extra list to keep static
memory usage low, contrary to most other unicode libs.

We don't support the normalization variants FCC nor FCD.

The character to script lookup is done with a sorted list of ranges, for less
space.  This is also generated from the current UCD.  The internally used script
indices are arbitrarily created via mkscript.pl from the current UCD, sorted
into Recommended Scripts (sorted by codepoints), Not Recommended Scripts (sorted
alphabetically) and Limited Use Scripts (sorted by codepoint).

With the optional `-DDISABLE_CHECK_XID` define, all strings need to contain
valid codepoints and XID_Start/Continue characters. This can then use a shorter
script list to check against, skipping all the undefined holes or non-identifier
characters. A normal parser does this already.
