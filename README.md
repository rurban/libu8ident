libu8ident - Check unicode security guidelines for identifiers
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
Leaving such checks to a linter is not recommended, and they don't even exist.
(_The C 20 Standard commitee is wrong. They believe the whole UCD is needed
for those checks. So they rather ignore the problem._)

Valid characters
----------------

Each identifer must start with a *ID_Start* and continue with a *ID_Continue*
matcher. See [TR31](http://www.unicode.org/reports/tr31/). As perl regex:

     / (?[ ( \p{Word} & \p{XID_Start} ) + [_] ])
       (?[ ( \p{Word} & \p{XID_Continue} ) ]) * /x

The tokenizer has variable options for the start and cont matchers. The default
is to use none.
This is normally done by a parser, to the library you just pass the len or
null-terminated identifier.  Optionally we can check for proper
`XID_Start`/`XID_Continue` properties also. But this may not use the
optimization `-DDISABLE_CHECK_XID`.

With the optional `U8ID_CHECK_XID` option we check for valid UTF-8
encoding, valid XID_Start/Continue properties and allowed script of
each character. We do this by checking for the Allowed
[IdentifierStatus](https://www.unicode.org/Public/security/latest/IdentifierStatus.txt).

Some parsers also need to check for allowed **median** characters, which
are not allowed at the very end of an identifier. Esp. for
unrestrictive mixed-script security profiles or insecure xid
ranges. This library does not do this yet.

**u8idlint** has its own tokenizer, which can be configured with the
**--xid** options: **ASCII, ALLOWED, ID, XID, C11** and
**ALLUTF8**. (sorted from most secure to most insecure).  ASCII
ignores all utf8 word boundaries, ALLOWED, the default option is the
same as the `U8ID_CHECK_XID` option in the library. ID allows all
letters, plus numbers, punctuation and marks, including all exotic
scripts. XID is ID plus some special exceptions to avoid the NFKC
quirks, because NFKC has a lot of confusable mappings and no
roundtrips. C11 uses the C11 standard insecure DefId unicode ranges.
ALLUTF8 allows all unicode characters as letters > 127, as in php, D,
nim or crystal.

Normalization
-------------

All utf8 identifiers and literals are parsed and stored as normalized
NFC variants (unlike Python 3), which prevents from various TR31, TR36 and TR39
unicode confusable and spoofing security problems with identifiers. See
http://www.unicode.org/reports/tr31/, http://www.unicode.org/reports/tr36/
and http://www.unicode.org/reports/tr39
Optionally we also support the NFKC, NFKD and NFD methods.

For example with NFKC the following two characters would be equal:
ℌ => H, Ⅸ => IX, ℯ => e, ℨ => Z (and not 3), ⒛ => 20, µ (Math) => μ (Greek) ...
Under NFC only glyphs looking the same, but varying the underlying
combining marks would be equal: Such as Café == Café.

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

Certain combinations of mixed scripts are defined with a user-defined
identifier security profile, the Restriction Levels 1-6.
https://www.unicode.org/reports/tr39/#Restriction_Level_Detection

1. **ASCII-Only**

All characters in the string are in the ASCII range. You don't need this library
for that use-case. (*Maybe still allow that for conformance testing*.
This is the recommended profile, don't fall into the unicode identifier trap.
*E.g. zig was right, rejecting those proposals.*)

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
  Cyrillic or Greek.

5. **Minimally Restrictive**

* There are no restrictions on the set of scripts that cover the string.
* The only restrictions are the identifier well-formedness criteria
  and Identifier Profile, allowing arbitrary mixtures of scripts such
  as Ωmega, Teχ, HλLF-LIFE, Toys-Я-Us.
  Bidi-formatting is only allowed with Hebrew or Arabic. (an extension over TR39)

6. **Unrestricted**

* There are no restrictions on the script coverage of the string.
* The only restrictions are the criteria on identifier
  well-formedness. Characters may be outside of the Identifier
  Profile.
  Bidi-formatting is allowed with all scripts.
* This level is primarily for use in detection APIs, providing return
  value indicating that the string does not match any of the levels
  1-5.

c11_4. **SAFEC23**

* We also provide a special profile, called **`U8ID_PROFILE_C11_4`**,
  defined by `-DU8ID_PROFILE_SAFEC23`. This is an extended Moderate
  Profile (4), plus allowing Greek with Latin, plus only allowing Allowed
  IdentifierStatus.
* `U8ID_PROFILE_C11_4` aka `U8ID_PROFILE_SAFEC23` is the secure
  extension over C11, disallowing the restricted and limited_use
  scripts and identifiers, arbitrary rtl and ltr overrides, and all
  the insecure mixed scripts combinations.  See `unic11.h`,
  `test-c11.c` and [c11.md](c11.md).

c11_6. **C11STD**

* The C11 standard allows a certain range of (mostly insecure)
  codepoints, and did not define combinations of mixed scripts, not a
  security profile.  Thus an insecure Unrestricted profile 6, ignoring
  the UCD IdentifierStatus.  This is `U8ID_PROFILE_C11_6`, defined by
  `-DU8ID_PROFILE_C11STD`
  See [c11.md](c11.md), `unic11.h` and http://www.open-std.org/jtc1/sc22/wg14/www/docs/n2731.pdf
  Annex D (p. 425)

Recommended is Level 4, the **Moderately Restrictive level** or its **C11_4** variant.
It is always easier to widen restrictions than narrow them.

configure options
-----------------

* `--with-norm=NFC,NFD,NFKC,NFKD,FCC,FCD`. Default: none (at run-time,
  NFC is the default)

* `--with-profile=2,3,4,5,6,c11_4,c11_6`. Default: none (at run-time, 4 is the default)

* `--enable-confus`

* `--with-croaring[=path-to-CRoaring]`

* `--enable-check-xid`, `--disable-check-xid` or none

If to check for the Allowed
[IdentifierStatus](https://www.unicode.org/Public/security/latest/IdentifierStatus.txt)
or not. `--disable-check-xid` sets `-DDISABLE_CHECK_XID`, `--enable-check-xid`
sets `-DENABLE_CHECK_XID`.
A normal unicode-aware parser might check for the XID property
this already, but in 2021 99% of all parsers still do the wrong thing
for unicode identifiers, even for this simple static check. Not yet
talking about allowed scripts, mixed scripts or confusables.

With the optional `-DDISABLE_CHECK_XID` define, all identifiers need
to contain valid codepoints, XID_Start/Continue characters, and accept
only Allowed Identifier codepoints. This can then use a shorter script
list to check against, skipping all the undefined holes or
non-identifier characters.

With the optional `-DENABLE_CHECK_XID` define, this library ensures that
all identifiers accept only Allowed Identifier codepoints. It can use the
same optimizations as `-DDISABLE_CHECK_XID`, it just adds the mandatory
is_allowed check at run-time.

When you know beforehand which normalization or profile you will need,
and your parsers knows about allowed identifier codepoints, define
that via `./configure --with-norm=NFC --with-profile=4 --disable-check-xid`,
resp. `cmake -DLIBU8IDENT_NORM=NFC -DLIBU8IDENT_PROFILE=4 -DBUILD_SHARED_LIBS=OFF`.
This skips a lot of unused code and branches.
The generic shared library has all the code for all normalizations,
profiles, xid check and branches at run-time.

e.g codesizes for u8idnorm.o with -Os

    amd64-gcc:   NFKC 217K, NFC+FCC 182K, NFD 113K, NFD 78K, FCD 52K
    amd64-clang: NFKC 218K, NFC+FCC 183K, NFD 114K, NFD 78K, FCD 52K

default: 365K with -g on amd64-gcc

For `-DU8ID_PROFILE_SAFEC23` see above. `c23_4` is also called
**SAFEC23**, `c11_6` is the std insecure C11 profile.

With `confus` enabled, the confusable API is added.
With `croaring` the confus API is about twice as fast, and needs half the size.

See the likewise **cmake** options: 

* `-DBUILD_SHARED_LIBS=ON,OFF`
* `-DLIBU8IDENT_NORM=NFC,NFKC,NFD,NFKD`
* `-DLIBU8IDENT_PROFILE=2,3,4,5,6,c11_4,c11_6`
* `-DLIBU8IDENT_ENABLE_CHECK_XID=On`
* `-DLIBU8IDENT_DISABLE_CHECK_XID=On`
* `-DHAVE_CONFUS=ON`
* `-DHAVE_CROARING=ON`

API
---

    #include "u8ident.h"

**u8id_options** is the sum of the following bits:

enum u8id_norm:

    U8ID_NFC  = 0  // the default, shortest canonical composed normalization
    U8ID_NFD  = 1  // the longer, decomposed normalization
    U8ID_NFKC = 2  // the compatibility normalization
    U8ID_NFKD = 3  // the longer compatibility decomposed normalization
    U8ID_FCD  = 4, // the faster variants
    U8ID_FCC  = 5, //

enum u8id_profile:

    U8ID_PROFILE_1 = 1      // ASCII only
    U8ID_PROFILE_2 = 2      // Single Script only
    U8ID_PROFILE_3 = 3      // Highly Restrictive
    U8ID_PROFILE_4 = 4      // Moderately Restrictive
    U8ID_PROFILE_5 = 5      // Minimally Restrictive
    U8ID_PROFILE_6 = 6      // Unrestricted
    U8ID_PROFILE_C11_6 = 7, // "C11STD"
    U8ID_PROFILE_C23_4 = 8, // 4 + Greek with only Allowed ID's ("SAFEC23")

enum u8id_options:

    U8ID_TR31_ALLOWED = 64, // hardcoded with --enable-check-xid. The UCD IdentifierStatis.txt
    U8ID_TR31_ID = 65,      // tr31 variants
    U8ID_TR31_XID = 66,
    U8ID_TR31_C11 = 67,
    U8ID_TR31_ALLUTF8 = 68,
    // room for more tr31 profiles
    
    U8ID_FOLDCASE = 128,         // optional for case-insensitive idents. case-folded
                                 // when normalized
    U8ID_WARN_CONFUSABLE = 256,  // requires -DHAVE_CONFUS
    U8ID_ERROR_CONFUSABLE = 512, // requires -DHAVE_CONFUS

`int u8ident_init (enum u8id_profile, enum u8id_norm, unsigned options)`

Initialize the library with a bitmask of options, which define the
performed checks. Recommended is `(U8ID_PROFILE_DEFAULT, U8ID_NORM_DEFAULT, 0)`.

`int u8ident_set_maxlength (int maxlen)`

of an identifier. Default: 1024. Beware that such longs identiers are
not really identifiable anymore, and keep them under 80 or even
less. Some filesystems do allow now 32K identifiers, which is a
glaring security hole, waiting to be exploited.

`u8id_ctx_t u8ident_new_ctx ()`

Generates a new identifier document/context/directory, which
initializes a new list of seen scripts. Contexts are optional. By
default all checks are done in the same context 0. With compilers and
interpreters a context is a source file, with filesystems a directory,
with usernames you may choose if you need to support different
languages at once.  I cannot think of any such usage, so better avoid
contexts with usernames to avoid mixups.

`int u8ident_set_ctx (u8id_ctx_t ctx)`

Changes to the context generated with `u8ident_new_ctx`.

`int u8ident_add_script_name (const char *name)`
`int u8ident_add_script (uint8_t script)`

Adds the script to the context, if it's known or declared
beforehand. Such as `use utf8 "Greek";` in cperl, or a
`#pragma unicode Braille` in some C to add some Limited_Use scripts.

`int u8ident_free_ctx (u8id_ctx_t ctx)`

Deletes the context generated with `u8ident_new_ctx`. This is
optional, all remaining contexts are deleted by `u8ident_free()`.

`int u8ident_free ()`

End this library, cleaning up all internal structures.

`uint8_t u8ident_get_script (const uint32_t cp)`

Lookup the script property for a codepoint.

`const char* u8ident_script_name (const int scr)`

Lookup the long script name for the internal script byte/index.

`bool u8ident_is_confusable (const uint32_t cp)`

Lookup if the codepoint is a confusable. Only with `--enable-confus /
-DHAVE_CONFUS`.  With `--with-croaring / -DHAVE_CROARING` this is
twice as fast, and needs half the size.

`enum u8id_errors u8ident_check (const u8* string, char** outnorm)`

`enum u8id_errors u8ident_check_buf (const char* buf, int len, char** outnorm)`

Two variants to check if this identifier is valid. u8ident_check_buf
avoids allocating a fresh string from the parsed input.  outnorm is
set to a fresh normalized string if valid.

Return values (`enum u8id_errors`):

  * 0  - valid without need to normalize.
  * 1   - valid with need to normalize.
  * 2   - warn about confusable
  * 3   - warn about confusable and need to normalize
  * -1  - invalid character class (only with `U8ID_CHECK_XID`)
  * -2  - invalid script
  * -3  - invalid mixed scripts
  * -4  - invalid UTF-8 encoding
  * -5  - invalid because confusable

Note that we explicitly allow the Latin confusables: 0 1 I ` |
i.e. U+30, U+31, U+49, U+60, U+7C

`char * u8ident_normalize (const char* buf, int len)`

Returns a freshly allocated normalized string, with the options defined at
`u8ident_init`.

`uint32_t u8ident_failed_char (const int ctx)`

Returns the failing codepoint, which failed in the last check.

`const char* u8ident_failed_script_name (const int ctx)`

Returns the constant script name, which failed in the last check.

`const char* u8ident_existing_scripts (int ctx)`

Returns a fresh string of the list of the seen scripts in this context
whenever a mixed script error occurs. Needed for the error message
"Invalid script %s, already have %s", where the 2nd %s is returned by
this function.  The returned string needs to be freed by the user.

Usage:

    if (u8id_check("wrongᴧᴫ") == U8ID_ERR_SCRIPTS) {
      const char *errstr = u8ident_existing_scripts(ctx);
      fprintf(stdout, "Invalid script %s for U+%X, already have %s.\n",
         u8ident_failed_script_name(ctx),
         u8ident_failed_char(ctx), errstr);
      free(errstr);
    }

u8idlint
--------

Included is the sample program **u8idlint** which parses program
source files for possible unicode identifier violations.
See `man u8idlint`.

Packaging
---------

Recommended is to use the static lib or sources with your known normalization,
profile and xid options.  E.g. via cmake or submodule integration.
Because the size and run-time varies wildly between all the possible
and needed options, and this is in the hot path of a parser.

A shared library needs to provide all the options at run-time,
i.e. empty configure options.

Build dependencies: ronn (`dnf install rubygem-ronn-ng`)

Optional dependencies:

  * CRoaring (the two amalgamated sources only).
    autotools downloads it automatically with `--enable-confus --with-roaring`.

Maintainer dependencies: wget, perl, xxd. Needed every year when the UCD changes.

Internals
---------

Each context keeps a list of all seen unique scripts, which are represented as a
byte.  4-8 bytes are kept in a word, so you rarely need to allocate room for the
scripts.

The normalization tables need to be updated every year with the new Unicode
database via `make regen-norm` (using my `perl-Unicode-Normalize` variant).
This is generated from the current UCD via the current perl, every
April/May.  Stored are small 3-way tables for the canonical decomposition (NFD)
of each utf-8 character.  With `U8ID_NFC` also the canonical composition (NFC)
tables and the reorder logic.  With `U8ID_NFKC` even the larger compatibility
composition tables and the reorder logic.

The NFC strings are always shorter, but need a 2nd table set (2x
memory) and 3x longer lookup times. If compiled with `--with-norm=NFD`
the library is smaller and faster, but the resulting identifiers maybe
a bit longer. The NFD table is very sparse, only 3 of 17 initial
planes are needed.  Some rare overlong entries (296 codepoints with >
5 byte of UTF-8) are searched in an extra list to keep static memory
usage low, contrary to most other unicode libs.

We don't support the normalization variants FCC nor FCD yet.

The character to script lookup is done with a sorted list of ranges,
for less space.  This is also generated from the current UCD.  The
internally used script indices are arbitrarily created via
`mkscripts.pl` from the current UCD, sorted into *Recommended Scripts*
(sorted by codepoints), *Not Recommended Scripts* (sorted
alphabetically) and *Limited Use Scripts* (sorted by codepoint).

With `-DDISABLE_CHECK_XID` and `-DENABLE_CHECK_XID` we can use the
shorter `nonxid_script_list[]`, as we know that only valid XID's are
checked.

With **CRoaring** some boolean bitset queries can be optimized. So far
only the confusables codepoints lookups are used. The others,
`allowed_croar.h` and the `nf*_croar.h` headers are too slow. See
`perf`. These optimizations on boolean ranges are work in progress, if
I can find faster lookups than binary search. Also for special
configurations, such as a new **c11** profile a single header and
optimized lookup method should be implemented, combining the script,
xid and decomposition in it. This would replace the ~6 lookups per
codepoint.

TODO
----

* Lookup optimization:
  For some common combinations generate a single lookup with all the needed values:
  NFC + PROFILE_4 + CHECK\_XID with the script byte in the first decompose lookup
  `UN8IF_canon_tbl`.

* **SCX variants**: Some codepoints are combinations, valid for a number of
  scripts.  These appear with the Common and Inherited scripts. When
  an SCX appears with more than one script, such as e.g. U+60C with
  `Arab Nkoo Rohg Syrc Thaa Yezi`, the variants need to be checked
  against the existing scripts in the current context.  If one of them
  already exists, the SCX list is collapsed to this. But if none
  exists we need to store the list and check it against the next yet unseen
  script, and check for mixed-script violations. Currently we only check if
  none of the SCX variants exist yet, and only then we have a new script.
  Which exactly is unknown, but the new script might lead to a mixed-script
  violation.

* allowed_id: seperate into start and cont lists.

* add special checks for zero-with (non-)joiners, only allowed in special
  median or cont positions. See TR31 2.3 A1,A2 or B.
  Ditto for other tr31 special median positions, e.g. MIDDLE DOT, HEBREW U+5F3,
  KATAKANA U+30A0, U+30FB.

* **[IdentifierType](http://www.unicode.org/reports/tr39/#Identifier_Status_and_Type)**
  The list of idtypes is provided, but not yet integrated into any API.
  E.g. if someone wants to allow the Technical idtype.
  Then you have to use `u8ident_get_idtypes ()` by yourself, and it is
  not exported (ie. unusable from the shared library)
  We only optionally check the IdentifierStatus Allowed with CHECK_XID, from
  this TR39 Table 1.

* **FCD**: This normalization is broken.

* Eventually provide **wchar** support. Technically easy, even easier than UTF-8.

AUTHOR
------
Reini Urban <rurban@cpan.org> 2014,2021
