C++ Identifier Security using Unicode Standard Annex 39
=======================================================

Date: 	    2022-01-07
Project: 	Programming Language C++
Audience: 	EWG
            CWG
			WG14
			WG21
			SG-16
Reply-to: 	Reini Urban <reini.urban@gmail.com>

Contents

1 Abstract
==========

In response to [P1949R7](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html)

Adopt Unicode Annex 39 "Unicode Security Mechanisms" as part of C++ 23 (and C23).

- TR39#5.2 Mixed-Scripts Moderately Restrictive profile, but allow Greek scripts,
- Disallow all Limited_Use and Excluded scripts,
- Only allow TR 39#1 Recommended, Inclusion, Technical Identifier Type properties,
- Demand NFC normalization. Reject all composable sequences as ill-formed. (from P1949)
- Reject illegal mark sequences (Lm, Mn, Mc) with mixed-scripts (SCX) as ill-formed.

Optionally:
- Implementations may allow an optional `#pragma unicode <LongScript>` that 
  Excluded scripts can be added to the allowed set of scripts.

Recommend binutils/linker identifier rules: Require UTF-8 and NFC. Maybe even unicode security.

In addition adopt this proposal as a Defect Report against C++20 and
earlier. The author provides the [libu8ident](https://github.com/rurban/libu8ident/)
library (Apache 2 licensed) and its generated tables to all implementors.

2 Changes
=========

none

3 Summary
=========

[P1949](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html)
correctly detected that Unicode identifiers are still not
identifiable, and are prone to bidi- and homoglyph attacks. But it
stated that implementing TR31 and TR39 would be too hard.
Having properly implemented the Unicode Security Guidelines for identifers
for several years, plus pushed Rust to do so also, proves the
contrary.

Further restriction of the TR31 profile to only recommended scripts
leads to smaller sets for identifiers, and implementation of a proper
TR39 mixed script profile and identifier types fixes most of the
known unicode security problems with identifiers. The only remaining
problems are bidi overrides in strings or comments, which cannot be
handled with identifier restrictions, but tokenizer or preprocessor
warnings, as recently added to gcc. `#include filename` restrictions
should be done also, but that is out of the scope of this document, as
the existing filesystems care much less about unicode security for
identifiers than programming languages. Spoofing attacks on filenames
are not yet seen in the wild, but will appear sooner or later, same
as they appeared in browsers and email. Also names in C object files:
linkers, .def files, ffi's.

Implementing TR39 mixed script detection per document (C++ Header and
Source file) forbids insecure mixes of Greek with Cyrillic, dangerous
Arabic RTL bidi attacks and most confusables. You can still write in
your language, but then only in commonly written languages, and not
mixed with others. Identifiers are still identifiable.

4 What will this proposal change?
=================================

# The set of TR31 XID ranges will become smaller.

Restricting the **Identifier_Type** plus the Allowed Scripts, plus demanding NFC
will shrink the original XID set from 971267 codepoints to 93036 codepoints.
The ranges expand from 36 to 315. (when split by scripts already, 25 splits happen).

# Only Recommended scripts are now allowed, Excluded and Limited_Use scripts are excluded.

These scripts will stay allowed:

    Common Inherited Latin Arabic Armenian Bengali Bopomofo Cyrillic
    Devanagari Ethiopic Georgian Greek Gujarati Gurmukhi Hangul Han Hebrew
    Hiragana Katakana Kannada Khmer Lao Malayalam Myanmar Oriya
    Sinhala Tamil Telugu Thaana Thai Tibetan

These Excluded Scripts are initially disallowed 
https://www.unicode.org/reports/tr31/#Table_Candidate_Characters_for_Exclusion_from_Identifiers
but can be optionally be allowed via a new `#pragma unicode Script`:

    Ahom Anatolian_Hieroglyphs Avestan Bassa_Vah Bhaiksuki Brahmi
    Braille Buginese Buhid Carian Caucasian_Albanian Chorasmian Coptic
    Cuneiform Cypriot Cypro_Minoan Deseret Dives_Akuru Dogra Duployan
    Egyptian_Hieroglyphs Elbasan Elymaic Glagolitic Gothic Grantha
    Gunjala_Gondi Hanunoo Hatran Imperial_Aramaic
    Inscriptional_Pahlavi Inscriptional_Parthian Kaithi Kharoshthi
    Khitan_Small_Script Khojki Khudawadi Linear_A Linear_B Lycian
    Lydian Mahajani Makasar Manichaean Marchen Masaram_Gondi
    Medefaidrin Mende_Kikakui Meroitic_Cursive Meroitic_Hieroglyphs
    Modi Mongolian Mro Multani Nabataean Nandinagari Nushu Ogham
    Old_Hungarian Old_Italic Old_North_Arabian Old_Permic Old_Persian
    Old_Sogdian Old_South_Arabian Old_Turkic Old_Uyghur Osmanya
    Pahawh_Hmong Palmyrene Pau_Cin_Hau Phags_Pa Phoenician
    Psalter_Pahlavi Rejang Runic Samaritan Sharada Shavian Siddham
    SignWriting Sogdian Sora_Sompeng Soyombo Tagalog Tagbanwa Takri
    Tangsa Tangut Tirhuta Toto Ugaritic Vithkuqi Warang_Citi Yezidi
    Zanabazar_Square

These Limited Use Scripts are now disallowed:
http://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts

    Adlam Balinese Bamum Batak Canadian_Aboriginal Chakma Cham Cherokee
    Hanifi_Rohingya Javanese Kayah_Li Lepcha Limbu Lisu Mandaic
    Meetei_Mayek Miao New_Tai_Lue Newa Nko Nyiakeng_Puachue_Hmong Ol_Chiki
    Osage Saurashtra Sundanese Syloti_Nagri Syriac Tai_Le Tai_Tham
    Tai_Viet Tifinagh Vai Wancho Yi Unknown

The script property and its name are defined in [TR24](https://www.unicode.org/reports/tr24/).
We use the long Unicode Script property value, not the abbrevated 4-letter short name, which
maps somehow to the 4-letter [ISO 15924 Codes](https://www.unicode.org/reports/tr24/#Relation_To_ISO15924).

# Documents with identifiers in many multiple scripts/languages will become illegal

C++23 (and C23) will follow the TR39 Security Profile 4 **Moderately
Restrictive**, with an exception for Greek. We call this profile **C23_4** or
**SAFEC23**.

* All identifiers in a document qualify as Single Script, or
* All identifiers in a document are covered by any of the following sets of scripts,
  according to the definition in Mixed Scripts:
  * Latin + Han + Hiragana + Katakana (Japanese)
  * Latin + Han + Bopomofo (Chinese)
  * Latin + Han + Hangul (Korean), or
* All identifiers in a document are covered by Latin and any one other
  Recommended script, except Cyrillic.

5 What will this proposal not change?
=====================================

# 5.1 The validity of “extended”" characters in identifiers.

All current compilers allow characters outside the basic source
character set directly in source today.

6 Why now
=========

One driving factor for addressing this now is that GCC has fixed their
long standing bug 67224 “UTF-8 support for identifier names in
GCC”. Clang has always supported too many code points in source
code. MSVC in its usual configuration defaults to code page 1252, but
can be told to accept UTF-8 source. With GCC now allowing it, the
barrier to use of Unicode characters outside the basic source
character set has dropped considerably. Use of characters via
universal character names was always possible, but never widely
used. Examples found in the wild of use of UCNs in identifiers come
from compiler and related tool test suites. There is no report yet from
misuse in C ABI's from linkers and binutils.

Restricting the profile of characters is much easier if no one is
depending on them.

The recent https://trojansource.codes effort caused gcc to emit a new
bidi warning, and github to implement similar warnings.

There used to be no linter, but there is now one: **u8idlint** from
https://github.com/rurban/libu8ident, which can be used to check for
ALLOWED,ID,XID,C11 or ALLUTF8 TR31 profiles, for various TR39 mixed script
profile violations and TR15 normalization problems.

So far only Rust, cperl and Java follow a unicode security guideline
for identifiers, zig and J refused to support non-ASCII
identifiers. Everbody else is vulnerable to potential security attacks
and does allow non-identifiable identifiers. They should rename
identifiers to "symbols".

7 TR24 Scripts, the SC and SCX properties
=========================================

# 7.1 SC

C++ only needs to map unicode characters to a script property via a
single byte.  There are currently 161 scripts assigned, 32 of them are
in common use as identifiers, hence called **Recommended** scripts. The
rest is split up into 127-31 **Excluded** scripts, which are not in common
use, and 161-127 **Limited_Use** scripts, which are not to be used in
identifiers at all.

New scripts are added on a yearly basis, but nothing was added to the
stable set of recommended scripts. For a while there was a list of
**Aspirational** scripts to be added eventually, but this list was abandoned.
Probably also because nobody but Java, cperl and Rust implemented its
identifier profile by scripts, rather went with insecure identifiers.

For error messages and an optional pragma to allow certain Exluded
scripts, we use the long **Script property value**. Do not use the
term "script name", as this is ambigious and [misused](https://www.unicode.org/reports/tr24/#Script_Names).  The
Script Property Value is the titlecased name of the script from the
UCD, with spaces replaced by underscores. They are defined in the
yearly updated [Scripts.txt](https://www.unicode.org/Public/UNIDATA/Scripts.txt)

# 7.2 SCX Extensions

Not all characters are uniquely used in a single script only.  Many
are used in a variable numbers of scripts. These are assigned to the
Common or Inherited script, and are exactly specified in the
[ScriptExtensions.txt](https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt),
aka SCX. The SCX property is a list of possible scripts per character.
This list is using the short 4-letter script property, which needs
to be resolved via the [PropertyValueAliases.txt](https://www.unicode.org/Public/UNIDATA/PropertyValueAliases.txt)
to its long script property value. (E.g. Syrc to Syriac)

    # Script_Extensions=Arab Syrc

    064B..0655    ; Arab Syrc # Mn  [11] ARABIC FATHATAN..ARABIC HAMZA BELOW

    # Script_Extensions=Adlm Arab Mand Mani Ougr Phlp Rohg Sogd Syrc

    0640          ; Adlm Arab Mand Mani Ougr Phlp Rohg Sogd Syrc # Lm       ARABIC TATWEEL

Some of the SCX scripts contain only a single script. These are directly added
to the list of SC scripts for the purpose of identifier security checks.

E.g.

    3006          ; Hani # Lo       IDEOGRAPHIC CLOSING MARK

U+3006 with the Common script property is assigned to the Hani -> Han script.

Multiple SCX list entries can resolved when the previous scripts in the identifier context
are already resolved to one or the other possibility. Thus for SCX=(Arab Syrc) we need to
check if Arabic or Syriac was already seen. If not, the new character with that SCX is illegal,
violating our Mixed Script profile.

## 7.3 Combining marks script run detection for spoofing

Using the Script property alone will not detect that the
U+30FC ( ー ) KATAKANA-HIRAGANA PROLONGED SOUND MARK (Script=Common, SCX=Hira Kana, gc=Lm)
should not be mixed with Latin. See [UTS39#5.4](https://www.unicode.org/reports/tr39/#Optional_Detection) and [UTS46](https://www.unicode.org/reports/tr46/).

U+30FC ( ー ) KATAKANA-HIRAGANA PROLONGED SOUND MARK should not continue a Latin
script run, but instead should only continue runs of Hiragana and Katakana scripts, observing
the Lm property (Modifier_Letter) and SCX=Hira Kana.

Check for unlikely sequences of **combining marks**:

- Forbid sequences of the same nonspacing mark.
- Forbid sequences of more than 4 nonspacing marks (gc=Mn or gc=Me).
- Forbid sequences of base character + nonspacing mark that look the
  same as or confusingly similar to the base character alone (because
  the nonspacing mark overlays a portion of the base character). An
  example is U+0069 LOWERCASE LETTER I + U+0307 COMBINING DOT ABOVE.

Since we disallow already most combining marks (at least the Latin
ones) with the requirement of NFC [P1949R7](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html), this set of cases is quite small.

The list of allowed combining mark characters (with Common or Inherited
scripts) in the C23++ TR31 profile is: XXX TODO

8 TR39 Identifier Type
======================

The **Identifier_Type** property [TR 39#1][https://www.unicode.org/reports/tr39/#Identifier_Status_and_Type Table 1] recommendation should be mandatory,
with the addition of the `Technical` Identifier\_Type to be allowed. 

I.e. `Limited_Use, Obsolete, Exclusion, Not_XID, Not_NFKC, Default_Ignorable,`
`Deprecated, Not_Character` are not part of identifiers.

Allowed are `Recommended, Inclusion, Technical`.

There are XXX Technical ids added to the original list of XXX Recommended, Inclusion ids.

9 TR39 Mixed Scripts
====================

TR39 defines some security profiles for identifers to avoid the most
common identifier insecurities, that identifiers will stay
identifiable.

We choose a variant of the **Moderately Restrictive** profile, with an
exception for Greek.  I called this profile **C23_4** or **SAFEC23**
in libu8ident.

* All identifiers in a document qualify as Single Script, or
* All identifiers in a document are covered by any of the following sets of scripts,
  according to the definition in Mixed Scripts:
  * Latin + Han + Hiragana + Katakana (Japanese)
  * Latin + Han + Bopomofo (Chinese)
  * Latin + Han + Hangul (Korean), or
* All identifiers in a document are covered by Latin and any one other
  Recommended script, except Cyrillic.

Thus it prevents Cyrillic mixed with Latin or any other script, but
does allow any East-Asian CFK language, other common and widely used
languages and Latin mixed with Greek, mainly used for its mathematical
symbols. Many mathematical symbols already exists outside of Greek,
but these are mainly used for operators in advanced programming languages,
not as identifiers.  See also http://xahlee.info/comp/unicode_math_operators.html
for a nice overview.

E.g. here we have some:

    U+2217 (∗) ASTERISK OPERATOR (Script=Common). Not_XID
    U+2107 (ℇ) EULER CONSTANT (Script=Common, Lu) is a proper letter, but with Restricted IdentifierStatus.
    U+2126 (Ω) OHM SIGN (Script=Greek, L&) is a greek letter, but with Restricted IdentifierStatus.
    U+2127 (℧) INVERTED OHM SIGN (Script=Common, So). Obsolete, Not_XID

TR39 also compiles a convenient [IdentifierStatus](https://www.unicode.org/Public/security/latest/IdentifierStatus.txt)
list. But all the math letters with Script=Common from U+2100 to
U+2200 are restricted, as Greek is forbidden mixed with Latin in the
original TR39 Moderately Restrictive profile. These are allowed
according to the TR31 and TR39 rules of SAFEC23, so we need to come up
with our own list of `XID_Start/XID_Continue` codepoints, excluding
the Limited Use and Excluded scripts. And if an implementation choses
to allow Excluded scripts with more logic to allow only this script.

It is recommended to already exclude Limited Use and Excluded scripts
from the initial list of identifier ranges, as this is the most common
use-case, and shortens the common search paths.  Only with the
`#pragma Unicode ExcludedScript` search the full XID lists and the full
scripts list.

The TR39 Mixed Scripts profile alone does not prevent from all
spoofing attacks, but the additional rules from 7.3 "Combining marks
script run detection for spoofing" are kept tiny.

10 Contexts
==========

This is not discussed in any of the unicode security guidelines for identifiers.
One could argue that a mixed-script profile is valid only for a single identifier,
or it is valid for whole source file document.

If valid for only a single identifier you could arbitralily mix up
Cyrillic with Greek identifiers in a C++ namespace, and thus these
identifiers would not be identifiable anymore, as both both can render
to the very same glyphs. Thus we adopt the notion of identifier
contexts.

With programming languages this is a source file, with objects files
this is a module.  For identifiers in object files see below [12
Issues with binutils, linkers, exported identifiers](#12 Issues with
binutils, linkers, exported identifiers). For filesystems this would
be a directory.

For every source file we need to store a context with the list of
already seen scripts and how many.  The maximal number of scripts is
4, for the case of Japanese mixed with Latin. (`Katakana + Hiragana +`
`Han + Latin`), thus we can save that list in a single 4-byte word, and
the lookup and memory management is trivial.


11 Implementations and Strategies
================================

I implemented for [cperl](https://github.com/perl11/cperl), a fork of
perl5, the General Security profile "Moderately restrictive" (4) for
identifiers in 2017, together with transparent normalization of
NFC. This is a dynamic language with the need for fast tokenizing, and
compilation. Still I did not see a need to restrict all source code
identifiers to be already in NFC. Even with the added unicode checks
and dynamic normalization the tokenizer is still faster than the
simplier perl5 tokenizer.

Then when GCC went to full insecure identifiers I implemented the more
general [libu8ident](https://github.com/rurban/libu8ident) library,
which can be used with all known TR39 identifier type profiles, the
mixed-script security profiles, TR31 XID character sets and all TR35
normalizations. There I tested various performance strategies of the
unicode lookups. Tested was CRoaring, which was only useful for sets
of single codepoints, the list of confusables. Most of the needed
lists were best structured as binary-search in range pairs.  Most of
them were fastest with special-casing the codepoints below U+128 with
a simple linear search. Binary search in an Eytzinger layout was not
convincibly faster, neither hybrid searches by 1. splitting up ranges
from single codepoints, nor 2. seperating 16bit from 32bit codepoints.

12 Issues with binutils, linkers, exported identifiers
=====================================================

The crux with C and somewhat also C++ identifiers, is that they can be
used with other earlier compilers or languages without any unicode security
profile or restriction. ffi's are very common, libraries or .def files
even more, thanksfully unicode names not at all yet.

binutils and linkers treat names as zero-terminated binary garbage,
same as in most current filesystems. Identifiers are not identifiable
there, and names are charset (=user) specific, whilst there are no header
fields for the used charset (e.g. if SHIFT-JIS or UTF-8), nor are
there any rules for name lookup (normalization). This is not solvable
here (in C nor C++), only there. Only in the Rust ecosystem there are
proper unicode identifier rules, but Rust can link against
C++/C. I haven't seen any exported unicode names in the wild, they are
only used in local symbols still. UTF-16 compilers such as MSVC do
export their UNICODE names either in the local character set or as
UTF-8. If used wildly, object files would not link anymore, as local
charactersets vary, and there is no characterset standard defined.

The C++/C working groups should urge the binutils/linker working
groups to adopt a more precise specification how exported identifiers
are represented in object files and libraries: UTF-8 or any charset,
and how they are looked up: any normalization, NFC or not at all.  My
recommendation would be to interpret them as UTF-8, require NFC, and
reject all illegal UTF-8 and non-NFC identifiers. As long as there no
unicode names in the wild this is still easy. There are also many
object file producers in the wild, with possibly completely insecure
unicode names in the future.

Even better would be for the C ABI's to also adopt secure unicode
identifiers, as linkers and FFI's have the same unicode security
problems as compilers, interpreters and filesystems.  Otherwise they
should at least clarifiy that their names are not identifiable, and
implementation defined.
