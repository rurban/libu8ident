C++ Identifier Syntax using Unicode Standard Annex 39

Date: 	    2021-12-28
Project: 	Programming Language C++
Audience: 	EWG
            CWG
Reply-to: 	Reini Urban <rurban@cpan.org>

Contents

1 Abstract
==========

In response to P1949R7 

Adopt Unicode Annex 39 as part of C++ 23.

- That Mixed Scripts follow the **Moderately Restrictive** Security
  profile for identifiers, with the exception that Greek is allowed
  together with Latin.

Fix Unicode Annex 31 from `XID_Start/XID_Continue` to IdentifierStatus
ALLOWED as part of C++ 23.

- That `XID_Start/Continue` should be filtered for the **Recommended scripts**.
  Skip **Excluded** and **Limited_Use scripts**.
- Provide an optional `#pragma unicode Script` that Excluded scripts
  can be added to the allowed set of scripts.

In addition adopt this proposal as a Defect Report against C++20 and
earlier.

2 Changes
=========

none

3 Summary
=========

[P1949](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html)
correctly detected that Unicode identifiers are still not
identifiable, and are prone to bidi- and homoglyph attacks. But it
stated that implementing TR31 and TR39 would be too hard. Having
properly implemented the Unicode Security Guidelines for identifers
for several years, plus pushed Rust to do so also, proves the
contrary.

Further restriction of the TR31 profile to only recommended scripts
leads to smaller sets for identifiers, and implementation of a proper
TR39 mixed script profile fixes most of the current unicode security
problems with identifiers. The only remaining problems are bidi
overrides in strings or comments, which cannot be handled with
identifier restrictions, but tokenizer or preprocessor warnings, as
recently added to gcc. `#include filename` restrictions should be done
also, but that is out of the scope of this document, as the existing
filesystems care much less about unicode security for identifiers than
programming languages.

Implementing mixed script detection per document (C++ Header and
Source file) forbids insecure mixes of Greek with Cyrillic, dangerous
Arabic RTL bidi attacks and most confusables. You can still write in
your language, but then only in commonly written languages, and not
mixed with others. Identifiers are still identifiable.

4 What will this proposal change?
=================================

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

# Documents with identifiers in many multiple scripts/languages will become illegal

C++23 will follow the TR39 Security Profile 4 **Moderately
Restrictive**, with an exception for Greek. Called Profile C23_4 or
SAFEC11 in libu8ident.

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
symbols.

5 What will this proposal not change?
=====================================

5.1 The validity of TR31 `XID_Start/XID_Continue` characters in
identifiers

5.2 The validity of “extended”" characters in identifiers

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
from compiler and related tool test suites. 

Restricting the profile of characters is much easier if no one is
depending on them.

The recent https://trojansource.codes effort caused gcc to emit a new
bidi warning, and github to implement similar warnings.

There used to be no linter, but there is now one: **u8idlint** from
https://github.com/rurban/libu8ident, which can be used to check for
ALLOWED,ID,XID,C11 or ALLUTF8 TR31 profiles, for various mixed script
profile violations and normalization methods.

So far only Rust, cperl and Java follow a unicode security guideline
for identifiers, zig and J refused to support non-ASCII
identifiers. Everbody else is vulnerable to potential security attacks
and does allow non-identifiable identifiers. They should rename
identifiers to "symbols".

7 Implementations and Strategies
================================

I implemented for [cperl](https://github.com/perl11/cperl), a fork of
perl5, the General Security profile "Moderately restrictive" (4) for
identifiers in 2017, together with transparent normalization of
NFC. This is a dynamic language with the need for fast tokenizing, and
compilation. Still I did not see a need to restrict all source code
identifiers to be already in NFC. Even with the added unicode checks
and dynamic normalization the tokenizer is still faster than the
simplier perl5 tokenizer.

Then I implemented the more general
[libu8ident](https://github.com/rurban/libu8ident) library, which can
be used with all known tr39 mixed-script security profiles, tr31 character
sets and all tr35 normalizations. There I tested various performance
strategies of the unicode lookups. Tested was CRoaring, which was only
useful for sets of single codepoints, the list of confusables. Most of
the needed lists were best structured as binary-search in range pairs.
Most of them were fastest with special-casing the codepoints below
U+128 with a simple linear search. Binary search in an Eytzinger
layout was not convincibly faster.

Still a not yet tested is to store in the script-filtered `XID_Start` and
`XID_Continue` range lists all the needed information, such as the
`Sc` and `Scx` properties, and its `NFC` normalization. The NFC composition
would be useful if the identifier are required to be NFC, as proposed
in [P1949](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html).

8 Issues with binutils, linkers, exported identifiers
=====================================================

The crux with C and somewhat also C++ identifiers, is that they can be
used with other earlier compilers or languages without any unicode security
profile or restriction. ffi's are very common, thanksfully unicode
names not at all yet.

binutils and linkers treat names as zero-terminated binary chunk, same
as in current filesystems. Identifiers are not identifiable there, and
names are charset specific, whilst there are no header fields for the
used charset (e.g. if SHIFT-JIS or UTF-8), nor are there any rules for
name lookup (normalization). This is not solvable here, only
there. Only in the Rust ecosystem there are proper unicode identifier
rules, and Rust can be linked against C++/C. I haven't seen any
exported unicode names, they are only used in local symbols
still. UTF-16 compilers such as MSVC do export their UNICODE names
either in the local character set or as UTF-8.

The C++/C working groups should urge the binutils/linker working
groups to adopt a more precise specification how exported identifiers are
represented in object files and libraries: UTF-8 or any charset,
and how they are looked up: any normalization, NFC or not at all.
