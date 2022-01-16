C++ Identifier Security using Unicode Standard Annex 39
=======================================================

    Date:       2022-01-15
    Project:    Programming Language C++
    Audience:   EWG
                CWG
                WG14
                WG21
                SG-16
    Reply-to:   Reini Urban <reini.urban@gmail.com>

1 Abstract
==========

In response to [P1949R7](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html)

Adopt Unicode Annex 39 "Unicode Security Mechanisms" as part of C++ 23 (and C23).

* Comply to a variant of [TR39#5.2](https://www.unicode.org/reports/tr39/#Restriction_Level_Detection)
  Mixed-Scripts Moderately Restrictive profile, but allow Greek scripts,
* Disallow all Limited Use [TR31#Table_7](http://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts)
  and Excluded scripts [TR31#Table_4](https://www.unicode.org/reports/tr31/#Table_Candidate_Characters_for_Exclusion_from_Identifiers),
* Only allow [TR39#Table 1](https://www.unicode.org/reports/tr39/#Identifier_Status_and_Type Table 1)
  Recommended, Inclusion, Technical Identifier Type properties,
* Demand NFC normalization. Reject all composable sequences as ill-formed.
  (from [P1949](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html)
* Reject illegal combining mark sequences (Sk, Cf, Mn, Me) with
  mixed-scripts (SCX) as ill-formed. [TR39#5.4](https://www.unicode.org/reports/tr39/#Optional_Detection)

Optionally:

* Implementations may allow an optional `#pragma unicode <LongScript>` that
  Excluded scripts can be added to the allowed set of scripts per source file.

Recommend binutils/linker ABI identifier rules: names are UTF-8,
add add identifier checks. E.g. `readelf -L -Ue`.

In addition adopt this proposal as a Defect Report against C++20 and
earlier. The author provides the
[libu8ident](https://github.com/rurban/libu8ident/) library (Apache 2
licensed) and its generated tables to all implementors.

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

4 What will this proposal change
================================

4.1 The set of TR31 XID ranges will become smaller
----------------------------------------------

Restricting the **Identifier_Type** plus the Allowed Scripts, plus demanding NFC
will shrink the original XID set from 971267 codepoints to 93036 codepoints.
The ranges expand from 36 to 315. (when split by scripts already, 25 splits happen).

`ID_Start` consists of Lu + Ll + Lt + Lm + Lo + Nl, +`Other_ID_Start`,
 -`Pattern_Syntax`, -`Pattern_White_Space`

131997 codepoints

`ID_Continue` consists of `ID_Start`, + Mn + Mc + Nd + Pc, +`Other_ID_Continue`,
-`Pattern_Syntax`, -`Pattern_White_Space`.

135072 codepoints (= ID_Start + 3075)

`XID_Start` and  `XID_Continue` ensure that `isIdentifer(string)` then
`isIdentifier(NFKx(string))` (_removing the NFKC quirks_)

`XID_Start`: 131974 codepoints,
`XID_Continue`: 135053 codepoints (= `XID_Start` + 3098)

4.2 Only Recommended scripts are now allowed, Excluded and Limited_Use not
--------------------------------------------------------------------------

These scripts will stay allowed:

    Common Inherited Latin Arabic Armenian Bengali Bopomofo Cyrillic
    Devanagari Ethiopic Georgian Greek Gujarati Gurmukhi Hangul Han Hebrew
    Hiragana Katakana Kannada Khmer Lao Malayalam Myanmar Oriya
    Sinhala Tamil Telugu Thaana Thai Tibetan

These Excluded Scripts are initially disallowed
[TR31#Table_4](https://www.unicode.org/reports/tr31/#Table_Candidate_Characters_for_Exclusion_from_Identifiers)
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

These Limited Use Scripts are now disallowed [TR31#Table_7](http://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts)

    Adlam Balinese Bamum Batak Canadian_Aboriginal Chakma Cham Cherokee
    Hanifi_Rohingya Javanese Kayah_Li Lepcha Limbu Lisu Mandaic
    Meetei_Mayek Miao New_Tai_Lue Newa Nko Nyiakeng_Puachue_Hmong Ol_Chiki
    Osage Saurashtra Sundanese Syloti_Nagri Syriac Tai_Le Tai_Tham
    Tai_Viet Tifinagh Vai Wancho Yi Unknown

The script property and its name are defined in
[TR24](https://www.unicode.org/reports/tr24/).  We use the long
Unicode Script property value, not the abbrevated 4-letter short name,
which maps somehow to the 4-letter [ISO 15924
Codes](https://www.unicode.org/reports/tr24/#Relation_To_ISO15924).

4.3 Documents with identifiers in many multiple scripts/languages will become illegal
---------------------------------------------------------------------------------

C++23 (and C23) will follow the TR39 Security Profile 4 **Moderately
Restrictive**, with an exception for Greek. We call this profile **C23_4** or
**SAFEC23**.

* All identifiers in a document qualify as Single Script, or
* All identifiers in a document are covered by any of the following sets of
  scripts, according to the definition in Mixed Scripts:
  + Latin + Han + Hiragana + Katakana (Japanese)
  + Latin + Han + Bopomofo (Chinese)
  + Latin + Han + Hangul (Korean), or
* All identifiers in a document are covered by Latin and any one other
  Recommended script, except Cyrillic.

5 What will this proposal not change
====================================

5.1 The validity of “extended”" characters in identifiers
---------------------------------------------------------

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
from compiler and related tool test suites, but it's trivial to come
up with such spoofing attacks. There is no report yet from misuse in C
ABI's from linkers and binutils.

Restricting the profile of characters is much easier if no one is
depending on them.

The recent <https://trojansource.codes> effort caused gcc to emit a
new bidi warning, and github to implement similar warnings. Note that
secure identifiers don't help against bidi overrides in strings or
comments, these issues are orthogonal.

There used to be no linter, but there is now one: **u8idlint** from
<https://github.com/rurban/libu8ident>, which can be used to check for
ALLOWED,SAFEC23,ID,XID,C11 or ALLUTF8 TR31 profiles, for various TR39
mixed script profile violations, confusables, invalid combining marks
and TR15 normalization problems.

So far only Rust, cperl and Java follow a unicode security guideline
for identifiers, zig and J refused to support non-ASCII
identifiers. Everbody else is vulnerable to potential security attacks
and does allow non-identifiable identifiers. They should rename
identifiers to "symbols".

7 TR24 Scripts, the SC and SCX properties
=========================================

7.1 SC
-----

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
term "script name", as this is ambigious and
[misused](https://www.unicode.org/reports/tr24/#Script_Names).  The
Script Property Value is the titlecased name of the script from the
UCD, with spaces replaced by underscores. They are defined in the
yearly updated
[Scripts.txt](https://www.unicode.org/Public/UNIDATA/Scripts.txt)

7.2 SCX Extensions
------------------

Not all characters are uniquely used in a single script only.  Many
are used in a variable numbers of scripts. These are assigned to the
Common or Inherited script, and are exactly specified in the
[ScriptExtensions.txt](https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt),
aka SCX. The SCX property is a list of possible scripts per character.
This list is using the short 4-letter script property, which needs to
be resolved via the
[PropertyValueAliases.txt](https://www.unicode.org/Public/UNIDATA/PropertyValueAliases.txt)
to its long script property value. (E.g. Syrc to Syriac)

    # Script_Extensions=Arab Syrc

    064B..0655 ; Arab Syrc # Mn  [11] ARABIC FATHATAN..ARABIC HAMZA BELOW

    # Script_Extensions=Adlm Arab Mand Mani Ougr Phlp Rohg Sogd Syrc

    0640       ; Adlm Arab Mand Mani Ougr Phlp Rohg Sogd Syrc # Lm  ARABIC TATWEEL

Some of the SCX scripts contain only a single script. These are directly added
to the list of SC scripts for the purpose of identifier security checks.

E.g.

    3006       ; Hani # Lo       IDEOGRAPHIC CLOSING MARK

U+3006 with the Common script property is assigned to the Hani -> Han script.

Multiple SCX list entries can resolved when the previous scripts in
the identifier context are already resolved to one or the other
possibility. Thus for SCX=(Arab Syrc) we need to check if Arabic or
Syriac was already seen. If not, the new character with that SCX is
illegal, violating our Mixed Script profile.

7.3 Combining marks script run detection for spoofing
-----------------------------------------------------

Check for unlikely sequences of **combining marks**:

* Forbid sequences of the same nonspacing mark.
* Forbid sequences of more than 4 nonspacing marks (gc=Mn or gc=Me).
* Optionally forbid sequences of base character + nonspacing mark that
  look the same as or confusingly similar to the base character alone
  (because the nonspacing mark overlays a portion of the base
  character). An example is U+0069 LOWERCASE LETTER I + U+0307
  COMBINING DOT ABOVE.

Since we disallow already most combining marks (at least the Latin
ones) with the requirement of NFC
[P1949R7](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html),
this set of cases is quite small.

Special-cases:

Using the Script property alone will not detect that the U+30FC ( ー )
KATAKANA-HIRAGANA PROLONGED SOUND MARK (Script=Common, SCX=Hira Kana,
gc=Lm) should not be mixed with Latin. See
[TR39#5.4](https://www.unicode.org/reports/tr39/#Optional_Detection)
and [TR46](https://www.unicode.org/reports/tr46/).
We only have to check only 4 such explicitly japanese-only PROLONGED
SOUND MARKs, all other Lm modifiers may mix with all SCX.

The list of allowed combining mark characters (with Common or Inherited
scripts) in the C23++ TR31 profile is: Lm `Modifier_Letter`,
Mc `Spacing_Mark`, Mn `Nonspacing_Mark`, Me `Enclosing_Mark`. Sk and Cf are
not part of XIDs.

67 matches for "XID_Continue # Lm" in buffer: DerivedCoreProperties.txt

``` txt
02B0..02C1    ; XID_Continue # Lm  [18] MODIFIER LETTER SMALL H..
                                        MODIFIER LETTER REVERSED GLOTTAL STOP
02C6..02D1    ; XID_Continue # Lm  [12] MODIFIER LETTER CIRCUMFLEX ACCENT..
                                        MODIFIER LETTER HALF TRIANGULAR
...

```

513 matches for "XID_Continue # M" in buffer: DerivedCoreProperties.txt

``` txt
0300..036F    ; XID_Continue # Mn [112] COMBINING GRAVE ACCENT..
                                        COMBINING LATIN SMALL LETTER X
0483..0487    ; XID_Continue # Mn   [5] COMBINING CYRILLIC TITLO..
                                        COMBINING CYRILLIC POKRYTIE
...
```

From these 67 Lm plus 513 M\[cn\] ranges filtering out the non-C23 XID candidates,
only #8 Identifier_Type = Recommended, Inclusion, Technical, plus only #4.2
Recommended Scripts, plus only codepoints with multiple SCX entries,
leads to these ranges. (TODO #8, Scripts, NFC)

``` txt
A9CF          ; Bugi Java # Lm       JAVANESE PANGRANGKEP
                                     (Javanese Limited, Buginese Excl)
3031..3035    ; Hira Kana # Lm   [5] VERTICAL KANA REPEAT MARK..
                                     VERTICAL KANA REPEAT MARK LOWER HALF
30FC          ; Hira Kana # Lm       KATAKANA-HIRAGANA PROLONGED SOUND MARK
FF70          ; Hira Kana # Lm       HALFWIDTH KATAKANA-HIRAGANA PROLONGED
                                     SOUND MARK
FF9E..FF9F    ; Hira Kana # Lm   [2] HALFWIDTH KATAKANA VOICED SOUND MARK..
                                     SEMI-VOICED SOUND MARK
0640          ; Adlm Arab Mand Mani Ougr Phlp Rohg Sogd Syrc # Lm ARABIC TATWEEL
102E0         ; Arab Copt # Mn       COPTIC EPACT THOUSANDS MARK
064B..0655    ; Arab Syrc # Mn  [11] ARABIC FATHATAN..ARABIC HAMZA BELOW
0670          ; Arab Syrc # Mn       ARABIC LETTER SUPERSCRIPT ALEF
1CD5..1CD6    ; Beng Deva # Mn   [2] VEDIC TONE YAJURVEDIC AGGRAVATED INDEPENDENT
                                     SVARITA..INDEPENDENT SVARITA
1CD8          ; Beng Deva # Mn       VEDIC TONE CANDRA BELOW
1CE1          ; Beng Deva # Mc       VEDIC TONE ATHARVAVEDIC INDEPENDENT SVARITA
1CED          ; Beng Deva # Mn       VEDIC SIGN TIRYAK
A8F1          ; Beng Deva # Mn       COMBINING DEVANAGARI SIGN AVAGRAHA
302A..302D    ; Bopo Hani # Mn   [4] IDEOGRAPHIC LEVEL TONE MARK..ENTERING TONE MARK
0484          ; Cyrl Glag # Mn       COMBINING CYRILLIC PALATALIZATION
0487          ; Cyrl Glag # Mn       COMBINING CYRILLIC POKRYTIE
A66F          ; Cyrl Glag # Mn       COMBINING CYRILLIC VZMET
0485..0486    ; Cyrl Latn # Mn   [2] COMBINING CYRILLIC DASIA PNEUMATA..PSILI PNEUMATA
0483          ; Cyrl Perm # Mn       COMBINING CYRILLIC TITLO
1DF8          ; Cyrl Syrc # Mn       COMBINING DOT ABOVE LEFT
1CF8..1CF9    ; Deva Gran # Mn   [2] VEDIC TONE RING ABOVE..DOUBLE RING ABOVE
1CD7          ; Deva Shrd # Mn       VEDIC TONE YAJURVEDIC KATHAKA INDEPENDENT SVARITA
1CD9          ; Deva Shrd # Mn       -"- SCHROEDER
1CDC..1CDD    ; Deva Shrd # Mn   [2] VEDIC TONE KATHAKA ANUDATTA..DOT BELOW
1CE0          ; Deva Shrd # Mn       VEDIC TONE RIGVEDIC KASHMIRI INDEPENDENT SVARITA
11301         ; Gran Taml # Mn       GRANTHA SIGN CANDRABINDU
11303         ; Gran Taml # Mc       GRANTHA SIGN VISARGA
1133B..1133C  ; Gran Taml # Mn   [2] COMBINING BINDU BELOW..GRANTHA SIGN NUKTA
3099..309A    ; Hira Kana # Mn   [2] COMBINING KATAKANA-HIRAGANA VOICED SOUND MARK..
                                     SEMI-VOICED SOUND MARK
1CF4          ; Deva Gran Knda # Mn       VEDIC TONE CANDRA ABOVE
20F0          ; Deva Gran Latn # Mn       COMBINING ASTERISK ABOVE
1CD0          ; Beng Deva Gran Knda # Mn       VEDIC TONE KARSHANA
1CD2          ; Beng Deva Gran Knda # Mn       VEDIC TONE PRENKHA
1CDA          ; Deva Knda Mlym Orya Taml Telu # Mn       VEDIC TONE DOUBLE SVARITA
0952          ; Beng Deva Gran Gujr Guru Knda Latn Mlym Orya Taml Telu Tirh
              # Mn DEVANAGARI STRESS SIGN ANUDATTA
0951          ; Beng Deva Gran Gujr Guru Knda Latn Mlym Orya Shrd Taml Telu Tirh
              # Mn DEVANAGARI STRESS SIGN UDATTA
```

Thus some of the Common `XID_Continue` marks therefore cannot be
detected with the SCX logic. But all of them do not combine with Latin
and are most likely already filtered by by the Mixed Script profile.
And all of the Combining Marks are caught by the NFC requirement.

On the other hand Modifier Letters are freestanding base characters,
which can be combined with any other letter. We only have the SCX
logic.

See [TR31#2.1 Combining\_Marks](https://www.unicode.org/reports/tr31/#Combining_Marks)
and [TR31#2.2 Modifier\_Letters](https://www.unicode.org/reports/tr31/#Modifier_Letters)

See also [TR24#5.1 Handling Characters with the Common Script
Property](https://www.unicode.org/reports/tr24/#Common) and [TR24#5.2
Handling Combining Marks](https://www.unicode.org/reports/tr24/#Nonspacing_Marks).

8 TR39 Identifier Type
======================

The **Identifier_Type** property TR39#Table 1
<https://www.unicode.org/reports/tr39/#Identifier_Status_and_Type Table_1>
recommendation should be mandatory, with the addition of the `Technical`
Identifier\_Type to be allowed.

I.e. `Limited_Use, Obsolete, Exclusion, Not_XID, Not_NFKC, Default_Ignorable,`
`Deprecated, Not_Character` are not part of identifiers.

Allowed are `Recommended, Inclusion, Technical` TR39 Identifier Types.

There are 80 Technical ranges added to the original list of
Recommended and Inclusion ID's.

    grep ', U8ID_Technical' scripts.h | egrep -v 'Not_XID|U8ID_Obsolete|U8ID_Exclusion'

See 17 Appendix E - IDType Technical.

9 TR39 Mixed Scripts
====================

TR39 defines some security profiles for identifers to avoid the most
common identifier insecurities, that identifiers will stay
identifiable.

We choose a variant of the **Moderately Restrictive** profile, with an
exception for Greek.  I called this profile **C23_4** or **SAFEC23**
in libu8ident.

* All identifiers in a document qualify as Single Script, or
* All identifiers in a document are covered by any of the following
  sets of scripts, according to the definition in Mixed Scripts:
  + Latin + Han + Hiragana + Katakana (Japanese)
  + Latin + Han + Bopomofo (Chinese)
  + Latin + Han + Hangul (Korean), or
* All identifiers in a document are covered by Latin and any one other
  Recommended script, except Cyrillic.

Thus it prevents Cyrillic mixed with Latin or any other script, but
does allow any East-Asian CFK language, other common and widely used
languages and Latin mixed with Greek, mainly used for its mathematical
symbols. Many mathematical symbols already exists outside of Greek,
but these are mainly used for operators in advanced programming languages,
not as identifiers.  See also <http://xahlee.info/comp/unicode_math_operators.html>
for a nice overview.

E.g. here we have some:

* U+2217 (∗) ASTERISK OPERATOR (Script=Common). Not_XID
* U+2107 (ℇ) EULER CONSTANT (Script=Common, Lu) is a proper letter,
             but with Restricted IdentifierStatus.
* U+2126 (Ω) OHM SIGN (Script=Greek, L&) is a greek letter,
             but with Restricted IdentifierStatus.
* U+2127 (℧) INVERTED OHM SIGN (Script=Common, So). Obsolete, Not_XID

TR39 also compiles a convenient
[IdentifierStatus](https://www.unicode.org/Public/security/latest/IdentifierStatus.txt)
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

This is not discussed in any of the unicode security guidelines for
identifiers.  One could argue that a mixed-script profile is valid
only for a single identifier, or it is valid for whole source file
document.

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
C++/C. I haven't detected any exported unicode names in the wild, they
are only used in local symbols still. UTF-16 compilers such as MSVC do
export their UNICODE names either in the local character set or as
UTF-8. If used wildly, object files would not link anymore, as local
character sets vary, and there is no character set standard defined.

The C++/C working groups should urge the binutils/linker working
groups to adopt a more precise specification how exported identifiers
are represented in object files and libraries: UTF-8 or any charset,
and how they are looked up: any normalization, NFC or not at all.  My
recommendation would be to interpret them as UTF-8, require NFC, and
reject all illegal UTF-8 and non-NFC identifiers. As long as there no
unicode names in the wild this is still easy. There are also many
object file producers in the wild, with possibly completely insecure
unicode names in the future.

binutils `readelf -L -Ul` is currently broken displaying unicode identifiers.
I have patches to display them in the current multi-byte locale, and to add
ui8id checks with -L. I haven't found violations so far in my used libraries.

Even better would be for the C ABI's to also adopt secure unicode
identifiers, as linkers and FFI's have the same unicode security
problems as compilers, interpreters and filesystems.  Otherwise they
should at least clarifiy that their names/"symbols" are not
identifiable, and implementation defined and their interpretation locale
specific. (i.e. you cannot copy them across locales).

13 Appendix A - C23XID_Start
============================

Created with mkc23 from libu8ident

``` c
// Filtering allowed scripts, XID_Start, safe IDTypes and NFC
const struct sc safec23_start_list[432] = {
    {'$', '$', SC_Latin},
    {'A', 'Z', SC_Latin},
    {'_', '_', SC_Latin},
    {'a', 'z', SC_Latin},
    {0x7A, 0x7A, 2}, // Latin z
    {0xAA, 0xAA, 2}, // Latin ª
    {0xB5, 0xB5, 0}, // Common µ
    {0xBA, 0xBA, 2}, // Latin º
    {0xC0, 0xD6, 2}, // Latin À..Ö
    {0xD8, 0xF6, 2}, // Latin Ø..ö
    {0xF8, 0x2B8, 2}, // Latin ø..ʸ
    {0x2BA, 0x2C1, 0}, // Common ʺ..ˁ
    {0x2C6, 0x2D1, 0}, // Common ˆ..ˑ
    {0x2E0, 0x2E4, 2}, // Latin ˠ..ˤ
    {0x2EC, 0x2EC, 0}, // Common ˬ
    {0x2EE, 0x2EE, 0}, // Common ˮ
    {0x370, 0x373, 11}, // Greek Ͱ..ͳ
    {0x376, 0x377, 11}, // Greek Ͷ..ͷ
    {0x37B, 0x37D, 11}, // Greek ͻ..ͽ
    {0x37F, 0x37F, 11}, // Greek Ϳ
    {0x386, 0x386, 11}, // Greek Ά
    {0x388, 0x38A, 11}, // Greek Έ..Ί
    {0x38C, 0x38C, 11}, // Greek Ό
    {0x38E, 0x3A1, 11}, // Greek Ύ..Ρ
    {0x3A3, 0x3E1, 11}, // Greek Σ..ϡ
    {0x3F0, 0x3F5, 11}, // Greek ϰ..ϵ
    {0x3F7, 0x3FF, 11}, // Greek Ϸ..Ͽ
    {0x401, 0x481, 7}, // Cyrillic Ё..ҁ
    {0x48A, 0x52F, 7}, // Cyrillic Ҋ..ԯ
    {0x531, 0x556, 4}, // Armenian Ա..Ֆ
    {0x559, 0x559, 4}, // Armenian ՙ
    {0x560, 0x588, 4}, // Armenian ՠ..ֈ
    {0x5D0, 0x5EA, 16}, // Hebrew א..ת
    {0x5EF, 0x5F2, 16}, // Hebrew ׯ..ײ
    {0x620, 0x63F, 3}, // Arabic ؠ..ؿ
    {0x641, 0x64A, 3}, // Arabic ف..ي
    {0x66E, 0x66F, 3}, // Arabic ٮ..ٯ
    {0x671, 0x6D3, 3}, // Arabic ٱ..ۓ
    {0x6D5, 0x6D5, 3}, // Arabic ە
    {0x6E5, 0x6E6, 3}, // Arabic ۥ..ۦ
    {0x6EE, 0x6EF, 3}, // Arabic ۮ..ۯ
    {0x6FA, 0x6FC, 3}, // Arabic ۺ..ۼ
    {0x6FF, 0x6FF, 3}, // Arabic ۿ
    {0x750, 0x77F, 3}, // Arabic ݐ..ݿ
    {0x781, 0x7A5, 28}, // Thaana ށ..ޥ
    {0x7B1, 0x7B1, 28}, // Thaana ޱ
    {0x870, 0x887, 3}, // Arabic ࡰ..ࢇ
    {0x889, 0x88E, 3}, // Arabic ࢉ..ࢎ
    {0x8A0, 0x8C9, 3}, // Arabic ࢠ..ࣉ
    {0x904, 0x939, 8}, // Devanagari ऄ..ह
    {0x93D, 0x93D, 8}, // Devanagari ऽ
    {0x950, 0x950, 8}, // Devanagari ॐ
    {0x960, 0x961, 8}, // Devanagari ॠ..ॡ
    {0x971, 0x97F, 8}, // Devanagari ॱ..ॿ
    {0x985, 0x98C, 5}, // Bengali অ..ঌ
    {0x98F, 0x990, 5}, // Bengali এ..ঐ
    {0x993, 0x9A8, 5}, // Bengali ও..ন
    {0x9AA, 0x9B0, 5}, // Bengali প..র
    {0x9B2, 0x9B2, 5}, // Bengali ল
    {0x9B6, 0x9B9, 5}, // Bengali শ..হ
    {0x9BD, 0x9BD, 5}, // Bengali ঽ
    {0x9CE, 0x9CE, 5}, // Bengali ৎ
    {0x9E0, 0x9E1, 5}, // Bengali ৠ..ৡ
    {0x9F0, 0x9F1, 5}, // Bengali ৰ..ৱ
    {0x9FC, 0x9FC, 5}, // Bengali ৼ
    {0xA05, 0xA0A, 13}, // Gurmukhi ਅ..ਊ
    {0xA0F, 0xA10, 13}, // Gurmukhi ਏ..ਐ
    {0xA13, 0xA28, 13}, // Gurmukhi ਓ..ਨ
    {0xA2A, 0xA30, 13}, // Gurmukhi ਪ..ਰ
    {0xA32, 0xA32, 13}, // Gurmukhi ਲ
    {0xA35, 0xA35, 13}, // Gurmukhi ਵ
    {0xA38, 0xA39, 13}, // Gurmukhi ਸ..ਹ
    {0xA5C, 0xA5C, 13}, // Gurmukhi ੜ
    {0xA72, 0xA74, 13}, // Gurmukhi ੲ..ੴ
    {0xA85, 0xA8D, 12}, // Gujarati અ..ઍ
    {0xA8F, 0xA91, 12}, // Gujarati એ..ઑ
    {0xA93, 0xAA8, 12}, // Gujarati ઓ..ન
    {0xAAA, 0xAB0, 12}, // Gujarati પ..ર
    {0xAB2, 0xAB3, 12}, // Gujarati લ..ળ
    {0xAB5, 0xAB9, 12}, // Gujarati વ..હ
    {0xABD, 0xABD, 12}, // Gujarati ઽ
    {0xAD0, 0xAD0, 12}, // Gujarati ૐ
    {0xAE0, 0xAE1, 12}, // Gujarati ૠ..ૡ
    {0xAF9, 0xAF9, 12}, // Gujarati ૹ
    {0xB05, 0xB0C, 24}, // Oriya ଅ..ଌ
    {0xB0F, 0xB10, 24}, // Oriya ଏ..ଐ
    {0xB13, 0xB28, 24}, // Oriya ଓ..ନ
    {0xB2A, 0xB30, 24}, // Oriya ପ..ର
    {0xB32, 0xB33, 24}, // Oriya ଲ..ଳ
    {0xB35, 0xB39, 24}, // Oriya ଵ..ହ
    {0xB3D, 0xB3D, 24}, // Oriya ଽ
    {0xB5F, 0xB61, 24}, // Oriya ୟ..ୡ
    {0xB71, 0xB71, 24}, // Oriya ୱ
    {0xB83, 0xB83, 26}, // Tamil ஃ
    {0xB85, 0xB8A, 26}, // Tamil அ..ஊ
    {0xB8E, 0xB90, 26}, // Tamil எ..ஐ
    {0xB92, 0xB95, 26}, // Tamil ஒ..க
    {0xB99, 0xB9A, 26}, // Tamil ங..ச
    {0xB9C, 0xB9C, 26}, // Tamil ஜ
    {0xB9E, 0xB9F, 26}, // Tamil ஞ..ட
    {0xBA3, 0xBA4, 26}, // Tamil ண..த
    {0xBA8, 0xBAA, 26}, // Tamil ந..ப
    {0xBAE, 0xBB9, 26}, // Tamil ம..ஹ
    {0xBD0, 0xBD0, 26}, // Tamil ௐ
    {0xC05, 0xC0C, 27}, // Telugu అ..ఌ
    {0xC0E, 0xC10, 27}, // Telugu ఎ..ఐ
    {0xC12, 0xC28, 27}, // Telugu ఒ..న
    {0xC2A, 0xC39, 27}, // Telugu ప..హ
    {0xC3D, 0xC3D, 27}, // Telugu ఽ
    {0xC58, 0xC5A, 27}, // Telugu ౘ..ౚ
    {0xC5D, 0xC5D, 27}, // Telugu ౝ
    {0xC60, 0xC61, 27}, // Telugu ౠ..ౡ
    {0xC80, 0xC80, 19}, // Kannada ಀ
    {0xC85, 0xC8C, 19}, // Kannada ಅ..ಌ
    {0xC8E, 0xC90, 19}, // Kannada ಎ..ಐ
    {0xC92, 0xCA8, 19}, // Kannada ಒ..ನ
    {0xCAA, 0xCB3, 19}, // Kannada ಪ..ಳ
    {0xCB5, 0xCB9, 19}, // Kannada ವ..ಹ
    {0xCBD, 0xCBD, 19}, // Kannada ಽ
    {0xCDD, 0xCDE, 19}, // Kannada ೝ..ೞ
    {0xCE0, 0xCE1, 19}, // Kannada ೠ..ೡ
    {0xCF1, 0xCF2, 19}, // Kannada ೱ..ೲ
    {0xD04, 0xD0C, 22}, // Malayalam ഄ..ഌ
    {0xD0E, 0xD10, 22}, // Malayalam എ..ഐ
    {0xD12, 0xD3A, 22}, // Malayalam ഒ..ഺ
    {0xD3D, 0xD3D, 22}, // Malayalam ഽ
    {0xD4E, 0xD4E, 22}, // Malayalam ൎ
    {0xD54, 0xD56, 22}, // Malayalam ൔ..ൖ
    {0xD5F, 0xD61, 22}, // Malayalam ൟ..ൡ
    {0xD7A, 0xD7F, 22}, // Malayalam ൺ..ൿ
    {0xD85, 0xD96, 25}, // Sinhala අ..ඖ
    {0xD9A, 0xDB1, 25}, // Sinhala ක..න
    {0xDB3, 0xDBB, 25}, // Sinhala ඳ..ර
    {0xDBD, 0xDBD, 25}, // Sinhala ල
    {0xDC0, 0xDC6, 25}, // Sinhala ව..ෆ
    {0xE01, 0xE30, 29}, // Thai ก..ะ
    {0xE32, 0xE32, 29}, // Thai า
    {0xE40, 0xE46, 29}, // Thai เ..ๆ
    {0xE81, 0xE82, 21}, // Lao ກ..ຂ
    {0xE84, 0xE84, 21}, // Lao ຄ
    {0xE86, 0xE8A, 21}, // Lao ຆ..ຊ
    {0xE8C, 0xEA3, 21}, // Lao ຌ..ຣ
    {0xEA5, 0xEA5, 21}, // Lao ລ
    {0xEA7, 0xEB0, 21}, // Lao ວ..ະ
    {0xEB2, 0xEB2, 21}, // Lao າ
    {0xEBD, 0xEBD, 21}, // Lao ຽ
    {0xEC0, 0xEC4, 21}, // Lao ເ..ໄ
    {0xEC6, 0xEC6, 21}, // Lao ໆ
    {0xEDC, 0xEDF, 21}, // Lao ໜ..ໟ
    {0xF00, 0xF00, 30}, // Tibetan ༀ
    {0xF40, 0xF42, 30}, // Tibetan ཀ..ག
    {0xF44, 0xF47, 30}, // Tibetan ང..ཇ
    {0xF49, 0xF4C, 30}, // Tibetan ཉ..ཌ
    {0xF4E, 0xF51, 30}, // Tibetan ཎ..ད
    {0xF53, 0xF56, 30}, // Tibetan ན..བ
    {0xF58, 0xF5B, 30}, // Tibetan མ..ཛ
    {0xF5D, 0xF68, 30}, // Tibetan ཝ..ཨ
    {0xF6A, 0xF6C, 30}, // Tibetan ཪ..ཬ
    {0xF88, 0xF8C, 30}, // Tibetan ྈ..ྌ
    {0x1000, 0x102A, 23}, // Myanmar က..ဪ
    {0x103F, 0x103F, 23}, // Myanmar ဿ
    {0x1050, 0x1055, 23}, // Myanmar ၐ..ၕ
    {0x105A, 0x105D, 23}, // Myanmar ၚ..ၝ
    {0x1061, 0x1061, 23}, // Myanmar ၡ
    {0x1065, 0x1066, 23}, // Myanmar ၥ..ၦ
    {0x106E, 0x1070, 23}, // Myanmar ၮ..ၰ
    {0x1075, 0x1081, 23}, // Myanmar ၵ..ႁ
    {0x108E, 0x108E, 23}, // Myanmar ႎ
    {0x10A0, 0x10C5, 10}, // Georgian Ⴀ..Ⴥ
    {0x10C7, 0x10C7, 10}, // Georgian Ⴧ
    {0x10CD, 0x10CD, 10}, // Georgian Ⴭ
    {0x10D0, 0x10FA, 10}, // Georgian ა..ჺ
    {0x10FC, 0x10FF, 10}, // Georgian ჼ..ჿ
    {0x1101, 0x11FF, 14}, // Hangul ᄁ..ᇿ
    {0x1201, 0x1248, 9}, // Ethiopic ሁ..ቈ
    {0x124A, 0x124D, 9}, // Ethiopic ቊ..ቍ
    {0x1250, 0x1256, 9}, // Ethiopic ቐ..ቖ
    {0x1258, 0x1258, 9}, // Ethiopic ቘ
    {0x125A, 0x125D, 9}, // Ethiopic ቚ..ቝ
    {0x1260, 0x1288, 9}, // Ethiopic በ..ኈ
    {0x128A, 0x128D, 9}, // Ethiopic ኊ..ኍ
    {0x1290, 0x12B0, 9}, // Ethiopic ነ..ኰ
    {0x12B2, 0x12B5, 9}, // Ethiopic ኲ..ኵ
    {0x12B8, 0x12BE, 9}, // Ethiopic ኸ..ኾ
    {0x12C0, 0x12C0, 9}, // Ethiopic ዀ
    {0x12C2, 0x12C5, 9}, // Ethiopic ዂ..ዅ
    {0x12C8, 0x12D6, 9}, // Ethiopic ወ..ዖ
    {0x12D8, 0x1310, 9}, // Ethiopic ዘ..ጐ
    {0x1312, 0x1315, 9}, // Ethiopic ጒ..ጕ
    {0x1318, 0x135A, 9}, // Ethiopic ጘ..ፚ
    {0x1380, 0x138F, 9}, // Ethiopic ᎀ..ᎏ
    {0x1780, 0x17B3, 20}, // Khmer ក..ឳ
    {0x17D7, 0x17D7, 20}, // Khmer ៗ
    {0x17DC, 0x17DC, 20}, // Khmer ៜ
    {0x1C80, 0x1C88, 7}, // Cyrillic ᲀ..ᲈ
    {0x1C90, 0x1CBA, 10}, // Georgian Ა..Ჺ
    {0x1CBD, 0x1CBF, 10}, // Georgian Ჽ..Ჿ
    {0x1CEB, 0x1CEC, 8}, // Devanagari ᳫ..ᳬ
    {0x1CEE, 0x1CF1, 8}, // Devanagari ᳮ..ᳱ
    {0x1CF5, 0x1CF6, 0}, // Common ᳵ..ᳶ
    {0x1D00, 0x1D25, 2}, // Latin ᴀ..ᴥ
    {0x1D27, 0x1D2A, 11}, // Greek ᴧ..ᴪ
    {0x1D2C, 0x1D5C, 2}, // Latin ᴬ..ᵜ
    {0x1D5E, 0x1D61, 11}, // Greek ᵞ..ᵡ
    {0x1D63, 0x1D65, 2}, // Latin ᵣ..ᵥ
    {0x1D67, 0x1D6A, 11}, // Greek ᵧ..ᵪ
    {0x1D6C, 0x1D77, 2}, // Latin ᵬ..ᵷ
    {0x1D79, 0x1DBE, 2}, // Latin ᵹ..ᶾ
    {0x1E00, 0x1EFF, 2}, // Latin Ḁ..ỿ
    {0x1F01, 0x1F15, 11}, // Greek ἁ..ἕ
    {0x1F18, 0x1F1D, 11}, // Greek Ἐ..Ἕ
    {0x1F20, 0x1F45, 11}, // Greek ἠ..ὅ
    {0x1F48, 0x1F4D, 11}, // Greek Ὀ..Ὅ
    {0x1F50, 0x1F57, 11}, // Greek ὐ..ὗ
    {0x1F59, 0x1F59, 11}, // Greek Ὑ
    {0x1F5B, 0x1F5B, 11}, // Greek Ὓ
    {0x1F5D, 0x1F5D, 11}, // Greek Ὕ
    {0x1F5F, 0x1F70, 11}, // Greek Ὗ..ὰ
    {0x1F72, 0x1F72, 11}, // Greek ὲ
    {0x1F74, 0x1F74, 11}, // Greek ὴ
    {0x1F76, 0x1F76, 11}, // Greek ὶ
    {0x1F78, 0x1F78, 11}, // Greek ὸ
    {0x1F7A, 0x1F7A, 11}, // Greek ὺ
    {0x1F7C, 0x1F7C, 11}, // Greek ὼ
    {0x1F80, 0x1FB4, 11}, // Greek ᾀ..ᾴ
    {0x1FB6, 0x1FBA, 11}, // Greek ᾶ..Ὰ
    {0x1FBC, 0x1FBC, 11}, // Greek ᾼ
    {0x1FC2, 0x1FC4, 11}, // Greek ῂ..ῄ
    {0x1FC6, 0x1FC8, 11}, // Greek ῆ..Ὲ
    {0x1FCA, 0x1FCA, 11}, // Greek Ὴ
    {0x1FCC, 0x1FCC, 11}, // Greek ῌ
    {0x1FD0, 0x1FD2, 11}, // Greek ῐ..ῒ
    {0x1FD6, 0x1FDA, 11}, // Greek ῖ..Ὶ
    {0x1FE0, 0x1FE2, 11}, // Greek ῠ..ῢ
    {0x1FE4, 0x1FEA, 11}, // Greek ῤ..Ὺ
    {0x1FEC, 0x1FEC, 11}, // Greek Ῥ
    {0x1FF2, 0x1FF4, 11}, // Greek ῲ..ῴ
    {0x1FF6, 0x1FF8, 11}, // Greek ῶ..Ὸ
    {0x1FFA, 0x1FFA, 11}, // Greek Ὼ
    {0x1FFC, 0x1FFC, 11}, // Greek ῼ
    {0x2071, 0x2071, 2}, // Latin ⁱ
    {0x207F, 0x207F, 2}, // Latin ⁿ
    {0x2090, 0x209C, 2}, // Latin ₐ..ₜ
    {0x2102, 0x2102, 0}, // Common ℂ
    {0x2107, 0x2107, 0}, // Common ℇ
    {0x210A, 0x2113, 0}, // Common ℊ..ℓ
    {0x2115, 0x2115, 0}, // Common ℕ
    {0x2118, 0x211D, 0}, // Common ℘..ℝ
    {0x2124, 0x2124, 0}, // Common ℤ
    {0x2128, 0x2128, 0}, // Common ℨ
    {0x212C, 0x2131, 0}, // Common ℬ..ℱ
    {0x2133, 0x2139, 0}, // Common ℳ..ℹ
    {0x213C, 0x213F, 0}, // Common ℼ..ℿ
    {0x2145, 0x2149, 0}, // Common ⅅ..ⅉ
    {0x214E, 0x214E, 2}, // Latin ⅎ
    {0x2160, 0x2188, 2}, // Latin Ⅰ..ↈ
    {0x2C60, 0x2C7F, 2}, // Latin Ⱡ..Ɀ
    {0x2D00, 0x2D25, 10}, // Georgian ⴀ..ⴥ
    {0x2D27, 0x2D27, 10}, // Georgian ⴧ
    {0x2D2D, 0x2D2D, 10}, // Georgian ⴭ
    {0x2D80, 0x2D96, 9}, // Ethiopic ⶀ..ⶖ
    {0x2DA0, 0x2DA6, 9}, // Ethiopic ⶠ..ⶦ
    {0x2DA8, 0x2DAE, 9}, // Ethiopic ⶨ..ⶮ
    {0x2DB0, 0x2DB6, 9}, // Ethiopic ⶰ..ⶶ
    {0x2DB8, 0x2DBE, 9}, // Ethiopic ⶸ..ⶾ
    {0x2DC0, 0x2DC6, 9}, // Ethiopic ⷀ..ⷆ
    {0x2DC8, 0x2DCE, 9}, // Ethiopic ⷈ..ⷎ
    {0x2DD0, 0x2DD6, 9}, // Ethiopic ⷐ..ⷖ
    {0x2DD8, 0x2DDE, 9}, // Ethiopic ⷘ..ⷞ
    {0x3005, 0x3007, 15}, // Han 々..〇
    {0x3021, 0x3029, 15}, // Han 〡..〩
    {0x3031, 0x3035, 0}, // Common 〱..〵
    {0x3038, 0x303B, 15}, // Han 〸..〻
    {0x3041, 0x3096, 17}, // Hiragana ぁ..ゖ
    {0x309D, 0x309F, 17}, // Hiragana ゝ..ゟ
    {0x30A1, 0x30FA, 18}, // Katakana ァ..ヺ
    {0x30FC, 0x30FC, 0}, // Common ー
    {0x30FE, 0x30FF, 18}, // Katakana ヾ..ヿ
    {0x3105, 0x312F, 6}, // Bopomofo ㄅ..ㄯ
    {0x3131, 0x318E, 14}, // Hangul ㄱ..ㆎ
    {0x31A0, 0x31BF, 6}, // Bopomofo ㆠ..ㆿ
    {0x31F0, 0x31FF, 18}, // Katakana ㇰ..ㇿ
    {0x4E00, 0x9FFF, 15}, // Han 一..鿿
    {0xA640, 0xA66E, 7}, // Cyrillic Ꙁ..ꙮ
    {0xA67F, 0xA69D, 7}, // Cyrillic ꙿ..ꚝ
    {0xA717, 0xA71F, 0}, // Common ꜗ..ꜟ
    {0xA722, 0xA787, 2}, // Latin Ꜣ..ꞇ
    {0xA78B, 0xA7CA, 2}, // Latin Ꞌ..ꟊ
    {0xA7D0, 0xA7D1, 2}, // Latin Ꟑ..ꟑ
    {0xA7D3, 0xA7D3, 2}, // Latin ꟓ
    {0xA7D5, 0xA7D9, 2}, // Latin ꟕ..ꟙ
    {0xA7F2, 0xA7FF, 2}, // Latin ꟲ..ꟿ
    {0xA8F2, 0xA8F7, 8}, // Devanagari ꣲ..ꣷ
    {0xA8FB, 0xA8FB, 8}, // Devanagari ꣻ
    {0xA8FD, 0xA8FE, 8}, // Devanagari ꣽ..ꣾ
    {0xA960, 0xA97C, 14}, // Hangul ꥠ..ꥼ
    {0xA9CF, 0xA9CF, 0}, // Common ꧏ
    {0xA9E0, 0xA9E4, 23}, // Myanmar ꧠ..ꧤ
    {0xA9E6, 0xA9EF, 23}, // Myanmar ꧦ..ꧯ
    {0xA9FA, 0xA9FE, 23}, // Myanmar ꧺ..ꧾ
    {0xAA60, 0xAA76, 23}, // Myanmar ꩠ..ꩶ
    {0xAA7A, 0xAA7A, 23}, // Myanmar ꩺ
    {0xAA7E, 0xAA7F, 23}, // Myanmar ꩾ..ꩿ
    {0xAB01, 0xAB06, 9}, // Ethiopic ꬁ..ꬆ
    {0xAB09, 0xAB0E, 9}, // Ethiopic ꬉ..ꬎ
    {0xAB11, 0xAB16, 9}, // Ethiopic ꬑ..ꬖ
    {0xAB20, 0xAB26, 9}, // Ethiopic ꬠ..ꬦ
    {0xAB28, 0xAB2E, 9}, // Ethiopic ꬨ..ꬮ
    {0xAB30, 0xAB5A, 2}, // Latin ꬰ..ꭚ
    {0xAB5C, 0xAB64, 2}, // Latin ꭜ..ꭤ
    {0xAB66, 0xAB69, 2}, // Latin ꭦ..ꭩ
    {0xD7B0, 0xD7C6, 14}, // Hangul ힰ..ퟆ
    {0xD7CB, 0xD7FB, 14}, // Hangul ퟋ..ퟻ
    {0xFA0E, 0xFA0F, 15}, // Han 﨎..﨏
    {0xFA11, 0xFA11, 15}, // Han 﨑
    {0xFA13, 0xFA14, 15}, // Han 﨓..﨔
    {0xFA1F, 0xFA1F, 15}, // Han 﨟
    {0xFA21, 0xFA21, 15}, // Han 﨡
    {0xFA23, 0xFA24, 15}, // Han 﨣..﨤
    {0xFA27, 0xFA29, 15}, // Han 﨧..﨩
    {0xFB00, 0xFB06, 2}, // Latin ﬀ..ﬆ
    {0xFB13, 0xFB17, 4}, // Armenian ﬓ..ﬗ
    {0xFB20, 0xFB28, 16}, // Hebrew ﬠ..ﬨ
    {0xFB4F, 0xFB4F, 16}, // Hebrew ﭏ
    {0xFB51, 0xFBB1, 3}, // Arabic ﭑ..ﮱ
    {0xFBD3, 0xFC5D, 3}, // Arabic ﯓ..ﱝ
    {0xFC64, 0xFD3D, 3}, // Arabic ﱤ..ﴽ
    {0xFD50, 0xFD8F, 3}, // Arabic ﵐ..ﶏ
    {0xFD92, 0xFDC7, 3}, // Arabic ﶒ..ﷇ
    {0xFDF0, 0xFDF9, 3}, // Arabic ﷰ..ﷹ
    {0xFE71, 0xFE71, 3}, // Arabic ﹱ
    {0xFE73, 0xFE73, 3}, // Arabic ﹳ
    {0xFE77, 0xFE77, 3}, // Arabic ﹷ
    {0xFE79, 0xFE79, 3}, // Arabic ﹹ
    {0xFE7B, 0xFE7B, 3}, // Arabic ﹻ
    {0xFE7D, 0xFE7D, 3}, // Arabic ﹽ
    {0xFE7F, 0xFEFC, 3}, // Arabic ﹿ..ﻼ
    {0xFF21, 0xFF3A, 2}, // Latin Ａ..Ｚ
    {0xFF41, 0xFF5A, 2}, // Latin ａ..ｚ
    {0xFF66, 0xFF6F, 18}, // Katakana ｦ..ｯ
    {0xFF71, 0xFF9D, 18}, // Katakana ｱ..ﾝ
    {0xFFA0, 0xFFBE, 14}, // Hangul ﾠ..ﾾ
    {0xFFC2, 0xFFC7, 14}, // Hangul ￂ..ￇ
    {0xFFCA, 0xFFCF, 14}, // Hangul ￊ..ￏ
    {0xFFD2, 0xFFD7, 14}, // Hangul ￒ..ￗ
    {0xFFDA, 0xFFDC, 14}, // Hangul ￚ..ￜ
    {0x10140, 0x10174, 11}, // Greek 𐅀..𐅴
    {0x10780, 0x10785, 2}, // Latin 𐞀..𐞅
    {0x10787, 0x107B0, 2}, // Latin 𐞇..𐞰
    {0x107B2, 0x107BA, 2}, // Latin 𐞲..𐞺
    {0x16FE3, 0x16FE3, 15}, // Han 𖿣
    {0x1AFF0, 0x1AFF3, 18}, // Katakana 𚿰..𚿳
    {0x1AFF5, 0x1AFFB, 18}, // Katakana 𚿵..𚿻
    {0x1AFFD, 0x1AFFE, 18}, // Katakana 𚿽..𚿾
    {0x1B000, 0x1B000, 18}, // Katakana 𛀀
    {0x1B002, 0x1B11F, 17}, // Hiragana 𛀂..𛄟
    {0x1B121, 0x1B122, 18}, // Katakana 𛄡..𛄢
    {0x1B150, 0x1B152, 17}, // Hiragana 𛅐..𛅒
    {0x1B164, 0x1B167, 18}, // Katakana 𛅤..𛅧
    {0x1D400, 0x1D454, 0}, // Common 𝐀..𝑔
    {0x1D456, 0x1D49C, 0}, // Common 𝑖..𝒜
    {0x1D49E, 0x1D49F, 0}, // Common 𝒞..𝒟
    {0x1D4A2, 0x1D4A2, 0}, // Common 𝒢
    {0x1D4A5, 0x1D4A6, 0}, // Common 𝒥..𝒦
    {0x1D4A9, 0x1D4AC, 0}, // Common 𝒩..𝒬
    {0x1D4AE, 0x1D4B9, 0}, // Common 𝒮..𝒹
    {0x1D4BB, 0x1D4BB, 0}, // Common 𝒻
    {0x1D4BD, 0x1D4C3, 0}, // Common 𝒽..𝓃
    {0x1D4C5, 0x1D505, 0}, // Common 𝓅..𝔅
    {0x1D507, 0x1D50A, 0}, // Common 𝔇..𝔊
    {0x1D50D, 0x1D514, 0}, // Common 𝔍..𝔔
    {0x1D516, 0x1D51C, 0}, // Common 𝔖..𝔜
    {0x1D51E, 0x1D539, 0}, // Common 𝔞..𝔹
    {0x1D53B, 0x1D53E, 0}, // Common 𝔻..𝔾
    {0x1D540, 0x1D544, 0}, // Common 𝕀..𝕄
    {0x1D546, 0x1D546, 0}, // Common 𝕆
    {0x1D54A, 0x1D550, 0}, // Common 𝕊..𝕐
    {0x1D552, 0x1D6A5, 0}, // Common 𝕒..𝚥
    {0x1D6A8, 0x1D6C0, 0}, // Common 𝚨..𝛀
    {0x1D6C2, 0x1D6DA, 0}, // Common 𝛂..𝛚
    {0x1D6DC, 0x1D6FA, 0}, // Common 𝛜..𝛺
    {0x1D6FC, 0x1D714, 0}, // Common 𝛼..𝜔
    {0x1D716, 0x1D734, 0}, // Common 𝜖..𝜴
    {0x1D736, 0x1D74E, 0}, // Common 𝜶..𝝎
    {0x1D750, 0x1D76E, 0}, // Common 𝝐..𝝮
    {0x1D770, 0x1D788, 0}, // Common 𝝰..𝞈
    {0x1D78A, 0x1D7A8, 0}, // Common 𝞊..𝞨
    {0x1D7AA, 0x1D7C2, 0}, // Common 𝞪..𝟂
    {0x1D7C4, 0x1D7CB, 0}, // Common 𝟄..𝟋
    {0x1DF00, 0x1DF1E, 2}, // Latin 𝼀..𝼞
    {0x1E7E0, 0x1E7E6, 9}, // Ethiopic 𞟠..𞟦
    {0x1E7E8, 0x1E7EB, 9}, // Ethiopic 𞟨..𞟫
    {0x1E7ED, 0x1E7EE, 9}, // Ethiopic 𞟭..𞟮
    {0x1E7F0, 0x1E7FE, 9}, // Ethiopic 𞟰..𞟾
    {0x1EE00, 0x1EE03, 3}, // Arabic 𞸀..𞸃
    {0x1EE05, 0x1EE1F, 3}, // Arabic 𞸅..𞸟
    {0x1EE21, 0x1EE22, 3}, // Arabic 𞸡..𞸢
    {0x1EE24, 0x1EE24, 3}, // Arabic 𞸤
    {0x1EE27, 0x1EE27, 3}, // Arabic 𞸧
    {0x1EE29, 0x1EE32, 3}, // Arabic 𞸩..𞸲
    {0x1EE34, 0x1EE37, 3}, // Arabic 𞸴..𞸷
    {0x1EE39, 0x1EE39, 3}, // Arabic 𞸹
    {0x1EE3B, 0x1EE3B, 3}, // Arabic 𞸻
    {0x1EE42, 0x1EE42, 3}, // Arabic 𞹂
    {0x1EE47, 0x1EE47, 3}, // Arabic 𞹇
    {0x1EE49, 0x1EE49, 3}, // Arabic 𞹉
    {0x1EE4B, 0x1EE4B, 3}, // Arabic 𞹋
    {0x1EE4D, 0x1EE4F, 3}, // Arabic 𞹍..𞹏
    {0x1EE51, 0x1EE52, 3}, // Arabic 𞹑..𞹒
    {0x1EE54, 0x1EE54, 3}, // Arabic 𞹔
    {0x1EE57, 0x1EE57, 3}, // Arabic 𞹗
    {0x1EE59, 0x1EE59, 3}, // Arabic 𞹙
    {0x1EE5B, 0x1EE5B, 3}, // Arabic 𞹛
    {0x1EE5D, 0x1EE5D, 3}, // Arabic 𞹝
    {0x1EE5F, 0x1EE5F, 3}, // Arabic 𞹟
    {0x1EE61, 0x1EE62, 3}, // Arabic 𞹡..𞹢
    {0x1EE64, 0x1EE64, 3}, // Arabic 𞹤
    {0x1EE67, 0x1EE6A, 3}, // Arabic 𞹧..𞹪
    {0x1EE6C, 0x1EE72, 3}, // Arabic 𞹬..𞹲
    {0x1EE74, 0x1EE77, 3}, // Arabic 𞹴..𞹷
    {0x1EE79, 0x1EE7C, 3}, // Arabic 𞹹..𞹼
    {0x1EE7E, 0x1EE7E, 3}, // Arabic 𞹾
    {0x1EE80, 0x1EE89, 3}, // Arabic 𞺀..𞺉
    {0x1EE8B, 0x1EE9B, 3}, // Arabic 𞺋..𞺛
    {0x1EEA1, 0x1EEA3, 3}, // Arabic 𞺡..𞺣
    {0x1EEA5, 0x1EEA9, 3}, // Arabic 𞺥..𞺩
    {0x1EEAB, 0x1EEBB, 3}, // Arabic 𞺫..𞺻
    {0x20000, 0x2A6DF, 15}, // Han 𠀀..𪛟
    {0x2A700, 0x2B738, 15}, // Han 𪜀..𫜸
    {0x2B740, 0x2B81D, 15}, // Han 𫝀..𫠝
    {0x2B820, 0x2CEA1, 15}, // Han 𫠠..𬺡
    {0x2CEB0, 0x2EBE0, 15}, // Han 𬺰..𮯠
    {0x30000, 0x3134A, 15}, // Han 𰀀..𱍊
};
// 315 ranges, 117 singles, 99629 codepoints
```

14 Appendix A - C23XID_Continue
===============================

Created with mkc23 from libu8ident

``` c
// Filtering allowed scripts, XID_Continue,!XID_Start, safe IDTypes, NFC and !MARK
const struct sc safec23_cont_list[22] = {
    {0x30, 0x39, 0}, // Common 0..9
    {0x5F, 0x5F, 0}, // Common _
    {0xB7, 0xB7, 0}, // Common ·
    {0x660, 0x669, 3}, // Arabic ٠..٩
    {0x6F0, 0x6F9, 3}, // Arabic ۰..۹
    {0x966, 0x96F, 8}, // Devanagari ०..९
    {0x9E6, 0x9EF, 5}, // Bengali ০..৯
    {0xA66, 0xA6F, 13}, // Gurmukhi ੦..੯
    {0xAE6, 0xAEF, 12}, // Gujarati ૦..૯
    {0xB66, 0xB6F, 24}, // Oriya ୦..୯
    {0xBE6, 0xBEF, 26}, // Tamil ௦..௯
    {0xC66, 0xC6F, 27}, // Telugu ౦..౯
    {0xCE6, 0xCEF, 19}, // Kannada ೦..೯
    {0xD66, 0xD6F, 22}, // Malayalam ൦..൯
    {0xE50, 0xE59, 29}, // Thai ๐..๙
    {0xED0, 0xED9, 21}, // Lao ໐..໙
    {0xF20, 0xF29, 30}, // Tibetan ༠..༩
    {0x1040, 0x1049, 23}, // Myanmar ၀..၉
    {0x1090, 0x1099, 23}, // Myanmar ႐..႙
    {0x17E0, 0x17E9, 20}, // Khmer ០..៩
    {0x203F, 0x2040, 0}, // Common ‿..⁀
    {0xA9F0, 0xA9F9, 23}, // Myanmar ꧰..꧹
};
// 20 ranges, 2 singles, 172 codepoints
```

15 Appendix C - XID_Continue # Lm
=================================

Needed for [TR39#5.4](https://www.unicode.org/reports/tr39/#Optional_Detection)
and [TR31#2.2](https://www.unicode.org/reports/tr31/#Modifier_Letters)

67 matches for "XID_Continue # Lm" in buffer: DerivedCoreProperties.txt

``` txt
02B0..02C1    ; XID_Continue # Lm  [18] MODIFIER LETTER SMALL H..
                                        MODIFIER LETTER REVERSED GLOTTAL STOP
02C6..02D1    ; XID_Continue # Lm  [12] MODIFIER LETTER CIRCUMFLEX ACCENT..
                                        MODIFIER LETTER HALF TRIANGULAR COLON
02E0..02E4    ; XID_Continue # Lm   [5] MODIFIER LETTER SMALL GAMMA..
                                        MODIFIER LETTER SMALL REVERSED GLOTTAL STOP
02EC          ; XID_Continue # Lm       MODIFIER LETTER VOICING
02EE          ; XID_Continue # Lm       MODIFIER LETTER DOUBLE APOSTROPHE
0374          ; XID_Continue # Lm       GREEK NUMERAL SIGN
0559          ; XID_Continue # Lm       ARMENIAN MODIFIER LETTER LEFT HALF RING
0640          ; XID_Continue # Lm       ARABIC TATWEEL
06E5..06E6    ; XID_Continue # Lm   [2] ARABIC SMALL WAW..
                                        ARABIC SMALL YEH
07F4..07F5    ; XID_Continue # Lm   [2] NKO HIGH TONE APOSTROPHE..
                                        NKO LOW TONE APOSTROPHE
07FA          ; XID_Continue # Lm       NKO LAJANYALAN
081A          ; XID_Continue # Lm       SAMARITAN MODIFIER LETTER EPENTHETIC YUT
0824          ; XID_Continue # Lm       SAMARITAN MODIFIER LETTER SHORT A
0828          ; XID_Continue # Lm       SAMARITAN MODIFIER LETTER I
08C9          ; XID_Continue # Lm       ARABIC SMALL FARSI YEH
0971          ; XID_Continue # Lm       DEVANAGARI SIGN HIGH SPACING DOT
0E46          ; XID_Continue # Lm       THAI CHARACTER MAIYAMOK
0EC6          ; XID_Continue # Lm       LAO KO LA
10FC          ; XID_Continue # Lm       MODIFIER LETTER GEORGIAN NAR
17D7          ; XID_Continue # Lm       KHMER SIGN LEK TOO
1843          ; XID_Continue # Lm       MONGOLIAN LETTER TODO LONG VOWEL SIGN
1AA7          ; XID_Continue # Lm       TAI THAM SIGN MAI YAMOK
1C78..1C7D    ; XID_Continue # Lm   [6] OL CHIKI MU TTUDDAG..OL CHIKI AHAD
1D2C..1D6A    ; XID_Continue # Lm  [63] MODIFIER LETTER CAPITAL A..
                                        GREEK SUBSCRIPT SMALL LETTER CHI
1D78          ; XID_Continue # Lm       MODIFIER LETTER CYRILLIC EN
1D9B..1DBF    ; XID_Continue # Lm  [37] MODIFIER LETTER SMALL TURNED ALPHA..
                                        MODIFIER LETTER SMALL THETA
2071          ; XID_Continue # Lm       SUPERSCRIPT LATIN SMALL LETTER I
207F          ; XID_Continue # Lm       SUPERSCRIPT LATIN SMALL LETTER N
2090..209C    ; XID_Continue # Lm  [13] LATIN SUBSCRIPT SMALL LETTER A..
                                        LATIN SUBSCRIPT SMALL LETTER T
2C7C..2C7D    ; XID_Continue # Lm   [2] LATIN SUBSCRIPT SMALL LETTER J..
                                        MODIFIER LETTER CAPITAL V
2D6F          ; XID_Continue # Lm       TIFINAGH MODIFIER LETTER LABIALIZATION MARK
3005          ; XID_Continue # Lm       IDEOGRAPHIC ITERATION MARK
3031..3035    ; XID_Continue # Lm   [5] VERTICAL KANA REPEAT MARK..
                                        VERTICAL KANA REPEAT MARK LOWER HALF
303B          ; XID_Continue # Lm       VERTICAL IDEOGRAPHIC ITERATION MARK
309D..309E    ; XID_Continue # Lm   [2] HIRAGANA ITERATION MARK..
                                        HIRAGANA VOICED ITERATION MARK
30FC..30FE    ; XID_Continue # Lm   [3] KATAKANA-HIRAGANA PROLONGED SOUND MARK..
                                        KATAKANA VOICED ITERATION MARK
A015          ; XID_Continue # Lm       YI SYLLABLE WU
A4F8..A4FD    ; XID_Continue # Lm   [6] LISU LETTER TONE MYA TI..
                                        LISU LETTER TONE MYA JEU
A60C          ; XID_Continue # Lm       VAI SYLLABLE LENGTHENER
A67F          ; XID_Continue # Lm       CYRILLIC PAYEROK
A69C..A69D    ; XID_Continue # Lm   [2] MODIFIER LETTER CYRILLIC HARD SIGN..
                                        MODIFIER LETTER CYRILLIC SOFT SIGN
A717..A71F    ; XID_Continue # Lm   [9] MODIFIER LETTER DOT VERTICAL BAR..
                                        LOW INVERTED EXCLAMATION MARK
A770          ; XID_Continue # Lm       MODIFIER LETTER US
A788          ; XID_Continue # Lm       MODIFIER LETTER LOW CIRCUMFLEX ACCENT
A7F2..A7F4    ; XID_Continue # Lm   [3] MODIFIER LETTER CAPITAL C..
                                        MODIFIER LETTER CAPITAL Q
A7F8..A7F9    ; XID_Continue # Lm   [2] MODIFIER LETTER CAPITAL H WITH STROKE..
                                        MODIFIER LETTER SMALL LIGATURE OE
A9CF          ; XID_Continue # Lm       JAVANESE PANGRANGKEP
A9E6          ; XID_Continue # Lm       MYANMAR MODIFIER LETTER SHAN REDUPLICATION
AA70          ; XID_Continue # Lm       MYANMAR MODIFIER LETTER KHAMTI REDUPLICATION
AADD          ; XID_Continue # Lm       TAI VIET SYMBOL SAM
AAF3..AAF4    ; XID_Continue # Lm   [2] MEETEI MAYEK SYLLABLE REPETITION MARK..
                                        MEETEI MAYEK WORD REPETITION MARK
AB5C..AB5F    ; XID_Continue # Lm   [4] MODIFIER LETTER SMALL HENG..
                                        MODIFIER LETTER SMALL U WITH LEFT HOOK
AB69          ; XID_Continue # Lm       MODIFIER LETTER SMALL TURNED W
FF70          ; XID_Continue # Lm       HALFWIDTH KATA-HIRA PROLONGED SOUND MARK
FF9E..FF9F    ; XID_Continue # Lm   [2] HALFWIDTH KATAKANA VOICED SOUND MARK..
                                        SEMI-VOICED SOUND MARK
10780..10785  ; XID_Continue # Lm   [6] MODIFIER LETTER SMALL CAPITAL AA..
                                        MODIFIER LETTER SMALL B WITH HOOK
10787..107B0  ; XID_Continue # Lm  [42] MODIFIER LETTER SMALL DZ DIGRAPH..
                                        MODIFIER LETTER SMALL V WITH RIGHT HOOK
107B2..107BA  ; XID_Continue # Lm   [9] MODIFIER LETTER SMALL CAPITAL Y..
                                        MODIFIER LETTER SMALL S WITH CURL
16B40..16B43  ; XID_Continue # Lm   [4] PAHAWH HMONG SIGN VOS SEEV..
                                        PAHAWH HMONG SIGN IB YAM
16F93..16F9F  ; XID_Continue # Lm  [13] MIAO LETTER TONE-2..
                                        MIAO LETTER REFORMED TONE-8
16FE0..16FE1  ; XID_Continue # Lm   [2] TANGUT ITERATION MARK..
                                        NUSHU ITERATION MARK
16FE3         ; XID_Continue # Lm       OLD CHINESE ITERATION MARK
1AFF0..1AFF3  ; XID_Continue # Lm   [4] KATAKANA LETTER MINNAN TONE-2..
                                        KATAKANA LETTER MINNAN TONE-5
1AFF5..1AFFB  ; XID_Continue # Lm   [7] KATAKANA LETTER MINNAN TONE-7..
                                        KATAKANA LETTER MINNAN NASALIZED TONE-5
1AFFD..1AFFE  ; XID_Continue # Lm   [2] KATAKANA LETTER MINNAN NASALIZED TONE-7..
                                        KATAKANA LETTER MINNAN NASALIZED TONE-8
1E137..1E13D  ; XID_Continue # Lm   [7] NYIAKENG PUACHUE HMONG SIGN FOR PERSON..
                                        NYIAKENG PUACHUE HMONG SYLLABLE LENGTHENER
1E94B         ; XID_Continue # Lm       ADLAM NASALIZATION MARK
```

16 Appendix D - XID_Continue # M
=================================

Needed for [TR39#5.4](https://www.unicode.org/reports/tr39/#Optional_Detection)

513 matches for "XID_Continue # M" in buffer: DerivedCoreProperties.txt

``` txt
0300..036F    ; XID_Continue # Mn [112] COMBINING GRAVE ACCENT..
                                        COMBINING LATIN SMALL LETTER X
0483..0487    ; XID_Continue # Mn   [5] COMBINING CYRILLIC TITLO..
                                        COMBINING CYRILLIC POKRYTIE
0591..05BD    ; XID_Continue # Mn  [45] HEBREW ACCENT ETNAHTA..
                                        HEBREW POINT METEG
05BF          ; XID_Continue # Mn       HEBREW POINT RAFE
05C1..05C2    ; XID_Continue # Mn   [2] HEBREW POINT SHIN DOT..
                                        HEBREW POINT SIN DOT
05C4..05C5    ; XID_Continue # Mn   [2] HEBREW MARK UPPER DOT..
                                        HEBREW MARK LOWER DOT
05C7          ; XID_Continue # Mn       HEBREW POINT QAMATS QATAN
0610..061A    ; XID_Continue # Mn  [11] ARABIC SIGN SALLALLAHOU ALAYHE WASSALLAM..
                                        ARABIC SMALL KASRA
064B..065F    ; XID_Continue # Mn  [21] ARABIC FATHATAN..
                                        ARABIC WAVY HAMZA BELOW
0670          ; XID_Continue # Mn       ARABIC LETTER SUPERSCRIPT ALEF
06D6..06DC    ; XID_Continue # Mn   [7] ARABIC SMALL HIGH LIGATURE SAD WITH LAM
                                        WITH ALEF MAKSURA..HIGH SEEN
06DF..06E4    ; XID_Continue # Mn   [6] ARABIC SMALL HIGH ROUNDED ZERO..MADDA
06E7..06E8    ; XID_Continue # Mn   [2] ARABIC SMALL HIGH YEH..NOON
06EA..06ED    ; XID_Continue # Mn   [4] ARABIC EMPTY CENTRE LOW STOP..MEEM
0711          ; XID_Continue # Mn       SYRIAC LETTER SUPERSCRIPT ALAPH
0730..074A    ; XID_Continue # Mn  [27] SYRIAC PTHAHA ABOVE..BARREKH
07A6..07B0    ; XID_Continue # Mn  [11] THAANA ABAFILI..THAANA SUKUN
07EB..07F3    ; XID_Continue # Mn   [9] NKO COMBINING SHORT HIGH TONE..
                                        NKO COMBINING DOUBLE DOT ABOVE
07FD          ; XID_Continue # Mn       NKO DANTAYALAN
0816..0819    ; XID_Continue # Mn   [4] SAMARITAN MARK IN..
                                        SAMARITAN MARK DAGESH
081B..0823    ; XID_Continue # Mn   [9] SAMARITAN MARK EPENTHETIC YUT..
                                        SAMARITAN VOWEL SIGN A
0825..0827    ; XID_Continue # Mn   [3] SAMARITAN VOWEL SIGN SHORT A..SIGN U
0829..082D    ; XID_Continue # Mn   [5] SAMARITAN VOWEL SIGN LONG I..
                                        SAMARITAN MARK NEQUDAA
0859..085B    ; XID_Continue # Mn   [3] MANDAIC AFFRICATION MARK..
                                        MANDAIC GEMINATION MARK
0898..089F    ; XID_Continue # Mn   [8] ARABIC SMALL HIGH WORD AL-JUZ..
                                        ARABIC HALF MADDA OVER MADDA
08CA..08E1    ; XID_Continue # Mn  [24] ARABIC SMALL HIGH FARSI YEH..
                                        ARABIC SMALL HIGH SIGN SAFHA
08E3..0902    ; XID_Continue # Mn  [32] ARABIC TURNED DAMMA BELOW..
                                        DEVANAGARI SIGN ANUSVARA
0903          ; XID_Continue # Mc       DEVANAGARI SIGN VISARGA
093A          ; XID_Continue # Mn       DEVANAGARI VOWEL SIGN OE
093B          ; XID_Continue # Mc       DEVANAGARI VOWEL SIGN OOE
093C          ; XID_Continue # Mn       DEVANAGARI SIGN NUKTA
093E..0940    ; XID_Continue # Mc   [3] DEVANAGARI VOWEL SIGN AA..II
0941..0948    ; XID_Continue # Mn   [8] DEVANAGARI VOWEL SIGN U..AI
0949..094C    ; XID_Continue # Mc   [4] DEVANAGARI VOWEL SIGN CANDRA O..AU
094D          ; XID_Continue # Mn       DEVANAGARI SIGN VIRAMA
094E..094F    ; XID_Continue # Mc   [2] DEVANAGARI VOWEL SIGN PRISHTHAMATRA E..AW
0951..0957    ; XID_Continue # Mn   [7] DEVANAGARI STRESS SIGN UDATTA..
                                        DEVANAGARI VOWEL SIGN UUE
0962..0963    ; XID_Continue # Mn   [2] DEVANAGARI VOWEL SIGN VOCALIC L..LL
0981          ; XID_Continue # Mn       BENGALI SIGN CANDRABINDU
0982..0983    ; XID_Continue # Mc   [2] BENGALI SIGN ANUSVARA..VISARGA
09BC          ; XID_Continue # Mn       BENGALI SIGN NUKTA
09BE..09C0    ; XID_Continue # Mc   [3] BENGALI VOWEL SIGN AA..II
09C1..09C4    ; XID_Continue # Mn   [4] BENGALI VOWEL SIGN U..VOCALIC RR
09C7..09C8    ; XID_Continue # Mc   [2] BENGALI VOWEL SIGN E..AI
09CB..09CC    ; XID_Continue # Mc   [2] BENGALI VOWEL SIGN O..AU
09CD          ; XID_Continue # Mn       BENGALI SIGN VIRAMA
09D7          ; XID_Continue # Mc       BENGALI AU LENGTH MARK
09E2..09E3    ; XID_Continue # Mn   [2] BENGALI VOWEL SIGN VOCALIC L..LL
09FE          ; XID_Continue # Mn       BENGALI SANDHI MARK
0A01..0A02    ; XID_Continue # Mn   [2] GURMUKHI SIGN ADAK BINDI..BINDI
0A03          ; XID_Continue # Mc       GURMUKHI SIGN VISARGA
0A3C          ; XID_Continue # Mn       GURMUKHI SIGN NUKTA
0A3E..0A40    ; XID_Continue # Mc   [3] GURMUKHI VOWEL SIGN AA..II
0A41..0A42    ; XID_Continue # Mn   [2] GURMUKHI VOWEL SIGN U..UU
0A47..0A48    ; XID_Continue # Mn   [2] GURMUKHI VOWEL SIGN EE..AI
0A4B..0A4D    ; XID_Continue # Mn   [3] GURMUKHI VOWEL SIGN OO..
                                        GURMUKHI SIGN VIRAMA
0A51          ; XID_Continue # Mn       GURMUKHI SIGN UDAAT
0A70..0A71    ; XID_Continue # Mn   [2] GURMUKHI TIPPI..GURMUKHI ADDAK
0A75          ; XID_Continue # Mn       GURMUKHI SIGN YAKASH
0A81..0A82    ; XID_Continue # Mn   [2] GUJARATI SIGN CANDRABINDU..
                                        GUJARATI SIGN ANUSVARA
0A83          ; XID_Continue # Mc       GUJARATI SIGN VISARGA
0ABC          ; XID_Continue # Mn       GUJARATI SIGN NUKTA
0ABE..0AC0    ; XID_Continue # Mc   [3] GUJARATI VOWEL SIGN AA..II
0AC1..0AC5    ; XID_Continue # Mn   [5] GUJARATI VOWEL SIGN U..CANDRA E
0AC7..0AC8    ; XID_Continue # Mn   [2] GUJARATI VOWEL SIGN E..AI
0AC9          ; XID_Continue # Mc       GUJARATI VOWEL SIGN CANDRA O
0ACB..0ACC    ; XID_Continue # Mc   [2] GUJARATI VOWEL SIGN O..AU
0ACD          ; XID_Continue # Mn       GUJARATI SIGN VIRAMA
0AE2..0AE3    ; XID_Continue # Mn   [2] GUJARATI VOWEL SIGN VOCALIC L..LL
0AFA..0AFF    ; XID_Continue # Mn   [6] GUJARATI SIGN SUKUN..
                                        GUJARATI SIGN TWO-CIRCLE NUKTA ABOVE
0B01          ; XID_Continue # Mn       ORIYA SIGN CANDRABINDU
0B02..0B03    ; XID_Continue # Mc   [2] ORIYA SIGN ANUSVARA..
                                        ORIYA SIGN VISARGA
0B3C          ; XID_Continue # Mn       ORIYA SIGN NUKTA
0B3E          ; XID_Continue # Mc       ORIYA VOWEL SIGN AA
0B3F          ; XID_Continue # Mn       ORIYA VOWEL SIGN I
0B40          ; XID_Continue # Mc       ORIYA VOWEL SIGN II
0B41..0B44    ; XID_Continue # Mn   [4] ORIYA VOWEL SIGN U..VOCALIC RR
0B47..0B48    ; XID_Continue # Mc   [2] ORIYA VOWEL SIGN E..AI
0B4B..0B4C    ; XID_Continue # Mc   [2] ORIYA VOWEL SIGN O..AU
0B4D          ; XID_Continue # Mn       ORIYA SIGN VIRAMA
0B55..0B56    ; XID_Continue # Mn   [2] ORIYA SIGN OVERLINE..
                                        ORIYA AI LENGTH MARK
0B57          ; XID_Continue # Mc       ORIYA AU LENGTH MARK
0B62..0B63    ; XID_Continue # Mn   [2] ORIYA VOWEL SIGN VOCALIC L..LL
0B82          ; XID_Continue # Mn       TAMIL SIGN ANUSVARA
0BBE..0BBF    ; XID_Continue # Mc   [2] TAMIL VOWEL SIGN AA..I
0BC0          ; XID_Continue # Mn       TAMIL VOWEL SIGN II
0BC1..0BC2    ; XID_Continue # Mc   [2] TAMIL VOWEL SIGN U..UU
0BC6..0BC8    ; XID_Continue # Mc   [3] TAMIL VOWEL SIGN E..AI
0BCA..0BCC    ; XID_Continue # Mc   [3] TAMIL VOWEL SIGN O..AU
0BCD          ; XID_Continue # Mn       TAMIL SIGN VIRAMA
0BD7          ; XID_Continue # Mc       TAMIL AU LENGTH MARK
0C00          ; XID_Continue # Mn       TELUGU SIGN COMBINING CANDRABINDU ABOVE
0C01..0C03    ; XID_Continue # Mc   [3] TELUGU SIGN CANDRABINDU..VISARGA
0C04          ; XID_Continue # Mn       TELUGU SIGN COMBINING ANUSVARA ABOVE
0C3C          ; XID_Continue # Mn       TELUGU SIGN NUKTA
0C3E..0C40    ; XID_Continue # Mn   [3] TELUGU VOWEL SIGN AA..II
0C41..0C44    ; XID_Continue # Mc   [4] TELUGU VOWEL SIGN U..VOCALIC RR
0C46..0C48    ; XID_Continue # Mn   [3] TELUGU VOWEL SIGN E..AI
0C4A..0C4D    ; XID_Continue # Mn   [4] TELUGU VOWEL SIGN O..SIGN VIRAMA
0C55..0C56    ; XID_Continue # Mn   [2] TELUGU LENGTH MARK..AI LENGTH MARK
0C62..0C63    ; XID_Continue # Mn   [2] TELUGU VOWEL SIGN VOCALIC L..LL
0C81          ; XID_Continue # Mn       KANNADA SIGN CANDRABINDU
0C82..0C83    ; XID_Continue # Mc   [2] KANNADA SIGN ANUSVARA..VISARGA
0CBC          ; XID_Continue # Mn       KANNADA SIGN NUKTA
0CBE          ; XID_Continue # Mc       KANNADA VOWEL SIGN AA
0CBF          ; XID_Continue # Mn       KANNADA VOWEL SIGN I
0CC0..0CC4    ; XID_Continue # Mc   [5] KANNADA VOWEL SIGN II..VOCALIC RR
0CC6          ; XID_Continue # Mn       KANNADA VOWEL SIGN E
0CC7..0CC8    ; XID_Continue # Mc   [2] KANNADA VOWEL SIGN EE..AI
0CCA..0CCB    ; XID_Continue # Mc   [2] KANNADA VOWEL SIGN O..OO
0CCC..0CCD    ; XID_Continue # Mn   [2] KANNADA VOWEL SIGN AU..VIRAMA
0CD5..0CD6    ; XID_Continue # Mc   [2] KANNADA LENGTH MARK..AI LENGTH MARK
0CE2..0CE3    ; XID_Continue # Mn   [2] KANNADA VOWEL SIGN VOCALIC L..LL
0D00..0D01    ; XID_Continue # Mn   [2] MALAYALAM SIGN COMBINING ANUSVARA ABOVE..
                                        CANDRABINDU
0D02..0D03    ; XID_Continue # Mc   [2] MALAYALAM SIGN ANUSVARA..VISARGA
0D3B..0D3C    ; XID_Continue # Mn   [2] MALAYALAM SIGN VERTICAL BAR VIRAMA..
                                        CIRCULAR VIRAMA
0D3E..0D40    ; XID_Continue # Mc   [3] MALAYALAM VOWEL SIGN AA..II
0D41..0D44    ; XID_Continue # Mn   [4] MALAYALAM VOWEL SIGN U..VOCALIC RR
0D46..0D48    ; XID_Continue # Mc   [3] MALAYALAM VOWEL SIGN E..AI
0D4A..0D4C    ; XID_Continue # Mc   [3] MALAYALAM VOWEL SIGN O..AU
0D4D          ; XID_Continue # Mn       MALAYALAM SIGN VIRAMA
0D57          ; XID_Continue # Mc       MALAYALAM AU LENGTH MARK
0D62..0D63    ; XID_Continue # Mn   [2] MALAYALAM VOWEL SIGN VOCALIC L..LL
0D81          ; XID_Continue # Mn       SINHALA SIGN CANDRABINDU
0D82..0D83    ; XID_Continue # Mc   [2] SINHALA SIGN ANUSVARAYA..VISARGAYA
0DCA          ; XID_Continue # Mn       SINHALA SIGN AL-LAKUNA
0DCF..0DD1    ; XID_Continue # Mc   [3] SINHALA VOWEL SIGN AELA-PILLA..
                                        DIGA AEDA-PILLA
0DD2..0DD4    ; XID_Continue # Mn   [3] SINHALA VOWEL SIGN KETTI IS-PILLA..
                                        PAA-PILLA
0DD6          ; XID_Continue # Mn       SINHALA VOWEL SIGN DIGA PAA-PILLA
0DD8..0DDF    ; XID_Continue # Mc   [8] SINHALA VOWEL SIGN GAETTA-PILLA..
                                        GAYANUKITTA
0DF2..0DF3    ; XID_Continue # Mc   [2] SINHALA VOWEL SIGN DIGA GAETTA-PILLA..
                                        GAYANUKITTA
0E31          ; XID_Continue # Mn       THAI CHARACTER MAI HAN-AKAT
0E34..0E3A    ; XID_Continue # Mn   [7] THAI CHARACTER SARA I..PHINTHU
0E47..0E4E    ; XID_Continue # Mn   [8] THAI CHARACTER MAITAIKHU..YAMAKKAN
0EB1          ; XID_Continue # Mn       LAO VOWEL SIGN MAI KAN
0EB4..0EBC    ; XID_Continue # Mn   [9] LAO VOWEL SIGN I..SEMIVOWEL SIGN LO
0EC8..0ECD    ; XID_Continue # Mn   [6] LAO TONE MAI EK..NIGGAHITA
0F18..0F19    ; XID_Continue # Mn   [2] TIBETAN ASTROLOGICAL SIGN -KHYUD PA..
                                        SDONG TSHUGS
0F35          ; XID_Continue # Mn       TIBETAN MARK NGAS BZUNG NYI ZLA
0F37          ; XID_Continue # Mn       TIBETAN MARK NGAS BZUNG SGOR RTAGS
0F39          ; XID_Continue # Mn       TIBETAN MARK TSA -PHRU
0F3E..0F3F    ; XID_Continue # Mc   [2] TIBETAN SIGN YAR TSHES..MAR TSHES
0F71..0F7E    ; XID_Continue # Mn  [14] TIBETAN VOWEL SIGN AA..RJES SU NGA RO
0F7F          ; XID_Continue # Mc       TIBETAN SIGN RNAM BCAD
0F80..0F84    ; XID_Continue # Mn   [5] TIBETAN VOWEL SIGN REVERSED I..
                                        MARK HALANTA
0F86..0F87    ; XID_Continue # Mn   [2] TIBETAN SIGN LCI RTAGS..YANG RTAGS
0F8D..0F97    ; XID_Continue # Mn  [11] TIBETAN SUBJOINED SIGN LCE TSA CAN..
                                        LETTER JA
0F99..0FBC    ; XID_Continue # Mn  [36] TIBETAN SUBJOINED LETTER NYA..
                                        FIXED-FORM RA
0FC6          ; XID_Continue # Mn       TIBETAN SYMBOL PADMA GDAN
102B..102C    ; XID_Continue # Mc   [2] MYANMAR VOWEL SIGN TALL AA..AA
102D..1030    ; XID_Continue # Mn   [4] MYANMAR VOWEL SIGN I..UU
1031          ; XID_Continue # Mc       MYANMAR VOWEL SIGN E
1032..1037    ; XID_Continue # Mn   [6] MYANMAR VOWEL SIGN AI..DOT BELOW
1038          ; XID_Continue # Mc       MYANMAR SIGN VISARGA
1039..103A    ; XID_Continue # Mn   [2] MYANMAR SIGN VIRAMA..ASAT
103B..103C    ; XID_Continue # Mc   [2] MYANMAR CONSONANT SIGN MEDIAL YA..RA
103D..103E    ; XID_Continue # Mn   [2] MYANMAR CONSONANT SIGN MEDIAL WA..HA
1056..1057    ; XID_Continue # Mc   [2] MYANMAR VOWEL SIGN VOCALIC R..RR
1058..1059    ; XID_Continue # Mn   [2] MYANMAR VOWEL SIGN VOCALIC L..LL
105E..1060    ; XID_Continue # Mn   [3] MYANMAR CONSONANT SIGN MON MEDIAL NA..LA
1062..1064    ; XID_Continue # Mc   [3] MYANMAR VOWEL SIGN SGAW KAREN EU..KE PHO
1067..106D    ; XID_Continue # Mc   [7] MYANMAR VOWEL SIGN WESTERN PWO KAREN EU..
                                        TONE-5
1071..1074    ; XID_Continue # Mn   [4] MYANMAR VOWEL SIGN GEBA KAREN I..KAYAH EE
1082          ; XID_Continue # Mn       MYANMAR CONSONANT SIGN SHAN MEDIAL WA
1083..1084    ; XID_Continue # Mc   [2] MYANMAR VOWEL SIGN SHAN AA..E
1085..1086    ; XID_Continue # Mn   [2] MYANMAR VOWEL SIGN SHAN E ABOVE..FINAL Y
1087..108C    ; XID_Continue # Mc   [6] MYANMAR SIGN SHAN TONE-2..TONE-3
108D          ; XID_Continue # Mn       MYANMAR SIGN SHAN COUNCIL EMPHATIC TONE
108F          ; XID_Continue # Mc       MYANMAR SIGN RUMAI PALAUNG TONE-5
109A..109C    ; XID_Continue # Mc   [3] MYANMAR SIGN KHAMTI TONE-1..AITON A
109D          ; XID_Continue # Mn       MYANMAR VOWEL SIGN AITON AI
135D..135F    ; XID_Continue # Mn   [3] ETHIOPIC COMBINING GEMINATION AND
                                        VOWEL LENGTH MARK..MARK
1712..1714    ; XID_Continue # Mn   [3] TAGALOG VOWEL SIGN I..VIRAMA
1715          ; XID_Continue # Mc       TAGALOG SIGN PAMUDPOD
1732..1733    ; XID_Continue # Mn   [2] HANUNOO VOWEL SIGN I..U
1734          ; XID_Continue # Mc       HANUNOO SIGN PAMUDPOD
1752..1753    ; XID_Continue # Mn   [2] BUHID VOWEL SIGN I..U
1772..1773    ; XID_Continue # Mn   [2] TAGBANWA VOWEL SIGN I..U
17B4..17B5    ; XID_Continue # Mn   [2] KHMER VOWEL INHERENT AQ..AA
17B6          ; XID_Continue # Mc       KHMER VOWEL SIGN AA
17B7..17BD    ; XID_Continue # Mn   [7] KHMER VOWEL SIGN I..UA
17BE..17C5    ; XID_Continue # Mc   [8] KHMER VOWEL SIGN OE..AU
17C6          ; XID_Continue # Mn       KHMER SIGN NIKAHIT
17C7..17C8    ; XID_Continue # Mc   [2] KHMER SIGN REAHMUK..YUUKALEAPINTU
17C9..17D3    ; XID_Continue # Mn  [11] KHMER SIGN MUUSIKATOAN..BATHAMASAT
17DD          ; XID_Continue # Mn       KHMER SIGN ATTHACAN
180B..180D    ; XID_Continue # Mn   [3] MONGOLIAN FREE VARIATION SELECTOR ONE..
                                        THREE
180F          ; XID_Continue # Mn       MONGOLIAN FREE VARIATION SELECTOR FOUR
1885..1886    ; XID_Continue # Mn   [2] MONGOLIAN LETTER ALI GALI BALUDA..
                                        THREE BALUDA
18A9          ; XID_Continue # Mn       MONGOLIAN LETTER ALI GALI DAGALGA
1920..1922    ; XID_Continue # Mn   [3] LIMBU VOWEL SIGN A..U
1923..1926    ; XID_Continue # Mc   [4] LIMBU VOWEL SIGN EE..AU
1927..1928    ; XID_Continue # Mn   [2] LIMBU VOWEL SIGN E..O
1929..192B    ; XID_Continue # Mc   [3] LIMBU SUBJOINED LETTER YA..WA
1930..1931    ; XID_Continue # Mc   [2] LIMBU SMALL LETTER KA..NGA
1932          ; XID_Continue # Mn       LIMBU SMALL LETTER ANUSVARA
1933..1938    ; XID_Continue # Mc   [6] LIMBU SMALL LETTER TA..LA
1939..193B    ; XID_Continue # Mn   [3] LIMBU SIGN MUKPHRENG..-I
1A17..1A18    ; XID_Continue # Mn   [2] BUGINESE VOWEL SIGN I..U
1A19..1A1A    ; XID_Continue # Mc   [2] BUGINESE VOWEL SIGN E..O
1A1B          ; XID_Continue # Mn       BUGINESE VOWEL SIGN AE
1A55          ; XID_Continue # Mc       TAI THAM CONSONANT SIGN MEDIAL RA
1A56          ; XID_Continue # Mn       TAI THAM CONSONANT SIGN MEDIAL LA
1A57          ; XID_Continue # Mc       TAI THAM CONSONANT SIGN LA TANG LAI
1A58..1A5E    ; XID_Continue # Mn   [7] TAI THAM SIGN MAI KANG LAI..
                                        CONSONANT SIGN SA
1A60          ; XID_Continue # Mn       TAI THAM SIGN SAKOT
1A61          ; XID_Continue # Mc       TAI THAM VOWEL SIGN A
1A62          ; XID_Continue # Mn       TAI THAM VOWEL SIGN MAI SAT
1A63..1A64    ; XID_Continue # Mc   [2] TAI THAM VOWEL SIGN AA..TALL AA
1A65..1A6C    ; XID_Continue # Mn   [8] TAI THAM VOWEL SIGN I..OA BELOW
1A6D..1A72    ; XID_Continue # Mc   [6] TAI THAM VOWEL SIGN OY..THAM AI
1A73..1A7C    ; XID_Continue # Mn  [10] TAI THAM VOWEL SIGN OA ABOVE..
                                        KHUEN-LUE KARAN
1A7F          ; XID_Continue # Mn       TAI THAM COMBINING CRYPTOGRAMMIC DOT
1AB0..1ABD    ; XID_Continue # Mn  [14] COMBINING DOUBLED CIRCUMFLEX ACCENT..
                                        COMBINING PARENTHESES BELOW
1ABF..1ACE    ; XID_Continue # Mn  [16] COMBINING LATIN SMALL LETTER W BELOW..
                                        INSULAR T
1B00..1B03    ; XID_Continue # Mn   [4] BALINESE SIGN ULU RICEM..SURANG
1B04          ; XID_Continue # Mc       BALINESE SIGN BISAH
1B34          ; XID_Continue # Mn       BALINESE SIGN REREKAN
1B35          ; XID_Continue # Mc       BALINESE VOWEL SIGN TEDUNG
1B36..1B3A    ; XID_Continue # Mn   [5] BALINESE VOWEL SIGN ULU..RA REPA
1B3B          ; XID_Continue # Mc       BALINESE VOWEL SIGN RA REPA TEDUNG
1B3C          ; XID_Continue # Mn       BALINESE VOWEL SIGN LA LENGA
1B3D..1B41    ; XID_Continue # Mc   [5] BALINESE VOWEL SIGN LA LENGA TEDUNG..
                                        TALING REPA TEDUNG
1B42          ; XID_Continue # Mn       BALINESE VOWEL SIGN PEPET
1B43..1B44    ; XID_Continue # Mc   [2] BALINESE VOWEL SIGN PEPET TEDUNG..
                                        BALINESE ADEG ADEG
1B6B..1B73    ; XID_Continue # Mn   [9] BALINESE MUSICAL SYMBOL COMBINING TEGEH..
                                        GONG
1B80..1B81    ; XID_Continue # Mn   [2] SUNDANESE SIGN PANYECEK..PANGLAYAR
1B82          ; XID_Continue # Mc       SUNDANESE SIGN PANGWISAD
1BA1          ; XID_Continue # Mc       SUNDANESE CONSONANT SIGN PAMINGKAL
1BA2..1BA5    ; XID_Continue # Mn   [4] SUNDANESE CONSONANT SIGN PANYAKRA..
                                        SUNDANESE VOWEL SIGN PANYUKU
1BA6..1BA7    ; XID_Continue # Mc   [2] SUNDANESE VOWEL SIGN PANAELAENG..PANOLONG
1BA8..1BA9    ; XID_Continue # Mn   [2] SUNDANESE VOWEL SIGN PAMEPET..PANEULEUNG
1BAA          ; XID_Continue # Mc       SUNDANESE SIGN PAMAAEH
1BAB..1BAD    ; XID_Continue # Mn   [3] SUNDANESE SIGN VIRAMA..
                                        CONSONANT SIGN PASANGAN WA
1BE6          ; XID_Continue # Mn       BATAK SIGN TOMPI
1BE7          ; XID_Continue # Mc       BATAK VOWEL SIGN E
1BE8..1BE9    ; XID_Continue # Mn   [2] BATAK VOWEL SIGN PAKPAK E..EE
1BEA..1BEC    ; XID_Continue # Mc   [3] BATAK VOWEL SIGN I..O
1BED          ; XID_Continue # Mn       BATAK VOWEL SIGN KARO O
1BEE          ; XID_Continue # Mc       BATAK VOWEL SIGN U
1BEF..1BF1    ; XID_Continue # Mn   [3] BATAK VOWEL SIGN U FOR SIMALUNGUN SA..
                                        BATAK CONSONANT SIGN H
1BF2..1BF3    ; XID_Continue # Mc   [2] BATAK PANGOLAT..BATAK PANONGONAN
1C24..1C2B    ; XID_Continue # Mc   [8] LEPCHA SUBJOINED LETTER YA..VOWEL SIGN UU
1C2C..1C33    ; XID_Continue # Mn   [8] LEPCHA VOWEL SIGN E..CONSONANT SIGN T
1C34..1C35    ; XID_Continue # Mc   [2] LEPCHA CONSONANT SIGN NYIN-DO..KANG
1C36..1C37    ; XID_Continue # Mn   [2] LEPCHA SIGN RAN..NUKTA
1CD0..1CD2    ; XID_Continue # Mn   [3] VEDIC TONE KARSHANA..PRENKHA
1CD4..1CE0    ; XID_Continue # Mn  [13] VEDIC SIGN YAJURVEDIC MIDLINE SVARITA..
                                        VEDIC TONE RIGVEDIC KASHMIRI INDEPENDENT
                                        SVARITA
1CE1          ; XID_Continue # Mc       VEDIC TONE ATHARVAVEDIC INDEPENDENT
                                        SVARITA
1CE2..1CE8    ; XID_Continue # Mn   [7] VEDIC SIGN VISARGA SVARITA..
                                        VEDIC SIGN VISARGA ANUDATTA WITH TAIL
1CED          ; XID_Continue # Mn       VEDIC SIGN TIRYAK
1CF4          ; XID_Continue # Mn       VEDIC TONE CANDRA ABOVE
1CF7          ; XID_Continue # Mc       VEDIC SIGN ATIKRAMA
1CF8..1CF9    ; XID_Continue # Mn   [2] VEDIC TONE RING ABOVE..DOUBLE RING ABOVE
1DC0..1DFF    ; XID_Continue # Mn  [64] COMBINING DOTTED GRAVE ACCENT..
                                        RIGHT ARROWHEAD AND DOWN ARROWHEAD BELOW
20D0..20DC    ; XID_Continue # Mn  [13] COMBINING LEFT HARPOON ABOVE..
                                        COMBINING FOUR DOTS ABOVE
20E1          ; XID_Continue # Mn       COMBINING LEFT RIGHT ARROW ABOVE
20E5..20F0    ; XID_Continue # Mn  [12] COMBINING REVERSE SOLIDUS OVERLAY..
                                        COMBINING ASTERISK ABOVE
2CEF..2CF1    ; XID_Continue # Mn   [3] COPTIC COMBINING NI ABOVE..SPIRITUS LENIS
2D7F          ; XID_Continue # Mn       TIFINAGH CONSONANT JOINER
2DE0..2DFF    ; XID_Continue # Mn  [32] COMBINING CYRILLIC LETTER BE..
                                        IOTIFIED BIG YUS
302A..302D    ; XID_Continue # Mn   [4] IDEOGRAPHIC LEVEL TONE MARK..
                                        IDEOGRAPHIC ENTERING TONE MARK
302E..302F    ; XID_Continue # Mc   [2] HANGUL SINGLE DOT TONE MARK..
                                        HANGUL DOUBLE DOT TONE MARK
3099..309A    ; XID_Continue # Mn   [2] COMBINING KATAKANA-HIRAGANA VOICED
                                        SOUND MARK..SEMI-VOICED SOUND MARK
A66F          ; XID_Continue # Mn       COMBINING CYRILLIC VZMET
A674..A67D    ; XID_Continue # Mn  [10] COMBINING CYRILLIC LETTER UKRAINIAN IE..
                                        PAYEROK
A69E..A69F    ; XID_Continue # Mn   [2] COMBINING CYRILLIC LETTER EF..IOTIFIED E
A6F0..A6F1    ; XID_Continue # Mn   [2] BAMUM COMBINING MARK KOQNDON..TUKWENTIS
A802          ; XID_Continue # Mn       SYLOTI NAGRI SIGN DVISVARA
A806          ; XID_Continue # Mn       SYLOTI NAGRI SIGN HASANTA
A80B          ; XID_Continue # Mn       SYLOTI NAGRI SIGN ANUSVARA
A823..A824    ; XID_Continue # Mc   [2] SYLOTI NAGRI VOWEL SIGN A..I
A825..A826    ; XID_Continue # Mn   [2] SYLOTI NAGRI VOWEL SIGN U..E
A827          ; XID_Continue # Mc       SYLOTI NAGRI VOWEL SIGN OO
A82C          ; XID_Continue # Mn       SYLOTI NAGRI SIGN ALTERNATE HASANTA
A880..A881    ; XID_Continue # Mc   [2] SAURASHTRA SIGN ANUSVARA..VISARGA
A8B4..A8C3    ; XID_Continue # Mc  [16] SAURASHTRA CONSONANT SIGN HAARU..
                                        SAURASHTRA VOWEL SIGN AU
A8C4..A8C5    ; XID_Continue # Mn   [2] SAURASHTRA SIGN VIRAMA..CANDRABINDU
A8E0..A8F1    ; XID_Continue # Mn  [18] COMBINING DEVANAGARI DIGIT ZERO..
                                        SIGN AVAGRAHA
A8FF          ; XID_Continue # Mn       DEVANAGARI VOWEL SIGN AY
A926..A92D    ; XID_Continue # Mn   [8] KAYAH LI VOWEL UE..TONE CALYA PLOPHU
A947..A951    ; XID_Continue # Mn  [11] REJANG VOWEL SIGN I..CONSONANT SIGN R
A952..A953    ; XID_Continue # Mc   [2] REJANG CONSONANT SIGN H..REJANG VIRAMA
A980..A982    ; XID_Continue # Mn   [3] JAVANESE SIGN PANYANGGA..LAYAR
A983          ; XID_Continue # Mc       JAVANESE SIGN WIGNYAN
A9B3          ; XID_Continue # Mn       JAVANESE SIGN CECAK TELU
A9B4..A9B5    ; XID_Continue # Mc   [2] JAVANESE VOWEL SIGN TARUNG..TOLONG
A9B6..A9B9    ; XID_Continue # Mn   [4] JAVANESE VOWEL SIGN WULU..SUKU MENDUT
A9BA..A9BB    ; XID_Continue # Mc   [2] JAVANESE VOWEL SIGN TALING..DIRGA MURE
A9BC..A9BD    ; XID_Continue # Mn   [2] JAVANESE VOWEL SIGN PEPET..KERET
A9BE..A9C0    ; XID_Continue # Mc   [3] JAVANESE CONSONANT SIGN PENGKAL..PANGKON
A9E5          ; XID_Continue # Mn       MYANMAR SIGN SHAN SAW
AA29..AA2E    ; XID_Continue # Mn   [6] CHAM VOWEL SIGN AA..OE
AA2F..AA30    ; XID_Continue # Mc   [2] CHAM VOWEL SIGN O..AI
AA31..AA32    ; XID_Continue # Mn   [2] CHAM VOWEL SIGN AU..UE
AA33..AA34    ; XID_Continue # Mc   [2] CHAM CONSONANT SIGN YA..RA
AA35..AA36    ; XID_Continue # Mn   [2] CHAM CONSONANT SIGN LA..WA
AA43          ; XID_Continue # Mn       CHAM CONSONANT SIGN FINAL NG
AA4C          ; XID_Continue # Mn       CHAM CONSONANT SIGN FINAL M
AA4D          ; XID_Continue # Mc       CHAM CONSONANT SIGN FINAL H
AA7B          ; XID_Continue # Mc       MYANMAR SIGN PAO KAREN TONE
AA7C          ; XID_Continue # Mn       MYANMAR SIGN TAI LAING TONE-2
AA7D          ; XID_Continue # Mc       MYANMAR SIGN TAI LAING TONE-5
AAB0          ; XID_Continue # Mn       TAI VIET MAI KANG
AAB2..AAB4    ; XID_Continue # Mn   [3] TAI VIET VOWEL I..U
AAB7..AAB8    ; XID_Continue # Mn   [2] TAI VIET MAI KHIT..VOWEL IA
AABE..AABF    ; XID_Continue # Mn   [2] TAI VIET VOWEL AM..TONE MAI EK
AAC1          ; XID_Continue # Mn       TAI VIET TONE MAI THO
AAEB          ; XID_Continue # Mc       MEETEI MAYEK VOWEL SIGN II
AAEC..AAED    ; XID_Continue # Mn   [2] MEETEI MAYEK VOWEL SIGN UU..AAI
AAEE..AAEF    ; XID_Continue # Mc   [2] MEETEI MAYEK VOWEL SIGN AU..AAU
AAF5          ; XID_Continue # Mc       MEETEI MAYEK VOWEL SIGN VISARGA
AAF6          ; XID_Continue # Mn       MEETEI MAYEK VIRAMA
ABE3..ABE4    ; XID_Continue # Mc   [2] MEETEI MAYEK VOWEL SIGN ONAP..INAP
ABE5          ; XID_Continue # Mn       MEETEI MAYEK VOWEL SIGN ANAP
ABE6..ABE7    ; XID_Continue # Mc   [2] MEETEI MAYEK VOWEL SIGN YENAP..SOUNAP
ABE8          ; XID_Continue # Mn       MEETEI MAYEK VOWEL SIGN UNAP
ABE9..ABEA    ; XID_Continue # Mc   [2] MEETEI MAYEK VOWEL SIGN CHEINAP..NUNG
ABEC          ; XID_Continue # Mc       MEETEI MAYEK LUM IYEK
ABED          ; XID_Continue # Mn       MEETEI MAYEK APUN IYEK
FB1E          ; XID_Continue # Mn       HEBREW POINT JUDEO-SPANISH VARIKA
FE00..FE0F    ; XID_Continue # Mn  [16] VARIATION SELECTOR-1..-16
FE20..FE2F    ; XID_Continue # Mn  [16] COMBINING LIGATURE LEFT HALF..
                                        COMBINING CYRILLIC TITLO RIGHT HALF
101FD         ; XID_Continue # Mn       PHAISTOS DISC SIGN COMBINING OBLIQUE
                                        STROKE
102E0         ; XID_Continue # Mn       COPTIC EPACT THOUSANDS MARK
10376..1037A  ; XID_Continue # Mn   [5] COMBINING OLD PERMIC LETTER AN..SII
10A01..10A03  ; XID_Continue # Mn   [3] KHAROSHTHI VOWEL SIGN I..VOCALIC R
10A05..10A06  ; XID_Continue # Mn   [2] KHAROSHTHI VOWEL SIGN E..O
10A0C..10A0F  ; XID_Continue # Mn   [4] KHAROSHTHI VOWEL LENGTH MARK..
                                        SIGN VISARGA
10A38..10A3A  ; XID_Continue # Mn   [3] KHAROSHTHI SIGN BAR ABOVE..DOT BELOW
10A3F         ; XID_Continue # Mn       KHAROSHTHI VIRAMA
10AE5..10AE6  ; XID_Continue # Mn   [2] MANICHAEAN ABBREVIATION MARK ABOVE..BELOW
10D24..10D27  ; XID_Continue # Mn   [4] HANIFI ROHINGYA SIGN HARBAHAY..TASSI
10EAB..10EAC  ; XID_Continue # Mn   [2] YEZIDI COMBINING HAMZA MARK..MADDA MARK
10F46..10F50  ; XID_Continue # Mn  [11] SOGDIAN COMBINING DOT BELOW..STROKE BELOW
10F82..10F85  ; XID_Continue # Mn   [4] OLD UYGHUR COMBINING DOT ABOVE..
                                        TWO DOTS BELOW
11000         ; XID_Continue # Mc       BRAHMI SIGN CANDRABINDU
11001         ; XID_Continue # Mn       BRAHMI SIGN ANUSVARA
11002         ; XID_Continue # Mc       BRAHMI SIGN VISARGA
11038..11046  ; XID_Continue # Mn  [15] BRAHMI VOWEL SIGN AA..BRAHMI VIRAMA
11070         ; XID_Continue # Mn       BRAHMI SIGN OLD TAMIL VIRAMA
11073..11074  ; XID_Continue # Mn   [2] BRAHMI VOWEL SIGN OLD TAMIL SHORT E..O
1107F..11081  ; XID_Continue # Mn   [3] BRAHMI NUMBER JOINER..SIGN ANUSVARA
11082         ; XID_Continue # Mc       KAITHI SIGN VISARGA
110B0..110B2  ; XID_Continue # Mc   [3] KAITHI VOWEL SIGN AA..II
110B3..110B6  ; XID_Continue # Mn   [4] KAITHI VOWEL SIGN U..AI
110B7..110B8  ; XID_Continue # Mc   [2] KAITHI VOWEL SIGN O..AU
110B9..110BA  ; XID_Continue # Mn   [2] KAITHI SIGN VIRAMA..KAITHI SIGN NUKTA
110C2         ; XID_Continue # Mn       KAITHI VOWEL SIGN VOCALIC R
11100..11102  ; XID_Continue # Mn   [3] CHAKMA SIGN CANDRABINDU..VISARGA
11127..1112B  ; XID_Continue # Mn   [5] CHAKMA VOWEL SIGN A..UU
1112C         ; XID_Continue # Mc       CHAKMA VOWEL SIGN E
1112D..11134  ; XID_Continue # Mn   [8] CHAKMA VOWEL SIGN AI..CHAKMA MAAYYAA
11145..11146  ; XID_Continue # Mc   [2] CHAKMA VOWEL SIGN AA..EI
11173         ; XID_Continue # Mn       MAHAJANI SIGN NUKTA
11180..11181  ; XID_Continue # Mn   [2] SHARADA SIGN CANDRABINDU..ANUSVARA
11182         ; XID_Continue # Mc       SHARADA SIGN VISARGA
111B3..111B5  ; XID_Continue # Mc   [3] SHARADA VOWEL SIGN AA..II
111B6..111BE  ; XID_Continue # Mn   [9] SHARADA VOWEL SIGN U..O
111BF..111C0  ; XID_Continue # Mc   [2] SHARADA VOWEL SIGN AU..VIRAMA
111C9..111CC  ; XID_Continue # Mn   [4] SHARADA SANDHI MARK..
                                        EXTRA SHORT VOWEL MARK
111CE         ; XID_Continue # Mc       SHARADA VOWEL SIGN PRISHTHAMATRA E
111CF         ; XID_Continue # Mn       SHARADA SIGN INVERTED CANDRABINDU
1122C..1122E  ; XID_Continue # Mc   [3] KHOJKI VOWEL SIGN AA..II
1122F..11231  ; XID_Continue # Mn   [3] KHOJKI VOWEL SIGN U..AI
11232..11233  ; XID_Continue # Mc   [2] KHOJKI VOWEL SIGN O..AU
11234         ; XID_Continue # Mn       KHOJKI SIGN ANUSVARA
11235         ; XID_Continue # Mc       KHOJKI SIGN VIRAMA
11236..11237  ; XID_Continue # Mn   [2] KHOJKI SIGN NUKTA..SHADDA
1123E         ; XID_Continue # Mn       KHOJKI SIGN SUKUN
112DF         ; XID_Continue # Mn       KHUDAWADI SIGN ANUSVARA
112E0..112E2  ; XID_Continue # Mc   [3] KHUDAWADI VOWEL SIGN AA..II
112E3..112EA  ; XID_Continue # Mn   [8] KHUDAWADI VOWEL SIGN U..VIRAMA
11300..11301  ; XID_Continue # Mn   [2] GRANTHA SIGN COMBINING ANUSVARA ABOVE..
                                        GRANTHA SIGN CANDRABINDU
11302..11303  ; XID_Continue # Mc   [2] GRANTHA SIGN ANUSVARA..VISARGA
1133B..1133C  ; XID_Continue # Mn   [2] COMBINING BINDU BELOW..GRANTHA SIGN NUKTA
1133E..1133F  ; XID_Continue # Mc   [2] GRANTHA VOWEL SIGN AA..I
11340         ; XID_Continue # Mn       GRANTHA VOWEL SIGN II
11341..11344  ; XID_Continue # Mc   [4] GRANTHA VOWEL SIGN U..VOCALIC RR
11347..11348  ; XID_Continue # Mc   [2] GRANTHA VOWEL SIGN EE..AI
1134B..1134D  ; XID_Continue # Mc   [3] GRANTHA VOWEL SIGN OO..VIRAMA
11357         ; XID_Continue # Mc       GRANTHA AU LENGTH MARK
11362..11363  ; XID_Continue # Mc   [2] GRANTHA VOWEL SIGN VOCALIC L..LL
11366..1136C  ; XID_Continue # Mn   [7] COMBINING GRANTHA DIGIT ZERO..SIX
11370..11374  ; XID_Continue # Mn   [5] COMBINING GRANTHA LETTER A..PA
11435..11437  ; XID_Continue # Mc   [3] NEWA VOWEL SIGN AA..II
11438..1143F  ; XID_Continue # Mn   [8] NEWA VOWEL SIGN U..AI
11440..11441  ; XID_Continue # Mc   [2] NEWA VOWEL SIGN O..AU
11442..11444  ; XID_Continue # Mn   [3] NEWA SIGN VIRAMA..ANUSVARA
11445         ; XID_Continue # Mc       NEWA SIGN VISARGA
11446         ; XID_Continue # Mn       NEWA SIGN NUKTA
1145E         ; XID_Continue # Mn       NEWA SANDHI MARK
114B0..114B2  ; XID_Continue # Mc   [3] TIRHUTA VOWEL SIGN AA..II
114B3..114B8  ; XID_Continue # Mn   [6] TIRHUTA VOWEL SIGN U..VOCALIC LL
114B9         ; XID_Continue # Mc       TIRHUTA VOWEL SIGN E
114BA         ; XID_Continue # Mn       TIRHUTA VOWEL SIGN SHORT E
114BB..114BE  ; XID_Continue # Mc   [4] TIRHUTA VOWEL SIGN AI..AU
114BF..114C0  ; XID_Continue # Mn   [2] TIRHUTA SIGN CANDRABINDU..ANUSVARA
114C1         ; XID_Continue # Mc       TIRHUTA SIGN VISARGA
114C2..114C3  ; XID_Continue # Mn   [2] TIRHUTA SIGN VIRAMA..NUKTA
115AF..115B1  ; XID_Continue # Mc   [3] SIDDHAM VOWEL SIGN AA..II
115B2..115B5  ; XID_Continue # Mn   [4] SIDDHAM VOWEL SIGN U..VOCALIC RR
115B8..115BB  ; XID_Continue # Mc   [4] SIDDHAM VOWEL SIGN E..AU
115BC..115BD  ; XID_Continue # Mn   [2] SIDDHAM SIGN CANDRABINDU..ANUSVARA
115BE         ; XID_Continue # Mc       SIDDHAM SIGN VISARGA
115BF..115C0  ; XID_Continue # Mn   [2] SIDDHAM SIGN VIRAMA..NUKTA
115DC..115DD  ; XID_Continue # Mn   [2] SIDDHAM VOWEL SIGN ALTERNATE U..UU
11630..11632  ; XID_Continue # Mc   [3] MODI VOWEL SIGN AA..II
11633..1163A  ; XID_Continue # Mn   [8] MODI VOWEL SIGN U..AI
1163B..1163C  ; XID_Continue # Mc   [2] MODI VOWEL SIGN O..AU
1163D         ; XID_Continue # Mn       MODI SIGN ANUSVARA
1163E         ; XID_Continue # Mc       MODI SIGN VISARGA
1163F..11640  ; XID_Continue # Mn   [2] MODI SIGN VIRAMA..ARDHACANDRA
116AB         ; XID_Continue # Mn       TAKRI SIGN ANUSVARA
116AC         ; XID_Continue # Mc       TAKRI SIGN VISARGA
116AD         ; XID_Continue # Mn       TAKRI VOWEL SIGN AA
116AE..116AF  ; XID_Continue # Mc   [2] TAKRI VOWEL SIGN I..II
116B0..116B5  ; XID_Continue # Mn   [6] TAKRI VOWEL SIGN U..AU
116B6         ; XID_Continue # Mc       TAKRI SIGN VIRAMA
116B7         ; XID_Continue # Mn       TAKRI SIGN NUKTA
1171D..1171F  ; XID_Continue # Mn   [3] AHOM CONSONANT SIGN MEDIAL LA..
                                        LIGATING RA
11720..11721  ; XID_Continue # Mc   [2] AHOM VOWEL SIGN A..AA
11722..11725  ; XID_Continue # Mn   [4] AHOM VOWEL SIGN I..UU
11726         ; XID_Continue # Mc       AHOM VOWEL SIGN E
11727..1172B  ; XID_Continue # Mn   [5] AHOM VOWEL SIGN AW..KILLER
1182C..1182E  ; XID_Continue # Mc   [3] DOGRA VOWEL SIGN AA..II
1182F..11837  ; XID_Continue # Mn   [9] DOGRA VOWEL SIGN U..ANUSVARA
11838         ; XID_Continue # Mc       DOGRA SIGN VISARGA
11839..1183A  ; XID_Continue # Mn   [2] DOGRA SIGN VIRAMA..NUKTA
11930..11935  ; XID_Continue # Mc   [6] DIVES AKURU VOWEL SIGN AA..E
11937..11938  ; XID_Continue # Mc   [2] DIVES AKURU VOWEL SIGN AI..O
1193B..1193C  ; XID_Continue # Mn   [2] DIVES AKURU SIGN ANUSVARA..CANDRABINDU
1193D         ; XID_Continue # Mc       DIVES AKURU SIGN HALANTA
1193E         ; XID_Continue # Mn       DIVES AKURU VIRAMA
11940         ; XID_Continue # Mc       DIVES AKURU MEDIAL YA
11942         ; XID_Continue # Mc       DIVES AKURU MEDIAL RA
11943         ; XID_Continue # Mn       DIVES AKURU SIGN NUKTA
119D1..119D3  ; XID_Continue # Mc   [3] NANDINAGARI VOWEL SIGN AA..II
119D4..119D7  ; XID_Continue # Mn   [4] NANDINAGARI VOWEL SIGN U..VOCALIC RR
119DA..119DB  ; XID_Continue # Mn   [2] NANDINAGARI VOWEL SIGN E..AI
119DC..119DF  ; XID_Continue # Mc   [4] NANDINAGARI VOWEL SIGN O..VISARGA
119E0         ; XID_Continue # Mn       NANDINAGARI SIGN VIRAMA
119E4         ; XID_Continue # Mc       NANDINAGARI VOWEL SIGN PRISHTHAMATRA E
11A01..11A0A  ; XID_Continue # Mn  [10] ZANABAZAR SQUARE VOWEL SIGN I..
                                        LENGTH MARK
11A33..11A38  ; XID_Continue # Mn   [6] ZANABAZAR SQUARE FINAL CONSONANT MARK..
                                        ZANABAZAR SQUARE SIGN ANUSVARA
11A39         ; XID_Continue # Mc       ZANABAZAR SQUARE SIGN VISARGA
11A3B..11A3E  ; XID_Continue # Mn   [4] ZANABAZAR SQUARE CLUSTER-FINAL LETTER YA..
                                        ZANABAZAR SQUARE CLUSTER-FINAL LETTER VA
11A47         ; XID_Continue # Mn       ZANABAZAR SQUARE SUBJOINER
11A51..11A56  ; XID_Continue # Mn   [6] SOYOMBO VOWEL SIGN I..OE
11A57..11A58  ; XID_Continue # Mc   [2] SOYOMBO VOWEL SIGN AI..AU
11A59..11A5B  ; XID_Continue # Mn   [3] SOYOMBO VOWEL SIGN VOCALIC R..
                                        SOYOMBO VOWEL LENGTH MARK
11A8A..11A96  ; XID_Continue # Mn  [13] SOYOMBO FINAL CONSONANT SIGN G..ANUSVARA
11A97         ; XID_Continue # Mc       SOYOMBO SIGN VISARGA
11A98..11A99  ; XID_Continue # Mn   [2] SOYOMBO GEMINATION MARK..SUBJOINER
11C2F         ; XID_Continue # Mc       BHAIKSUKI VOWEL SIGN AA
11C30..11C36  ; XID_Continue # Mn   [7] BHAIKSUKI VOWEL SIGN I..VOCALIC L
11C38..11C3D  ; XID_Continue # Mn   [6] BHAIKSUKI VOWEL SIGN E..ANUSVARA
11C3E         ; XID_Continue # Mc       BHAIKSUKI SIGN VISARGA
11C3F         ; XID_Continue # Mn       BHAIKSUKI SIGN VIRAMA
11C92..11CA7  ; XID_Continue # Mn  [22] MARCHEN SUBJOINED LETTER KA..ZA
11CA9         ; XID_Continue # Mc       MARCHEN SUBJOINED LETTER YA
11CAA..11CB0  ; XID_Continue # Mn   [7] MARCHEN SUBJOINED LETTER RA..
                                        MARCHEN VOWEL SIGN AA
11CB1         ; XID_Continue # Mc       MARCHEN VOWEL SIGN I
11CB2..11CB3  ; XID_Continue # Mn   [2] MARCHEN VOWEL SIGN U..E
11CB4         ; XID_Continue # Mc       MARCHEN VOWEL SIGN O
11CB5..11CB6  ; XID_Continue # Mn   [2] MARCHEN SIGN ANUSVARA..CANDRABINDU
11D31..11D36  ; XID_Continue # Mn   [6] MASARAM GONDI VOWEL SIGN AA..
                                        MASARAM GONDI VOWEL SIGN VOCALIC R
11D3A         ; XID_Continue # Mn       MASARAM GONDI VOWEL SIGN E
11D3C..11D3D  ; XID_Continue # Mn   [2] MASARAM GONDI VOWEL SIGN AI..O
11D3F..11D45  ; XID_Continue # Mn   [7] MASARAM GONDI VOWEL SIGN AU..
                                        MASARAM GONDI VIRAMA
11D47         ; XID_Continue # Mn       MASARAM GONDI RA-KARA
11D8A..11D8E  ; XID_Continue # Mc   [5] GUNJALA GONDI VOWEL SIGN AA..UU
11D90..11D91  ; XID_Continue # Mn   [2] GUNJALA GONDI VOWEL SIGN EE..AI
11D93..11D94  ; XID_Continue # Mc   [2] GUNJALA GONDI VOWEL SIGN OO..AU
11D95         ; XID_Continue # Mn       GUNJALA GONDI SIGN ANUSVARA
11D96         ; XID_Continue # Mc       GUNJALA GONDI SIGN VISARGA
11D97         ; XID_Continue # Mn       GUNJALA GONDI VIRAMA
11EF3..11EF4  ; XID_Continue # Mn   [2] MAKASAR VOWEL SIGN I..U
11EF5..11EF6  ; XID_Continue # Mc   [2] MAKASAR VOWEL SIGN E..O
16AF0..16AF4  ; XID_Continue # Mn   [5] BASSA VAH COMBINING HIGH TONE..
                                        BASSA VAH COMBINING HIGH-LOW TONE
16B30..16B36  ; XID_Continue # Mn   [7] PAHAWH HMONG MARK CIM TUB..CIM TAUM
16F4F         ; XID_Continue # Mn       MIAO SIGN CONSONANT MODIFIER BAR
16F51..16F87  ; XID_Continue # Mc  [55] MIAO SIGN ASPIRATION..MIAO VOWEL SIGN UI
16F8F..16F92  ; XID_Continue # Mn   [4] MIAO TONE RIGHT..MIAO TONE BELOW
16FE4         ; XID_Continue # Mn       KHITAN SMALL SCRIPT FILLER
16FF0..16FF1  ; XID_Continue # Mc   [2] VIETNAMESE ALTERNATE READING MARK CA..
                                        VIETNAMESE ALTERNATE READING MARK NHAY
1BC9D..1BC9E  ; XID_Continue # Mn   [2] DUPLOYAN THICK LETTER SELECTOR..
                                        DUPLOYAN DOUBLE MARK
1CF00..1CF2D  ; XID_Continue # Mn  [46] ZNAMENNY COMBINING MARK GORAZDO NIZKO S
                                        KRYZHEM ON LEFT..
                                        ZNAMENNY COMBINING MARK KRYZH ON LEFT
1CF30..1CF46  ; XID_Continue # Mn  [23] ZNAMENNY COMBINING TONAL RANGE MARK
                                        MRACHNO..PRIZNAK MODIFIER ROG
1D165..1D166  ; XID_Continue # Mc   [2] MUSICAL SYMBOL COMBINING STEM..
                                        SPRECHGESANG STEM
1D167..1D169  ; XID_Continue # Mn   [3] MUSICAL SYMBOL COMBINING TREMOLO-1..3
1D16D..1D172  ; XID_Continue # Mc   [6] MUSICAL SYMBOL COMBINING AUGMENTATION
                                        DOT..FLAG-5
1D17B..1D182  ; XID_Continue # Mn   [8] MUSICAL SYMBOL COMBINING ACCENT..LOURE
1D185..1D18B  ; XID_Continue # Mn   [7] MUSICAL SYMBOL COMBINING DOIT..
                                        MUSICAL SYMBOL COMBINING TRIPLE TONGUE
1D1AA..1D1AD  ; XID_Continue # Mn   [4] MUSICAL SYMBOL COMBINING DOWN BOW..
                                        MUSICAL SYMBOL COMBINING SNAP PIZZICATO
1D242..1D244  ; XID_Continue # Mn   [3] COMBINING GREEK MUSICAL TRISEME..
                                        COMBINING GREEK MUSICAL PENTASEME
1DA00..1DA36  ; XID_Continue # Mn  [55] SIGNWRITING HEAD RIM..
                                        SIGNWRITING AIR SUCKING IN
1DA3B..1DA6C  ; XID_Continue # Mn  [50] SIGNWRITING MOUTH CLOSED NEUTRAL..
                                        SIGNWRITING EXCITEMENT
1DA75         ; XID_Continue # Mn       SIGNWRITING UPPER BODY TILTING FROM
                                        HIP JOINTS
1DA84         ; XID_Continue # Mn       SIGNWRITING LOCATION HEAD NECK
1DA9B..1DA9F  ; XID_Continue # Mn   [5] SIGNWRITING FILL MODIFIER-2..
                                        SIGNWRITING FILL MODIFIER-6
1DAA1..1DAAF  ; XID_Continue # Mn  [15] SIGNWRITING ROTATION MODIFIER-2..-16
1E000..1E006  ; XID_Continue # Mn   [7] COMBINING GLAGOLITIC LETTER AZU..ZHIVETE
1E008..1E018  ; XID_Continue # Mn  [17] COMBINING GLAGOLITIC LETTER ZEMLJA..HERU
1E01B..1E021  ; XID_Continue # Mn   [7] COMBINING GLAGOLITIC LETTER SHTA..YATI
1E023..1E024  ; XID_Continue # Mn   [2] COMBINING GLAGOLITIC LETTER YU..SMALL YUS
1E026..1E02A  ; XID_Continue # Mn   [5] COMBINING GLAGOLITIC LETTER YO..FITA
1E130..1E136  ; XID_Continue # Mn   [7] NYIAKENG PUACHUE HMONG TONE-B..-D
1E2AE         ; XID_Continue # Mn       TOTO SIGN RISING TONE
1E2EC..1E2EF  ; XID_Continue # Mn   [4] WANCHO TONE TUP..WANCHO TONE KOINI
1E8D0..1E8D6  ; XID_Continue # Mn   [7] MENDE KIKAKUI COMBINING NUMBER TEENS..
                                        MENDE KIKAKUI COMBINING NUMBER MILLIONS
1E944..1E94A  ; XID_Continue # Mn   [7] ADLAM ALIF LENGTHENER..ADLAM NUKTA
E0100..E01EF  ; XID_Continue # Mn [240] VARIATION SELECTOR-17..-256
```

17 Appendix E - IDType Technical
=================================

Needed for **#8 TR39 Identifier Type**. List of Technical ID characters, added
the TR39 Recommended and Inclusion IDTypes. TR39#Table 1
<https://www.unicode.org/reports/tr39/#Identifier_Status_and_Type Table 1>

`grep ' Technical ' IdentifierType.txt |
egrep -v 'Not_XID|Obsolete|Exclusion|Uncommon_Use|Limited_Use'`

``` txt
0180          ; Technical  # 1.1        LATIN SMALL LETTER B WITH STROKE
01C0..01C3    ; Technical  # 1.1    [4] LATIN LETTER DENTAL CLICK..
                                        RETROFLEX CLICK
0234..0236    ; Technical  # 4.0    [3] LATIN SMALL LETTER L WITH CURL..
                                        T WITH CURL
0250..0252    ; Technical  # 1.1    [3] LATIN SMALL LETTER TURNED A..ALPHA
0255          ; Technical  # 1.1        LATIN SMALL LETTER C WITH CURL
0258          ; Technical  # 1.1        LATIN SMALL LETTER REVERSED E
025A          ; Technical  # 1.1        LATIN SMALL LETTER SCHWA WITH HOOK
025C..0262    ; Technical  # 1.1    [7] LATIN SMALL LETTER REVERSED OPEN E..
                                        LATIN LETTER SMALL CAPITAL G
0264..0267    ; Technical  # 1.1    [4] LATIN SMALL LETTER RAMS HORN..
                                        LATIN SMALL LETTER HENG WITH HOOK
026A..0271    ; Technical  # 1.1    [8] LATIN LETTER SMALL CAPITAL I..
                                        LATIN SMALL LETTER M WITH HOOK
0273..0276    ; Technical  # 1.1    [4] LATIN SMALL LETTER N WITH RETROFLEX
                                        HOOK..LATIN LETTER SMALL CAPITAL OE
0278..027B    ; Technical  # 1.1    [4] LATIN SMALL LETTER PHI..
                                        LATIN SMALL LETTER TURNED R WITH HOOK
027D..0288    ; Technical  # 1.1   [12] LATIN SMALL LETTER R WITH TAIL..
                                        LATIN SMALL LETTER T WITH RETROFLEX HOOK
028A..0291    ; Technical  # 1.1    [8] LATIN SMALL LETTER UPSILON..
                                        LATIN SMALL LETTER Z WITH CURL
0293..029D    ; Technical  # 1.1   [11] LATIN SMALL LETTER EZH WITH CURL..
                                        LATIN SMALL LETTER J WITH CROSSED-TAIL
029F..02A8    ; Technical  # 1.1   [10] LATIN LETTER SMALL CAPITAL L..
                                        LATIN SMALL LETTER TC DIGRAPH WITH CURL
02A9..02AD    ; Technical  # 3.0    [5] LATIN SMALL LETTER FENG DIGRAPH..
                                        LATIN LETTER BIDENTAL PERCUSSIVE
02AE..02AF    ; Technical  # 4.0    [2] LATIN SMALL LETTER TURNED H WITH
                                        FISHHOOK..AND TAIL
02B9..02BA    ; Technical  # 1.1    [2] MODIFIER LETTER PRIME..DOUBLE PRIME
02BD..02C1    ; Technical  # 1.1    [5] MODIFIER LETTER REVERSED COMMA..
                                        MODIFIER LETTER REVERSED GLOTTAL STOP
02C6..02D1    ; Technical  # 1.1   [12] MODIFIER LETTER CIRCUMFLEX ACCENT..
                                        MODIFIER LETTER HALF TRIANGULAR COLON
02EE          ; Technical  # 3.0        MODIFIER LETTER DOUBLE APOSTROPHE
030E          ; Technical  # 1.1        COMBINING DOUBLE VERTICAL LINE ABOVE
0312          ; Technical  # 1.1        COMBINING TURNED COMMA ABOVE
0315          ; Technical  # 1.1        COMBINING COMMA ABOVE RIGHT
0317..031A    ; Technical  # 1.1    [4] COMBINING ACUTE ACCENT BELOW..
                                        COMBINING LEFT ANGLE ABOVE
031C..0320    ; Technical  # 1.1    [5] COMBINING LEFT HALF RING BELOW..
                                        COMBINING MINUS SIGN BELOW
0329..032C    ; Technical  # 1.1    [4] COMBINING VERTICAL LINE BELOW..
                                        COMBINING CARON BELOW
032F          ; Technical  # 1.1        COMBINING INVERTED BREVE BELOW
0333          ; Technical  # 1.1        COMBINING DOUBLE LOW LINE
0337          ; Technical  # 1.1        COMBINING SHORT SOLIDUS OVERLAY
033A..033F    ; Technical  # 1.1    [6] COMBINING INVERTED BRIDGE BELOW..
                                        COMBINING DOUBLE OVERLINE
0346..034E    ; Technical  # 3.0    [9] COMBINING BRIDGE ABOVE..
                                        COMBINING UPWARDS ARROW BELOW
0350..0357    ; Technical  # 4.0    [8] COMBINING RIGHT ARROWHEAD ABOVE..
                                        HALF RING ABOVE
0359..035C    ; Technical  # 4.1    [4] COMBINING ASTERISK BELOW..
                                        COMBINING DOUBLE BREVE BELOW
035D..035F    ; Technical  # 4.0    [3] COMBINING DOUBLE BREVE..MACRON BELOW
0360..0361    ; Technical  # 1.1    [2] COMBINING DOUBLE TILDE..INVERTED BREVE
0362          ; Technical  # 3.0        COMBINING DOUBLE RIGHTWARDS ARROW BELOW
03CF          ; Technical  # 5.1        GREEK CAPITAL KAI SYMBOL
03D7          ; Technical  # 3.0        GREEK KAI SYMBOL
0560          ; Technical  # 11.0       ARMENIAN SMALL LETTER TURNED AYB
0588          ; Technical  # 11.0       ARMENIAN SMALL LETTER YI WITH STROKE
0953..0954    ; Technical  # 1.1    [2] DEVANAGARI GRAVE ACCENT..
                                        DEVANAGARI ACUTE ACCENT
0D81          ; Technical  # 13.0       SINHALA SIGN CANDRABINDU
0F18..0F19    ; Technical  # 2.0    [2] TIBETAN ASTROLOGICAL SIGN -KHYUD PA..
                                        TIBETAN ASTROLOGICAL SIGN SDONG TSHUGS
17CE..17CF    ; Technical  # 3.0    [2] KHMER SIGN KAKABAT..
                                        KHMER SIGN AHSDA
1ABF..1AC0    ; Technical  # 13.0   [2] COMBINING LATIN SMALL LETTER W BELOW..
                                        TURNED W BELOW
1D00..1D2B    ; Technical  # 4.0   [44] LATIN LETTER SMALL CAPITAL A..
                                        CYRILLIC LETTER SMALL CAPITAL EL
1D2F          ; Technical  # 4.0        MODIFIER LETTER CAPITAL BARRED B
1D3B          ; Technical  # 4.0        MODIFIER LETTER CAPITAL REVERSED N
1D4E          ; Technical  # 4.0        MODIFIER LETTER SMALL TURNED I
1D6B          ; Technical  # 4.0        LATIN SMALL LETTER UE
1D6C..1D77    ; Technical  # 4.1   [12] LATIN SMALL LETTER B WITH MIDDLE TILDE..
                                        LATIN SMALL LETTER TURNED G
1D79..1D9A    ; Technical  # 4.1   [34] LATIN SMALL LETTER INSULAR G..
                                        EZH WITH RETROFLEX HOOK
1DC4..1DCA    ; Technical  # 5.0    [7] COMBINING MACRON-ACUTE..
                                        COMBINING LATIN SMALL LETTER R BELOW
1DCB..1DCD    ; Technical  # 5.1    [3] COMBINING BREVE-MACRON..
                                        COMBINING DOUBLE CIRCUMFLEX ABOVE
1DCF..1DD0    ; Technical  # 5.1    [2] COMBINING ZIGZAG BELOW..
                                        COMBINING IS BELOW
1DE7..1DF5    ; Technical  # 7.0   [15] COMBINING LATIN SMALL LETTER ALPHA..
                                        COMBINING UP TACK ABOVE
1DF6..1DF9    ; Technical  # 10.0   [4] COMBINING KAVYKA ABOVE RIGHT..
                                        COMBINING WIDE INVERTED BRIDGE BELOW
1DFB          ; Technical  # 9.0        COMBINING DELETION MARK
1DFC          ; Technical  # 6.0        COMBINING DOUBLE INVERTED BREVE BELOW
1DFD          ; Technical  # 5.2        COMBINING ALMOST EQUAL TO BELOW
1DFE..1DFF    ; Technical  # 5.0    [2] COMBINING LEFT ARROWHEAD ABOVE..
                                        COMBINING RIGHT ARROWHEAD AND DOWN
                                        ARROWHEAD BELOW
1E9C..1E9D    ; Technical  # 5.1    [2] LATIN SMALL LETTER LONG S WITH DIAGONAL
                                        STROKE..WITH HIGH STROKE
1E9F          ; Technical  # 5.1        LATIN SMALL LETTER DELTA
1EFA..1EFF    ; Technical  # 5.1    [6] LATIN CAPITAL LETTER MIDDLE-WELSH LL..
                                        LATIN SMALL LETTER Y WITH LOOP
203F..2040    ; Technical  # 1.1    [2] UNDERTIE..
                                        CHARACTER TIE
20D0..20DC    ; Technical  # 1.1   [13] COMBINING LEFT HARPOON ABOVE..
                                        COMBINING FOUR DOTS ABOVE
20E1          ; Technical  # 1.1        COMBINING LEFT RIGHT ARROW ABOVE
20E5..20EA    ; Technical  # 3.2    [6] COMBINING REVERSE SOLIDUS OVERLAY..
                                        COMBINING LEFTWARDS ARROW OVERLAY
20EB          ; Technical  # 4.1        COMBINING LONG DOUBLE SOLIDUS OVERLAY
20EC..20EF    ; Technical  # 5.0    [4] COMBINING RIGHTWARDS HARPOON WITH BARB
                                        DOWNWARDS..COMBINING RIGHT ARROW BELOW
20F0          ; Technical  # 5.1        COMBINING ASTERISK ABOVE
2118          ; Technical  # 1.1        SCRIPT CAPITAL P
212E          ; Technical  # 1.1        ESTIMATED SYMBOL
2C60..2C67    ; Technical  # 5.0    [8] LATIN CAPITAL LETTER L WITH DOUBLE BAR..
                                        LATIN CAPITAL LETTER H WITH DESCENDER
2C77          ; Technical  # 5.0        LATIN SMALL LETTER TAILLESS PHI
2C78..2C7B    ; Technical  # 5.1    [4] LATIN SMALL LETTER E WITH NOTCH..
                                        LATIN LETTER SMALL CAPITAL TURNED E
3021..302D    ; Technical  # 1.1   [13] HANGZHOU NUMERAL ONE..
                                        IDEOGRAPHIC ENTERING TONE MARK
3031..3035    ; Technical  # 1.1    [5] VERTICAL KANA REPEAT MARK..
                                        VERTICAL KANA REPEAT MARK LOWER HALF
303B..303C    ; Technical  # 3.2    [2] VERTICAL IDEOGRAPHIC ITERATION MARK..
                                        MASU MARK
A78E          ; Technical  # 6.0        LATIN SMALL LETTER L WITH RETROFLEX HOOK
                                        AND BELT
A7AF          ; Technical  # 11.0       LATIN LETTER SMALL CAPITAL Q
A7BA..A7BF    ; Technical  # 12.0   [6] LATIN CAPITAL LETTER GLOTTAL A..
                                        LATIN SMALL LETTER GLOTTAL U
A7FA          ; Technical  # 6.0        LATIN LETTER SMALL CAPITAL TURNED M
AB68          ; Technical  # 13.0       LATIN SMALL LETTER TURNED R WITH MIDDLE
                                        TILDE
FE20..FE23    ; Technical  # 1.1    [4] COMBINING LIGATURE LEFT HALF..
                                        COMBINING DOUBLE TILDE RIGHT HALF
FE24..FE26    ; Technical  # 5.1    [3] COMBINING MACRON LEFT HALF..
                                        COMBINING CONJOINING MACRON
FE27..FE2D    ; Technical  # 7.0    [7] COMBINING LIGATURE LEFT HALF BELOW..
                                        COMBINING CONJOINING MACRON BELOW
FE73          ; Technical  # 3.2        ARABIC TAIL FRAGMENT
1CF00..1CF2D  ; Technical  # 14.0  [46] ZNAMENNY COMBINING MARK GORAZDO NIZKO S
                                        KRYZHEM ON LEFT..KRYZH ON LEFT
1CF30..1CF46  ; Technical  # 14.0  [23] ZNAMENNY COMBINING TONAL RANGE MARK
                                        MRACHNO..PRIZNAK MODIFIER ROG
1D165..1D169  ; Technical  # 3.1    [5] MUSICAL SYMBOL COMBINING STEM..TREMOLO-3
1D16D..1D172  ; Technical  # 3.1    [6] MUSICAL SYMBOL COMBINING AUGMENTATION
                                        DOT..MUSICAL SYMBOL COMBINING FLAG-5
1D17B..1D182  ; Technical  # 3.1    [8] MUSICAL SYMBOL COMBINING ACCENT..LOURE
1D185..1D18B  ; Technical  # 3.1    [7] MUSICAL SYMBOL COMBINING DOIT..
                                        MUSICAL SYMBOL COMBINING TRIPLE TONGUE
1D1AA..1D1AD  ; Technical  # 3.1    [4] MUSICAL SYMBOL COMBINING DOWN BOW..
                                        MUSICAL SYMBOL COMBINING SNAP PIZZICATO
```

18 References
=============

* [AltId] Unicode Standard Annex.
  <http://www.unicode.org/reports/tr31/tr31-11.html#Alternative_Identifier_Syntax>

* [DefId] Unicode Standard Annex.
  <http://www.unicode.org/reports/tr31/tr31-11.html#Default_Identifier_Syntax>

* [ISO 15924 Codes] TR24 Unicode Script Property Values and ISO 15924 Codes.
  <https://www.unicode.org/reports/tr24/#Relation_To_ISO15924>

* [libu8ident] Reini Urban. 2020. unicode security guidelines for identifiers
  <https://github.com/rurban/libu8ident/>

* [N3146] Clark Nelson. 2010. Recommendations for extended identifier
  characters for C and C++.
  <https://wg21.link/n3146>

* [P1949] Steve Downey et al. 2021. C++ Identifier Syntax using Unicode
  Standard Annex 31
  <http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1949r7.html>

* [TR15] Ken Whistler. Unicode Normalization Forms.
  <http://www.unicode.org/reports/tr15>

* [TR24] Ken Whistler. Unicode Script Property.
  <https://www.unicode.org/reports/tr24/#Common>

* [TR24#5.1] Handling Characters with the Common Script Property
  <https://www.unicode.org/reports/tr24/#Common>

* [TR24#5.2] Handling Combining Marks
  <https://www.unicode.org/reports/tr24/#Nonspacing_Marks>

* [TR31] Mark Davis. Unicode Identifier and Pattern Syntax.
  <http://www.unicode.org/reports/tr31>

* [TR31#2.1] Combining Marks
  <https://www.unicode.org/reports/tr31/#Combining_Marks>

* [TR31#2.2] Modifier Letters
  <https://www.unicode.org/reports/tr31/#Modifier_Letters>

* [TR31#Table 4] Table Candidate Characters for Exclusion from Identifiers
  <https://www.unicode.org/reports/tr31/#Table_Candidate_Characters_for_Exclusion_from_Identifiers>

* [TR31#Table 7] Limited Use Scripts
  <http://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts>

* [TR36] Mark Davis and Michel Suignard. Unicode Security Considerations.
  <http://www.unicode.org/reports/tr36>

* [TR39] Mark Davis and Michel Suignard. Unicode Security Mechanisms.
  <http://www.unicode.org/reports/tr36>

* [TR39#Table 1] Identifier Status and Type Table
  <https://www.unicode.org/reports/tr39/#Identifier_Status_and_Type Table 1>

* [TR39#5.2] Mixed-Scripts Restriction-Level Detection
  <https://www.unicode.org/reports/tr39/#Restriction_Level_Detection>

* [TR39#5.4] Optional Detection
  <https://www.unicode.org/reports/tr39/#Optional_Detection>

* [TR44] Ken Whistler and Laurențiu Iancu. Unicode Character Database.
  <http://www.unicode.org/reports/tr44>

* [TR46] Mark Davis and Michel Suignard. Unicode IDNA Compatibility Processing.
  <http://www.unicode.org/reports/tr46>
