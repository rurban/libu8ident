TR31 Security Bugs (UCD Versions 1-14)
======================================

U+FF00..U+FFEF not as ID
---------------------------

Most of the U+FF00..U+FFEF Full and Halfwidth letters have incorrectly
`ID_Start` resp.  `ID_Continue` properties. XID ditto.
They should not, because they are confusable with the normal
characters in the base planes.  E.g. LATIN A-Z are indistuingishable
from Ａ..Ｚ, LATIN a-z from ａ..ｚ, likewise for the Katakana ｦ..ｯ and
ｱ..ﾝ, and the Hangul ﾠ..ﾾ, ￂ..ￇ, ￊ..ￏ, ￒ..ￗ ￚ..ￜ halfwidth letters.

This is esp. for TR39 a security risk. TR39 provides Identifier Type
properties to exclude insecure identifiers, but I cannot find any
other type property to set these U+FF21..U+FFDC IDs to, than
`Not_XID`. Thus the `ID_Start`/`ID_Continue` property should be
deleted for all of them. If they are not identifiable, they should not
be marked as such.

Medial letters in `ID_Start`, not `ID_Continue`
-------------------------------------------------

DerivedCoreProperties lists all of the Arabic and Thai MEDIAL letters,
which are part of identifiers in `ID_Start`, not in `ID Continue`. Only
the Combining marks are in `ID_Continue`.  Thus all unicode-aware
parsers accept such MEDIAL letters incorrectly in the start
position. They should only be allowed in the `ID_Continue` position,
and parsers should disallow them in the end positions for identifiers.

All the other medial letters (Myanmar, Canadian Aboriginal, Ahom,
Dives Akuru) are not part of Recommended Scripts, so they do not
affect TR39 security. But since almost nobody but Java, cperl and Rust
honor TR39 it's still affecting most parsers.

Other medial exceptions are noted in TR31 at 2.4 Specific Character
Adjustments, but the tables DerivedCoreProperties and TR39 Identifier
tables and thus all user parsers are wrong.
<https://www.unicode.org/reports/tr31/#Specific_Character_Adjustments>