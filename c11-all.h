/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021, 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   Generated by mkc26 from unic11.h.
   UNICODE version 16.0
*/
static const struct range_bool c11_start_list[] = {
    {'$', '$'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'},
    {0x00A8, 0x00A8},   {0x00AA, 0x00AA},
    {0x00AD, 0x00AD},   {0x00AF, 0x00AF},   {0x00B2, 0x00B5},
    {0x00B7, 0x00BA},   {0x00BC, 0x00BE},   {0x00C0, 0x00D6},
    {0x00D8, 0x00F6},   {0x00F8, 0x00FF},
    // {0x0100, 0x02FF}, // Latin, 2B0-2FF: Modifiers (2EA Bopomofo)
    {0xFF, 0x2FF}, // Latin ÿ..˿
    {0x370, 0x167F}, // Greek Ͱ..ᙿ
    {0x1681, 0x180D}, // Ogham (Excluded) ᚁ..᠍
    {0x180F, 0x1DBF}, // Mongolian (Excluded) ᠏..ᶿ
    {0x1E00, 0x1FFF}, // Latin Ḁ..῿
    {0x200B, 0x200D}, // Common ​..‍
    {0x202A, 0x202E}, // Common ‪..‮
    {0x203F, 0x2040}, // Common ‿..⁀
    {0x2054, 0x2054}, // Common ⁔
    {0x2060, 0x20CF}, // Common ⁠..⃏
    {0x2100, 0x218F}, // Common ℀..↏
    {0x2460, 0x24FF}, // Common ①..⓿
    {0x2776, 0x2793}, // Common ❶..➓
    {0x2C00, 0x2DFF}, // Glagolitic (Excluded) Ⰰ..ⷿ
    {0x2E80, 0x2FFF}, // Han ⺀..⿿
    {0x3004, 0x3007}, // Common 〄..〇
    {0x3021, 0x302F}, // Han 〡..〯
    {0x3031, 0xD7FF}, // Common 〱..퟿
    {0xF900, 0xFD3D}, // Han 豈..ﴽ
    {0xFD40, 0xFDCF}, // Arabic ﵀..﷏
    {0xFDF0, 0xFE1F}, // Arabic ﷰ..︟
    {0xFE30, 0xFE44}, // Common ︰..﹄
    {0xFE47, 0xFFFD}, // Common ﹇..�
    {0x10000, 0x1FFFD}, // Linear_B (Excluded) 𐀀..🿽
    {0x20000, 0x2FFFD}, // Han 𠀀..𯿽
    {0x30000, 0x3FFFD}, // Han 𰀀..𿿽
    {0x40000, 0x4FFFD}, // (null) (Limited) 񀀀..񏿽
    {0x50000, 0x5FFFD}, // (null) (Limited) 񐀀..񟿽
    {0x60000, 0x6FFFD}, // (null) (Limited) 񠀀..񯿽
    {0x70000, 0x7FFFD}, // (null) (Limited) 񰀀..񿿽
    {0x80000, 0x8FFFD}, // (null) (Limited) 򀀀..򏿽
    {0x90000, 0x9FFFD}, // (null) (Limited) 򐀀..򟿽
    {0xA0000, 0xAFFFD}, // (null) (Limited) 򠀀..򯿽
    {0xB0000, 0xBFFFD}, // (null) (Limited) 򰀀..򿿽
    {0xC0000, 0xCFFFD}, // (null) (Limited) 󀀀..󏿽
    {0xD0000, 0xDFFFD}, // (null) (Limited) 󐀀..󟿽
    {0xE0000, 0xEFFFD}, // (null) (Limited) 󠀀..󯿽
}; // 36 ranges, 1 singles, 971267 codepoints
static const struct range_bool c11_cont_list[] = {
    {'$', '$'},
    {'0', '9'},
    {0x300, 0x36F}, // Inherited ̀..ͯ
    {0x1DC0, 0x1DFF}, // Inherited ᷀..᷿
    {0x20D0, 0x20FF}, // Inherited ⃐..⃿
    {0xFE20, 0xFE2F}, // Inherited ︠..︯
}; // 4 ranges, 0 singles, 236 codepoints
