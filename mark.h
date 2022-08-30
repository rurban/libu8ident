/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2014, 2021, 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   All Combining_Mark (Mc | Me | Mn),
   All letters with non-spacing combining marks.
   Generated by mkmark.pl, do not modify.
*/
#include <stdint.h>
#include <wchar.h>

struct nsm_ws {
    uint32_t nsm;
    wchar_t  *letters;
};

/* All Combining Marks, sorted */
#ifdef EXTERN_SCRIPTS
extern const struct range_bool mark_list[299];
#else
const struct range_bool mark_list[] = {
    // clang-format off
    { 0x300, 0x36F },
    { 0x483, 0x489 },
    { 0x591, 0x5BD },
    { 0x5BF, 0x5BF },
    { 0x5C1, 0x5C2 },
    { 0x5C4, 0x5C5 },
    { 0x5C7, 0x5C7 },
    { 0x610, 0x61A },
    { 0x64B, 0x65F },
    { 0x670, 0x670 },
    { 0x6D6, 0x6DC },
    { 0x6DF, 0x6E4 },
    { 0x6E7, 0x6E8 },
    { 0x6EA, 0x6ED },
    { 0x711, 0x711 },
    { 0x730, 0x74A },
    { 0x7A6, 0x7B0 },
    { 0x7EB, 0x7F3 },
    { 0x7FD, 0x7FD },
    { 0x816, 0x819 },
    { 0x81B, 0x823 },
    { 0x825, 0x827 },
    { 0x829, 0x82D },
    { 0x859, 0x85B },
    { 0x898, 0x89F },
    { 0x8CA, 0x8E1 },
    { 0x8E3, 0x903 },
    { 0x93A, 0x93C },
    { 0x93E, 0x94F },
    { 0x951, 0x957 },
    { 0x962, 0x963 },
    { 0x981, 0x983 },
    { 0x9BC, 0x9BC },
    { 0x9BE, 0x9C4 },
    { 0x9C7, 0x9C8 },
    { 0x9CB, 0x9CD },
    { 0x9D7, 0x9D7 },
    { 0x9E2, 0x9E3 },
    { 0x9FE, 0x9FE },
    { 0xA01, 0xA03 },
    { 0xA3C, 0xA3C },
    { 0xA3E, 0xA42 },
    { 0xA47, 0xA48 },
    { 0xA4B, 0xA4D },
    { 0xA51, 0xA51 },
    { 0xA70, 0xA71 },
    { 0xA75, 0xA75 },
    { 0xA81, 0xA83 },
    { 0xABC, 0xABC },
    { 0xABE, 0xAC5 },
    { 0xAC7, 0xAC9 },
    { 0xACB, 0xACD },
    { 0xAE2, 0xAE3 },
    { 0xAFA, 0xAFF },
    { 0xB01, 0xB03 },
    { 0xB3C, 0xB3C },
    { 0xB3E, 0xB44 },
    { 0xB47, 0xB48 },
    { 0xB4B, 0xB4D },
    { 0xB55, 0xB57 },
    { 0xB62, 0xB63 },
    { 0xB82, 0xB82 },
    { 0xBBE, 0xBC2 },
    { 0xBC6, 0xBC8 },
    { 0xBCA, 0xBCD },
    { 0xBD7, 0xBD7 },
    { 0xC00, 0xC04 },
    { 0xC3C, 0xC3C },
    { 0xC3E, 0xC44 },
    { 0xC46, 0xC48 },
    { 0xC4A, 0xC4D },
    { 0xC55, 0xC56 },
    { 0xC62, 0xC63 },
    { 0xC81, 0xC83 },
    { 0xCBC, 0xCBC },
    { 0xCBE, 0xCC4 },
    { 0xCC6, 0xCC8 },
    { 0xCCA, 0xCCD },
    { 0xCD5, 0xCD6 },
    { 0xCE2, 0xCE3 },
    { 0xD00, 0xD03 },
    { 0xD3B, 0xD3C },
    { 0xD3E, 0xD44 },
    { 0xD46, 0xD48 },
    { 0xD4A, 0xD4D },
    { 0xD57, 0xD57 },
    { 0xD62, 0xD63 },
    { 0xD81, 0xD83 },
    { 0xDCA, 0xDCA },
    { 0xDCF, 0xDD4 },
    { 0xDD6, 0xDD6 },
    { 0xDD8, 0xDDF },
    { 0xDF2, 0xDF3 },
    { 0xE31, 0xE31 },
    { 0xE34, 0xE3A },
    { 0xE47, 0xE4E },
    { 0xEB1, 0xEB1 },
    { 0xEB4, 0xEBC },
    { 0xEC8, 0xECD },
    { 0xF18, 0xF19 },
    { 0xF35, 0xF35 },
    { 0xF37, 0xF37 },
    { 0xF39, 0xF39 },
    { 0xF3E, 0xF3F },
    { 0xF71, 0xF84 },
    { 0xF86, 0xF87 },
    { 0xF8D, 0xF97 },
    { 0xF99, 0xFBC },
    { 0xFC6, 0xFC6 },
    { 0x102B, 0x103E },
    { 0x1056, 0x1059 },
    { 0x105E, 0x1060 },
    { 0x1062, 0x1064 },
    { 0x1067, 0x106D },
    { 0x1071, 0x1074 },
    { 0x1082, 0x108D },
    { 0x108F, 0x108F },
    { 0x109A, 0x109D },
    { 0x135D, 0x135F },
    { 0x1712, 0x1715 },
    { 0x1732, 0x1734 },
    { 0x1752, 0x1753 },
    { 0x1772, 0x1773 },
    { 0x17B4, 0x17D3 },
    { 0x17DD, 0x17DD },
    { 0x180B, 0x180D },
    { 0x180F, 0x180F },
    { 0x1885, 0x1886 },
    { 0x18A9, 0x18A9 },
    { 0x1920, 0x192B },
    { 0x1930, 0x193B },
    { 0x1A17, 0x1A1B },
    { 0x1A55, 0x1A5E },
    { 0x1A60, 0x1A7C },
    { 0x1A7F, 0x1A7F },
    { 0x1AB0, 0x1ACE },
    { 0x1B00, 0x1B04 },
    { 0x1B34, 0x1B44 },
    { 0x1B6B, 0x1B73 },
    { 0x1B80, 0x1B82 },
    { 0x1BA1, 0x1BAD },
    { 0x1BE6, 0x1BF3 },
    { 0x1C24, 0x1C37 },
    { 0x1CD0, 0x1CD2 },
    { 0x1CD4, 0x1CE8 },
    { 0x1CED, 0x1CED },
    { 0x1CF4, 0x1CF4 },
    { 0x1CF7, 0x1CF9 },
    { 0x1DC0, 0x1DFF },
    { 0x20D0, 0x20F0 },
    { 0x2CEF, 0x2CF1 },
    { 0x2D7F, 0x2D7F },
    { 0x2DE0, 0x2DFF },
    { 0x302A, 0x302F },
    { 0x3099, 0x309A },
    { 0xA66F, 0xA672 },
    { 0xA674, 0xA67D },
    { 0xA69E, 0xA69F },
    { 0xA6F0, 0xA6F1 },
    { 0xA802, 0xA802 },
    { 0xA806, 0xA806 },
    { 0xA80B, 0xA80B },
    { 0xA823, 0xA827 },
    { 0xA82C, 0xA82C },
    { 0xA880, 0xA881 },
    { 0xA8B4, 0xA8C5 },
    { 0xA8E0, 0xA8F1 },
    { 0xA8FF, 0xA8FF },
    { 0xA926, 0xA92D },
    { 0xA947, 0xA953 },
    { 0xA980, 0xA983 },
    { 0xA9B3, 0xA9C0 },
    { 0xA9E5, 0xA9E5 },
    { 0xAA29, 0xAA36 },
    { 0xAA43, 0xAA43 },
    { 0xAA4C, 0xAA4D },
    { 0xAA7B, 0xAA7D },
    { 0xAAB0, 0xAAB0 },
    { 0xAAB2, 0xAAB4 },
    { 0xAAB7, 0xAAB8 },
    { 0xAABE, 0xAABF },
    { 0xAAC1, 0xAAC1 },
    { 0xAAEB, 0xAAEF },
    { 0xAAF5, 0xAAF6 },
    { 0xABE3, 0xABEA },
    { 0xABEC, 0xABED },
    { 0xFB1E, 0xFB1E },
    { 0xFE00, 0xFE0F },
    { 0xFE20, 0xFE2F },
    { 0x101FD, 0x101FD },
    { 0x102E0, 0x102E0 },
    { 0x10376, 0x1037A },
    { 0x10A01, 0x10A03 },
    { 0x10A05, 0x10A06 },
    { 0x10A0C, 0x10A0F },
    { 0x10A38, 0x10A3A },
    { 0x10A3F, 0x10A3F },
    { 0x10AE5, 0x10AE6 },
    { 0x10D24, 0x10D27 },
    { 0x10EAB, 0x10EAC },
    { 0x10F46, 0x10F50 },
    { 0x10F82, 0x10F85 },
    { 0x11000, 0x11002 },
    { 0x11038, 0x11046 },
    { 0x11070, 0x11070 },
    { 0x11073, 0x11074 },
    { 0x1107F, 0x11082 },
    { 0x110B0, 0x110BA },
    { 0x110C2, 0x110C2 },
    { 0x11100, 0x11102 },
    { 0x11127, 0x11134 },
    { 0x11145, 0x11146 },
    { 0x11173, 0x11173 },
    { 0x11180, 0x11182 },
    { 0x111B3, 0x111C0 },
    { 0x111C9, 0x111CC },
    { 0x111CE, 0x111CF },
    { 0x1122C, 0x11237 },
    { 0x1123E, 0x1123E },
    { 0x112DF, 0x112EA },
    { 0x11300, 0x11303 },
    { 0x1133B, 0x1133C },
    { 0x1133E, 0x11344 },
    { 0x11347, 0x11348 },
    { 0x1134B, 0x1134D },
    { 0x11357, 0x11357 },
    { 0x11362, 0x11363 },
    { 0x11366, 0x1136C },
    { 0x11370, 0x11374 },
    { 0x11435, 0x11446 },
    { 0x1145E, 0x1145E },
    { 0x114B0, 0x114C3 },
    { 0x115AF, 0x115B5 },
    { 0x115B8, 0x115C0 },
    { 0x115DC, 0x115DD },
    { 0x11630, 0x11640 },
    { 0x116AB, 0x116B7 },
    { 0x1171D, 0x1172B },
    { 0x1182C, 0x1183A },
    { 0x11930, 0x11935 },
    { 0x11937, 0x11938 },
    { 0x1193B, 0x1193E },
    { 0x11940, 0x11940 },
    { 0x11942, 0x11943 },
    { 0x119D1, 0x119D7 },
    { 0x119DA, 0x119E0 },
    { 0x119E4, 0x119E4 },
    { 0x11A01, 0x11A0A },
    { 0x11A33, 0x11A39 },
    { 0x11A3B, 0x11A3E },
    { 0x11A47, 0x11A47 },
    { 0x11A51, 0x11A5B },
    { 0x11A8A, 0x11A99 },
    { 0x11C2F, 0x11C36 },
    { 0x11C38, 0x11C3F },
    { 0x11C92, 0x11CA7 },
    { 0x11CA9, 0x11CB6 },
    { 0x11D31, 0x11D36 },
    { 0x11D3A, 0x11D3A },
    { 0x11D3C, 0x11D3D },
    { 0x11D3F, 0x11D45 },
    { 0x11D47, 0x11D47 },
    { 0x11D8A, 0x11D8E },
    { 0x11D90, 0x11D91 },
    { 0x11D93, 0x11D97 },
    { 0x11EF3, 0x11EF6 },
    { 0x16AF0, 0x16AF4 },
    { 0x16B30, 0x16B36 },
    { 0x16F4F, 0x16F4F },
    { 0x16F51, 0x16F87 },
    { 0x16F8F, 0x16F92 },
    { 0x16FE4, 0x16FE4 },
    { 0x16FF0, 0x16FF1 },
    { 0x1BC9D, 0x1BC9E },
    { 0x1CF00, 0x1CF2D },
    { 0x1CF30, 0x1CF46 },
    { 0x1D165, 0x1D169 },
    { 0x1D16D, 0x1D172 },
    { 0x1D17B, 0x1D182 },
    { 0x1D185, 0x1D18B },
    { 0x1D1AA, 0x1D1AD },
    { 0x1D242, 0x1D244 },
    { 0x1DA00, 0x1DA36 },
    { 0x1DA3B, 0x1DA6C },
    { 0x1DA75, 0x1DA75 },
    { 0x1DA84, 0x1DA84 },
    { 0x1DA9B, 0x1DA9F },
    { 0x1DAA1, 0x1DAAF },
    { 0x1E000, 0x1E006 },
    { 0x1E008, 0x1E018 },
    { 0x1E01B, 0x1E021 },
    { 0x1E023, 0x1E024 },
    { 0x1E026, 0x1E02A },
    { 0x1E130, 0x1E136 },
    { 0x1E2AE, 0x1E2AE },
    { 0x1E2EC, 0x1E2EF },
    { 0x1E8D0, 0x1E8D6 },
    { 0x1E944, 0x1E94A },
    { 0xE0100, 0xE01EF },
    // clang-format on
};
#endif

/* All non-spacing combining marks, sorted */
enum nsm_marks {
    NSM_GRAVE,	/* 300 */
    NSM_ACUTE,	/* 301 */
    NSM_CIRCUMFLEX,	/* 302 */
    NSM_TILDE,	/* 303 */
    NSM_MACRON,	/* 304 */
    NSM_BREVE,	/* 306 */
    NSM_DOT_ABOVE,	/* 307 */
    NSM_DIAERESIS,	/* 308 */
    NSM_HOOK_ABOVE,	/* 309 */
    NSM_RING_ABOVE,	/* 30A */
    NSM_DOUBLE_ACUTE,	/* 30B */
    NSM_HACEK,	/* 30C */
    NSM_DOUBLE_GRAVE,	/* 30F */
    NSM_INVERTED_BREVE,	/* 311 */
    NSM_COMMA_ABOVE,	/* 313 */
    NSM_REVERSED_COMMA_ABOVE,	/* 314 */
    NSM_HORN,	/* 31B */
    NSM_DOT_BELOW,	/* 323 */
    NSM_DOUBLE_DOT_BELOW,	/* 324 */
    NSM_RING_BELOW,	/* 325 */
    NSM_COMMA_BELOW,	/* 326 */
    NSM_CEDILLA,	/* 327 */
    NSM_OGONEK,	/* 328 */
    NSM_CIRCUMFLEX_BELOW,	/* 32D */
    NSM_BREVE_BELOW,	/* 32E */
    NSM_TILDE_BELOW,	/* 330 */
    NSM_MACRON_BELOW,	/* 331 */
    NSM_THREE_DOTS_ABOVE,	/* 20DB */
    NSM_FOUR_DOTS_ABOVE,	/* 20DC */
    NSM_KATAKANA_HIRAGANA_VOICED_SOUND_MARK,	/* 3099 */
    NSM_KATAKANA_HIRAGANA_SEMI_VOICED_SOUND_MARK,	/* 309A */
    NSM_LAST
};

/* All letters with non-spacing combining marks, sorted.
   The first entry is the NSM, if letters exist.
 */
#ifdef EXTERN_SCRIPTS
extern const struct nsm_ws nsm_letters[31];
#else
const struct nsm_ws nsm_letters[] = {
    // clang-format off
    { 0x0300,  /* NSM: GRAVE 300 */
      L"\u00C0\u00C8\u00CC\u00D2\u00D9\u00E0\u00E8\u00EC\u00F2\u00F9\u01DB\u01DC\u01F8\u01F9\u0400\u040D\u0450\u045D\u1E14\u1E15\u1E50\u1E51\u1E80\u1E81\u1EA6\u1EA7\u1EB0\u1EB1\u1EC0\u1EC1\u1ED2\u1ED3\u1EDC\u1EDD\u1EEA\u1EEB\u1EF2\u1EF3\u1F02\u1F03\u1F0A\u1F0B\u1F12\u1F13\u1F1A\u1F1B\u1F22\u1F23\u1F2A\u1F2B\u1F32\u1F33\u1F3A\u1F3B\u1F42\u1F43\u1F4A\u1F4B\u1F52\u1F53\u1F5B\u1F62\u1F63\u1F6A\u1F6B\u1F70\u1F72\u1F74\u1F76\u1F78\u1F7A\u1F7C\u1FBA\u1FC8\u1FCA\u1FD2\u1FDA\u1FE2\u1FEA\u1FF8\u1FFA" },
      /* ÀÈÌÒÙàèìòùǛǜǸǹЀЍѐѝḔḕṐṑẀẁẦầẰằỀềỒồỜờỪừỲỳἂἃἊἋἒἓἚἛἢἣἪἫἲἳἺἻὂὃὊὋὒὓὛὢὣὪὫὰὲὴὶὸὺὼᾺῈῊῒῚῢῪῸῺ */
    { 0x0301,  /* NSM: ACUTE 301 */
      L"\u00C1\u00C9\u00CD\u00D3\u00DA\u00DD\u00E1\u00E9\u00ED\u00F3\u00FA\u00FD\u0106\u0107\u0139\u013A\u0143\u0144\u0154\u0155\u015A\u015B\u0179\u017A\u01D7\u01D8\u01F4\u01F5\u01FA\u01FB\u01FC\u01FD\u01FE\u01FF\u0386\u0388\u0389\u038A\u038C\u038E\u038F\u0390\u03AC\u03AD\u03AE\u03AF\u03B0\u03CC\u03CD\u03CE\u03D3\u0403\u040C\u0453\u045C\u1E08\u1E09\u1E16\u1E17\u1E2E\u1E2F\u1E30\u1E31\u1E3E\u1E3F\u1E4C\u1E4D\u1E52\u1E53\u1E54\u1E55\u1E78\u1E79\u1E82\u1E83\u1EA4\u1EA5\u1EAE\u1EAF\u1EBE\u1EBF\u1ED0\u1ED1\u1EDA\u1EDB\u1EE8\u1EE9\u1F04\u1F05\u1F0C\u1F0D\u1F14\u1F15\u1F1C\u1F1D\u1F24\u1F25\u1F2C\u1F2D\u1F34\u1F35\u1F3C\u1F3D\u1F44\u1F45\u1F4C\u1F4D\u1F54\u1F55\u1F5D\u1F64\u1F65\u1F6C\u1F6D" },
      /* ÁÉÍÓÚÝáéíóúýĆćĹĺŃńŔŕŚśŹźǗǘǴǵǺǻǼǽǾǿΆΈΉΊΌΎΏΐάέήίΰόύώϓЃЌѓќḈḉḖḗḮḯḰḱḾḿṌṍṒṓṔṕṸṹẂẃẤấẮắẾếỐốỚớỨứἄἅἌἍἔἕἜἝἤἥἬἭἴἵἼἽὄὅὌὍὔὕὝὤὥὬὭ */
    { 0x0302,  /* NSM: CIRCUMFLEX 302 */
      L"\u00C2\u00CA\u00CE\u00D4\u00DB\u00E2\u00EA\u00EE\u00F4\u00FB\u0108\u0109\u011C\u011D\u0124\u0125\u0134\u0135\u015C\u015D\u0174\u0175\u0176\u0177\u1E90\u1E91\u1EAC\u1EAD\u1EC6\u1EC7\u1ED8\u1ED9" },
      /* ÂÊÎÔÛâêîôûĈĉĜĝĤĥĴĵŜŝŴŵŶŷẐẑẬậỆệỘộ */
    { 0x0303,  /* NSM: TILDE 303 */
      L"\u00C3\u00D1\u00D5\u00E3\u00F1\u00F5\u0128\u0129\u0168\u0169\u1E7C\u1E7D\u1EAA\u1EAB\u1EB4\u1EB5\u1EBC\u1EBD\u1EC4\u1EC5\u1ED6\u1ED7\u1EE0\u1EE1\u1EEE\u1EEF\u1EF8\u1EF9" },
      /* ÃÑÕãñõĨĩŨũṼṽẪẫẴẵẼẽỄễỖỗỠỡỮữỸỹ */
    { 0x0304,  /* NSM: MACRON 304 */
      L"\u0100\u0101\u0112\u0113\u012A\u012B\u014C\u014D\u016A\u016B\u01D5\u01D6\u01DE\u01DF\u01E0\u01E1\u01E2\u01E3\u01EC\u01ED\u022A\u022B\u022C\u022D\u0230\u0231\u0232\u0233\u04E2\u04E3\u04EE\u04EF\u1E20\u1E21\u1E38\u1E39\u1E5C\u1E5D\u1FB1\u1FB9\u1FD1\u1FD9\u1FE1\u1FE9" },
      /* ĀāĒēĪīŌōŪūǕǖǞǟǠǡǢǣǬǭȪȫȬȭȰȱȲȳӢӣӮӯḠḡḸḹṜṝᾱᾹῑῙῡῩ */
    { 0x0306,  /* NSM: BREVE 306 */
      L"\u0102\u0103\u0114\u0115\u011E\u011F\u012C\u012D\u014E\u014F\u016C\u016D\u040E\u0419\u0439\u045E\u04C1\u04C2\u04D0\u04D1\u04D6\u04D7\u1E1C\u1E1D\u1EB6\u1EB7\u1FB0\u1FB8\u1FD0\u1FD8\u1FE0\u1FE8" },
      /* ĂăĔĕĞğĬĭŎŏŬŭЎЙйўӁӂӐӑӖӗḜḝẶặᾰᾸῐῘῠῨ */
    { 0x0307,  /* NSM: DOT ABOVE 307 */
      L"\u010A\u010B\u0116\u0117\u0120\u0121\u0130\u017B\u017C\u0226\u0227\u022E\u022F\u06A7\u06AC\u06B6\u06BF\u06CF\u0762\u0765\u087A\u1DA1\u1E02\u1E03\u1E0A\u1E0B\u1E1E\u1E1F\u1E22\u1E23\u1E40\u1E41\u1E44\u1E45\u1E56\u1E57\u1E58\u1E59\u1E60\u1E61\u1E64\u1E65\u1E66\u1E67\u1E68\u1E69\u1E6A\u1E6B\u1E86\u1E87\u1E8A\u1E8B\u1E8E\u1E8F\u1E9B\u312E\U00010798\U00010EB0" },
      /* ĊċĖėĠġİŻżȦȧȮȯڧڬڶڿۏݢݥࡺᶡḂḃḊḋḞḟḢḣṀṁṄṅṖṗṘṙṠṡṤṥṦṧṨṩṪṫẆẇẊẋẎẏẛㄮ𐞘𐺰 */
    { 0x0308,  /* NSM: DIAERESIS 308 */
      L"\u00C4\u00CB\u00CF\u00D6\u00DC\u00E4\u00EB\u00EF\u00F6\u00FC\u00FF\u0178\u03AA\u03AB\u03CA\u03CB\u03D4\u0401\u0407\u0451\u0457\u04D2\u04D3\u04DA\u04DB\u04DC\u04DD\u04DE\u04DF\u04E4\u04E5\u04E6\u04E7\u04EA\u04EB\u04EC\u04ED\u04F0\u04F1\u04F4\u04F5\u04F8\u04F9\u1DF2\u1DF3\u1DF4\u1E26\u1E27\u1E4E\u1E4F\u1E7A\u1E7B\u1E84\u1E85\u1E8C\u1E8D\u1E97" },
      /* ÄËÏÖÜäëïöüÿŸΪΫϊϋϔЁЇёїӒӓӚӛӜӝӞӟӤӥӦӧӪӫӬӭӰӱӴӵӸӹᷲᷳᷴḦḧṎṏṺṻẄẅẌẍẗ */
    { 0x0309,  /* NSM: HOOK ABOVE 309 */
      L"\u1EA2\u1EA3\u1EA8\u1EA9\u1EB2\u1EB3\u1EBA\u1EBB\u1EC2\u1EC3\u1EC8\u1EC9\u1ECE\u1ECF\u1ED4\u1ED5\u1EDE\u1EDF\u1EE6\u1EE7\u1EEC\u1EED\u1EF6\u1EF7" },
      /* ẢảẨẩẲẳẺẻỂểỈỉỎỏỔổỞởỦủỬửỶỷ */
    { 0x030A,  /* NSM: RING ABOVE 30A */
      L"\u00C5\u00E5\u016E\u016F\u1E98\u1E99" },
      /* ÅåŮůẘẙ */
    { 0x030B,  /* NSM: DOUBLE ACUTE 30B */
      L"\u0150\u0151\u0170\u0171\u04F2\u04F3" },
      /* ŐőŰűӲӳ */
    { 0x030C,  /* NSM: HACEK 30C */
      L"\u010C\u010D\u010E\u010F\u011A\u011B\u013D\u013E\u0147\u0148\u0158\u0159\u0160\u0161\u0164\u0165\u017D\u017E\u01CD\u01CE\u01CF\u01D0\u01D1\u01D2\u01D3\u01D4\u01D9\u01DA\u01E6\u01E7\u01E8\u01E9\u01EE\u01EF\u01F0\u021E\u021F" },
      /* ČčĎďĚěĽľŇňŘřŠšŤťŽžǍǎǏǐǑǒǓǔǙǚǦǧǨǩǮǯǰȞȟ */
    { 0x030F,  /* NSM: DOUBLE GRAVE 30F */
      L"\u0200\u0201\u0204\u0205\u0208\u0209\u020C\u020D\u0210\u0211\u0214\u0215\u0476\u0477" },
      /* ȀȁȄȅȈȉȌȍȐȑȔȕѶѷ */
    { 0x0311,  /* NSM: INVERTED BREVE 311 */
      L"\u0202\u0203\u0206\u0207\u020A\u020B\u020E\u020F\u0212\u0213\u0216\u0217" },
      /* ȂȃȆȇȊȋȎȏȒȓȖȗ */
    { 0x0313,  /* NSM: COMMA ABOVE 313 */
      L"\u1F00\u1F08\u1F10\u1F18\u1F20\u1F28\u1F30\u1F38\u1F40\u1F48\u1F50\u1F60\u1F68\u1FE4" },
      /* ἀἈἐἘἠἨἰἸὀὈὐὠὨῤ */
    { 0x0314,  /* NSM: REVERSED COMMA ABOVE 314 */
      L"\u1F01\u1F09\u1F11\u1F19\u1F21\u1F29\u1F31\u1F39\u1F41\u1F49\u1F51\u1F59\u1F61\u1F69\u1FE5\u1FEC" },
      /* ἁἉἑἙἡἩἱἹὁὉὑὙὡὩῥῬ */
    { 0x031B,  /* NSM: HORN 31B */
      L"\u01A0\u01A1\u01AF\u01B0" },
      /* ƠơƯư */
    { 0x0323,  /* NSM: DOT BELOW 323 */
      L"\u068A\u0694\u06A3\u06B9\u06FA\u06FB\u06FC\u0766\u088B\u08A5\u08B4\u1E04\u1E05\u1E0C\u1E0D\u1E24\u1E25\u1E32\u1E33\u1E36\u1E37\u1E42\u1E43\u1E46\u1E47\u1E5A\u1E5B\u1E62\u1E63\u1E6C\u1E6D\u1E7E\u1E7F\u1E88\u1E89\u1E92\u1E93\u1EA0\u1EA1\u1EB8\u1EB9\u1ECA\u1ECB\u1ECC\u1ECD\u1EE2\u1EE3\u1EE4\u1EE5\u1EF0\u1EF1\u1EF4\u1EF5\U0001BC26" },
      /* ڊڔڣڹۺۻۼݦࢋࢥࢴḄḅḌḍḤḥḲḳḶḷṂṃṆṇṚṛṢṣṬṭṾṿẈẉẒẓẠạẸẹỊịỌọỢợỤụỰựỴỵ𛰦 */
    { 0x0324,  /* NSM: DOUBLE DOT BELOW 324 */
      L"\u1E72\u1E73" },
      /* Ṳṳ */
    { 0x0325,  /* NSM: RING BELOW 325 */
      L"\u1E00\u1E01" },
      /* Ḁḁ */
    { 0x0326,  /* NSM: COMMA BELOW 326 */
      L"\u0218\u0219\u021A\u021B" },
      /* ȘșȚț */
    { 0x0327,  /* NSM: CEDILLA 327 */
      L"\u00C7\u00E7\u0122\u0123\u0136\u0137\u013B\u013C\u0145\u0146\u0156\u0157\u015E\u015F\u0162\u0163\u0228\u0229\u1E10\u1E11\u1E28\u1E29" },
      /* ÇçĢģĶķĻļŅņŖŗŞşŢţȨȩḐḑḨḩ */
    { 0x0328,  /* NSM: OGONEK 328 */
      L"\u0104\u0105\u0118\u0119\u012E\u012F\u0172\u0173\u01EA\u01EB" },
      /* ĄąĘęĮįŲųǪǫ */
    { 0x032D,  /* NSM: CIRCUMFLEX BELOW 32D */
      L"\u1E12\u1E13\u1E18\u1E19\u1E3C\u1E3D\u1E4A\u1E4B\u1E70\u1E71\u1E76\u1E77" },
      /* ḒḓḘḙḼḽṊṋṰṱṶṷ */
    { 0x032E,  /* NSM: BREVE BELOW 32E */
      L"\u1E2A\u1E2B" },
      /* Ḫḫ */
    { 0x0330,  /* NSM: TILDE BELOW 330 */
      L"\u1E1A\u1E1B\u1E2C\u1E2D\u1E74\u1E75" },
      /* ḚḛḬḭṴṵ */
    { 0x0331,  /* NSM: MACRON BELOW 331 */
      L"\u1E06\u1E07\u1E0E\u1E0F\u1E34\u1E35\u1E3A\u1E3B\u1E48\u1E49\u1E5E\u1E5F\u1E6E\u1E6F\u1E94\u1E95\u1E96" },
      /* ḆḇḎḏḴḵḺḻṈṉṞṟṮṯẔẕẖ */
    { 0x20DB,  /* NSM: THREE DOTS ABOVE 20DB */
      L"\u063F\u0685\u069E\u069F\u06A0\u06A8\u06B4\u06B7\u06BD\u0763\u08A7\u08C3\u08C4\u08C5" },
      /* ؿڅڞڟڠڨڴڷڽݣࢧࣃࣄࣅ */
    { 0x20DC,  /* NSM: FOUR DOTS ABOVE 20DC */
      L"\u0690\u0699\u075C" },
      /* ڐڙݜ */
    { 0x3099,  /* NSM: KATAKANA-HIRAGANA VOICED SOUND MARK 3099 */
      L"\u304C\u304E\u3050\u3052\u3054\u3056\u3058\u305A\u305C\u305E\u3060\u3062\u3065\u3067\u3069\u3070\u3073\u3076\u3079\u307C\u3094\u309E\u30AC\u30AE\u30B0\u30B2\u30B4\u30B6\u30B8\u30BA\u30BC\u30BE\u30C0\u30C2\u30C5\u30C7\u30C9\u30D0\u30D3\u30D6\u30D9\u30DC\u30F4\u30F7\u30F8\u30F9\u30FA\u30FE\uFF9E" },
      /* がぎぐげござじずぜぞだぢづでどばびぶべぼゔゞガギグゲゴザジズゼゾダヂヅデドバビブベボヴヷヸヹヺヾﾞ */
    { 0x309A,  /* NSM: KATAKANA-HIRAGANA SEMI-VOICED SOUND MARK 309A */
      L"\u3071\u3074\u3077\u307A\u307D\u30D1\u30D4\u30D7\u30DA\u30DD\uFF9F" },
      /* ぱぴぷぺぽパピプペポﾟ */
    // clang-format on
};
#endif

// This was just an experiment. It's slower than binary search in ranges.
#ifdef HAVE_CROARING
#  ifndef EXTERN_SCRIPTS
/* generated via mkroar.c */
const unsigned char mark_croar_bin[] = {
  0x3b, 0x30, 0x02, 0x00, 0x07, 0x00, 0x00, 0x37, 0x05, 0x01, 0x00, 0x3f,
  0x03, 0x0e, 0x00, 0xef, 0x00, 0xbd, 0x00, 0x00, 0x03, 0x6f, 0x00, 0x83,
  0x04, 0x06, 0x00, 0x91, 0x05, 0x2c, 0x00, 0xbf, 0x05, 0x00, 0x00, 0xc1,
  0x05, 0x01, 0x00, 0xc4, 0x05, 0x01, 0x00, 0xc7, 0x05, 0x00, 0x00, 0x10,
  0x06, 0x0a, 0x00, 0x4b, 0x06, 0x14, 0x00, 0x70, 0x06, 0x00, 0x00, 0xd6,
  0x06, 0x06, 0x00, 0xdf, 0x06, 0x05, 0x00, 0xe7, 0x06, 0x01, 0x00, 0xea,
  0x06, 0x03, 0x00, 0x11, 0x07, 0x00, 0x00, 0x30, 0x07, 0x1a, 0x00, 0xa6,
  0x07, 0x0a, 0x00, 0xeb, 0x07, 0x08, 0x00, 0xfd, 0x07, 0x00, 0x00, 0x16,
  0x08, 0x03, 0x00, 0x1b, 0x08, 0x08, 0x00, 0x25, 0x08, 0x02, 0x00, 0x29,
  0x08, 0x04, 0x00, 0x59, 0x08, 0x02, 0x00, 0x98, 0x08, 0x07, 0x00, 0xca,
  0x08, 0x17, 0x00, 0xe3, 0x08, 0x20, 0x00, 0x3a, 0x09, 0x02, 0x00, 0x3e,
  0x09, 0x11, 0x00, 0x51, 0x09, 0x06, 0x00, 0x62, 0x09, 0x01, 0x00, 0x81,
  0x09, 0x02, 0x00, 0xbc, 0x09, 0x00, 0x00, 0xbe, 0x09, 0x06, 0x00, 0xc7,
  0x09, 0x01, 0x00, 0xcb, 0x09, 0x02, 0x00, 0xd7, 0x09, 0x00, 0x00, 0xe2,
  0x09, 0x01, 0x00, 0xfe, 0x09, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x00, 0x3c,
  0x0a, 0x00, 0x00, 0x3e, 0x0a, 0x04, 0x00, 0x47, 0x0a, 0x01, 0x00, 0x4b,
  0x0a, 0x02, 0x00, 0x51, 0x0a, 0x00, 0x00, 0x70, 0x0a, 0x01, 0x00, 0x75,
  0x0a, 0x00, 0x00, 0x81, 0x0a, 0x02, 0x00, 0xbc, 0x0a, 0x00, 0x00, 0xbe,
  0x0a, 0x07, 0x00, 0xc7, 0x0a, 0x02, 0x00, 0xcb, 0x0a, 0x02, 0x00, 0xe2,
  0x0a, 0x01, 0x00, 0xfa, 0x0a, 0x05, 0x00, 0x01, 0x0b, 0x02, 0x00, 0x3c,
  0x0b, 0x00, 0x00, 0x3e, 0x0b, 0x06, 0x00, 0x47, 0x0b, 0x01, 0x00, 0x4b,
  0x0b, 0x02, 0x00, 0x55, 0x0b, 0x02, 0x00, 0x62, 0x0b, 0x01, 0x00, 0x82,
  0x0b, 0x00, 0x00, 0xbe, 0x0b, 0x04, 0x00, 0xc6, 0x0b, 0x02, 0x00, 0xca,
  0x0b, 0x03, 0x00, 0xd7, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x04, 0x00, 0x3c,
  0x0c, 0x00, 0x00, 0x3e, 0x0c, 0x06, 0x00, 0x46, 0x0c, 0x02, 0x00, 0x4a,
  0x0c, 0x03, 0x00, 0x55, 0x0c, 0x01, 0x00, 0x62, 0x0c, 0x01, 0x00, 0x81,
  0x0c, 0x02, 0x00, 0xbc, 0x0c, 0x00, 0x00, 0xbe, 0x0c, 0x06, 0x00, 0xc6,
  0x0c, 0x02, 0x00, 0xca, 0x0c, 0x03, 0x00, 0xd5, 0x0c, 0x01, 0x00, 0xe2,
  0x0c, 0x01, 0x00, 0x00, 0x0d, 0x03, 0x00, 0x3b, 0x0d, 0x01, 0x00, 0x3e,
  0x0d, 0x06, 0x00, 0x46, 0x0d, 0x02, 0x00, 0x4a, 0x0d, 0x03, 0x00, 0x57,
  0x0d, 0x00, 0x00, 0x62, 0x0d, 0x01, 0x00, 0x81, 0x0d, 0x02, 0x00, 0xca,
  0x0d, 0x00, 0x00, 0xcf, 0x0d, 0x05, 0x00, 0xd6, 0x0d, 0x00, 0x00, 0xd8,
  0x0d, 0x07, 0x00, 0xf2, 0x0d, 0x01, 0x00, 0x31, 0x0e, 0x00, 0x00, 0x34,
  0x0e, 0x06, 0x00, 0x47, 0x0e, 0x07, 0x00, 0xb1, 0x0e, 0x00, 0x00, 0xb4,
  0x0e, 0x08, 0x00, 0xc8, 0x0e, 0x05, 0x00, 0x18, 0x0f, 0x01, 0x00, 0x35,
  0x0f, 0x00, 0x00, 0x37, 0x0f, 0x00, 0x00, 0x39, 0x0f, 0x00, 0x00, 0x3e,
  0x0f, 0x01, 0x00, 0x71, 0x0f, 0x13, 0x00, 0x86, 0x0f, 0x01, 0x00, 0x8d,
  0x0f, 0x0a, 0x00, 0x99, 0x0f, 0x23, 0x00, 0xc6, 0x0f, 0x00, 0x00, 0x2b,
  0x10, 0x13, 0x00, 0x56, 0x10, 0x03, 0x00, 0x5e, 0x10, 0x02, 0x00, 0x62,
  0x10, 0x02, 0x00, 0x67, 0x10, 0x06, 0x00, 0x71, 0x10, 0x03, 0x00, 0x82,
  0x10, 0x0b, 0x00, 0x8f, 0x10, 0x00, 0x00, 0x9a, 0x10, 0x03, 0x00, 0x5d,
  0x13, 0x02, 0x00, 0x12, 0x17, 0x03, 0x00, 0x32, 0x17, 0x02, 0x00, 0x52,
  0x17, 0x01, 0x00, 0x72, 0x17, 0x01, 0x00, 0xb4, 0x17, 0x1f, 0x00, 0xdd,
  0x17, 0x00, 0x00, 0x0b, 0x18, 0x02, 0x00, 0x0f, 0x18, 0x00, 0x00, 0x85,
  0x18, 0x01, 0x00, 0xa9, 0x18, 0x00, 0x00, 0x20, 0x19, 0x0b, 0x00, 0x30,
  0x19, 0x0b, 0x00, 0x17, 0x1a, 0x04, 0x00, 0x55, 0x1a, 0x09, 0x00, 0x60,
  0x1a, 0x1c, 0x00, 0x7f, 0x1a, 0x00, 0x00, 0xb0, 0x1a, 0x1e, 0x00, 0x00,
  0x1b, 0x04, 0x00, 0x34, 0x1b, 0x10, 0x00, 0x6b, 0x1b, 0x08, 0x00, 0x80,
  0x1b, 0x02, 0x00, 0xa1, 0x1b, 0x0c, 0x00, 0xe6, 0x1b, 0x0d, 0x00, 0x24,
  0x1c, 0x13, 0x00, 0xd0, 0x1c, 0x02, 0x00, 0xd4, 0x1c, 0x14, 0x00, 0xed,
  0x1c, 0x00, 0x00, 0xf4, 0x1c, 0x00, 0x00, 0xf7, 0x1c, 0x02, 0x00, 0xc0,
  0x1d, 0x3f, 0x00, 0xd0, 0x20, 0x20, 0x00, 0xef, 0x2c, 0x02, 0x00, 0x7f,
  0x2d, 0x00, 0x00, 0xe0, 0x2d, 0x1f, 0x00, 0x2a, 0x30, 0x05, 0x00, 0x99,
  0x30, 0x01, 0x00, 0x6f, 0xa6, 0x03, 0x00, 0x74, 0xa6, 0x09, 0x00, 0x9e,
  0xa6, 0x01, 0x00, 0xf0, 0xa6, 0x01, 0x00, 0x02, 0xa8, 0x00, 0x00, 0x06,
  0xa8, 0x00, 0x00, 0x0b, 0xa8, 0x00, 0x00, 0x23, 0xa8, 0x04, 0x00, 0x2c,
  0xa8, 0x00, 0x00, 0x80, 0xa8, 0x01, 0x00, 0xb4, 0xa8, 0x11, 0x00, 0xe0,
  0xa8, 0x11, 0x00, 0xff, 0xa8, 0x00, 0x00, 0x26, 0xa9, 0x07, 0x00, 0x47,
  0xa9, 0x0c, 0x00, 0x80, 0xa9, 0x03, 0x00, 0xb3, 0xa9, 0x0d, 0x00, 0xe5,
  0xa9, 0x00, 0x00, 0x29, 0xaa, 0x0d, 0x00, 0x43, 0xaa, 0x00, 0x00, 0x4c,
  0xaa, 0x01, 0x00, 0x7b, 0xaa, 0x02, 0x00, 0xb0, 0xaa, 0x00, 0x00, 0xb2,
  0xaa, 0x02, 0x00, 0xb7, 0xaa, 0x01, 0x00, 0xbe, 0xaa, 0x01, 0x00, 0xc1,
  0xaa, 0x00, 0x00, 0xeb, 0xaa, 0x04, 0x00, 0xf5, 0xaa, 0x01, 0x00, 0xe3,
  0xab, 0x07, 0x00, 0xec, 0xab, 0x01, 0x00, 0x1e, 0xfb, 0x00, 0x00, 0x00,
  0xfe, 0x0f, 0x00, 0x20, 0xfe, 0x0f, 0x00, 0x6d, 0x00, 0xfd, 0x01, 0x00,
  0x00, 0xe0, 0x02, 0x00, 0x00, 0x76, 0x03, 0x04, 0x00, 0x01, 0x0a, 0x02,
  0x00, 0x05, 0x0a, 0x01, 0x00, 0x0c, 0x0a, 0x03, 0x00, 0x38, 0x0a, 0x02,
  0x00, 0x3f, 0x0a, 0x00, 0x00, 0xe5, 0x0a, 0x01, 0x00, 0x24, 0x0d, 0x03,
  0x00, 0xab, 0x0e, 0x01, 0x00, 0x46, 0x0f, 0x0a, 0x00, 0x82, 0x0f, 0x03,
  0x00, 0x00, 0x10, 0x02, 0x00, 0x38, 0x10, 0x0e, 0x00, 0x70, 0x10, 0x00,
  0x00, 0x73, 0x10, 0x01, 0x00, 0x7f, 0x10, 0x03, 0x00, 0xb0, 0x10, 0x0a,
  0x00, 0xc2, 0x10, 0x00, 0x00, 0x00, 0x11, 0x02, 0x00, 0x27, 0x11, 0x0d,
  0x00, 0x45, 0x11, 0x01, 0x00, 0x73, 0x11, 0x00, 0x00, 0x80, 0x11, 0x02,
  0x00, 0xb3, 0x11, 0x0d, 0x00, 0xc9, 0x11, 0x03, 0x00, 0xce, 0x11, 0x01,
  0x00, 0x2c, 0x12, 0x0b, 0x00, 0x3e, 0x12, 0x00, 0x00, 0xdf, 0x12, 0x0b,
  0x00, 0x00, 0x13, 0x03, 0x00, 0x3b, 0x13, 0x01, 0x00, 0x3e, 0x13, 0x06,
  0x00, 0x47, 0x13, 0x01, 0x00, 0x4b, 0x13, 0x02, 0x00, 0x57, 0x13, 0x00,
  0x00, 0x62, 0x13, 0x01, 0x00, 0x66, 0x13, 0x06, 0x00, 0x70, 0x13, 0x04,
  0x00, 0x35, 0x14, 0x11, 0x00, 0x5e, 0x14, 0x00, 0x00, 0xb0, 0x14, 0x13,
  0x00, 0xaf, 0x15, 0x06, 0x00, 0xb8, 0x15, 0x08, 0x00, 0xdc, 0x15, 0x01,
  0x00, 0x30, 0x16, 0x10, 0x00, 0xab, 0x16, 0x0c, 0x00, 0x1d, 0x17, 0x0e,
  0x00, 0x2c, 0x18, 0x0e, 0x00, 0x30, 0x19, 0x05, 0x00, 0x37, 0x19, 0x01,
  0x00, 0x3b, 0x19, 0x03, 0x00, 0x40, 0x19, 0x00, 0x00, 0x42, 0x19, 0x01,
  0x00, 0xd1, 0x19, 0x06, 0x00, 0xda, 0x19, 0x06, 0x00, 0xe4, 0x19, 0x00,
  0x00, 0x01, 0x1a, 0x09, 0x00, 0x33, 0x1a, 0x06, 0x00, 0x3b, 0x1a, 0x03,
  0x00, 0x47, 0x1a, 0x00, 0x00, 0x51, 0x1a, 0x0a, 0x00, 0x8a, 0x1a, 0x0f,
  0x00, 0x2f, 0x1c, 0x07, 0x00, 0x38, 0x1c, 0x07, 0x00, 0x92, 0x1c, 0x15,
  0x00, 0xa9, 0x1c, 0x0d, 0x00, 0x31, 0x1d, 0x05, 0x00, 0x3a, 0x1d, 0x00,
  0x00, 0x3c, 0x1d, 0x01, 0x00, 0x3f, 0x1d, 0x06, 0x00, 0x47, 0x1d, 0x00,
  0x00, 0x8a, 0x1d, 0x04, 0x00, 0x90, 0x1d, 0x01, 0x00, 0x93, 0x1d, 0x04,
  0x00, 0xf3, 0x1e, 0x03, 0x00, 0xf0, 0x6a, 0x04, 0x00, 0x30, 0x6b, 0x06,
  0x00, 0x4f, 0x6f, 0x00, 0x00, 0x51, 0x6f, 0x36, 0x00, 0x8f, 0x6f, 0x03,
  0x00, 0xe4, 0x6f, 0x00, 0x00, 0xf0, 0x6f, 0x01, 0x00, 0x9d, 0xbc, 0x01,
  0x00, 0x00, 0xcf, 0x2d, 0x00, 0x30, 0xcf, 0x16, 0x00, 0x65, 0xd1, 0x04,
  0x00, 0x6d, 0xd1, 0x05, 0x00, 0x7b, 0xd1, 0x07, 0x00, 0x85, 0xd1, 0x06,
  0x00, 0xaa, 0xd1, 0x03, 0x00, 0x42, 0xd2, 0x02, 0x00, 0x00, 0xda, 0x36,
  0x00, 0x3b, 0xda, 0x31, 0x00, 0x75, 0xda, 0x00, 0x00, 0x84, 0xda, 0x00,
  0x00, 0x9b, 0xda, 0x04, 0x00, 0xa1, 0xda, 0x0e, 0x00, 0x00, 0xe0, 0x06,
  0x00, 0x08, 0xe0, 0x10, 0x00, 0x1b, 0xe0, 0x06, 0x00, 0x23, 0xe0, 0x01,
  0x00, 0x26, 0xe0, 0x04, 0x00, 0x30, 0xe1, 0x06, 0x00, 0xae, 0xe2, 0x00,
  0x00, 0xec, 0xe2, 0x03, 0x00, 0xd0, 0xe8, 0x06, 0x00, 0x44, 0xe9, 0x06,
  0x00, 0x01, 0x00, 0x00, 0x01, 0xef, 0x00
};
const unsigned int mark_croar_bin_len = 1219;
#  else
extern const unsigned int mark_croar_bin_len;
extern const unsigned char mark_croar_bin[1219]; // checkme on updates
#  endif // EXTERN_SCRIPTS
#endif // HAVE_CROARING
