/* ex: set ro ft=c: -*- mode: c; buffer-read-only: t -*- */
/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2014, 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   All Combining_Mark (Mc | Me | Mn)
   Generated by mkmark.pl, do not modify.
*/

/* All Combining Marks, sorted */
#ifdef EXT_SCRIPTS
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

// This was just an experiment. It's slower than binary search in ranges.
#ifdef HAVE_CROARING
#  ifndef EXT_SCRIPTS
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
    0x00, 0x01, 0x00, 0x00, 0x01, 0xef, 0x00};
const unsigned int mark_croar_bin_len = 1219;
#  else
extern const unsigned int mark_croar_bin_len;
extern const unsigned char mark_croar_bin[1219]; // checkme on updates
#  endif // EXT_SCRIPTS
#endif   // HAVE_CROARING
