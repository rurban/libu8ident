/* libu8ident_c - TR39-limited unicode security guidelines for C/C++ identifiers.
   Copyright 2021,2022,2025,2026 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   TR39 amalgam — single-file implementation for C compiler integration.
   No preprocessor conditionals.  Profile hardcoded to TR39_4.
 */
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <wchar.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Visibility and compiler hints (inlined from u8id_private.h) ---- */
#if defined _WIN32 || defined __CYGWIN__
#  define U8ID_EXTERN __declspec(dllexport)
#  define U8ID_LOCAL
#elif __GNUC__ >= 4
#  define U8ID_EXTERN __attribute__((visibility("default")))
#  define U8ID_LOCAL __attribute__((visibility("hidden")))
#else
#  define U8ID_EXTERN
#  define U8ID_LOCAL
#endif

#if __GNUC__ >= 3
#  define likely(expr)   __builtin_expect((long)((expr) != 0), 1)
#  define unlikely(expr) __builtin_expect((long)((expr) != 0), 0)
#  define INLINE static inline
#else
#  define likely(expr)   (expr)
#  define unlikely(expr) (expr)
#  define INLINE static
#endif

/* ---- Utility macros ---- */
#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)
#define strEQ(s1, s2) !strcmp((s1), (s2))
#define strEQc(s1, s2) !strcmp((s1), s2 "")

/* ---- Types and constants (inlined from u8id_private.h + u8ident.h) ---- */

#define U8ID_CTX_TRESH 5
#define U8ID_SCR_TRESH 8

struct ctx_t {
  uint8_t count;
  uint8_t has_han : 1;
  uint8_t is_japanese : 1;
  uint8_t is_chinese : 1;
  uint8_t is_korean : 1;
  uint8_t is_rtl : 1;
  uint32_t last_cp;
  union {
    uint64_t scr64;
    uint8_t scr8[U8ID_SCR_TRESH];
    uint8_t *u8p;
  };
};

typedef unsigned u8id_ctx_t;

enum u8id_norm {
  U8ID_NFC = 0,
  U8ID_NFD = 1,
  U8ID_NFKC = 2,
  U8ID_NFKD = 3,
  U8ID_FCD = 4,
  U8ID_FCC = 5
};

enum u8id_profile {
  U8ID_PROFILE_1 = 1,
  U8ID_PROFILE_2 = 2,
  U8ID_PROFILE_3 = 3,
  U8ID_PROFILE_4 = 4,
  U8ID_PROFILE_5 = 5,
  U8ID_PROFILE_6 = 6,
  U8ID_PROFILE_C11_6 = 7,
  U8ID_PROFILE_TR39_4 = 8,
};

enum u8id_options {
  U8ID_TR31_XID = 64,
  U8ID_TR31_ID = 65,
  U8ID_TR31_ALLOWED = 66,
  U8ID_TR31_TR39 = 67,
  U8ID_TR31_C23 = 68,
  U8ID_TR31_C11 = 69,
  U8ID_TR31_ALLUTF8 = 70,
  U8ID_TR31_ASCII = 71,
  U8ID_FOLDCASE = 128,
  U8ID_WARN_CONFUSABLE = 256,
  U8ID_ERROR_CONFUSABLE = 512,
};
#define U8ID_TR31_MASK 127

enum u8id_errors {
  U8ID_EOK = 0,
  U8ID_EOK_NORM = 1,
  U8ID_EOK_WARN_CONFUS = 2,
  U8ID_EOK_NORM_WARN_CONFUS = 3,
  U8ID_ERR_XID = -1,
  U8ID_ERR_SCRIPT = -2,
  U8ID_ERR_SCRIPTS = -3,
  U8ID_ERR_ENCODING = -4,
  U8ID_ERR_COMBINE = -5,
  U8ID_ERR_CONFUS = -6,
};

#define U8ID_NORM_DEFAULT U8ID_NFC
#define U8ID_PROFILE_DEFAULT U8ID_PROFILE_TR39_4
#define U8ID_TR31_DEFAULT U8ID_TR31_TR39

/* ---- Types needed by the tail's scx/nsm lookups (from scripts.h, mark.h) ---- */
struct scx {
  uint32_t from;
  uint32_t to;
  uint8_t gc;      // enum u8id_gc is too large
  const char *scx; // indices into sc
};

struct nsm_ws {
  uint32_t nsm;
  wchar_t *letters;
};

/* ---- Data (unitr39.h is self-contained; remaining data inlined below) ---- */
#include "unitr39.h"

/* ---- Inlined data from scripts.h, mark.h ---- */

const struct range_bool bidi_list[] = {
    // clang-format off
    { 0x202A, 0x202E }, // LRE, RLE, PDF, LRO, RLO
    { 0x2066, 0x2069 }, // LRI, RLI, FSI, PDI
    // clang-format on
};

const uint32_t greek_confus_list[] = {
    0x0370, // ( Ͱ → Ⱶ ) GREEK CAPITAL LETTER HETA → LATIN CAPITAL LETTER HALF H
    0x0377, // ( ͷ → ᴎ ) GREEK SMALL LETTER PAMPHYLIAN DIGAMMA → LATIN LETTER
            // SMALL CAPITAL REVERSED N
    0x037B, // ( ͻ → ɔ ) GREEK SMALL REVERSED LUNATE SIGMA SYMBOL → LATIN SMALL
            // LETTER OPEN O
    0x037D, // ( ͽ → ꜿ ) GREEK SMALL REVERSED DOTTED LUNATE SIGMA SYMBOL → LATIN
            // SMALL LETTER REVERSED C WITH DOT
    0x037F, // ( Ϳ → J ) GREEK CAPITAL LETTER YOT → LATIN CAPITAL LETTER J
    0x0391, // ( Α → A ) GREEK CAPITAL LETTER ALPHA → LATIN CAPITAL LETTER A
    0x0392, // ( Β → B ) GREEK CAPITAL LETTER BETA → LATIN CAPITAL LETTER B
    0x0395, // ( Ε → E ) GREEK CAPITAL LETTER EPSILON → LATIN CAPITAL LETTER E
    0x0396, // ( Ζ → Z ) GREEK CAPITAL LETTER ZETA → LATIN CAPITAL LETTER Z
    0x0397, // ( Η → H ) GREEK CAPITAL LETTER ETA → LATIN CAPITAL LETTER H
    0x0399, // ( Ι → l ) GREEK CAPITAL LETTER IOTA → LATIN SMALL LETTER L
    0x039A, // ( Κ → K ) GREEK CAPITAL LETTER KAPPA → LATIN CAPITAL LETTER K
    0x039B, // ( Λ → Ʌ ) GREEK CAPITAL LETTER LAMDA → LATIN CAPITAL LETTER
            // TURNED V
    0x039C, // ( Μ → M ) GREEK CAPITAL LETTER MU → LATIN CAPITAL LETTER M
    0x039D, // ( Ν → N ) GREEK CAPITAL LETTER NU → LATIN CAPITAL LETTER N
    0x039F, // ( Ο → O ) GREEK CAPITAL LETTER OMICRON → LATIN CAPITAL LETTER O
    0x03A1, // ( Ρ → P ) GREEK CAPITAL LETTER RHO → LATIN CAPITAL LETTER P
    0x03A3, // ( Σ → Ʃ ) GREEK CAPITAL LETTER SIGMA → LATIN CAPITAL LETTER ESH
    0x03A4, // ( Τ → T ) GREEK CAPITAL LETTER TAU → LATIN CAPITAL LETTER T
    0x03A5, // ( Υ → Y ) GREEK CAPITAL LETTER UPSILON → LATIN CAPITAL LETTER Y
    0x03A7, // ( Χ → X ) GREEK CAPITAL LETTER CHI → LATIN CAPITAL LETTER X
    0x03B1, // ( α → a ) GREEK SMALL LETTER ALPHA → LATIN SMALL LETTER A
    0x03B2, // ( β → ß ) GREEK SMALL LETTER BETA → LATIN SMALL LETTER SHARP S
    0x03B3, // ( γ → y ) GREEK SMALL LETTER GAMMA → LATIN SMALL LETTER Y
    0x03B4, // ( δ → ẟ ) GREEK SMALL LETTER DELTA → LATIN SMALL LETTER DELTA
    0x03BA, // ( κ → ĸ ) GREEK SMALL LETTER KAPPA → LATIN SMALL LETTER KRA
    0x03BB, // ( ꟛ → λ ) LATIN SMALL LETTER LAMBDA → GREEK SMALL LETTER
            // LAMDA
    0x03BF, // ( ο → o ) GREEK SMALL LETTER OMICRON → LATIN SMALL LETTER O
    0x03C1, // ( ρ → p ) GREEK SMALL LETTER RHO → LATIN SMALL LETTER P
    0x03C4, // ( τ → ᴛ ) GREEK SMALL LETTER TAU → LATIN LETTER SMALL CAPITAL T
    0x03C5, // ( υ → u ) GREEK SMALL LETTER UPSILON → LATIN SMALL LETTER U
    0x03C6, // ( φ → ɸ ) GREEK SMALL LETTER PHI → LATIN SMALL LETTER PHI
    0x03C7, // ( ꭕ → χ ) LATIN SMALL LETTER CHI WITH LOW LEFT SERIF → GREEK
            // SMALL LETTER CHI
    0x03C9, // ( ꞷ → ω ) LATIN SMALL LETTER OMEGA → GREEK SMALL LETTER OMEGA
    0x03D0, // ( ϐ → ß ) GREEK BETA SYMBOL → LATIN SMALL LETTER SHARP S
    0x03D2, // ( ϒ → Y ) GREEK UPSILON WITH HOOK SYMBOL → LATIN CAPITAL LETTER Y
    0x03D5, // ( ϕ → ɸ ) GREEK PHI SYMBOL → LATIN SMALL LETTER PHI
    0x03DC, // ( Ϝ → F ) GREEK LETTER DIGAMMA → LATIN CAPITAL LETTER F
    0x03F0, // ( ϰ → ĸ ) GREEK KAPPA SYMBOL → LATIN SMALL LETTER KRA
    0x03F2, // ( ϲ → c ) GREEK LUNATE SIGMA SYMBOL → LATIN SMALL LETTER C
    0x03F3, // ( ϳ → j ) GREEK LETTER YOT → LATIN SMALL LETTER J
    0x03F5, // ( ϵ → ꞓ ) GREEK LUNATE EPSILON SYMBOL → LATIN SMALL LETTER C WITH
            // BAR
    0x03F7, // ( Ϸ → Þ ) GREEK CAPITAL LETTER SHO → LATIN CAPITAL LETTER THORN
    0x03F8, // ( ϸ → p ) GREEK SMALL LETTER SHO → LATIN SMALL LETTER P
    0x03F9, // ( Ϲ → C ) GREEK CAPITAL LUNATE SIGMA SYMBOL → LATIN CAPITAL
            // LETTER C
    0x03FA, // ( Ϻ → M ) GREEK CAPITAL LETTER SAN → LATIN CAPITAL LETTER M
    0x03FD, // ( Ͻ → Ɔ ) GREEK CAPITAL REVERSED LUNATE SIGMA SYMBOL → LATIN
            // CAPITAL LETTER OPEN O
    0x03FF, // ( Ͽ → Ꜿ ) GREEK CAPITAL REVERSED DOTTED LUNATE SIGMA SYMBOL →
            // LATIN CAPITAL LETTER REVERSED C WITH DOT
    0x1D26, // ( ᴦ → r ) GREEK LETTER SMALL CAPITAL GAMMA → LATIN SMALL LETTER R
    0x1D27, // ( ᴧ → ʌ ) GREEK LETTER SMALL CAPITAL LAMDA → LATIN SMALL LETTER
            // TURNED V
    0x1D29, // ( ᴩ → ᴘ ) GREEK LETTER SMALL CAPITAL RHO → LATIN LETTER SMALL
            // CAPITAL P
    0x1FBE, // ( ι → i ) GREEK PROSGEGRAMMENI → LATIN SMALL LETTER I
    0x2129, // ( ℩ → ɿ ) TURNED GREEK SMALL LETTER IOTA → LATIN SMALL LETTER
            // REVERSED R WITH FISHHOOK
    0x1D20D, // ( 𝈍 → V ) GREEK VOCAL NOTATION SYMBOL-14 → LATIN CAPITAL LETTER
             // V
    0x1D213, // ( 𝈓 → F ) GREEK VOCAL NOTATION SYMBOL-20 → LATIN CAPITAL LETTER
             // F
    0x1D216, // ( 𝈖 → R ) GREEK VOCAL NOTATION SYMBOL-23 → LATIN CAPITAL LETTER
             // R
    0x1D217, // ( 𝈗 → Ɐ ) GREEK VOCAL NOTATION SYMBOL-24 → LATIN CAPITAL LETTER
             // TURNED A
    0x1D21A, // ( 𝈚 → O̵ ) GREEK VOCAL NOTATION SYMBOL-52 → LATIN CAPITAL LETTER
             // O, COMBINING SHORT STROKE OVERLAY
    0x1D221, // ( 𝈡 → Ɛ ) GREEK INSTRUMENTAL NOTATION SYMBOL-7 → LATIN CAPITAL
             // LETTER OPEN E
    0x1D22A, // ( 𝈪 → L ) GREEK INSTRUMENTAL NOTATION SYMBOL-23 → LATIN CAPITAL
             // LETTER L
    0x1D230, // ( 𝈰 → ꟻ ) GREEK INSTRUMENTAL NOTATION SYMBOL-30 → LATIN
             // EPIGRAPHIC LETTER REVERSED F
};

const struct sc nonxid_script_list[] = {
    // clang-format off
    {0x0000, 0x0040, 0},	// Common
    {0x0041, 0x005A, 2},	// Latin
    {0x005B, 0x0060, 0},	// Common (Not_XID)
    {0x0061, 0x007A, 2},	// Latin
    {0x007B, 0x00A9, 0},	// Common (Not_XID)
    {0x00AA, 0x00AA, 2},	// Latin (Not_NFKC)
    {0x00AB, 0x00B9, 0},	// Common (Not_XID)
    {0x00BA, 0x00BA, 2},	// Latin (Not_NFKC)
    {0x00BB, 0x00BF, 0},	// Common (Not_XID)
    {0x00C0, 0x00D6, 2},	// Latin
    {0x00D7, 0x00D7, 0},	// Common (Not_XID)
    {0x00D8, 0x00F6, 2},	// Latin
    {0x00F7, 0x00F7, 0},	// Common (Not_XID)
    {0x00F8, 0x02B8, 2},	// Latin
    {0x02B9, 0x02DF, 0},	// Common
    {0x02E0, 0x02E4, 2},	// Latin (Not_NFKC)
    {0x02E5, 0x02E9, 0},	// Common (Not_XID)
    {0x02EA, 0x02EB, 6},	// Bopomofo (Limited_Use Not_XID)
    {0x02EC, 0x02FF, 0},	// Common
    {0x0300, 0x036F, 1},	// Inherited
    {0x0370, 0x0373, 11},	// Greek (Obsolete)
    {0x0374, 0x0374, 0},	// Common (Not_NFKC)
    {0x0375, 0x037D, 11},	// Greek (Technical Not_XID)
    {0x037E, 0x037E, 0},	// Common (Not_NFKC)
    {0x037F, 0x0384, 11},	// Greek (Obsolete)
    {0x0385, 0x0385, 0},	// Common (Not_NFKC)
    {0x0386, 0x0386, 11},	// Greek
    {0x0387, 0x0387, 0},	// Common (Not_NFKC)
    {0x0388, 0x03E1, 11},	// Greek
    {0x03E2, 0x03EF, 44},	// Coptic (Exclusion)
    {0x03F0, 0x03FF, 11},	// Greek (Not_NFKC)
    {0x0400, 0x0484, 7},	// Cyrillic (Uncommon_Use)
    {0x0485, 0x0486, 1},	// Inherited (Technical Obsolete)
    {0x0487, 0x052F, 7},	// Cyrillic (Technical Obsolete)
    {0x0531, 0x058F, 4},	// Armenian
    {0x0591, 0x05F4, 16},	// Hebrew (Uncommon_Use)
    {0x0600, 0x0604, 3},	// Arabic (Not_XID)
    {0x0605, 0x0605, 0},	// Common (Not_XID)
    {0x0606, 0x060B, 3},	// Arabic (Not_XID)
    {0x060C, 0x060C, 0},	// Common (Not_XID)
    {0x060D, 0x061A, 3},	// Arabic (Not_XID)
    {0x061B, 0x061B, 0},	// Common (Not_XID)
    {0x061C, 0x061E, 3},	// Arabic (Default_Ignorable)
    {0x061F, 0x061F, 0},	// Common (Not_XID)
    {0x0620, 0x063F, 3},	// Arabic
    {0x0640, 0x0640, 0},	// Common (Obsolete)
    {0x0641, 0x064A, 3},	// Arabic
    {0x064B, 0x0655, 1},	// Inherited
    {0x0656, 0x066F, 3},	// Arabic (Uncommon_Use)
    {0x0670, 0x0670, 1},	// Inherited
    {0x0671, 0x06DC, 3},	// Arabic
    {0x06DD, 0x06DD, 0},	// Common (Not_XID)
    {0x06DE, 0x06FF, 3},	// Arabic (Not_XID)
    {0x0700, 0x074F, 166},	// Syriac (Limited_Use Not_XID)
    {0x0750, 0x077F, 3},	// Arabic (Uncommon_Use)
    {0x0780, 0x07B1, 28},	// Thaana
    {0x07C0, 0x07FF, 159},	// Nko (Limited_Use)
    {0x0800, 0x083E, 114},	// Samaritan (Exclusion)
    {0x0840, 0x085E, 154},	// Mandaic (Limited_Use)
    {0x0860, 0x086A, 166},	// Syriac (Limited_Use)
    {0x0870, 0x08E1, 3},	// Arabic
    {0x08E2, 0x08E2, 0},	// Common (Not_XID)
    {0x08E3, 0x08FF, 3},	// Arabic (Uncommon_Use)
    {0x0900, 0x0950, 8},	// Devanagari (Uncommon_Use)
    {0x0951, 0x0954, 1},	// Inherited (Obsolete)
    {0x0955, 0x0963, 8},	// Devanagari (Uncommon_Use)
    {0x0964, 0x0965, 0},	// Common (Not_XID)
    {0x0966, 0x097F, 8},	// Devanagari
    {0x0980, 0x09FE, 5},	// Bengali (Obsolete)
    {0x0A01, 0x0A76, 13},	// Gurmukhi (Uncommon_Use)
    {0x0A81, 0x0AFF, 12},	// Gujarati (Uncommon_Use)
    {0x0B01, 0x0B77, 24},	// Oriya
    {0x0B82, 0x0BFA, 26},	// Tamil
    {0x0C00, 0x0C7F, 27},	// Telugu (Obsolete)
    {0x0C80, 0x0CF3, 19},	// Kannada (Uncommon_Use)
    {0x0D00, 0x0D7F, 22},	// Malayalam (Uncommon_Use)
    {0x0D81, 0x0DF4, 25},	// Sinhala
    {0x0E01, 0x0E3A, 29},	// Thai
    {0x0E3F, 0x0E3F, 0},	// Common (Not_XID)
    {0x0E40, 0x0E5B, 29},	// Thai
    {0x0E81, 0x0EDF, 21},	// Lao
    {0x0F00, 0x0FD4, 30},	// Tibetan
    {0x0FD5, 0x0FD8, 0},	// Common (Not_XID)
    {0x0FD9, 0x0FDA, 30},	// Tibetan (Not_XID)
    {0x1000, 0x109F, 23},	// Myanmar
    {0x10A0, 0x10FA, 10},	// Georgian (Obsolete)
    {0x10FB, 0x10FB, 0},	// Common (Not_XID)
    {0x10FC, 0x10FF, 10},	// Georgian (Not_NFKC)
    {0x1100, 0x11FF, 14},	// Hangul (Obsolete)
    {0x1200, 0x1399, 9},	// Ethiopic
    {0x13A0, 0x13FD, 147},	// Cherokee (Limited_Use)
    {0x1400, 0x167F, 144},	// Canadian_Aboriginal (Limited_Use Not_XID)
    {0x1680, 0x169C, 94},	// Ogham (Exclusion Not_XID)
    {0x16A0, 0x16EA, 113},	// Runic (Exclusion)
    {0x16EB, 0x16ED, 0},	// Common (Exclusion Not_XID)
    {0x16EE, 0x16F8, 113},	// Runic (Exclusion)
    {0x1700, 0x171F, 124},	// Tagalog (Exclusion)
    {0x1720, 0x1734, 61},	// Hanunoo (Exclusion)
    {0x1735, 0x1736, 0},	// Common (Exclusion Not_XID)
    {0x1740, 0x1753, 40},	// Buhid (Exclusion)
    {0x1760, 0x1773, 125},	// Tagbanwa (Exclusion)
    {0x1780, 0x17F9, 20},	// Khmer
    {0x1800, 0x1801, 87},	// Mongolian (Exclusion Not_XID)
    {0x1802, 0x1803, 0},	// Common (Exclusion Not_XID)
    {0x1804, 0x1804, 87},	// Mongolian (Exclusion Not_XID)
    {0x1805, 0x1805, 0},	// Common (Exclusion Not_XID)
    {0x1806, 0x18AA, 87},	// Mongolian (Exclusion Not_XID)
    {0x18B0, 0x18F5, 144},	// Canadian_Aboriginal (Limited_Use)
    {0x1900, 0x194F, 152},	// Limbu (Limited_Use)
    {0x1950, 0x1974, 167},	// Tai_Le (Limited_Use)
    {0x1980, 0x19DF, 157},	// New_Tai_Lue (Limited_Use)
    {0x19E0, 0x19FF, 20},	// Khmer (Not_XID)
    {0x1A00, 0x1A1F, 39},	// Buginese (Exclusion)
    {0x1A20, 0x1AAD, 168},	// Tai_Tham (Limited_Use)
    {0x1AB0, 0x1AEB, 1},	// Inherited (Obsolete)
    {0x1B00, 0x1B7F, 141},	// Balinese (Limited_Use)
    {0x1B80, 0x1BBF, 164},	// Sundanese (Limited_Use)
    {0x1BC0, 0x1BFF, 143},	// Batak (Limited_Use)
    {0x1C00, 0x1C4F, 151},	// Lepcha (Limited_Use)
    {0x1C50, 0x1C7F, 161},	// Ol_Chiki (Limited_Use)
    {0x1C80, 0x1C8A, 7},	// Cyrillic (Obsolete)
    {0x1C90, 0x1CBF, 10},	// Georgian
    {0x1CC0, 0x1CC7, 164},	// Sundanese (Limited_Use Not_XID)
    {0x1CD0, 0x1CD2, 1},	// Inherited (Obsolete)
    {0x1CD3, 0x1CD3, 0},	// Common (Obsolete Not_XID)
    {0x1CD4, 0x1CE0, 1},	// Inherited (Obsolete)
    {0x1CE1, 0x1CE1, 0},	// Common (Obsolete)
    {0x1CE2, 0x1CE8, 1},	// Inherited (Obsolete)
    {0x1CE9, 0x1CEC, 0},	// Common (Obsolete)
    {0x1CED, 0x1CED, 1},	// Inherited (Obsolete)
    {0x1CEE, 0x1CF3, 0},	// Common (Obsolete)
    {0x1CF4, 0x1CF4, 1},	// Inherited (Obsolete)
    {0x1CF5, 0x1CF7, 0},	// Common (Obsolete)
    {0x1CF8, 0x1CF9, 1},	// Inherited (Obsolete)
    {0x1CFA, 0x1CFA, 0},	// Common (Exclusion)
    {0x1D00, 0x1D25, 2},	// Latin
    {0x1D26, 0x1D2A, 11},	// Greek
    {0x1D2B, 0x1D2B, 7},	// Cyrillic
    {0x1D2C, 0x1D5C, 2},	// Latin (Not_NFKC)
    {0x1D5D, 0x1D61, 11},	// Greek (Not_NFKC)
    {0x1D62, 0x1D65, 2},	// Latin (Not_NFKC)
    {0x1D66, 0x1D6A, 11},	// Greek (Not_NFKC)
    {0x1D6B, 0x1D77, 2},	// Latin
    {0x1D78, 0x1D78, 7},	// Cyrillic (Not_NFKC)
    {0x1D79, 0x1DBE, 2},	// Latin
    {0x1DBF, 0x1DBF, 11},	// Greek (Not_NFKC)
    {0x1DC0, 0x1DFF, 1},	// Inherited (Technical Obsolete)
    {0x1E00, 0x1EFF, 2},	// Latin
    {0x1F00, 0x1FFE, 11},	// Greek (Obsolete)
    {0x2000, 0x200B, 0},	// Common (Not_NFKC)
    {0x200C, 0x200D, 1},	// Inherited (Default_Ignorable)
    {0x200E, 0x2070, 0},	// Common (Default_Ignorable)
    {0x2071, 0x2071, 2},	// Latin (Not_NFKC)
    {0x2074, 0x207E, 0},	// Common (Not_NFKC)
    {0x207F, 0x207F, 2},	// Latin (Not_NFKC)
    {0x2080, 0x208E, 0},	// Common (Not_NFKC)
    {0x2090, 0x209C, 2},	// Latin (Not_NFKC)
    {0x20A0, 0x20C1, 0},	// Common (Not_XID)
    {0x20D0, 0x20F0, 1},	// Inherited
    {0x2100, 0x2125, 0},	// Common (Not_NFKC)
    {0x2126, 0x2126, 11},	// Greek (Not_NFKC)
    {0x2127, 0x2129, 0},	// Common (Obsolete Not_XID)
    {0x212A, 0x212B, 2},	// Latin (Not_NFKC)
    {0x212C, 0x2131, 0},	// Common (Not_NFKC)
    {0x2132, 0x2132, 2},	// Latin (Obsolete)
    {0x2133, 0x214D, 0},	// Common (Not_NFKC)
    {0x214E, 0x214E, 2},	// Latin (Obsolete)
    {0x214F, 0x215F, 0},	// Common (Obsolete Not_XID)
    {0x2160, 0x2188, 2},	// Latin (Not_NFKC)
    {0x2189, 0x27FF, 0},	// Common (Not_NFKC)
    {0x2800, 0x28FF, 38},	// Braille (Technical Not_XID)
    {0x2900, 0x2BFF, 0},	// Common (Not_XID)
    {0x2C00, 0x2C5F, 56},	// Glagolitic (Exclusion)
    {0x2C60, 0x2C7F, 2},	// Latin
    {0x2C80, 0x2CFF, 44},	// Coptic (Exclusion)
    {0x2D00, 0x2D2D, 10},	// Georgian (Obsolete)
    {0x2D30, 0x2D7F, 170},	// Tifinagh (Limited_Use)
    {0x2D80, 0x2DDE, 9},	// Ethiopic (Uncommon_Use)
    {0x2DE0, 0x2DFF, 7},	// Cyrillic (Obsolete)
    {0x2E00, 0x2E5D, 0},	// Common (Technical Obsolete Not_XID)
    {0x2E80, 0x2FD5, 15},	// Han (Not_XID)
    {0x2FF0, 0x3004, 0},	// Common (Not_XID)
    {0x3005, 0x3005, 15},	// Han
    {0x3006, 0x3006, 0},	// Common
    {0x3007, 0x3007, 15},	// Han
    {0x3008, 0x3020, 0},	// Common (Not_XID)
    {0x3021, 0x3029, 15},	// Han
    {0x302A, 0x302D, 1},	// Inherited
    {0x302E, 0x302F, 14},	// Hangul (Technical Obsolete)
    {0x3030, 0x3037, 0},	// Common (Not_XID)
    {0x3038, 0x303B, 15},	// Han (Not_NFKC)
    {0x303C, 0x303F, 0},	// Common
    {0x3041, 0x3096, 17},	// Hiragana
    {0x3099, 0x309A, 1},	// Inherited (Uncommon_Use)
    {0x309B, 0x309C, 0},	// Common (Not_NFKC)
    {0x309D, 0x309F, 17},	// Hiragana
    {0x30A0, 0x30A0, 0},	// Common
    {0x30A1, 0x30FA, 18},	// Katakana
    {0x30FB, 0x30FC, 0},	// Common
    {0x30FD, 0x30FF, 18},	// Katakana
    {0x3105, 0x312F, 6},	// Bopomofo (Limited_Use)
    {0x3131, 0x318E, 14},	// Hangul (Not_NFKC)
    {0x3190, 0x319F, 0},	// Common (Not_XID)
    {0x31A0, 0x31BF, 6},	// Bopomofo (Limited_Use)
    {0x31C0, 0x31EF, 0},	// Common (Not_XID)
    {0x31F0, 0x31FF, 18},	// Katakana (Obsolete)
    {0x3200, 0x321E, 14},	// Hangul (Not_NFKC)
    {0x3220, 0x325F, 0},	// Common (Not_NFKC)
    {0x3260, 0x327E, 14},	// Hangul (Not_NFKC)
    {0x327F, 0x32CF, 0},	// Common (Technical Not_XID)
    {0x32D0, 0x32FE, 18},	// Katakana (Not_NFKC)
    {0x32FF, 0x32FF, 0},	// Common (Not_NFKC)
    {0x3300, 0x3357, 18},	// Katakana (Not_NFKC)
    {0x3358, 0x33FF, 0},	// Common (Not_NFKC)
    {0x3400, 0x4DBF, 15},	// Han (Uncommon_Use)
    {0x4DC0, 0x4DFF, 0},	// Common (Technical Not_XID)
    {0x4E00, 0x9FFF, 15},	// Han
    {0xA000, 0xA4C6, 173},	// Yi (Limited_Use)
    {0xA4D0, 0xA4FF, 153},	// Lisu (Limited_Use)
    {0xA500, 0xA62B, 171},	// Vai (Limited_Use)
    {0xA640, 0xA69F, 7},	// Cyrillic (Obsolete)
    {0xA6A0, 0xA6F7, 142},	// Bamum (Limited_Use)
    {0xA700, 0xA721, 0},	// Common (Obsolete Not_XID)
    {0xA722, 0xA787, 2},	// Latin (Technical Obsolete)
    {0xA788, 0xA78A, 0},	// Common
    {0xA78B, 0xA7FF, 2},	// Latin (Uncommon_Use)
    {0xA800, 0xA82C, 165},	// Syloti_Nagri (Limited_Use)
    {0xA830, 0xA839, 0},	// Common (Not_XID)
    {0xA840, 0xA877, 109},	// Phags_Pa (Exclusion)
    {0xA880, 0xA8D9, 163},	// Saurashtra (Limited_Use)
    {0xA8E0, 0xA8FF, 8},	// Devanagari (Obsolete)
    {0xA900, 0xA92D, 150},	// Kayah_Li (Limited_Use)
    {0xA92E, 0xA92E, 0},	// Common (Not_XID)
    {0xA92F, 0xA92F, 150},	// Kayah_Li (Limited_Use Not_XID)
    {0xA930, 0xA95F, 112},	// Rejang (Exclusion)
    {0xA960, 0xA97C, 14},	// Hangul (Obsolete)
    {0xA980, 0xA9CD, 149},	// Javanese (Limited_Use)
    {0xA9CF, 0xA9CF, 0},	// Common (Limited_Use Uncommon_Use)
    {0xA9D0, 0xA9DF, 149},	// Javanese (Limited_Use)
    {0xA9E0, 0xA9FE, 23},	// Myanmar (Obsolete)
    {0xAA00, 0xAA5F, 146},	// Cham (Limited_Use)
    {0xAA60, 0xAA7F, 23},	// Myanmar (Uncommon_Use)
    {0xAA80, 0xAADF, 169},	// Tai_Viet (Limited_Use)
    {0xAAE0, 0xAAF6, 155},	// Meetei_Mayek (Limited_Use)
    {0xAB01, 0xAB2E, 9},	// Ethiopic (Uncommon_Use)
    {0xAB30, 0xAB5A, 2},	// Latin (Obsolete)
    {0xAB5B, 0xAB5B, 0},	// Common (Not_XID)
    {0xAB5C, 0xAB64, 2},	// Latin (Not_NFKC)
    {0xAB65, 0xAB65, 11},	// Greek (Obsolete)
    {0xAB66, 0xAB69, 2},	// Latin (Uncommon_Use)
    {0xAB6A, 0xAB6B, 0},	// Common (Not_XID)
    {0xAB70, 0xABBF, 147},	// Cherokee (Limited_Use)
    {0xABC0, 0xABF9, 155},	// Meetei_Mayek (Limited_Use)
    {0xAC00, 0xD7FB, 14},	// Hangul
    {0xF900, 0xFAD9, 15},	// Han (Not_NFKC)
    {0xFB00, 0xFB06, 2},	// Latin (Not_NFKC)
    {0xFB13, 0xFB17, 4},	// Armenian (Not_NFKC)
    {0xFB1D, 0xFB4F, 16},	// Hebrew (Not_NFKC)
    {0xFB50, 0xFD3D, 3},	// Arabic (Not_NFKC)
    {0xFD3E, 0xFD3F, 0},	// Common (Technical Not_XID)
    {0xFD40, 0xFDFF, 3},	// Arabic (Technical Not_XID)
    {0xFE00, 0xFE0F, 1},	// Inherited (Default_Ignorable)
    {0xFE10, 0xFE19, 0},	// Common (Not_NFKC)
    {0xFE20, 0xFE2D, 1},	// Inherited
    {0xFE2E, 0xFE2F, 7},	// Cyrillic (Uncommon_Use Technical)
    {0xFE30, 0xFE6B, 0},	// Common (Not_NFKC)
    {0xFE70, 0xFEFC, 3},	// Arabic (Not_NFKC)
    {0xFEFF, 0xFF20, 0},	// Common (Default_Ignorable)
    {0xFF21, 0xFF3A, 2},	// Latin (Not_NFKC)
    {0xFF3B, 0xFF40, 0},	// Common (Not_NFKC)
    {0xFF41, 0xFF5A, 2},	// Latin (Not_NFKC)
    {0xFF5B, 0xFF65, 0},	// Common (Not_NFKC)
    {0xFF66, 0xFF6F, 18},	// Katakana (Not_NFKC)
    {0xFF70, 0xFF70, 0},	// Common (Not_NFKC)
    {0xFF71, 0xFF9D, 18},	// Katakana (Not_NFKC)
    {0xFF9E, 0xFF9F, 0},	// Common (Not_NFKC)
    {0xFFA0, 0xFFDC, 14},	// Hangul (Default_Ignorable)
    {0xFFE0, 0xFFFD, 0},	// Common (Not_NFKC)
    {0x10000, 0x100FA, 74},	// Linear_B (Exclusion)
    {0x10100, 0x1013F, 0},	// Common (Exclusion Not_XID)
    {0x10140, 0x1018E, 11},	// Greek (Obsolete)
    {0x10190, 0x1019C, 0},	// Common (Not_XID)
    {0x101A0, 0x101A0, 11},	// Greek (Not_XID)
    {0x101D0, 0x101FC, 0},	// Common (Obsolete Not_XID)
    {0x101FD, 0x101FD, 1},	// Inherited (Obsolete)
    {0x10280, 0x1029C, 75},	// Lycian (Exclusion)
    {0x102A0, 0x102D0, 41},	// Carian (Exclusion)
    {0x102E0, 0x102E0, 1},	// Inherited (Obsolete)
    {0x102E1, 0x102FB, 0},	// Common (Obsolete Not_XID)
    {0x10300, 0x1032F, 97},	// Old_Italic (Exclusion)
    {0x10330, 0x1034A, 57},	// Gothic (Exclusion)
    {0x10350, 0x1037A, 99},	// Old_Permic (Exclusion)
    {0x10380, 0x1039F, 135},	// Ugaritic (Exclusion)
    {0x103A0, 0x103D5, 100},	// Old_Persian (Exclusion)
    {0x10400, 0x1044F, 48},	// Deseret (Exclusion)
    {0x10450, 0x1047F, 116},	// Shavian (Exclusion)
    {0x10480, 0x104A9, 105},	// Osmanya (Exclusion)
    {0x104B0, 0x104FB, 162},	// Osage (Limited_Use)
    {0x10500, 0x10527, 53},	// Elbasan (Exclusion)
    {0x10530, 0x1056F, 42},	// Caucasian_Albanian (Exclusion)
    {0x10570, 0x105BC, 136},	// Vithkuqi (Exclusion)
    {0x105C0, 0x105F3, 131},	// Todhri (Exclusion)
    {0x10600, 0x10767, 73},	// Linear_A (Exclusion)
    {0x10780, 0x107BA, 2},	// Latin (Uncommon_Use)
    {0x10800, 0x1083F, 46},	// Cypriot (Exclusion)
    {0x10840, 0x1085F, 63},	// Imperial_Aramaic (Exclusion)
    {0x10860, 0x1087F, 107},	// Palmyrene (Exclusion)
    {0x10880, 0x108AF, 90},	// Nabataean (Exclusion)
    {0x108E0, 0x108FF, 62},	// Hatran (Exclusion)
    {0x10900, 0x1091F, 110},	// Phoenician (Exclusion)
    {0x10920, 0x1093F, 76},	// Lydian (Exclusion)
    {0x10940, 0x10959, 118},	// Sidetic (Exclusion)
    {0x10980, 0x1099F, 85},	// Meroitic_Hieroglyphs (Exclusion)
    {0x109A0, 0x109FF, 84},	// Meroitic_Cursive (Exclusion)
    {0x10A00, 0x10A58, 68},	// Kharoshthi (Exclusion)
    {0x10A60, 0x10A7F, 102},	// Old_South_Arabian (Exclusion)
    {0x10A80, 0x10A9F, 98},	// Old_North_Arabian (Exclusion)
    {0x10AC0, 0x10AF6, 79},	// Manichaean (Exclusion)
    {0x10B00, 0x10B3F, 33},	// Avestan (Exclusion)
    {0x10B40, 0x10B5F, 65},	// Inscriptional_Parthian (Exclusion)
    {0x10B60, 0x10B7F, 64},	// Inscriptional_Pahlavi (Exclusion)
    {0x10B80, 0x10BAF, 111},	// Psalter_Pahlavi (Exclusion)
    {0x10C00, 0x10C48, 103},	// Old_Turkic (Exclusion)
    {0x10C80, 0x10CFF, 96},	// Old_Hungarian (Exclusion)
    {0x10D00, 0x10D39, 148},	// Hanifi_Rohingya (Limited_Use)
    {0x10D40, 0x10D8F, 55},	// Garay (Exclusion)
    {0x10E60, 0x10E7E, 3},	// Arabic (Not_XID)
    {0x10E80, 0x10EB1, 138},	// Yezidi (Exclusion)
    {0x10EC2, 0x10EFF, 3},	// Arabic (Uncommon_Use)
    {0x10F00, 0x10F27, 101},	// Old_Sogdian (Exclusion)
    {0x10F30, 0x10F59, 120},	// Sogdian (Exclusion)
    {0x10F70, 0x10F89, 104},	// Old_Uyghur (Exclusion)
    {0x10FB0, 0x10FCB, 43},	// Chorasmian (Exclusion)
    {0x10FE0, 0x10FF6, 54},	// Elymaic (Exclusion)
    {0x11000, 0x1107F, 37},	// Brahmi (Exclusion)
    {0x11080, 0x110CD, 66},	// Kaithi (Exclusion)
    {0x110D0, 0x110F9, 121},	// Sora_Sompeng (Exclusion)
    {0x11100, 0x11147, 145},	// Chakma (Limited_Use)
    {0x11150, 0x11176, 77},	// Mahajani (Exclusion)
    {0x11180, 0x111DF, 115},	// Sharada (Exclusion)
    {0x111E1, 0x111F4, 25},	// Sinhala (Not_XID)
    {0x11200, 0x11241, 70},	// Khojki (Exclusion)
    {0x11280, 0x112A9, 89},	// Multani (Exclusion)
    {0x112B0, 0x112F9, 71},	// Khudawadi (Exclusion)
    {0x11300, 0x11339, 58},	// Grantha (Exclusion)
    {0x1133B, 0x1133B, 1},	// Inherited (Uncommon_Use)
    {0x1133C, 0x11374, 58},	// Grantha
    {0x11380, 0x113E2, 134},	// Tulu_Tigalari (Exclusion)
    {0x11400, 0x11461, 158},	// Newa (Limited_Use)
    {0x11480, 0x114D9, 130},	// Tirhuta (Exclusion)
    {0x11580, 0x115DD, 117},	// Siddham (Exclusion)
    {0x11600, 0x11659, 86},	// Modi (Exclusion)
    {0x11660, 0x1166C, 87},	// Mongolian (Exclusion Not_XID)
    {0x11680, 0x116C9, 127},	// Takri (Exclusion)
    {0x116D0, 0x116E3, 23},	// Myanmar (Uncommon_Use)
    {0x11700, 0x11746, 31},	// Ahom (Exclusion)
    {0x11800, 0x1183B, 50},	// Dogra (Exclusion)
    {0x118A0, 0x118FF, 137},	// Warang_Citi (Exclusion)
    {0x11900, 0x11959, 49},	// Dives_Akuru (Exclusion)
    {0x119A0, 0x119E4, 92},	// Nandinagari (Exclusion)
    {0x11A00, 0x11A47, 139},	// Zanabazar_Square (Exclusion)
    {0x11A50, 0x11AA2, 122},	// Soyombo (Exclusion)
    {0x11AB0, 0x11ABF, 144},	// Canadian_Aboriginal (Limited_Use)
    {0x11AC0, 0x11AF8, 108},	// Pau_Cin_Hau (Exclusion)
    {0x11B00, 0x11B09, 8},	// Devanagari (Not_XID)
    {0x11B60, 0x11B67, 115},	// Sharada (Exclusion)
    {0x11BC0, 0x11BF9, 123},	// Sunuwar (Exclusion)
    {0x11C00, 0x11C6C, 36},	// Bhaiksuki (Exclusion)
    {0x11C70, 0x11CB6, 80},	// Marchen (Exclusion Not_XID)
    {0x11D00, 0x11D59, 81},	// Masaram_Gondi (Exclusion)
    {0x11D60, 0x11DA9, 59},	// Gunjala_Gondi (Exclusion)
    {0x11DB0, 0x11DE9, 132},	// Tolong_Siki (Exclusion)
    {0x11EE0, 0x11EF8, 78},	// Makasar (Exclusion)
    {0x11F00, 0x11F5A, 67},	// Kawi (Exclusion)
    {0x11FB0, 0x11FB0, 153},	// Lisu (Limited_Use)
    {0x11FC0, 0x11FFF, 26},	// Tamil (Not_XID)
    {0x12000, 0x12543, 45},	// Cuneiform (Exclusion)
    {0x12F90, 0x12FF2, 47},	// Cypro_Minoan (Exclusion)
    {0x13000, 0x143FA, 52},	// Egyptian_Hieroglyphs (Exclusion)
    {0x14400, 0x14646, 32},	// Anatolian_Hieroglyphs (Exclusion)
    {0x16100, 0x16139, 60},	// Gurung_Khema (Exclusion)
    {0x16800, 0x16A38, 142},	// Bamum (Limited_Use)
    {0x16A40, 0x16A6F, 88},	// Mro (Uncommon_Use Exclusion)
    {0x16A70, 0x16AC9, 128},	// Tangsa (Exclusion)
    {0x16AD0, 0x16AF5, 34},	// Bassa_Vah (Exclusion)
    {0x16B00, 0x16B8F, 106},	// Pahawh_Hmong (Exclusion)
    {0x16D40, 0x16D79, 72},	// Kirat_Rai (Exclusion)
    {0x16E40, 0x16E9A, 82},	// Medefaidrin (Exclusion)
    {0x16EA0, 0x16ED3, 35},	// Beria_Erfe (Exclusion)
    {0x16F00, 0x16F9F, 156},	// Miao (Limited_Use)
    {0x16FE0, 0x16FE0, 129},	// Tangut (Exclusion)
    {0x16FE1, 0x16FE1, 93},	// Nushu (Exclusion)
    {0x16FE2, 0x16FE3, 15},	// Han (Not_XID)
    {0x16FE4, 0x16FE4, 69},	// Khitan_Small_Script (Exclusion)
    {0x16FF0, 0x16FF6, 15},	// Han (Obsolete)
    {0x17000, 0x18AFF, 129},	// Tangut (Exclusion)
    {0x18B00, 0x18CFF, 69},	// Khitan_Small_Script (Exclusion)
    {0x18D00, 0x18DF2, 129},	// Tangut (Exclusion)
    {0x1AFF0, 0x1B000, 18},	// Katakana (Uncommon_Use)
    {0x1B001, 0x1B11F, 17},	// Hiragana (Obsolete)
    {0x1B120, 0x1B122, 18},	// Katakana (Obsolete)
    {0x1B132, 0x1B152, 17},	// Hiragana (Obsolete)
    {0x1B155, 0x1B167, 18},	// Katakana (Obsolete)
    {0x1B170, 0x1B2FB, 93},	// Nushu (Exclusion)
    {0x1BC00, 0x1BC9F, 51},	// Duployan (Exclusion)
    {0x1BCA0, 0x1CEF0, 0},	// Common (Default_Ignorable)
    {0x1CF00, 0x1CF46, 1},	// Inherited
    {0x1CF50, 0x1D166, 0},	// Common (Technical Not_XID)
    {0x1D167, 0x1D169, 1},	// Inherited
    {0x1D16A, 0x1D17A, 0},	// Common (Technical Not_XID)
    {0x1D17B, 0x1D182, 1},	// Inherited
    {0x1D183, 0x1D184, 0},	// Common (Technical Not_XID)
    {0x1D185, 0x1D18B, 1},	// Inherited
    {0x1D18C, 0x1D1A9, 0},	// Common (Technical Not_XID)
    {0x1D1AA, 0x1D1AD, 1},	// Inherited
    {0x1D1AE, 0x1D1EA, 0},	// Common (Technical Not_XID)
    {0x1D200, 0x1D245, 11},	// Greek (Obsolete Not_XID)
    {0x1D2C0, 0x1D7FF, 0},	// Common (Not_XID)
    {0x1D800, 0x1DAAF, 119},	// SignWriting (Exclusion Not_XID)
    {0x1DF00, 0x1DF2A, 2},	// Latin
    {0x1E000, 0x1E02A, 56},	// Glagolitic (Exclusion)
    {0x1E030, 0x1E08F, 7},	// Cyrillic (Not_NFKC)
    {0x1E100, 0x1E14F, 160},	// Nyiakeng_Puachue_Hmong (Limited_Use)
    {0x1E290, 0x1E2AE, 133},	// Toto (Exclusion)
    {0x1E2C0, 0x1E2FF, 172},	// Wancho (Limited_Use)
    {0x1E4D0, 0x1E4F9, 91},	// Nag_Mundari (Exclusion)
    {0x1E5D0, 0x1E5FF, 95},	// Ol_Onal (Exclusion)
    {0x1E6C0, 0x1E6FF, 126},	// Tai_Yo (Exclusion)
    {0x1E7E0, 0x1E7FE, 9},	// Ethiopic
    {0x1E800, 0x1E8D6, 83},	// Mende_Kikakui (Exclusion)
    {0x1E900, 0x1E95F, 140},	// Adlam (Limited_Use)
    {0x1EC71, 0x1ED3D, 0},	// Common (Not_XID)
    {0x1EE00, 0x1EEF1, 3},	// Arabic (Not_NFKC)
    {0x1F000, 0x1F1FF, 0},	// Common (Not_XID)
    {0x1F200, 0x1F200, 17},	// Hiragana (Not_NFKC)
    {0x1F201, 0x1FBFA, 0},	// Common (Not_NFKC)
    {0x20000, 0x33479, 15},	// Han (Uncommon_Use)
    {0xE0001, 0xE007F, 0},	// Common (Deprecated)
    {0xE0100, 0xE01EF, 1},	// Inherited (Default_Ignorable)
    // clang-format on
};

const struct scx scx_list[] = {
    // clang-format off
    {0x02C7, 0x02C7, GC_Lm, "\x06\x02"},	// Bopo Latn
    {0x02C9, 0x02CB, GC_Lm, "\x06\x02"},	// Bopo Latn
    {0x02CD, 0x02CD, GC_Lm, "\x02\x99"},	// Latn Lisu
    {0x02D7, 0x02D7, GC_Sk, "\x02\x1d"},	// Latn Thai                      (Not_XID)
    {0x02D9, 0x02D9, GC_Sk, "\x06\x02"},	// Bopo Latn                      (Not_NFKC)
    {0x0302, 0x0302, GC_Mn, "\x93\x07\x02\xaa"},	// Cher Cyrl Latn Tfng
    {0x0303, 0x0303, GC_Mn, "\x38\x02\x7b\xa6\x1d"},	// Glag Latn Sunu Syrc Thai
    {0x0305, 0x0305, GC_Mn, "\x2c\x35\x38\x39\x12\x02"},	// Copt Elba Glag Goth Kana Latn  (Uncommon_Use)
    {0x0306, 0x0306, GC_Mn, "\x07\x0b\x02\x63\xaa"},	// Cyrl Grek Latn Perm Tfng
    {0x0309, 0x0309, GC_Mn, "\x02\xaa"},	// Latn Tfng
    {0x030A, 0x030A, GC_Mn, "\x33\x02\xa6"},	// Dupl Latn Syrc
    {0x030B, 0x030B, GC_Mn, "\x93\x07\x02\xa2"},	// Cher Cyrl Latn Osge
    {0x030C, 0x030C, GC_Mn, "\x93\x02\xa7"},	// Cher Latn Tale
    {0x030D, 0x030D, GC_Mn, "\x02\x7b"},	// Latn Sunu                      (Uncommon_Use)
    {0x030E, 0x030E, GC_Mn, "\x09\x02"},	// Ethi Latn
    {0x0310, 0x0310, GC_Mn, "\x02\x7b"},	// Latn Sunu
    {0x0311, 0x0311, GC_Mn, "\x07\x02\x83"},	// Cyrl Latn Todr
    {0x0313, 0x0313, GC_Mn, "\x0b\x02\x63\x83"},	// Grek Latn Perm Todr
    {0x0323, 0x0323, GC_Mn, "\x93\x33\x12\x02\xa6\xaa"},	// Cher Dupl Kana Latn Syrc Tfng
    {0x0324, 0x0324, GC_Mn, "\x93\x33\x02\xa6"},	// Cher Dupl Latn Syrc
    {0x0325, 0x0325, GC_Mn, "\x02\xa6"},	// Latn Syrc
    {0x032D, 0x032D, GC_Mn, "\x02\x7b\xa6"},	// Latn Sunu Syrc
    {0x032E, 0x032E, GC_Mn, "\x02\xa6"},	// Latn Syrc
    {0x0330, 0x0330, GC_Mn, "\x93\x02\xa6"},	// Cher Latn Syrc
    {0x0342, 0x0345, GC_Mn, "\x0b"},	// Grek
    {0x0358, 0x0358, GC_Mn, "\x02\xa2"},	// Latn Osge                      (Uncommon_Use)
    {0x035E, 0x035E, GC_Mn, "\x2a\x02\x83"},	// Aghb Latn Todr
    {0x0363, 0x036F, GC_Mn, "\x02"},	// Latn                           (Obsolete)
    {0x0374, 0x0375, GC_Lm, "\x2c\x0b"},	// Copt Grek                      (Not_NFKC)
    {0x0483, 0x0483, GC_Mn, "\x07\x63"},	// Cyrl Perm                      (Obsolete)
    {0x0484, 0x0484, GC_Mn, "\x07\x38"},	// Cyrl Glag                      (Technical Obsolete)
    {0x0485, 0x0486, GC_Mn, "\x07\x02"},	// Cyrl Latn                      (Technical Obsolete)
    {0x0487, 0x0487, GC_Mn, "\x07\x38"},	// Cyrl Glag                      (Technical Obsolete)
    {0x0589, 0x0589, GC_Po, "\x04\x0a\x38"},	// Armn Geor Glag                 (Not_XID)
    {0x061C, 0x061C, GC_Cf, "\x03\xa6\x1c"},	// Arab Syrc Thaa                 (Default_Ignorable)
    {0x064B, 0x0655, GC_Mn, "\x03\xa6"},	// Arab Syrc
    {0x0660, 0x0669, GC_Nd, "\x03\x1c\x8a"},	// Arab Thaa Yezi
    {0x0670, 0x0670, GC_Mn, "\x03\xa6"},	// Arab Syrc
    {0x06D4, 0x06D4, GC_Po, "\x03\x94"},	// Arab Rohg                      (Not_XID)
    {0x0966, 0x096F, GC_Nd, "\x08\x32\x42\x4d"},	// Deva Dogr Kthi Mahj
    {0x09E6, 0x09EF, GC_Nd, "\x05\x91\xa5"},	// Beng Cakm Sylo
    {0x0A66, 0x0A6F, GC_Nd, "\x0d\x59"},	// Guru Mult                      (Uncommon_Use)
    {0x0AE6, 0x0AEF, GC_Nd, "\x0c\x46"},	// Gujr Khoj
    {0x0BE6, 0x0BF3, GC_Nd, "\x3a\x1a"},	// Gran Taml                      (Uncommon_Use)
    {0x0CE6, 0x0CEF, GC_Nd, "\x13\x5c\x86"},	// Knda Nand Tutg
    {0x1040, 0x1049, GC_Nd, "\x91\x17\xa7"},	// Cakm Mymr Tale
    {0x10FB, 0x10FB, GC_Po, "\x0a\x38\x02"},	// Geor Glag Latn                 (Not_XID)
    {0x16EB, 0x16ED, GC_Po, "\x71"},	// Runr                           (Exclusion Not_XID)
    {0x1735, 0x1736, GC_Po, "\x28\x3d\x7d\x7c"},	// Buhd Hano Tagb Tglg            (Exclusion Not_XID)
    {0x1802, 0x1803, GC_Po, "\x57\x6d"},	// Mong Phag                      (Exclusion Not_XID)
    {0x1805, 0x1805, GC_Po, "\x57\x6d"},	// Mong Phag                      (Exclusion Not_XID)
    {0x1CD0, 0x1CD0, GC_Mn, "\x05\x08\x3a\x13"},	// Beng Deva Gran Knda            (Obsolete)
    {0x1CD1, 0x1CD1, GC_Mn, "\x08"},	// Deva                           (Obsolete)
    {0x1CD2, 0x1CD2, GC_Mn, "\x05\x08\x3a\x13"},	// Beng Deva Gran Knda            (Obsolete)
    {0x1CD3, 0x1CD3, GC_Po, "\x08\x3a\x13"},	// Deva Gran Knda                 (Obsolete Not_XID)
    {0x1CD4, 0x1CD4, GC_Mn, "\x08"},	// Deva                           (Obsolete)
    {0x1CD5, 0x1CD5, GC_Mn, "\x05\x08\x9e\x1b\x82"},	// Beng Deva Newa Telu Tirh       (Obsolete)
    {0x1CD6, 0x1CD6, GC_Mn, "\x05\x08\x1b"},	// Beng Deva Telu                 (Obsolete)
    {0x1CD7, 0x1CD7, GC_Mn, "\x08\x9e\x73"},	// Deva Newa Shrd                 (Obsolete)
    {0x1CD8, 0x1CD8, GC_Mn, "\x05\x08\x9e\x1b"},	// Beng Deva Newa Telu            (Obsolete)
    {0x1CD9, 0x1CD9, GC_Mn, "\x08\x73"},	// Deva Shrd                      (Obsolete)
    {0x1CDA, 0x1CDA, GC_Mn, "\x08\x13\x16\x18\x1a\x1b"},	// Deva Knda Mlym Orya Taml Telu  (Obsolete)
    {0x1CDB, 0x1CDB, GC_Mn, "\x08"},	// Deva                           (Obsolete)
    {0x1CDC, 0x1CDD, GC_Mn, "\x08\x73"},	// Deva Shrd                      (Obsolete)
    {0x1CDE, 0x1CDF, GC_Mn, "\x08"},	// Deva                           (Obsolete)
    {0x1CE0, 0x1CE0, GC_Mn, "\x08\x73"},	// Deva Shrd                      (Obsolete)
    {0x1CE1, 0x1CE1, GC_Mc, "\x05\x08"},	// Beng Deva                      (Obsolete)
    {0x1CE2, 0x1CE2, GC_Mn, "\x08\x9e\x82"},	// Deva Newa Tirh                 (Obsolete)
    {0x1CE3, 0x1CE8, GC_Mn, "\x08"},	// Deva                           (Obsolete)
    {0x1CE9, 0x1CE9, GC_Lo, "\x08\x5c\x9e"},	// Deva Nand Newa                 (Obsolete)
    {0x1CEA, 0x1CEA, GC_Lo, "\x05\x08\x73"},	// Beng Deva Shrd                 (Obsolete)
    {0x1CEB, 0x1CEB, GC_Lo, "\x08\x9e"},	// Deva Newa                      (Obsolete)
    {0x1CEC, 0x1CEC, GC_Lo, "\x08"},	// Deva                           (Obsolete)
    {0x1CED, 0x1CED, GC_Mn, "\x05\x08\x9e\x73"},	// Beng Deva Newa Shrd            (Obsolete)
    {0x1CEE, 0x1CF1, GC_Lo, "\x08"},	// Deva                           (Obsolete)
    {0x1CF3, 0x1CF3, GC_Lo, "\x08\x3a"},	// Deva Gran                      (Obsolete)
    {0x1CF4, 0x1CF4, GC_Mn, "\x08\x3a\x13\x86"},	// Deva Gran Knda Tutg            (Obsolete)
    {0x1CF5, 0x1CF6, GC_Lo, "\x05\x08"},	// Beng Deva                      (Obsolete)
    {0x1CF7, 0x1CF7, GC_Mc, "\x05"},	// Beng                           (Obsolete)
    {0x1CF8, 0x1CF9, GC_Mn, "\x08\x3a"},	// Deva Gran                      (Obsolete)
    {0x1CFA, 0x1CFA, GC_Lo, "\x5c"},	// Nand                           (Exclusion)
    {0x1DC0, 0x1DC1, GC_Mn, "\x0b"},	// Grek                           (Technical Obsolete)
    {0x1DF8, 0x1DF8, GC_Mn, "\x07\x02\xa6"},	// Cyrl Latn Syrc
    {0x1DFA, 0x1DFA, GC_Mn, "\xa6"},	// Syrc                           (Limited_Use Technical)
    {0x202F, 0x202F, GC_Zs, "\x02\x57\x6d"},	// Latn Mong Phag                 (Not_NFKC)
    {0x204F, 0x204F, GC_Po, "\x8c\x03"},	// Adlm Arab                      (Not_XID)
    {0x205A, 0x205A, GC_Po, "\x29\x0a\x38\x60\x4b\x67"},	// Cari Geor Glag Hung Lyci Orkh  (Obsolete Not_XID)
    {0x205D, 0x205D, GC_Po, "\x29\x0b\x60\x55"},	// Cari Grek Hung Mero            (Obsolete Not_XID)
    {0x20F0, 0x20F0, GC_Mn, "\x08\x3a\x02"},	// Deva Gran Latn
    {0x2E17, 0x2E17, GC_Pd, "\x2c\x02"},	// Copt Latn                      (Not_XID)
    {0x2E30, 0x2E30, GC_Po, "\x21\x67"},	// Avst Orkh                      (Exclusion Not_XID)
    {0x2E3C, 0x2E3C, GC_Po, "\x33"},	// Dupl                           (Exclusion Not_XID)
    {0x2E41, 0x2E41, GC_Po, "\x8c\x03\x60"},	// Adlm Arab Hung                 (Not_XID)
    {0x2E43, 0x2E43, GC_Po, "\x07\x38"},	// Cyrl Glag                      (Not_XID)
    {0x2FF0, 0x2FFF, GC_So, "\x0f\x81"},	// Hani Tang                      (Not_XID)
    {0x3003, 0x3003, GC_Po, "\x06\x0e\x0f\x11\x12"},	// Bopo Hang Hani Hira Kana       (Not_XID)
    {0x3006, 0x3006, GC_Lo, "\x0f"},	// Hani
    {0x300C, 0x3011, GC_Ps, "\x06\x0e\x0f\x11\x12\xad"},	// Bopo Hang Hani Hira Kana Yiii  (Not_XID)
    {0x3013, 0x3013, GC_So, "\x06\x0e\x0f\x11\x12"},	// Bopo Hang Hani Hira Kana       (Not_XID)
    {0x3014, 0x301B, GC_Ps, "\x06\x0e\x0f\x11\x12\xad"},	// Bopo Hang Hani Hira Kana Yiii  (Not_XID)
    {0x301C, 0x301F, GC_Pd, "\x06\x0e\x0f\x11\x12"},	// Bopo Hang Hani Hira Kana       (Not_XID)
    {0x302A, 0x302D, GC_Mn, "\x06\x0f"},	// Bopo Hani
    {0x3030, 0x3030, GC_Pd, "\x06\x0e\x0f\x11\x12"},	// Bopo Hang Hani Hira Kana       (Not_XID)
    {0x3031, 0x3035, GC_Lm, "\x11\x12"},	// Hira Kana
    {0x3037, 0x3037, GC_So, "\x06\x0e\x0f\x11\x12"},	// Bopo Hang Hani Hira Kana       (Not_XID)
    {0x303C, 0x303D, GC_Lo, "\x0f\x11\x12"},	// Hani Hira Kana
    {0x303E, 0x303F, GC_So, "\x0f"},	// Hani                           (Not_XID)
    {0x3099, 0x309C, GC_Mn, "\x11\x12"},	// Hira Kana                      (Uncommon_Use)
    {0x30A0, 0x30A0, GC_Pd, "\x11\x12"},	// Hira Kana
    {0x30FB, 0x30FB, GC_Po, "\x06\x0e\x0f\x11\x12\xad"},	// Bopo Hang Hani Hira Kana Yiii
    {0x30FC, 0x30FC, GC_Lm, "\x11\x12"},	// Hira Kana
    {0x3190, 0x319F, GC_So, "\x0f"},	// Hani                           (Not_XID)
    {0x31C0, 0x31E5, GC_So, "\x0f"},	// Hani                           (Not_XID)
    {0x31EF, 0x31EF, GC_So, "\x0f\x81"},	// Hani Tang                      (Not_XID)
    {0x3220, 0x3247, GC_No, "\x0f"},	// Hani                           (Not_NFKC)
    {0x3280, 0x32B0, GC_No, "\x0f"},	// Hani                           (Not_NFKC)
    {0x32C0, 0x32CB, GC_So, "\x0f"},	// Hani                           (Not_NFKC)
    {0x32FF, 0x32FF, GC_So, "\x0f"},	// Hani                           (Not_NFKC)
    {0x3358, 0x3370, GC_So, "\x0f"},	// Hani                           (Not_NFKC)
    {0x337B, 0x337F, GC_So, "\x0f"},	// Hani                           (Not_NFKC)
    {0x33E0, 0x33FE, GC_So, "\x0f"},	// Hani                           (Not_NFKC)
    {0xA66F, 0xA66F, GC_Mn, "\x07\x38"},	// Cyrl Glag                      (Uncommon_Use)
    {0xA700, 0xA707, GC_Sk, "\x0f\x02"},	// Hani Latn                      (Obsolete Not_XID)
    {0xA8F1, 0xA8F1, GC_Mn, "\x05\x08\x86"},	// Beng Deva Tutg                 (Obsolete)
    {0xA8F3, 0xA8F3, GC_Lo, "\x08\x1a"},	// Deva Taml                      (Obsolete)
    {0xA92E, 0xA92E, GC_Po, "\x96\x02\x17"},	// Kali Latn Mymr                 (Not_XID)
    {0xA9CF, 0xA9CF, GC_Lm, "\x27\x95"},	// Bugi Java                      (Limited_Use Uncommon_Use)
    {0xFD3E, 0xFD3F, GC_Pe, "\x03\x9f"},	// Arab Nkoo                      (Technical Not_XID)
    {0xFDF2, 0xFDF2, GC_Lo, "\x03\x1c"},	// Arab Thaa                      (Not_NFKC)
    {0xFDFD, 0xFDFD, GC_So, "\x03\x1c"},	// Arab Thaa                      (Technical Not_XID)
    {0xFE45, 0xFE46, GC_Po, "\x06\x0e\x0f\x11\x12"},	// Bopo Hang Hani Hira Kana       (Technical Not_XID)
    {0xFF61, 0xFF65, GC_Po, "\x06\x0e\x0f\x11\x12\xad"},	// Bopo Hang Hani Hira Kana Yiii  (Not_NFKC)
    {0xFF70, 0xFF70, GC_Lm, "\x11\x12"},	// Hira Kana                      (Not_NFKC)
    {0xFF9E, 0xFF9F, GC_Lm, "\x11\x12"},	// Hira Kana                      (Not_NFKC)
    {0x10100, 0x10101, GC_Po, "\x2f\x2e\x4a"},	// Cpmn Cprt Linb                 (Exclusion Not_XID)
    {0x10102, 0x10102, GC_Po, "\x2e\x4a"},	// Cprt Linb                      (Exclusion Not_XID)
    {0x10107, 0x10133, GC_No, "\x2e\x49\x4a"},	// Cprt Lina Linb                 (Exclusion Not_XID)
    {0x10137, 0x1013F, GC_So, "\x2e\x4a"},	// Cprt Linb                      (Exclusion Not_XID)
    {0x102E0, 0x102FB, GC_Mn, "\x03\x2c"},	// Arab Copt                      (Obsolete)
    {0x10AF2, 0x10AF2, GC_Po, "\x4f\x68"},	// Mani Ougr                      (Exclusion Not_XID)
    {0x11301, 0x11301, GC_Mn, "\x3a\x1a"},	// Gran Taml
    {0x11303, 0x11303, GC_Mc, "\x3a\x1a"},	// Gran Taml
    {0x1133B, 0x1133C, GC_Mn, "\x3a\x1a"},	// Gran Taml                      (Uncommon_Use)
    {0x11FD0, 0x11FD1, GC_No, "\x3a\x1a"},	// Gran Taml                      (Not_XID)
    {0x11FD3, 0x11FD3, GC_No, "\x3a\x1a"},	// Gran Taml                      (Not_XID)
    {0x1BCA0, 0x1BCA3, GC_Cf, "\x33"},	// Dupl                           (Default_Ignorable)
    {0x1D360, 0x1D371, GC_No, "\x0f"},	// Hani                           (Not_XID)
    {0x1F250, 0x1F251, GC_So, "\x0f"},	// Hani                           (Not_NFKC)
    // clang-format on
};

const char *const all_scripts[] = {
    // clang-format off
    // Recommended Scripts (not need to add them)
    // https://www.unicode.org/reports/tr31/#Table_Recommended_Scripts
    "Common",	// 0
    "Inherited",	// 1
    "Latin",	// 2
    "Arabic",	// 3
    "Armenian",	// 4
    "Bengali",	// 5
    "Bopomofo",	// 6
    "Cyrillic",	// 7
    "Devanagari",	// 8
    "Ethiopic",	// 9
    "Georgian",	// 10
    "Greek",	// 11
    "Gujarati",	// 12
    "Gurmukhi",	// 13
    "Hangul",	// 14
    "Han",	// 15
    "Hebrew",	// 16
    "Hiragana",	// 17
    "Katakana",	// 18
    "Kannada",	// 19
    "Khmer",	// 20
    "Lao",	// 21
    "Malayalam",	// 22
    "Myanmar",	// 23
    "Oriya",	// 24
    "Sinhala",	// 25
    "Tamil",	// 26
    "Telugu",	// 27
    "Thaana",	// 28
    "Thai",	// 29
    "Tibetan",	// 30
    // Excluded Scripts (but can be added expliclitly)
    // https://www.unicode.org/reports/tr31/#Table_Candidate_Characters_for_Exclusion_from_Identifiers
    "Ahom",	// 31
    "Anatolian_Hieroglyphs",	// 32
    "Avestan",	// 33
    "Bassa_Vah",	// 34
    "Beria_Erfe",	// 35
    "Bhaiksuki",	// 36
    "Brahmi",	// 37
    "Braille",	// 38
    "Buginese",	// 39
    "Buhid",	// 40
    "Carian",	// 41
    "Caucasian_Albanian",	// 42
    "Chorasmian",	// 43
    "Coptic",	// 44
    "Cuneiform",	// 45
    "Cypriot",	// 46
    "Cypro_Minoan",	// 47
    "Deseret",	// 48
    "Dives_Akuru",	// 49
    "Dogra",	// 50
    "Duployan",	// 51
    "Egyptian_Hieroglyphs",	// 52
    "Elbasan",	// 53
    "Elymaic",	// 54
    "Garay",	// 55
    "Glagolitic",	// 56
    "Gothic",	// 57
    "Grantha",	// 58
    "Gunjala_Gondi",	// 59
    "Gurung_Khema",	// 60
    "Hanunoo",	// 61
    "Hatran",	// 62
    "Imperial_Aramaic",	// 63
    "Inscriptional_Pahlavi",	// 64
    "Inscriptional_Parthian",	// 65
    "Kaithi",	// 66
    "Kawi",	// 67
    "Kharoshthi",	// 68
    "Khitan_Small_Script",	// 69
    "Khojki",	// 70
    "Khudawadi",	// 71
    "Kirat_Rai",	// 72
    "Linear_A",	// 73
    "Linear_B",	// 74
    "Lycian",	// 75
    "Lydian",	// 76
    "Mahajani",	// 77
    "Makasar",	// 78
    "Manichaean",	// 79
    "Marchen",	// 80
    "Masaram_Gondi",	// 81
    "Medefaidrin",	// 82
    "Mende_Kikakui",	// 83
    "Meroitic_Cursive",	// 84
    "Meroitic_Hieroglyphs",	// 85
    "Modi",	// 86
    "Mongolian",	// 87
    "Mro",	// 88
    "Multani",	// 89
    "Nabataean",	// 90
    "Nag_Mundari",	// 91
    "Nandinagari",	// 92
    "Nushu",	// 93
    "Ogham",	// 94
    "Ol_Onal",	// 95
    "Old_Hungarian",	// 96
    "Old_Italic",	// 97
    "Old_North_Arabian",	// 98
    "Old_Permic",	// 99
    "Old_Persian",	// 100
    "Old_Sogdian",	// 101
    "Old_South_Arabian",	// 102
    "Old_Turkic",	// 103
    "Old_Uyghur",	// 104
    "Osmanya",	// 105
    "Pahawh_Hmong",	// 106
    "Palmyrene",	// 107
    "Pau_Cin_Hau",	// 108
    "Phags_Pa",	// 109
    "Phoenician",	// 110
    "Psalter_Pahlavi",	// 111
    "Rejang",	// 112
    "Runic",	// 113
    "Samaritan",	// 114
    "Sharada",	// 115
    "Shavian",	// 116
    "Siddham",	// 117
    "Sidetic",	// 118
    "SignWriting",	// 119
    "Sogdian",	// 120
    "Sora_Sompeng",	// 121
    "Soyombo",	// 122
    "Sunuwar",	// 123
    "Tagalog",	// 124
    "Tagbanwa",	// 125
    "Tai_Yo",	// 126
    "Takri",	// 127
    "Tangsa",	// 128
    "Tangut",	// 129
    "Tirhuta",	// 130
    "Todhri",	// 131
    "Tolong_Siki",	// 132
    "Toto",	// 133
    "Tulu_Tigalari",	// 134
    "Ugaritic",	// 135
    "Vithkuqi",	// 136
    "Warang_Citi",	// 137
    "Yezidi",	// 138
    "Zanabazar_Square",	// 139
    // Limited Use Scripts
    // https://www.unicode.org/reports/tr31/#Table_Limited_Use_Scripts
    "Adlam",	// 140
    "Balinese",	// 141
    "Bamum",	// 142
    "Batak",	// 143
    "Canadian_Aboriginal",	// 144
    "Chakma",	// 145
    "Cham",	// 146
    "Cherokee",	// 147
    "Hanifi_Rohingya",	// 148
    "Javanese",	// 149
    "Kayah_Li",	// 150
    "Lepcha",	// 151
    "Limbu",	// 152
    "Lisu",	// 153
    "Mandaic",	// 154
    "Meetei_Mayek",	// 155
    "Miao",	// 156
    "New_Tai_Lue",	// 157
    "Newa",	// 158
    "Nko",	// 159
    "Nyiakeng_Puachue_Hmong",	// 160
    "Ol_Chiki",	// 161
    "Osage",	// 162
    "Saurashtra",	// 163
    "Sundanese",	// 164
    "Syloti_Nagri",	// 165
    "Syriac",	// 166
    "Tai_Le",	// 167
    "Tai_Tham",	// 168
    "Tai_Viet",	// 169
    "Tifinagh",	// 170
    "Vai",	// 171
    "Wancho",	// 172
    "Yi",	// 173
    "Unknown",	// 174
    // clang-format on
};

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
      L"\u010A\u010B\u0116\u0117\u0120\u0121\u0130\u017B\u017C\u0226\u0227\u022E\u022F\u06A7\u06AC\u06B6\u06BF\u06CF\u0762\u0765\u087A\u1DA1\u1E02\u1E03\u1E0A\u1E0B\u1E1E\u1E1F\u1E22\u1E23\u1E40\u1E41\u1E44\u1E45\u1E56\u1E57\u1E58\u1E59\u1E60\u1E61\u1E64\u1E65\u1E66\u1E67\u1E68\u1E69\u1E6A\u1E6B\u1E86\u1E87\u1E8A\u1E8B\u1E8E\u1E8F\u1E9B\u312E\U000105C9\U000105E4\U00010798\U00010EB0" },
      /* ĊċĖėĠġİŻżȦȧȮȯڧڬڶڿۏݢݥࡺᶡḂḃḊḋḞḟḢḣṀṁṄṅṖṗṘṙṠṡṤṥṦṧṨṩṪṫẆẇẊẋẎẏẛㄮ𐗉𐗤𐞘𐺰 */
    { 0x0308,  /* NSM: DIAERESIS 308 */
      L"\u00C4\u00CB\u00CF\u00D6\u00DC\u00E4\u00EB\u00EF\u00F6\u00FC\u00FF\u0178\u03AA\u03AB\u03CA\u03CB\u03D4\u0401\u0407\u0451\u0457\u04D2\u04D3\u04DA\u04DB\u04DC\u04DD\u04DE\u04DF\u04E4\u04E5\u04E6\u04E7\u04EA\u04EB\u04EC\u04ED\u04F0\u04F1\u04F4\u04F5\u04F8\u04F9\u1DF2\u1DF3\u1DF4\u1E26\u1E27\u1E4E\u1E4F\u1E7A\u1E7B\u1E84\u1E85\u1E8C\u1E8D\u1E97" },
      /* ÄËÏÖÜäëïöüÿŸΪΫϊϋϔЁЇёїӒӓӚӛӜӝӞӟӤӥӦӧӪӫӬӭӰӱӴӵӸӹᷲᷳᷴḦḧṎṏṺṻẄẅẌẍẗ */
    { 0x0309,  /* NSM: HOOK ABOVE 309 */
      L"\u1EA2\u1EA3\u1EA8\u1EA9\u1EB2\u1EB3\u1EBA\u1EBB\u1EC2\u1EC3\u1EC8\u1EC9\u1ECE\u1ECF\u1ED4\u1ED5\u1EDE\u1EDF\u1EE6\u1EE7\u1EEC\u1EED\u1EF6\u1EF7" },
      /* ẢảẨẩẲẳẺẻỂểỈỉỎỏỔổỞởỦủỬửỶỷ */
    { 0x030A,  /* NSM: RING ABOVE 30A */
      L"\u00C5\u00E5\u016E\u016F\u088F\u1E98\u1E99" },
      /* ÅåŮů࢏ẘẙ */
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

/* ---- Global state ---- */

unsigned s_u8id_options = U8ID_TR31_ALLOWED;
enum u8id_norm s_u8id_norm = U8ID_NFC;
enum u8id_profile s_u8id_profile = U8ID_PROFILE_TR39_4;
unsigned s_maxlen = 1024;

U8ID_LOCAL const char *u8ident_errstr(int errcode) {
  static const char *const _str[] = {
      "ERR_CONFUS",      "ERR_COMBINE",          "ERR_ENCODING",
      "ERR_SCRIPTS",     "ERR_SCRIPT",           "ERR_XID",
      "EOK",             "EOK_NORM",             "EOK_WARN_CONFUS",
      "EOK_NORM_WARN_CONFUS",
  };
  assert(errcode >= -6 && errcode <= 3);
  return _str[errcode + 6];
}

/* ---- Context management ---- */

struct ctx_t ctx[U8ID_CTX_TRESH] = {{0}};
static u8id_ctx_t i_ctx = 0;
struct ctx_t *ctxp = NULL;

/* Generates a new identifier document/context/directory, which
   initializes a new list of seen scripts. */
U8ID_EXTERN u8id_ctx_t u8ident_new_ctx(void) {
  // thread-safety later
  u8id_ctx_t i = ++i_ctx;
  if (i == U8ID_CTX_TRESH) {
    ctxp = (struct ctx_t *)calloc(U8ID_CTX_TRESH + 1, sizeof(struct ctx_t));
    if (!ctxp) {
      fprintf(stderr, "u8ident: out of memory\n"); abort();
    }
    // extra work, just for debugging. we never access these
    memcpy(ctxp, &ctx, U8ID_CTX_TRESH * sizeof(struct ctx_t));
  } else if (i > U8ID_CTX_TRESH) {
    struct ctx_t *p = (struct ctx_t *)realloc(ctxp, (i + 1) * sizeof(struct ctx_t));
    if (!p) {
      fprintf(stderr, "u8ident: out of memory\n"); abort();
    }
    ctxp = p;
    memset(&ctxp[i], 0, sizeof(struct ctx_t));
  } else {
    ctxp = &ctx[i];
  }
  return i_ctx;
}

U8ID_LOCAL struct ctx_t *u8ident_ctx(void);

/* Create a deep copy of the current context.  Useful when you need to
   check the same identifier against different profiles without losing
   the accumulated script list.  Returns a new context ID; the caller
   must free it with u8ident_free_ctx when done.

   Example — check one identifier against C23 and C11:

       u8ident_init(TR39_4, NFC, C23);
       enum u8id_errors ret_c23 = u8ident_check(id, NULL);
       u8id_ctx_t saved = u8ident_copy_ctx();
       u8ident_init(TR39_4, NFC, C11);
       enum u8id_errors ret_c11 = u8ident_check(id, NULL);
       u8ident_free_ctx(saved);
*/
U8ID_EXTERN u8id_ctx_t u8ident_copy_ctx(void) {
  const struct ctx_t *old = u8ident_ctx();
  u8id_ctx_t new_i = u8ident_new_ctx();
  struct ctx_t *newc =
      (new_i < U8ID_CTX_TRESH) ? &ctx[new_i] : &ctxp[new_i];
  memcpy(newc, old, sizeof(struct ctx_t));
  if (old->count > 8 && old->u8p) {
    newc->u8p = malloc(old->count);
    memcpy(newc->u8p, old->u8p, old->count);
  }
  return new_i;
}

/* Changes to the context previously generated with `u8ident_new_ctx`. */
U8ID_EXTERN int u8ident_set_ctx(u8id_ctx_t i) {
  if (i <= i_ctx) {
    i_ctx = i;
    return 0;
  } else
    return -1;
}

/* Changes to the context previously generated with `u8ident_new_ctx`. */
U8ID_LOCAL struct ctx_t *u8ident_ctx(void) {
  return (i_ctx < U8ID_CTX_TRESH) ? &ctx[i_ctx] : &ctxp[i_ctx];
}

// search in linear vector of scripts per ctx
U8ID_LOCAL bool u8ident_has_script_ctx(const uint8_t scr, const struct ctx_t *c) {
  if (!c->count)
    return false;
  const uint8_t *u8p = (c->count > 8) ? c->u8p : c->scr8;
  for (int i = 0; i < c->count; i++) {
    if (scr == u8p[i])
      return true;
  }
  return false;
}

U8ID_LOCAL bool u8ident_has_script(const uint8_t scr) {
  return u8ident_has_script_ctx(scr, u8ident_ctx());
}

U8ID_LOCAL int u8ident_add_script_ctx(const uint8_t scr, struct ctx_t *c) {
  if (scr < 2 || scr >= FIRST_LIMITED_USE_SCRIPT)
    return -1;
  int i = c->count;
  if (unlikely(i == 8)) {
    uint8_t *p = malloc(16);
    memcpy(p, c->scr8, 8);
    c->u8p = p;
    c->u8p[i] = scr;
  } else if (unlikely(i > 8 && (i & 7) == 7)) {
    c->u8p = realloc(c->u8p, i + 8);
    c->u8p[i] = scr;
  } else {
    if (i > 8) {
      if (!c->u8p) {
        c->u8p = calloc(16, 1);
        memcpy(c->u8p, c->scr8, 8);
      }
      c->u8p[i] = scr;
    } else {
      c->scr8[i] = scr;
    }
  }
  if (scr == SC_Han)
    c->has_han = 1;
  else if (scr == SC_Bopomofo)
    c->is_chinese = 1;
  else if (scr == SC_Katakana || scr == SC_Hiragana)
    c->is_japanese = 1;
  else if (scr == SC_Hangul)
    c->is_korean = 1;
  else if (scr == SC_Hebrew || scr == SC_Arabic)
    c->is_rtl = 1;
  c->count++;
  return 0;
}

static inline bool linear_search(const uint32_t cp,
                                 const struct range_bool *sc_list,
                                 const int len) {
  struct range_bool *s = (struct range_bool *)sc_list;
  for (int i = 0; i < len; i++) {
    assert(s->from <= s->to);
    if ((cp - s->from) <= (s->to - s->from))
      return true;
    if (cp <= s->to) // s is sorted. not found
      return false;
    s++;
  }
  return false;
}

static inline void *binary_search(const uint32_t cp, const char *list,
                                       const size_t len, const size_t size) {
  int n = (int)len;
  const char *p = list;
  struct sc *pos;
  while (n > 0) {
    pos = (struct sc *)(p + size * (n / 2));
    // hack: with unsigned wrapping max-cp is always higher, so false
    // was: (cp >= pos->from && cp <= pos->to)
    if ((cp - pos->from) <= (pos->to - pos->from))
      return pos;
    else if (cp < pos->from)
      n /= 2;
    else {
      p = (char *)pos + size;
      n -= (n / 2) + 1;
    }
  }
  return NULL;
}

// hybrid search: linear or binary
static inline uint8_t sc_search(const uint32_t cp, const struct sc *sc_list,
                                const size_t len) {
  if (cp < 255) { // 14 ranges a 9 byte (126 byte, i.e cache loads)
    struct sc *s = (struct sc *)sc_list;
    for (size_t i = 0; i < len; i++) {
      if ((cp - s->from) <= (s->to - s->from)) // faster in-between trick
        return s->scr;
      if (cp <= s->to) // s is sorted. not found
        return 255;
      s++;
    }
    return 255;
  } else {
    const struct sc *sc =
        (struct sc *)binary_search(cp, (char *)sc_list, len, sizeof(*sc_list));
    return sc ? sc->scr : 255;
  }
}

static inline bool range_bool_search(const uint32_t cp,
                                     const struct range_bool *list,
                                     const size_t len) {
  return binary_search(cp, (char *)list, len, sizeof(*list)) ? true : false;
}

U8ID_EXTERN uint8_t u8ident_get_script(const uint32_t cp) {
  // faster check, as we have no NON-xid's
  return sc_search(cp, nonxid_script_list, ARRAY_SIZE(nonxid_script_list));
}

/* Search for list of script indices */
U8ID_LOCAL const struct scx *u8ident_get_scx(const uint32_t cp) {
  return (const struct scx *)binary_search(
      cp, (char *)scx_list, ARRAY_SIZE(scx_list), sizeof(*scx_list));
}
/* Search for TR39 XID entry, in start or cont lists */

U8ID_LOCAL bool u8ident_is_tr39_MEDIAL(uint32_t cp) {
  return range_bool_search(cp, tr39_medial_list, ARRAY_SIZE(tr39_medial_list));
}
U8ID_LOCAL bool u8ident_is_bidi(const uint32_t cp) {
  return linear_search(cp, bidi_list, ARRAY_SIZE(bidi_list));
}


static const struct range_bool ascii_start_list[] = {
    {'$', '$'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}};
static const struct range_bool ascii_cont_list[] = {
    {'$', '$'},
    {'0', '9'},
};
U8ID_LOCAL bool isASCII_start(const uint32_t cp) {
  return range_bool_search(cp, ascii_start_list, ARRAY_SIZE(ascii_start_list));
}
U8ID_LOCAL bool isASCII_cont(const uint32_t cp) {
  return range_bool_search(cp, ascii_cont_list, ARRAY_SIZE(ascii_cont_list));
}
// Note: This includes 0..9 already
U8ID_LOCAL bool isTR39_start(const uint32_t cp) {
  return binary_search(cp, (char *)tr39_start_list, ARRAY_SIZE(tr39_start_list),
                       sizeof(*tr39_start_list))
             ? true
             : false;
}
U8ID_LOCAL bool isTR39_cont(const uint32_t cp) {
  return binary_search(cp, (char *)tr39_cont_list, ARRAY_SIZE(tr39_cont_list),
                       sizeof(*tr39_cont_list))
             ? true
             : false;
}

/* ---- TR39 lookup ---- */
/* Internal: struct-pointer versions used by check_buf */
static const struct sc_tr39 *isTR39_start_p(const uint32_t cp) {
  return (const struct sc_tr39 *)binary_search(
      cp, (char *)tr39_start_list, ARRAY_SIZE(tr39_start_list),
      sizeof(*tr39_start_list));
}

static const struct sc_tr39 *isTR39_cont_p(const uint32_t cp) {
  return (const struct sc_tr39 *)binary_search(
      cp, (char *)tr39_cont_list, ARRAY_SIZE(tr39_cont_list),
      sizeof(*tr39_cont_list));
}

U8ID_LOCAL const struct sc_tr39 *u8ident_get_tr39(const uint32_t cp) {
  const struct sc_tr39 *sc = isTR39_start_p(cp);
  return sc ? sc : isTR39_cont_p(cp);
}

U8ID_LOCAL bool isALLUTF8_start(const uint32_t cp) {
  return isASCII_start(cp) || cp > 127;
}
U8ID_LOCAL bool isALLUTF8_cont(const uint32_t cp) {
  return isASCII_cont(cp) || cp > 127;
}


// bitmask of u8id_idtypes

static inline int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}

U8ID_EXTERN bool u8ident_is_greek_latin_confus(const uint32_t cp) {
  return bsearch(&cp, greek_confus_list, ARRAY_SIZE(greek_confus_list),
                 sizeof(*greek_confus_list), compar32) != NULL;
}


U8ID_EXTERN const char *u8ident_script_name(const int scr) {
  if (scr < 0 || scr > LAST_SCRIPT)
    return NULL;
  assert(scr >= 0 && scr <= LAST_SCRIPT);
  return all_scripts[scr];
}

/* returns the failing codepoint, which failed in the last check. */
U8ID_EXTERN uint32_t u8ident_failed_char(const u8id_ctx_t i) {
  if (i <= i_ctx) {
    const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    return c->last_cp;
  } else {
    return 0;
  }
}
/* returns the constant script name, which failed in the last check. */
U8ID_EXTERN const char *u8ident_failed_script_name(const u8id_ctx_t i) {
  if (i <= i_ctx) {
    const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
    const uint32_t cp = c->last_cp;
    if (cp > 0)
      return u8ident_script_name(u8ident_get_script(cp));
  }
  return NULL;
}

/* Optionally adds a script to the context, if it's known or declared
   beforehand. Such as `use utf8 "Greek";` in cperl.
   0, 1, 2 are always included by default.
*/
U8ID_EXTERN int u8ident_add_script(uint8_t scr) {
  return u8ident_add_script_ctx(scr, u8ident_ctx());
}

/* Deletes the context generated with `u8ident_new_ctx`. This is
   optional, all remaining contexts are deleted by `u8ident_free` */
U8ID_EXTERN int u8ident_free_ctx(u8id_ctx_t i) {
  if (i_ctx < U8ID_CTX_TRESH)
    ctxp = &ctx[0];
  if (i <= i_ctx) {
    if (ctxp[i].count > 8)
      free(ctxp[i].u8p);
    memset(&ctxp[i], 0, sizeof(u8id_ctx_t));
    if (i > 0)
      i_ctx = i - 1; // switch to the previous context
    else
      i_ctx = 0; // deleting 0 will lead to a reset
    return 0;
  } else
    return -1;
}

/* End this library, cleaning up all internal structures. */
U8ID_EXTERN void u8ident_free(void) {
  for (u8id_ctx_t i = 0; i <= i_ctx; i++) {
    u8ident_free_ctx(i);
  }
  if (i_ctx >= U8ID_CTX_TRESH) {
    free(ctxp);
  }
}

/* Returns a fresh string of the list of the seen scripts in this
   context whenever a mixed script error occurs. Needed for the error message
   "Invalid script %s, already have %s", where the 2nd %s is returned by this
   function. The returned string needs to be freed by the user.

   Usage:

   if (u8id_check("wrongᴧᴫ") == U8ID_ERR_SCRIPTS) {
       const char *errstr = u8ident_existing_scripts(ctx);
       fprintf(stdout, "Invalid script %s, already have %s\n",
           u8ident_failed_script_name(ctx),
           u8ident_existing_scripts(ctx));
     free(errstr);
   }
*/
U8ID_EXTERN const char *u8ident_existing_scripts(const u8id_ctx_t i) {
  if (unlikely(i > i_ctx))
    return NULL;
  const struct ctx_t *c = (i_ctx < U8ID_CTX_TRESH) ? &ctx[i] : &ctxp[i];
  const uint8_t *u8p = (c->count > 8) ? c->u8p : c->scr8;
  /* First pass: compute exact allocation size. */
  size_t len = 1; /* NUL terminator */
  for (int j = 0; j < c->count; j++) {
    const char *str = u8ident_script_name(u8p[j]);
    if (!str)
      return NULL;
    if (j > 0)
      len += 2; /* ", " separator */
    len += strlen(str);
  }
  char *res = malloc(len);
  if (!res)
    return NULL;
  /* Second pass: write into the exact-sized buffer. */
  char *p = res;
  for (int j = 0; j < c->count; j++) {
    const char *str = u8ident_script_name(u8p[j]);
    if (j > 0) {
      memcpy(p, ", ", 2);
      p += 2;
    }
    const size_t l = strlen(str);
    memcpy(p, str, l);
    p += l;
  }
  *p = '\0';
  return res;
}


/* ---- tr31 function table ---- */

/* ---- tr31 options ---- */

U8ID_LOCAL enum u8id_options u8ident_tr31(void) {
  return U8ID_TR31_DEFAULT;
}

/* ---- Initialization  (hardcoded TR39_4) ---- */

U8ID_EXTERN int u8ident_init(enum u8id_profile profile, enum u8id_norm norm,
                        unsigned options) {
  if (options > 1023)
    return -1;
  if (profile < U8ID_PROFILE_1 || profile > U8ID_PROFILE_TR39_4)
    return -1;
  if (norm > U8ID_FCC)
    return -1;
  u8ident_free();
  s_u8id_norm = U8ID_NFC;
  s_u8id_profile = U8ID_PROFILE_TR39_4;
  s_u8id_options = (options & ~127) | U8ID_TR31_ALLOWED;
  return 0;
}

enum u8id_norm u8ident_norm(void) { return s_u8id_norm; }
enum u8id_profile u8ident_profile(void) { return s_u8id_profile; }
unsigned u8ident_options(void) { return s_u8id_options; }

U8ID_EXTERN void u8ident_set_maxlength(unsigned maxlen) {
  if (maxlen > 1)
    s_maxlen = maxlen;
}
unsigned u8ident_maxlength(void) { return s_maxlen; }

/* ---- Helper: check if script is in SCX byte-string ---- */

static bool in_SCX(const enum u8id_sc scr, const char *scx) {
  unsigned char *x = (unsigned char *)scx;
  while (*x) {
    if (*x == (unsigned char)scr)
      return true;
    x++;
  }
  return false;
}

/* ---- NSM check (non-spacing mark sequences to forbid) ---- */

static bool nsm_check(const uint32_t base_cp, const uint32_t cp) {
  if (cp == 0x307 && (base_cp == 'i' || base_cp == 0x131 ||
                       base_cp == 0x237 || base_cp == 0x25F ||
                       base_cp == 0x284 || base_cp == 0x1DA1 ||
                       base_cp == 0x10798 || base_cp == 0x1D6A4 ||
                       base_cp == 0x1D645))
    return false;
  for (unsigned i = 0; i < ARRAY_SIZE(nsm_letters); i++) {
    const struct nsm_ws *l = &nsm_letters[i];
    if (l->nsm > cp)
      break;
    if (l->nsm != cp)
      continue;
    if (wcschr(l->letters, (wchar_t)base_cp))
      return false;
  }
  return true;
}

/* ---- UTF-8 helpers ---- */

typedef struct {
  uint8_t mask;
  uint8_t lead;
  uint32_t beg;
  uint32_t end;
  int bits_stored;
} _utf_t;

static const _utf_t *utf[] = {
    [0] = &(_utf_t){0x3f, 0x80, 0,       0,        6},
    [1] = &(_utf_t){0x7f, 0x00, 0000,    0177,     7},
    [2] = &(_utf_t){0x1f, 0xc0, 0200,    03777,    5},
    [3] = &(_utf_t){0x0f, 0xe0, 04000,   0177777,  4},
    [4] = &(_utf_t){0x07, 0xf0, 0200000, 04177777, 3},
    &(_utf_t){0},
};

static int utf8_len(const unsigned char ch) {
  int len = 0;
  for (_utf_t **u = (_utf_t **)utf; *u; ++u) {
    if ((ch & ~(*u)->mask) == (*u)->lead)
      break;
    ++len;
  }
  return len;
}

U8ID_LOCAL uint32_t dec_utf8(char **strp) {
  const unsigned char *str = (const unsigned char *)*strp;
  int bytes = utf8_len(*str);
  int shift;
  uint32_t cp;
  if (bytes > 4) {
    errno = EILSEQ;
    return 0;
  }
  shift = utf[0]->bits_stored * (bytes - 1);
  cp = (*str++ & utf[bytes]->mask) << shift;
  for (int i = 1; i < bytes; ++i, ++str) {
    shift -= utf[0]->bits_stored;
    cp |= (*str & utf[0]->mask) << shift;
  }
  *strp = (char *)str;
  return cp;
}

/* ---- Core: check_buf (no #if, uses struct pointers) ---- */
/* FXIME: update from unifdef u8ident.c */

U8ID_EXTERN enum u8id_errors u8ident_check_buf(const char *buf, const int bufsz,
                                          char **outnorm) {
  char *s = (char *)buf;
  const char *e = (char *)&buf[bufsz];
  struct ctx_t *ctx = u8ident_ctx();
  enum u8id_errors ret = U8ID_EOK;
  (void)outnorm;

  uint32_t prev_cp = 0, base_cp = 0;
  int seq_mn = 0;
  enum u8id_sc basesc = SC_Unknown;
  bool has_latin = u8ident_has_script_ctx(SC_Latin, ctx);

  uint32_t cp = dec_utf8(&s);
  const struct sc_tr39 *tr39 = isTR39_start_p(cp);
  if (unlikely(!tr39)) {
    ctx->last_cp = cp;
    return U8ID_ERR_XID;
  }

  do {
    enum u8id_sc scr = tr39->sc;
    bool is_new = false;
    char *scx = NULL;

    /* Latin always compatible */
    if (likely(scr == SC_Latin)) {
      if (!u8ident_has_script_ctx(SC_Latin, ctx)) {
        has_latin = true;
        u8ident_add_script_ctx(SC_Latin, ctx);
      }
      basesc = scr;
      goto next_cp;
    }

    /* Disallow Limited Use scripts */
    if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT)) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }
    /* Disallow bidi formatting */
    if (unlikely(!ctx->is_rtl && u8ident_is_bidi(cp))) {
      ctx->last_cp = cp;
      return U8ID_ERR_SCRIPT;
    }

    /* Common/Inherited SCX handling */
    if (scr == SC_Common || scr == SC_Inherited) {
      tr39 = u8ident_get_tr39(cp);
      if (tr39 && tr39->scx) {
        scx = (char *)tr39->scx;
        const enum u8id_gc gc = tr39->gc;
        int n = 0;
        if (ctx->count) {
          if (!ctx->is_japanese &&
              ((cp >= 0x30FC && cp <= 0x30FE) || cp == 0xFF70)) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          if (!has_latin) {
            if (strEQc(scx, "\x11\x12") && !ctx->is_japanese) {
              ctx->last_cp = cp;
              return U8ID_ERR_SCRIPTS;
            }
            if (strEQc(scx, "\x06\x0e\x0f\x11\x12") && !ctx->is_japanese &&
                !ctx->has_han && !ctx->is_korean) {
              ctx->last_cp = cp;
              return U8ID_ERR_SCRIPTS;
            }
          }
        }
        if (gc == GC_Mn || gc == GC_Mc) {
          if (!ctx->count || basesc == SC_Unknown) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (!in_SCX(basesc, tr39->scx)) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (cp == prev_cp) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (gc == GC_Mn && ++seq_mn > 4) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          } else if (!nsm_check(base_cp, cp)) {
            ctx->last_cp = cp;
            return U8ID_ERR_COMBINE;
          }
        } else {
          seq_mn = 0;
        }
        char *x = scx;
        while (*x) {
          n += u8ident_has_script_ctx(*x, ctx) ? 1 : 0;
          x++;
        }
        if (!n)
          is_new = true;
      }
    } else {
      base_cp = cp;
    }

    /* New script detection */
    if (!is_new && !(scr == SC_Common || scr == SC_Inherited))
      is_new = !u8ident_has_script_ctx(scr, ctx);

    if (is_new) {
      if (unlikely(scr >= FIRST_LIMITED_USE_SCRIPT)) {
        ctx->last_cp = cp;
        return U8ID_ERR_SCRIPT;
      }
      if (ctx->count) {
        if (scr == SC_Bopomofo) {
          if (unlikely(!ctx->has_han && !has_latin)) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          goto add_ok;
        } else if (scr == SC_Han) {
          if (unlikely(!(ctx->is_chinese || ctx->is_japanese ||
                         ctx->is_korean || has_latin))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          goto add_ok;
        } else if (scr == SC_Katakana || scr == SC_Hiragana) {
          if (unlikely(!(ctx->is_japanese || ctx->has_han || has_latin))) {
            ctx->last_cp = cp;
            return U8ID_ERR_SCRIPTS;
          }
          goto add_ok;
        } else if (scr == SC_Common || scr == SC_Inherited) {
          goto add_ok;
        }
        /* TR39_4: max 2 scripts, no Cyrillic */
        if (ctx->count >= 2 || scr == SC_Cyrillic) {
          ctx->last_cp = cp;
          return U8ID_ERR_SCRIPTS;
        }
        /* Greek confusable check */
        if (scr == SC_Greek && has_latin) {
          if (u8ident_is_greek_latin_confus(cp)) {
            ctx->last_cp = cp;
            return U8ID_ERR_CONFUS;
          }
          goto add_ok;
        }
      }
add_ok:
      basesc = scr;
      if (!u8ident_has_script_ctx(scr, ctx))
        u8ident_add_script_ctx(scr, ctx);
    } else if (scr != SC_Common && scr != SC_Inherited) {
      basesc = scr;
      base_cp = cp;
    } else {
      /* Existing Common/Inherited without SCX */
      if (scr == SC_Greek && has_latin &&
          u8ident_is_greek_latin_confus(cp)) {
        ctx->last_cp = cp;
        return U8ID_ERR_CONFUS;
      }
      const enum u8id_gc gc = tr39->gc;
      if (gc == GC_Mn || gc == GC_Me) {
        if (cp == prev_cp) {
          ctx->last_cp = cp;
          return U8ID_ERR_COMBINE;
        } else if (++seq_mn > 4) {
          ctx->last_cp = cp;
          return U8ID_ERR_COMBINE;
        } else if (!nsm_check(base_cp, cp)) {
          ctx->last_cp = cp;
          return U8ID_ERR_COMBINE;
        }
      }
      if (basesc == SC_Unknown &&
          (gc == GC_Mn || gc == GC_Me || gc == GC_Mc)) {
        ctx->last_cp = cp;
        return U8ID_ERR_COMBINE;
      }
    }

next_cp:
    prev_cp = cp;
    cp = dec_utf8(&s);
    if (likely(s <= e && cp != 0)) {
      tr39 = isTR39_cont_p(cp);
      if (unlikely(!tr39))
        tr39 = isTR39_start_p(cp);
      if (unlikely(!tr39)) {
        ctx->last_cp = cp;
        return U8ID_ERR_XID;
      }
      if (s == e && u8ident_is_tr39_MEDIAL(cp)) {
        ctx->last_cp = cp;
        return U8ID_ERR_XID;
      }
    }
  } while (s <= e);

  return ret;
}

/* ---- String wrapper ---- */

U8ID_EXTERN enum u8id_errors u8ident_check(const uint8_t *string, char **outnorm) {
  return u8ident_check_buf((char *)string, strlen((char *)string), outnorm);
}

