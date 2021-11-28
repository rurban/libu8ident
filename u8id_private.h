#pragma once
#include <stddef.h>
#include <inttypes.h>
#include <errno.h>

#define EXTERN extern

// UTF-8 helpers

/* from https://rosettacode.org/wiki/UTF-8_encode_and_decode#C
   taken from the safeclib
 */
typedef struct {
    uint8_t mask; /* char data will be bitwise AND with this */
    uint8_t lead; /* start bytes of current char in utf-8 encoded character */
    uint32_t beg; /* beginning of codepoint range */
    uint32_t end; /* end of codepoint range */
    int bits_stored; /* number of bits from the codepoint that fits in char */
} _utf_t;

static const _utf_t *utf[] = {
    /*             mask                 lead                beg      end    bits */
    [0] = &(_utf_t){0x3f/*0b00111111*/, 0x80/*0b10000000*/, 0,       0,        6},
    [1] = &(_utf_t){0x7f/*0b01111111*/, 0x00/*0b00000000*/, 0000,    0177,     7},
    [2] = &(_utf_t){0x1f/*0b00011111*/, 0xc0/*0b11000000*/, 0200,    03777,    5},
    [3] = &(_utf_t){0x0f/*0b00001111*/, 0xe0/*0b11100000*/, 04000,   0177777,  4},
    [4] = &(_utf_t){0x07/*0b00000111*/, 0xf0/*0b11110000*/, 0200000, 04177777, 3},
    &(_utf_t){0},
};

static int utf8_len(const unsigned char ch) {
    int len = 0;
    for (_utf_t **u = (_utf_t **)utf; *u; ++u) {
        if ((ch & ~(*u)->mask) == (*u)->lead) {
            break;
        }
        ++len;
    }
#if 0 /* error handled in caller */
    if (len > 4) { /* Malformed leading byte */
        // "illegal UTF-8 character" EILSEQ
    }
#endif
    return len;
}

static int cp_len(const uint32_t cp) {
    int len = 0;
    for (_utf_t **u = (_utf_t **)utf; *u; ++u) {
        if ((cp >= (*u)->beg) && (cp <= (*u)->end)) {
            break;
        }
        ++len;
    }
#if 0 /* error handled in caller */
    if (len > 4) { /* Malformed leading byte */
        // "illegal UTF-8 character" EILSEQ
    }
#endif
    return len;
}

/* convert utf8 to unicode codepoint (to_cp) */
static uint32_t dec_utf8(char** strp) {
    const unsigned char *restrict str = (unsigned char *)*strp;
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
    *strp = (char*)str;
    return cp;
}

/* convert unicode codepoint to utf8 (to_utf8) */
static char *enc_utf8(char *dest, const uint32_t cp) {
    const int bytes = cp_len(cp);

    if (bytes > 4) {
      errno = EILSEQ;
      return NULL;
    } else {
        int shift = utf[0]->bits_stored * (bytes - 1);
        dest[0] = (cp >> shift & utf[bytes]->mask) | utf[bytes]->lead;
        shift -= utf[0]->bits_stored;
        for (int i = 1; i < bytes; ++i) {
            dest[i] = (cp >> shift & utf[0]->mask) | utf[0]->lead;
            shift -= utf[0]->bits_stored;
        }
        dest[bytes] = '\0';
        return dest;
    }
}
