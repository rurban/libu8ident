/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2014, 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   See https://www.unicode.org/reports/tr15/tr15-51.html

   TODO: If the codepoint came from the decomposing table, there is no
   need to reorder.  Only reorder combining marks directly from the
   user.
   Optimize already properly composed NFC characters. No need to decompose,
   reorder and compose for most.
*/
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#ifdef DEBUG
#  include <stdio.h>
#endif
#include "u8id_private.h"
#include <u8ident.h>

#define STDCHAR char
#define TRUE true
#define FALSE false

#if !defined U8ID_NORM || (U8ID_NORM != FCD)
char tmp_stack[128];
#endif

//#pragma message "U8ID_NORM="_XSTR(U8ID_NORM)
//#pragma message "U8ID_NORM_DEFAULT="_XSTR(U8ID_NORM_DEFAULT)
//#if !defined U8ID_NORM || U8ID_NORM == NFKD
//#pragma message "NFKD"_XSTR(U8ID_NORM)
//#endif
//#if !defined U8ID_NORM || U8ID_NORM == NFD
//#pragma message "NFD:"_XSTR(U8ID_NORM)
//#endif
//#if !defined U8ID_NORM || U8ID_NORM_DEFAULT == U8ID_NFD
//#pragma message "NFD1:"_XSTR(U8ID_NORM_DEFAULT)
//#endif

#if !defined U8ID_NORM || U8ID_NORM == NFC || U8ID_NORM == NFD ||              \
    U8ID_NORM == FCC || U8ID_NORM == FCD
#  include "un8ifcan.h" /* for NFD Canonical Decomposition */
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFKC || U8ID_NORM == NFKD
#  include "un8ifcpt.h" /* for NFKD/NFKC Compat. Decomposition. */
#endif
#if !defined U8ID_NORM || U8ID_NORM != FCD
#  include "un8ifcmb.h" /* for reorder Canonical_Combining_Class_Values */
#endif
#if !defined U8ID_NORM || U8ID_NORM == NFKC || U8ID_NORM == NFC ||             \
    U8ID_NORM == FCC
#  include "un8ifexc.h" /* for NFC Composite exclusions */
#  include "un8ifcmp.h" /* for NFC Canonical Composition lists */
#endif
#include "hangul.h" /* Korean/Hangul has special (easy) normalization rules */

unsigned u8ident_options(void);
unsigned u8ident_maxlength(void);

#define _UNICODE_MAX 0x10ffff

// UTF-8 helpers

/* from https://rosettacode.org/wiki/UTF-8_encode_and_decode#C
   taken from the safeclib
 */
typedef struct {
  uint8_t mask;    /* char data will be bitwise AND with this */
  uint8_t lead;    /* start bytes of current char in utf-8 encoded character */
  uint32_t beg;    /* beginning of codepoint range */
  uint32_t end;    /* end of codepoint range */
  int bits_stored; /* number of bits from the codepoint that fits in char */
} _utf_t;

static const _utf_t *utf[] = {
    // clang-format off
  /*             mask                 lead                beg      end    bits */
  [0] = &(_utf_t){0x3f/*0b00111111*/, 0x80/*0b10000000*/, 0,       0,        6},
  [1] = &(_utf_t){0x7f/*0b01111111*/, 0x00/*0b00000000*/, 0000,    0177,     7},
  [2] = &(_utf_t){0x1f/*0b00011111*/, 0xc0/*0b11000000*/, 0200,    03777,    5},
  [3] = &(_utf_t){0x0f/*0b00001111*/, 0xe0/*0b11100000*/, 04000,   0177777,  4},
  [4] = &(_utf_t){0x07/*0b00000111*/, 0xf0/*0b11110000*/, 0200000, 04177777, 3},
  &(_utf_t){0},
    // clang-format on
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
LOCAL uint32_t dec_utf8(char **strp) {
  const unsigned char *str = (const unsigned char *)*strp;
  int bytes = utf8_len(*str);
  int shift;
  uint32_t cp;

  if (bytes > 4) {
    errno = EILSEQ;
    return 0;
  }
  shift = utf[0]->bits_stored * (bytes - 1);
  assert(shift >= 0);
  cp = (*str++ & utf[bytes]->mask) << shift;
  for (int i = 1; i < bytes; ++i, ++str) {
    shift -= utf[0]->bits_stored;
    assert(shift >= 0);
    cp |= (*str & utf[0]->mask) << shift;
  }
  *strp = (char *)str;
  return cp;
}

/* convert unicode codepoint to utf8 (to_utf8) */
LOCAL char *enc_utf8(char *dest, size_t *lenp, const uint32_t cp) {
  if (cp > _UNICODE_MAX) {
    errno = EILSEQ;
    *lenp = 0;
    return NULL;
  }
  const int bytes = cp_len(cp);

  if (bytes > 4) {
    errno = EILSEQ;
    *lenp = 0;
    return NULL;
  } else {
    int shift = utf[0]->bits_stored * (bytes - 1);
    assert(shift >= 0);
    dest[0] = (cp >> shift & utf[bytes]->mask) | utf[bytes]->lead;
    shift -= utf[0]->bits_stored;
    for (int i = 1; i < bytes; ++i) {
      assert(shift >= 0);
      dest[i] = (cp >> shift & utf[0]->mask) | utf[0]->lead;
      shift -= utf[0]->bits_stored;
    }
    *lenp = bytes;
    dest[bytes] = '\0';
    return dest;
  }
}

/* size of array for combining characters */
/* enough as an initial value? */
#define CC_SEQ_SIZE 10
#define CC_SEQ_STEP 5

#define ERR_ILSEQ -3
#define ERR_NOSPACE -2
#define ERR_INVAL -1
#define EOK 0

#if !defined U8ID_NORM || U8ID_NORM == NFKC || U8ID_NORM == NFKD

static inline int _bsearch_exc(const void *ptr1, const void *ptr2) {
  UN8IF_compat_exc_t *e1 = (UN8IF_compat_exc_t *)ptr1;
  UN8IF_compat_exc_t *e2 = (UN8IF_compat_exc_t *)ptr2;
  return e1->cp > e2->cp ? 1 : e1->cp == e2->cp ? 0 : -1;
}
#elif !defined U8ID_NORM || U8ID_NORM == NFC || U8ID_NORM == NFD ||            \
    U8ID_NORM == FCC || U8ID_NORM == FCD

static inline int _bsearch_exc(const void *ptr1, const void *ptr2) {
  UN8IF_canon_exc_t *e1 = (UN8IF_canon_exc_t *)ptr1;
  UN8IF_canon_exc_t *e2 = (UN8IF_canon_exc_t *)ptr2;
  return e1->cp > e2->cp ? 1 : e1->cp == e2->cp ? 0 : -1;
}
#endif

#if !defined U8ID_NORM || U8ID_NORM == NFC || U8ID_NORM == NFD ||              \
    U8ID_NORM == FCC || U8ID_NORM == FCD
/* Note that we can generate two versions of the tables.  The old format as
 * used in Unicode::Normalize, and the new 3x smaller NORMALIZE_IND_TBL cperl
 * variant, as used here and in cperl core since 5.27.2.
 * Return values:
 *   errors < 1 (see the ERR_* definitions)
 *   0: ok, passthru (not in table)
 *   >0: len of the returned utf-8 sequence
 */
static int _decomp_canonical_s(char *dest, size_t dmax, uint32_t cp) {
  /* the new format generated with cperl Unicode-Normalize/mkheader -uni -ind
   * -std
   */
  const UN8IF_canon_PLANE_T **plane, *row;
  if (unlikely(dmax < 8)) {
    *dest = 0;
    return ERR_NOSPACE;
  }
  plane = UN8IF_canon[cp >> 16];
  if (!plane) { /* Only the first 3 of 16 are filled */
    return EOK;
  }
  row = plane[(cp >> 8) & 0xff];
  if (row) { /* the first row is pretty filled, the rest very sparse */
    const UN8IF_canon_PLANE_T vi = row[cp & 0xff];
    if (!vi)
      return EOK;
#  if UN8IF_canon_exc_size > 0
    /* overlong: search in extra list */
    else if (unlikely(vi == (uint16_t)-1)) {
      UN8IF_canon_exc_t *e;
      assert(UN8IF_canon_exc_size);
      e = (UN8IF_canon_exc_t *)bsearch(
          &cp, &UN8IF_canon_exc, UN8IF_canon_exc_size,
          sizeof(UN8IF_canon_exc[0]), _bsearch_exc);
      if (e) {
        size_t l = strlen(e->v);
        if (l + 1 > dmax) {
          *dest = 0;
          return ERR_NOSPACE;
        }
        memcpy(dest, e->v, l + 1); /* incl \0 */
        return (int)l;
      }
      return EOK;
    }
#  endif
    else {
      /* value => length-index and offset */
      const int l = UN8IF_canon_LEN(vi);
      const int i = UN8IF_canon_IDX(vi);
      const char *tbl = (const char *)UN8IF_canon_tbl[l - 1];
      const int len = l;
#  if defined(__DEBUG)
      printf("U+%04X vi=0x%x (>>12, &fff) => TBL(%d)|%d\n", cp, vi, l, i);
#  endif
      assert(l > 0 && l <= UN8IF_canon_MAXLEN);
#  if 0
            /* 13.0: tbl sizes: (917,763,227,36) */
            /* l: 1-4 */
            assert((l == 1 && i < 917) || (l == 2 && i < 763) ||
                   (l == 3 && i < 227) || (l == 4 && i < 36) || 0);
            assert(dmax > 4);
#  endif
      memcpy(dest, &tbl[i * len], len); /* 33% perf */
      dest[len] = '\0';
      return len;
    }
  } else {
    return EOK;
  }
}
#endif // NFC, NFD, FCC, FCD

#if !defined U8ID_NORM || U8ID_NORM == NFKC || U8ID_NORM == NFKD
static int _decomp_compat_s(char *dest, size_t dmax, uint32_t cp) {
  /* the new format generated with cperl Unicode-Normalize/mkheader -uni -ind
   * -std
   */
  const UN8IF_compat_PLANE_T **plane, *row;
  plane = UN8IF_compat[cp >> 16];
  if (!plane) { /* Only the first 3 of 16 are filled */
    return EOK;
  }
  row = plane[(cp >> 8) & 0xff];
  if (row) { /* the first row is pretty filled, the rest very sparse */
    const UN8IF_compat_PLANE_T vi = row[cp & 0xff];
    if (!vi)
      return EOK;
#  if UN8IF_compat_exc_size > 0
    else if (unlikely(vi ==
                      (uint16_t)-1)) { /* overlong: search in extra list */
      UN8IF_compat_exc_t *e;
      assert(UN8IF_compat_exc_size);
      e = (UN8IF_compat_exc_t *)bsearch(
          &cp, &UN8IF_compat_exc, UN8IF_compat_exc_size,
          sizeof(UN8IF_compat_exc[0]), _bsearch_exc);
      if (e) {
        size_t l = strlen(e->v);
        if (l + 1 > dmax) {
          *dest = 0;
          return ERR_NOSPACE;
        }
        memcpy(dest, e->v, l + 1); /* incl \0 */
        return (int)l;
      }
      return EOK;
#  endif
    } else {
      /* value => length and index */
      const int l = UN8IF_compat_LEN(vi);
      const int i = UN8IF_compat_IDX(vi);
      const char *tbl = (const char *)UN8IF_compat_tbl[l - 1];
#  if 0 && defined(DEBUG)
            printf("U+%04X vi=0x%x (>>12, &&fff) => TBL(%d)|%d\n", cp, vi, l, i);
#  endif
      if (unlikely(dmax < (size_t)l)) {
        *dest = 0;
        return ERR_NOSPACE;
      }
      memcpy(dest, &tbl[i * l], l);
      dest[l] = L'\0';
      return l;
    }
  } else {
    return EOK;
  }
}
#endif // NFKC or NFKD

static int _decomp_hangul_s(char *dest, size_t dmax, uint32_t cp) {
  uint32_t sindex = cp - Hangul_SBase;
  uint32_t lindex = sindex / Hangul_NCount;
  uint32_t vindex = (sindex % Hangul_NCount) / Hangul_TCount;
  uint32_t tindex = sindex % Hangul_TCount;
  size_t dlen;

  if (unlikely(dmax < 4)) {
    return ERR_NOSPACE;
  }

  // encode to UTF-8
  enc_utf8(dest, &dlen, lindex + Hangul_LBase);
  enc_utf8(&dest[1], &dlen, vindex + Hangul_VBase);
  if (tindex) {
    enc_utf8(&dest[2], &dlen, tindex + Hangul_TBase);
    return 3;
  }
  return 2;
}

/* codepoint canonical or compatible decomposition.
   dmax should be > 4,
   19 with the single arabic outlier U+FDFA for compat accepted
*/
static int _decomp_s(char *restrict dest, size_t dmax, const uint32_t cp,
                     const bool iscompat) {
  assert(dmax > 0);
  /* The costly is_HANGUL_cp_high(cp) checks also all composing chars.
     Hangul_IsS only for the valid start points. Which we can do here. */
  if (Hangul_IsS(cp)) {
    return _decomp_hangul_s(dest, dmax, cp);
  } else {
#if defined U8ID_NORM && (U8ID_NORM == NFC || U8ID_NORM == NFD ||              \
                          U8ID_NORM == FCC || U8ID_NORM == FCD)
    (void)iscompat;
    assert(!iscompat);
    return _decomp_canonical_s(dest, dmax, cp);
#elif defined U8ID_NORM && (U8ID_NORM == NFKC || U8ID_NORM == NFKD)
    (void)iscompat;
    assert(iscompat);
    return _decomp_compat_s(dest, dmax, cp);
#else
    return iscompat ? _decomp_compat_s(dest, dmax, cp)
                    : _decomp_canonical_s(dest, dmax, cp);
#endif
  }
}

/**
 * @def u8id_decompose_s(dest,dmax,src,lenp,iscompat)
 * @brief
 *    Converts the UTF-8 string to the NFD or NFKD normalization,
 *    as defined in the latest Unicode standard. The conversion
 *    stops at the first null or after dmax characters.
 *
 * @details
 *    Composed characters are checked for the left-hand-size of the
 *    Decomposition_Mapping Unicode property, which means the codepoint will
 *    be normalized if the sequence is composed.
 *    This is equivalent to all 1963 combining mark characters, plus some
 *    remaining 869 non-mark and non-hangul normalizables.  Hangul has some
 *    special normalization logic.
 */
int u8id_decompose_s(char *restrict dest, long dmax, char *restrict src,
                     size_t *restrict lenp, const bool iscompat) {
  size_t orig_dmax;
  const char *overlap_bumper;
  uint32_t cp;
  int c;

  if (lenp)
    *lenp = 0;
  if (unlikely(dest == NULL)) {
    return ERR_INVAL;
  }
  if (unlikely(src == NULL || dest == NULL || dmax == 0 || dmax < 2 ||
               (unsigned)dmax > u8ident_maxlength())) {
    *dest = 0;
    return ERR_INVAL;
  }
  if (unlikely(dest == src)) {
    return ERR_INVAL;
  }
  if (unlikely(iscompat && dmax < 19)) {
    *dest = 0;
    return ERR_INVAL;
  }

  /* hold base of dest in case src was not copied */
  orig_dmax = (size_t)dmax;

  if (dest < src) {
    overlap_bumper = src;

    while (dmax > 0 && *src != 0) {
      const char *p = src;
      cp = dec_utf8((char **)&src);
      if (!cp)
        goto done;
      if (unlikely(dest == overlap_bumper)) {
        return ERR_INVAL;
      }
      if (unlikely(_UNICODE_MAX < cp)) {
        return ERR_ILSEQ;
      }

      c = _decomp_s(dest, dmax, cp, iscompat);
      if (c > 0) {
        dest += c;
        dmax -= c;
      } else if (c == 0) {
        if (cp < 128) {
          *dest++ = cp;
          dmax--;
        } else {
          long len = src - p;
          if (len > dmax) {
            *dest = 0;
            return ERR_NOSPACE;
          }
          memcpy(dest, p, len);
          dest += len;
          dmax -= len;
        }
      } else {
        return c;
      }
    }
  } else {
    overlap_bumper = dest;

    while (dmax > 0 && *src != 0) {
      const char *p = src;
      cp = dec_utf8((char **)&src);
      if (!cp)
        goto done;
      if (unlikely(src == overlap_bumper)) {
        return ERR_INVAL;
      }
      if (unlikely(_UNICODE_MAX < cp)) {
        return ERR_ILSEQ;
      }

      c = _decomp_s(dest, dmax, cp, iscompat);
      if (c > 0) {
        dest += c;
        dmax -= c;
      } else if (c == 0) {
        if (cp < 128) {
          *dest++ = cp;
          dmax--;
        } else {
          long len = src - p;
          if (len > dmax) {
            *dest = 0;
            return ERR_NOSPACE;
          }
          memcpy(dest, p, len);
          dest += len;
          dmax -= len;
        }
      } else {
        return c;
      }
    }
  }

done:
  if (lenp)
    *lenp = (size_t)((long)orig_dmax - dmax);
  if (dmax > 0) {
    *dest = 0;
    return 0;
  } else {
    return ERR_NOSPACE;
  }
}

#if !defined U8ID_NORM || U8ID_NORM != FCD

/* canonical ordering of combining characters (c.c.). */
typedef struct {
  uint8_t cc;  /* combining class */
  uint32_t cp; /* codepoint */
  size_t pos;  /* position */
} UN8IF_cc;

/* rc = u8id_reorder_s(tmp, len+1, dest); */
static inline int _compare_cc(const void *a, const void *b) {
  int ret_cc;
  ret_cc = ((UN8IF_cc *)a)->cc - ((UN8IF_cc *)b)->cc;
  if (ret_cc)
    return ret_cc;

  return (((UN8IF_cc *)a)->pos > ((UN8IF_cc *)b)->pos) -
         (((UN8IF_cc *)a)->pos < ((UN8IF_cc *)b)->pos);
}

static inline uint8_t _combin_class(uint32_t cp) {
  const STDCHAR **plane, *row;
  plane = UN8IF_combin[cp >> 16];
  if (!plane)
    return 0;
  row = plane[(cp >> 8) & 0xff];
  if (row)
    return row[cp & 0xff];
  else
    return 0;
}

/**
 * @def u8id_reorder_s(dest,dmax,src,len)
 *    Reorder all decomposed sequences in a UTF-8 string to NFD,
 *    as defined in the latest Unicode standard. The conversion
 *    stops at the first null or after dmax characters.
 */
static int u8id_reorder_s(unsigned char *restrict dest, long dmax,
                          const char *restrict src, const size_t len) {
  UN8IF_cc seq_ary[CC_SEQ_SIZE];
  UN8IF_cc *seq_ptr = (UN8IF_cc *)seq_ary; /* start with stack */
  UN8IF_cc *seq_ext = NULL;                /* heap when needed */
  size_t seq_max = CC_SEQ_SIZE;
  size_t cc_pos = 0;
  char *p = (char *)src;
  const char *e = p + len;
  unsigned char *orig_dest = dest;
  size_t orig_dmax = dmax;

  while (p < e) {
    uint8_t cur_cc;
    uint32_t cp = dec_utf8(&p);
    size_t dlen;
    cur_cc = _combin_class(cp);
    if (cur_cc != 0) {
      if (seq_max < cc_pos + 1) {       /* extend if need */
        seq_max = cc_pos + CC_SEQ_STEP; /* new size */
        if (CC_SEQ_SIZE == cc_pos) {    /* seq_ary full */
          seq_ext = (UN8IF_cc *)malloc(seq_max * sizeof(UN8IF_cc));
          memcpy(seq_ext, seq_ary, cc_pos * sizeof(UN8IF_cc));
        } else {
          seq_ext = (UN8IF_cc *)realloc(seq_ext, seq_max * sizeof(UN8IF_cc));
        }
        seq_ptr = seq_ext; /* use seq_ext from now */
      }

      seq_ptr[cc_pos].cc = cur_cc;
      seq_ptr[cc_pos].cp = cp;
      seq_ptr[cc_pos].pos = cc_pos;
      ++cc_pos;

      if (p < e)
        continue;
    }

    /* output */
    if (cc_pos) {
      if (unlikely(dmax - cc_pos <= 0)) {
        return ERR_NOSPACE;
      }

      if (cc_pos > 1) /* reorder if there are two Combining Classes */
        qsort((void *)seq_ptr, cc_pos, sizeof(UN8IF_cc), _compare_cc);

      for (size_t i = 0; i < cc_pos; i++) {
        enc_utf8((char *)dest, &dlen, seq_ptr[i].cp);
        dest += dlen;
        dmax -= dlen;
      }
      cc_pos = 0;
    }

    if (cur_cc == 0) {
      enc_utf8((char *)dest, &dlen, cp);
      dest += dlen;
      dmax -= dlen;
    }
    if (unlikely(dmax <= 0)) {
      memset(orig_dest, 0, orig_dmax);
      return ERR_NOSPACE;
    }
  }
  if (seq_ext)
    free(seq_ext);
  *dest = 0;
  // memset(dest, 0, dmax); // clear the slack?
  return 0;
}
#endif // != FCD

#if !defined U8ID_NORM ||                                                      \
    !(U8ID_NORM == NFD || U8ID_NORM == NFKD || U8ID_NORM == FCD)
//#if !defined U8ID_NORM || U8ID_NORM == NFC || U8ID_NORM == FCC

static uint32_t _composite_cp(uint32_t cp, uint32_t cp2) {
  const UN8IF_complist_s ***plane, **row, *cell;

  if (unlikely(!cp2)) {
    return EOK;
  }
  if (unlikely((_UNICODE_MAX < cp) || (_UNICODE_MAX < cp2))) {
    return ERR_ILSEQ;
  }

  if (Hangul_IsL(cp) && Hangul_IsV(cp2)) {
    uint32_t lindex = cp - Hangul_LBase;
    uint32_t vindex = cp2 - Hangul_VBase;
    return (Hangul_SBase + (lindex * Hangul_VCount + vindex) * Hangul_TCount);
  }
  if (Hangul_IsLV(cp) && Hangul_IsT(cp2)) {
    uint32_t tindex = cp2 - Hangul_TBase;
    return (cp + tindex);
  }
  plane = UN8IF_compos[cp >> 16];
  if (!plane) { /* only 3 of 16 are defined */
    return 0;
  }
  row = plane[(cp >> 8) & 0xff];
  if (!row) { /* the zero plane is pretty filled, the others sparse */
    return 0;
  }
  cell = row[cp & 0xff];
  if (!cell) {
    return 0;
  }
  /* no indirection here, but search in the composition lists */
  /* only 16 lists 011099-01d1bc need uint32, the rest can be short, uint16 */
  /* TODO: above which length is bsearch faster?
     But then we'd need to store the lengths also */
  if (likely(cp < UN8IF_COMPLIST_FIRST_LONG)) {
    UN8IF_complist_s *i;
    for (i = (UN8IF_complist_s *)cell; i->nextchar; i++) {
      if ((uint16_t)cp2 == i->nextchar) {
        return (uint32_t)(i->composite);
      } else if ((uint16_t)cp2 < i->nextchar) { /* nextchar is sorted */
        break;
      }
    }
  } else {
    UN8IF_complist *i;
    // GCC_DIAG_IGNORE(-Wcast-align)
    for (i = (UN8IF_complist *)cell; i->nextchar; i++) {
      // GCC_DIAG_RESTORE
      if (cp2 == i->nextchar) {
        return i->composite;
      } else if (cp2 < i->nextchar) { /* nextchar is sorted */
        break;
      }
    }
  }
  return 0;
}

/**
 * @def u8id_compose_s(dest,dmax,src,lenp,iscontig)
 *    Combine all decomposed sequences in a wide string to NFC,
 *    as defined in the latest Unicode standard. The conversion
 *    stops at the first null or after dmax characters. */
/* combine decomposed sequences to NFC. */
/* iscontig = false; composeContiguous? FCC if true */
static int u8id_compose_s(char *restrict dest, long dmax,
                          const char *restrict src, size_t *restrict lenp,
                          const bool iscontig) {
  char *p = (char *)src;
  const char *e = p + *lenp;
  uint32_t cpS = 0;       /* starter code point */
  bool valid_cpS = false; /* if false, cpS isn't initialized yet */
  uint8_t pre_cc = 0;

  uint32_t seq_ary[CC_SEQ_SIZE];
  uint32_t *seq_ptr = (uint32_t *)seq_ary; /* either stack or heap */
  uint32_t *seq_ext = NULL;                /* heap */
  size_t seq_max = CC_SEQ_SIZE;
  size_t cc_pos = 0;
  // char *orig_dest = dest;
  const long orig_dmax = dmax;

  if (unlikely((unsigned)dmax > u8ident_maxlength())) {
    *lenp = 0;
    return ERR_INVAL;
  }

  while (p < e) {
    uint8_t cur_cc;
    uint32_t cp = dec_utf8(&p);
    size_t dlen;
    cur_cc = _combin_class(cp);

    if (!valid_cpS) {
      if (cur_cc == 0) {
        cpS = cp; /* found the first Starter */
        valid_cpS = true;
        if (p < e)
          continue;
      } else {
        enc_utf8(dest, &dlen, cp);
        dest += dlen;
        dmax -= dlen;
        if (unlikely(dmax <= 0)) {
          return ERR_NOSPACE;
        }
        continue;
      }
    } else {
      bool composed;

      /* blocked */
      if ((iscontig && cc_pos) || /* discontiguous combination (FCC) */
          (cur_cc != 0 && pre_cc == cur_cc) || /* blocked by same CC */
          (pre_cc > cur_cc)) /* blocked by higher CC: revised D2 */
        composed = false;

      /* not blocked:
           iscontig && cc_pos == 0      -- contiguous combination
           cur_cc == 0 && pre_cc == 0     -- starter + starter
           cur_cc != 0 && pre_cc < cur_cc  -- lower CC */
      else {
        /* try composition */
        uint32_t cpComp = _composite_cp(cpS, cp);
        if (cpComp && !isExclusion(cpComp)) {
          cpS = cpComp;
          composed = true;
          /* pre_cc should not be changed to cur_cc */
          /* e.g. 1E14 = 0045 0304 0300 where CC(0304) == CC(0300) */
          if (p < e)
            continue;
        } else
          composed = false;
      }

      if (!composed) {
        pre_cc = cur_cc;
        if (cur_cc != 0 || !(p < e)) {
          if (seq_max < cc_pos + 1) {       /* extend if need */
            seq_max = cc_pos + CC_SEQ_STEP; /* new size */
            if (CC_SEQ_SIZE == cc_pos) {    /* seq_ary full */
              seq_ext = (uint32_t *)malloc(seq_max * sizeof(uint32_t));
              memcpy(seq_ext, seq_ary, cc_pos * sizeof(uint32_t));
            } else {
              seq_ext =
                  (uint32_t *)realloc(seq_ext, seq_max * sizeof(uint32_t));
            }
            seq_ptr = seq_ext; /* use seq_ext from now */
          }
          seq_ptr[cc_pos] = cp;
          ++cc_pos;
        }
        if (cur_cc != 0 && p < e)
          continue;
      }
    }

    /* output */
    enc_utf8(dest, &dlen, cpS); /* starter (composed or not) */
    dest += dlen;
    dmax -= dlen;
    if (unlikely(dmax <= 0)) {
      return ERR_NOSPACE;
    }

    if (cc_pos == 1) {
      enc_utf8(dest, &dlen, *seq_ptr);
      dest += dlen;
      dmax -= dlen;
      cc_pos = 0;
    } else if (cc_pos > 1) {
      memcpy(dest, seq_ptr, cc_pos);
      dest += cc_pos;
      dmax -= cc_pos;
      cc_pos = 0;
    }

    cpS = cp;
  }
  if (seq_ext)
    free(seq_ext);

  // memset(dest, 0, dmax); // clear the slack?
  *lenp = orig_dmax - dmax;
  return 0;
}
#endif // !(NFD, NFKD, FCD)

/* Returns a freshly allocated normalized string, in the option defined at
 * `u8ident_init`. */
/* TODO: more stack allocations for dest throughout */
// clang-format off
GCC_DIAG_IGNORE(-Wreturn-local-addr)
// clang-format on
EXTERN char *u8ident_normalize(const char *src, int srcsz) {
#if !defined U8ID_NORM || U8ID_NORM != FCD
  char *tmp_ptr;
  char *tmp = NULL;
  size_t tmp_size;
#endif
  const enum u8id_norm mode = u8ident_norm();
  const bool iscompat = (mode == U8ID_NFKC || mode == U8ID_NFKD);

  size_t dmax = srcsz;
  char *dest = NULL;
  size_t destlen;
  int err;
  if (iscompat && dmax < 19)
    dmax = 10;

  do {
    dmax *= 2;
    dest = realloc(dest, dmax);
    memset(dest, 0, dmax); // not really needed.
    err = u8id_decompose_s(dest, dmax, (char *)src, &destlen, iscompat);
  } while (err == ERR_NOSPACE);
  if (err) {
    free(dest);
    return NULL;
  }
#if !defined U8ID_NORM || (U8ID_NORM != FCD)
  if (mode == U8ID_FCD)
#else
  if (1)
#endif
    return dest;

#if !defined U8ID_NORM || (U8ID_NORM != FCD)
  /* temp. scratch space, on stack or heap */
  if (destlen + 2 < 128) {
    tmp_ptr = tmp_stack;
    tmp_size = 128;
  } else {
    tmp_size = destlen + 2;
    tmp_ptr = tmp = (char *)malloc(tmp_size);
  }
  // now reorder for some canonalization (if required)
  err = u8id_reorder_s((unsigned char *)tmp_ptr, tmp_size, dest, destlen);
  while (err == ERR_NOSPACE) {
    tmp_size *= 2;
    if (tmp)
      tmp_ptr = tmp = (char *)realloc(tmp_ptr, tmp_size);
    else
      tmp_ptr = tmp = (char *)malloc(tmp_size);
    memset(tmp_ptr, 0, tmp_size); // not really needed
    err = u8id_reorder_s((unsigned char *)tmp_ptr, tmp_size, dest, destlen);
  }

  // if decomposed
#  if !defined U8ID_NORM || !(U8ID_NORM == NFD || U8ID_NORM == NFKD)
  if (mode == U8ID_NFD || mode == U8ID_NFKD)
#  else
  if (1)
#  endif // NFD or NFKD
  {
    free(dest);
    if (tmp) // on heap
      return (char *)tmp_ptr;
    else { // cannot return our stack value
      tmp_ptr = (char *)malloc(strlen(tmp_stack) + 1);
      strcpy(tmp_ptr, tmp_stack);
      return (char *)tmp_ptr;
    }
  }

#  if !defined U8ID_NORM || !(U8ID_NORM == NFD || U8ID_NORM == NFKD)
  // now compose to a shorter sequence
  err = u8id_compose_s(dest, dmax, tmp_ptr, &destlen, mode == U8ID_FCC);
  if (tmp)
    free(tmp);
  if (err) {
    free(dest);
    return NULL;
  }
#  endif // !(NFD or NFKD)
#endif   // !FCD
  return dest;
}
