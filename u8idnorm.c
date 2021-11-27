/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2014, 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   See https://www.unicode.org/reports/tr15/tr15-51.html
*/
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "u8ident.h"
#include "u8id_private.h"

#define STDCHAR char
#define TRUE true
#define FALSE false
#include "un8ifcan.h" /* for NFD Canonical Decomposition */
#include "un8ifcmb.h" /* for reorder Canonical_Combining_Class_Values */
#include "un8ifcmp.h" /* for NFC Canonical Composition lists */
#include "un8ifexc.h" /* for NFC Composite exclusions */
#include "un8ifcpt.h" /* for NFKD/NFKC Compat. Decomposition. */
#include "hangul.h"   /* Korean/Hangul has special (easy) normalization rules */

#define _UNICODE_MAX 0x10ffff

/* size of array for combining characters */
/* enough as an initial value? */
#define CC_SEQ_SIZE 10
#define CC_SEQ_STEP 5

static int _bsearch_exc(const void *ptr1, const void *ptr2) {
    UN8IF_compat_exc_t *e1 = (UN8IF_compat_exc_t *)ptr1;
    UN8IF_compat_exc_t *e2 = (UN8IF_compat_exc_t *)ptr2;
    return e1->cp > e2->cp ? 1 : e1->cp == e2->cp ? 0 : -1;
}

/* Note that we can generate two versions of the tables.  The old format as
 * used in Unicode::Normalize, and the new 3x smaller NORMALIZE_IND_TBL cperl
 * variant, as used here and in cperl core since 5.27.2.
 */
static int _decomp_canonical_s(char *dest, size_t dmax, uint32_t cp) {
    /* the new format generated with cperl Unicode-Normalize/mkheader -uni -ind -std
     */
    const UN8IF_canon_PLANE_T **plane, *row;
    if (unlikely(dmax < 5)) {
        *dest = 0;
        return -1;
    }
    plane = UN8IF_canon[cp >> 16];
    if (!plane) { /* Only the first 3 of 16 are filled */
        return 0;
    }
    row = plane[(cp >> 8) & 0xff];
    if (row) { /* the first row is pretty filled, the rest very sparse */
        const UN8IF_canon_PLANE_T vi = row[cp & 0xff];
        if (!vi)
            return 0;
#if UN8IF_canon_exc_size > 0
        /* overlong: search in extra list */
        else if (unlikely(vi == (uint16_t)-1)) {
            UN8IF_canon_exc_t *e;
            assert(UN8IF_canon_exc_size);
            e = (UN8IF_canon_exc_t *)bsearch(
                &cp, &UN8IF_canon_exc, UN8IF_canon_exc_size,
                sizeof(UN8IF_canon_exc[0]), _bsearch_exc);
            if (e) {
                size_t l = strlen(e->v);
                memcpy(dest, e->v, l + 1); /* incl \0 */
                return (int)l;
            }
            return 0;
        }
#endif
        else {
            /* value => length-index and offset */
            const int l = UN8IF_canon_LEN(vi);
            const int i = UN8IF_canon_IDX(vi);
            const char *tbl = (const char *)UN8IF_canon_tbl[l - 1];
            const int len = l;
#if defined(DEBUG)
            printf("U+%04X vi=0x%x (>>12, &fff) => TBL(%d)|%d\n", cp, vi, l, i);
#endif
            assert(l > 0 && l <= 4);
#if 0
            /* 13.0: tbl sizes: (917,763,227,36) */
            /* l: 1-4 */
            assert((l == 1 && i < 917) || (l == 2 && i < 763) ||
                   (l == 3 && i < 227) || (l == 4 && i < 36) || 0);
            assert(dmax > 4);
#endif            
            memcpy(dest, &tbl[i * len], len); /* 33% perf */
            dest[len] = '\0';
            return len;
        }
    } else {
        return 0;
    }
}

// TODO (from cperl and safeclib)

// TODO u8 not wchar
static int _decomp_hangul_s(char *dest, size_t dmax, uint32_t cp) {
    uint32_t sindex = cp - Hangul_SBase;
    uint32_t lindex = sindex / Hangul_NCount;
    uint32_t vindex = (sindex % Hangul_NCount) / Hangul_TCount;
    uint32_t tindex = sindex % Hangul_TCount;

    if (unlikely(dmax < 4)) {
        return -1;
    }

#if 0
    // TODO encode to UTF-8
    _enc_u8(dest, dmax, (lindex + Hangul_LBase));
    _enc_u8(dest, dmax, (vindex + Hangul_VBase));
    if (tindex) {
	_enc_u8(dest, dmax, (tindex + Hangul_TBase));
        return 3;
    }
    return 2;
#endif
}

/* codepoint canonical or compatible decomposition.
   dmax should be > 4,
   19 with the single arabic outlier U+FDFA for compat accepted
*/
static int _decomp_s(char *restrict dest, size_t dmax, const uint32_t cp,
                     const bool iscompat)
{
    assert(dmax > 4);
    /* The costly is_HANGUL_cp_high(cp) checks also all composing chars.
       Hangul_IsS only for the valid start points. Which we can do here. */
    if (Hangul_IsS(cp)) {
        return _decomp_hangul_s(dest, dmax, cp);
    } else {
        return iscompat ? _decomp_compat_s(dest, dmax, cp)
                        : _decomp_canonical_s(dest, dmax, cp);
    }
}

/* canonical ordering of combining characters (c.c.). */
typedef struct {
    uint8_t cc;  /* combining class */
    uint32_t cp; /* codepoint */
    size_t pos;  /* position */
} UN8IF_cc;

/* rc = u8id_reorder_s(tmp, len+1, dest); */
static int _compare_cc(const void *a, const void *b) {
    int ret_cc;
    ret_cc = ((UN8IF_cc *)a)->cc - ((UN8IF_cc *)b)->cc;
    if (ret_cc)
        return ret_cc;

    return (((UN8IF_cc *)a)->pos > ((UN8IF_cc *)b)->pos) -
           (((UN8IF_cc *)a)->pos < ((UN8IF_cc *)b)->pos);
}

static uint32_t _composite_cp(uint32_t cp, uint32_t cp2) {
    const UN8IF_complist_s ***plane, **row, *cell;

    if (unlikely(!cp2)) {
        return 0;
    }
    if (unlikely((_UNICODE_MAX < cp) || (_UNICODE_MAX < cp2))) {
        return -1;
    }

    if (Hangul_IsL(cp) && Hangul_IsV(cp2)) {
        uint32_t lindex = cp - Hangul_LBase;
        uint32_t vindex = cp2 - Hangul_VBase;
        return (Hangul_SBase +
                (lindex * Hangul_VCount + vindex) * Hangul_TCount);
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
        //GCC_DIAG_IGNORE(-Wcast-align)
        for (i = (UN8IF_complist *)cell; i->nextchar; i++) {
            //GCC_DIAG_RESTORE
            if (cp2 == i->nextchar) {
                return i->composite;
            } else if (cp2 < i->nextchar) { /* nextchar is sorted */
                break;
            }
        }
    }
    return 0;
}

static uint8_t _combin_class(uint32_t cp) {
    const uint8_t **plane, *row;
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
 * @def u8id_decompose_s(dest,dmax,src,lenp,iscompat)
 * @brief
 *    Converts the UTF-8 string to the canonical NFD or NFKD normalization,
 *    as defined in the latest Unicode standard, latest 13.0.  The conversion
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
int u8id_decompose_s(char *restrict dest, size_t dmax,
                     const char *restrict src,
                     size_t *restrict lenp,
                     const bool iscompat)
{
    size_t orig_dmax;
    char *orig_dest;
    const char *overlap_bumper;
    uint32_t cp;
    int c;

    if (lenp)
        *lenp = 0;
    if (unlikely(dest == NULL)) {
        return -1;
    }
    if (unlikely(src == NULL || dest == NULL || dmax == 0 || dmax < 5 || dmax > 1024)) {
        *dest = 0;
        return -1;
    }
    if (unlikely(dest == src)) {
        return -1;
    }
    if (unlikely(iscompat && dmax < 19)) {
        *dest = 0;
        return -1;
    }

    /* hold base of dest in case src was not copied */
    orig_dmax = dmax;
    orig_dest = dest;

    if (dest < src) {
        overlap_bumper = src;

        while (dmax > 0) {
            cp = _dec_u8(src);
            if (unlikely(dest == overlap_bumper)) {
                return -1;
            }
            if (unlikely(_UNICODE_MAX < cp)) {
                return -1;
            }
            if (!cp)
                goto done;

            c = _decomp_s(dest, dmax, cp, iscompat);
            if (c > 0) {
                dest += c;
                dmax -= c;
            } else if (c == 0) {
                *dest++ = *src;
                dmax--;
            } else {
                return -c;
            }
            src++;
        }
    } else {
        overlap_bumper = dest;

        while (dmax > 0) {
            cp = _dec_u8(src);
            if (unlikely(src == overlap_bumper)) {
                return -1;
            }
            if (unlikely(_UNICODE_MAX < cp)) {
                return -1;
            }
            if (!cp)
                goto done;

            c = _decomp_s(dest, dmax, cp, iscompat);
            if (c > 0) {
                dest += c;
                dmax -= c;
            } else if (c == 0) {
                *dest++ = *src;
                dmax--;
            } else {
                return -c;
            }
            src++;
        }
    }

    if (lenp)
        *lenp = orig_dmax - dmax;
    return -1;

done:
    if (lenp)
        *lenp = orig_dmax - dmax;
    memset(dest, 0, dmax);
    return 0;
}

/**
 * @def u8id_reorder_s(dest,dmax,src,len)
 *    Reorder all decomposed sequences in a UTF-8 string to NFD,
 *    as defined in the latest Unicode standard, latest 13.0. The conversion
 *    stops at the first null or after dmax characters.
 */
int u8id_reorder_s(char *restrict dest, size_t dmax, const char *restrict src,
                       const size_t len)
{
    UN8IF_cc seq_ary[CC_SEQ_SIZE];
    UN8IF_cc *seq_ptr = (UN8IF_cc *)seq_ary; /* start with stack */
    UN8IF_cc *seq_ext = NULL;                /* heap when needed */
    size_t seq_max = CC_SEQ_SIZE;
    size_t cc_pos = 0;
    char *p = (char *)src;
    const char *e = p + len;
    char *orig_dest = dest;
    size_t orig_dmax = dmax;

    const size_t destsz = dmax;
    while (p < e) {
        uint8_t cur_cc;
        uint32_t cp = _dec_u8(p);
        p++;
#if SIZEOF_WCHAR_T == 2
        if (cp > 0xffff) {
            p++;
        }
#endif

        cur_cc = _combin_class(cp);
        if (cur_cc != 0) {
            if (seq_max < cc_pos + 1) {         /* extend if need */
                seq_max = cc_pos + CC_SEQ_STEP; /* new size */
                if (CC_SEQ_SIZE == cc_pos) {    /* seq_ary full */
                    seq_ext = (UN8IF_cc *)malloc(seq_max * sizeof(UN8IF_cc));
                    memcpy(seq_ext, seq_ary, cc_pos * sizeof(UN8IF_cc));
                } else {
                    seq_ext = (UN8IF_cc *)realloc(seq_ext,
                                                  seq_max * sizeof(UN8IF_cc));
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
            size_t i;

            if (unlikely(dmax - cc_pos <= 0)) {
                return -1;
            }

            if (cc_pos > 1) /* reorder if there are two Combining Classes */
                qsort((void *)seq_ptr, cc_pos, sizeof(UN8IF_cc), _compare_cc);

            for (i = 0; i < cc_pos; i++) {
                _enc_u8(dest, dmax, seq_ptr[i].cp);
            }
            cc_pos = 0;
        }

        if (cur_cc == 0) {
            _enc_u8(dest, dmax, cp);
        }

        if (unlikely(!dmax)) {
            return -1;
        }
    }
    if (seq_ext)
        free(seq_ext);
        /* surrogate pairs can actually collapse */
    memset(dest, 0, dmax);
    return 0;
}

/**
 * @def u8id_compose_s(dest,dmax,src,lenp,iscontig)
 *    Combine all decomposed sequences in a wide string to NFC,
 *    as defined in the latest Unicode standard, latest 10.0. The conversion
 *    stops at the first null or after dmax characters. */
/* combine decomposed sequences to NFC. */
/* iscontig = false; composeContiguous? FCC if true */
int u8id_compose_s(char *restrict dest, size_t dmax,
                   const char *restrict src,
                   size_t *restrict lenp,
                   const bool iscontig)
{
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
    char *orig_dest = dest;
    size_t orig_dmax = dmax;

    if (unlikely(dmax > 1024)) {
      *lenp = 0;
      return -1;
    }

    while (p < e) {
        uint8_t cur_cc;
        uint32_t cp = _dec_u8(p);
        p++;
#if SIZEOF_WCHAR_T == 2
        if (cp > 0xffff) {
            p++;
        }
#endif

        cur_cc = _combin_class(cp);

        if (!valid_cpS) {
            if (cur_cc == 0) {
                cpS = cp; /* found the first Starter */
                valid_cpS = true;
                if (p < e)
                    continue;
            } else {
                _enc_u8(dest, dmax, cp);
                if (unlikely(!dmax)) {
                    return -1;
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
                    if (seq_max < cc_pos + 1) {         /* extend if need */
                        seq_max = cc_pos + CC_SEQ_STEP; /* new size */
                        if (CC_SEQ_SIZE == cc_pos) {    /* seq_ary full */
                            seq_ext =
                                (uint32_t *)malloc(seq_max * sizeof(uint32_t));
                            memcpy(seq_ext, seq_ary, cc_pos * sizeof(uint32_t));
                        } else {
                            seq_ext = (uint32_t *)realloc(
                                seq_ext, seq_max * sizeof(uint32_t));
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
        _enc_u8(dest, dmax, cpS); /* starter (composed or not) */
        if (unlikely(!dmax)) {
            return -1;
        }

        if (cc_pos == 1) {
            _enc_u8(dest, dmax, *seq_ptr);
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

    memset(dest, 0, dmax);
    *lenp = orig_dmax - dmax;
    return 0;
}

int u8ident_may_normalize(const char* buf, int len) {
  return 1;
}

/* Returns a freshly allocated normalized string, in the option defined at `u8ident_init`. */
EXTERN uint8_t* u8ident_normalize(const char* buf, int len) {
  //
}
