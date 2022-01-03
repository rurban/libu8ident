/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

Measure binary_search in array vs croaring for confusables[] and
some range_bool sets, like allowed_id_list[] and the NORM lists.
croaring is 10-100% faster only for confusables,
and 70-100% slower for the range_bool sets.
A hybrid linear for <128 and bsearch is the fastest for most,
eytzinger for mark.
hybrid16 splits into 16bit and 32bit lists.

times in rdtsc cycles per lookup, less is better.
          | croaring | bsearch  | hybrid   | hybrid16 | eytzinger |
confus    : 70008      70022      70037    |				last
0.04% slower scripts   : 0          69968      69990      69872      70006    |
last 0.19% slower allowed_id: 70013      69888      69934      69905      69894
|	last 0.02% faster mark      : 70044      69908      69794      69794
69805    |	last 0.02% slower nfkd      : 69988      69857      69836 69860
69790    |	last 0.07% faster nfd       : 69948      69799      69813 69925
69792    |	last 0.03% faster nfkc      : 70172      70100      69990    |
last 0.16% faster nfc       : 70225      70040      69926    |
last 0.16% faster

with the scripts1.h variant: (first search range, then singles.
see branch scripts1)
nfkd: bsearch: 3326908 	2x bsearch: 4575870 	 37.54% slower
nfd:  bsearch: 2575716 	2x bsearch: 4131504 	 60.40% slower
nfkc: bsearch: 5633134 	2x bsearch: 7809620 	 38.64% slower
nfc:  bsearch: 3747484 	2x bsearch: 7600398 	 102.81% slower
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "u8id_private.h"
#include "scripts.h"
#include "u8idroar.h"
#undef EXT_SCRIPTS
#include "scripts16.h"
#include "confus.h"
#define EXT_SCRIPTS
#include "mark.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

volatile bool gret = false;
uint64_t tbase = 0UL; // time to run the loop with empty payload

#if defined(_MSC_VER)
#  define timer_start() __rdtsc()
#  define timer_end() __rdtsc()
#  if (SIZEOF_SIZE_T == 8)
#    pragma intrinsic (_BitsScanForward64)
#  else
#    pragma intrinsic (_BitsScanForward)
#  endif
#else
// see
// https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
// 3.2.1 The Improved Benchmarking Method
static inline uint64_t timer_start() {
#  if defined(__i386__) || (defined(__x86_64__) && SIZEOF_SIZE_T == 4)
  uint32_t cycles_high, cycles_low;
  __asm__ volatile("cpuid\n\t"
                   "rdtsc\n\t"
                   "mov %%edx, %0\n\t"
                   "mov %%eax, %1\n\t"
                   : "=r"(cycles_high), "=r"(cycles_low)::"%eax", "%ebx",
                     "%ecx", "%edx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
#  elif defined __x86_64__
  uint32_t cycles_high, cycles_low;
  __asm__ volatile("cpuid\n\t"
                   "rdtsc\n\t"
                   "mov %%edx, %0\n\t"
                   "mov %%eax, %1\n\t"
                   : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx",
                     "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
#  else
  return rdtsc();
#  endif
}

static inline uint64_t timer_end() {
#  if defined(__i386__) || (defined(__x86_64__) && SIZEOF_SIZE_T == 4)
  uint32_t cycles_high, cycles_low;
  __asm__ volatile("rdtscp\n\t"
                   "mov %%edx, %0\n\t"
                   "mov %%eax, %1\n\t"
                   "cpuid\n\t"
                   : "=r"(cycles_high), "=r"(cycles_low)::"%eax", "%ebx",
                     "%ecx", "%edx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
#  elif defined __x86_64__
  uint32_t cycles_high, cycles_low;
  __asm__ volatile("rdtscp\n\t"
                   "mov %%edx, %0\n\t"
                   "mov %%eax, %1\n\t"
                   "cpuid\n\t"
                   : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx",
                     "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
#  else
  return rdtsc();
#  endif
}

#endif

#if 0
static inline bool linear_search(const uint32_t cp, const char *list,
                                 const size_t len, const size_t size) {
  const char *p = list;
  struct range_bool *s = (struct range_bool *)list;
  for (size_t i = 0; i < len; i++) {
    if ((cp - s->from) <= (s->to - s->from))
      return true;
    if (cp <= s->to) // s is sorted. not found
      return false;
    p += size;
    s = (struct range_bool *)p;
  }
  return false;
}
#endif

static inline struct sc *binary_search(const uint32_t cp, const char *list,
                                       const size_t len, const size_t size) {
  int n = (int)len;
  const char *p = list;
  struct sc *pos;
  while (n > 0) {
    pos = (struct sc *)(p + size * (n / 2));
    // if ((cp - pos->from) <= (pos->to - pos->from)) // in-between trick slower
    // here
    if (cp >= pos->from && cp <= pos->to)
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

#if 1
// TODO branch-free with ranges
static struct sc *binary_search_fast(const uint32_t cp, const char *list,
                                     const size_t len, const size_t size) {
  int n = (int)len;
  const char *p = list;
  struct sc *pos;
  while (n > 0) {
    pos = (struct sc *)(p + size * (n / 2));
    if ((cp - pos->from) <= (pos->to - pos->from)) // faster in-between trick
      // if (cp >= pos->from && cp <= pos->to)
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

static size_t sc_eytzinger_sort(const struct sc *restrict in,
                                struct sc *restrict out, const size_t len,
                                size_t i, const size_t k) {
  if (k <= len) {
    i = sc_eytzinger_sort(in, out, len, i, 2 * k);
    out[k] = in[i++];
    i = sc_eytzinger_sort(in, out, len, i, 2 * k + 1);
  }
  return i;
}
static size_t range_bool_eytzinger_sort(const struct range_bool *restrict in,
                                        struct range_bool *restrict out,
                                        const size_t len, size_t i,
                                        const size_t k) {
  if (k <= len) {
    i = range_bool_eytzinger_sort(in, out, len, i, 2 * k);
    out[k] = in[i++];
    i = range_bool_eytzinger_sort(in, out, len, i, 2 * k + 1);
  }
  return i;
}

static struct sc *eytzinger_search(const uint32_t cp, const char *elist,
                                   const size_t len, const size_t size) {
  size_t k = 1;
  const char *p = elist;
  struct sc *pos;
  while (k <= len) {
    // __builtin_prefetch(p + (size * k));
    pos = (struct sc *)(p + (size * k));
#  if 0 // cmov is actually slower here
    k = 2 * k  + (cp < pos->to);
#  else
    if (cp >= pos->to)
      k = 2 * k;
    else
      k = 2 * k + 1;
#  endif
  }
#  ifdef HAVE___BUILTIN_FFS
  k >>= __builtin_ffs(~k);
#  elif (_MSC_VER)
  unsigned long index;
  if
#    if (SIZEOF_SIZE_T == 8)
  (_BitsScanForward64(&index, ~k))
#    else
  (_BitsScanForward(&index, ~k))
#    endif
    k >>= index;
#  else
#    error no __builtin_ffs
#  endif
  return (struct sc *)(p + (size * k));
}
#endif

// without croaring
static int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}

static inline bool array_search_hybr(const uint32_t cp, const uint32_t *list,
                                     const size_t len) {
  if (cp < 127) {
    // linear search
    uint32_t *s = (uint32_t *)list;
    for (size_t i = 0; i < len; i++) {
      if (cp == *s)
        return true;
      else if (cp < *s)
        return false;
      s++;
    }
    return false;
  } else {
    return bsearch(&cp, list, len, 4, compar32) ? true : false;
  }
}

static inline bool range_bool_search(const uint32_t cp,
                                     const struct range_bool *list,
                                     const size_t len) {
  return binary_search(cp, (char *)list, len, sizeof(*list)) ? true : false;
}

static inline bool range_bool_search_hybr(const uint32_t cp,
                                          const struct range_bool *list,
                                          const size_t len) {
  if (cp < 127) {
    // linear search
    struct range_bool *s = (struct range_bool *)list;
    for (size_t i = 0; i < len; i++) {
      if ((cp - s->from) <= (s->to - s->from)) // faster in-between trick
        return true;
      if (cp <= s->to) // s is sorted. not found
        return false;
      s++;
    }
    return false;
  } else {
    return binary_search(cp, (char *)list, len, sizeof(*list)) ? true : false;
  }
}

static inline bool rb16_search_hybr(const uint32_t cp,
                                    const struct range_bool16 *list16,
                                    const size_t len16,
                                    const struct range_bool *list32,
                                    const size_t len32) {
  if (cp < 127) {
    // linear search
    struct range_bool16 *s = (struct range_bool16 *)list16;
    for (size_t i = 0; i < len16; i++) {
      if (((uint16_t)cp - s->from) <=
          (s->to - s->from)) // faster in-between trick
        return true;
      if (cp <= s->to) // s is sorted. not found
        return false;
      s++;
    }
    return false;
  } else if (cp <= 0xffff) {
    return binary_search(cp, (char *)list16, len16, sizeof(*list16)) ? true
                                                                     : false;
  } else {
    return binary_search(cp, (char *)list32, len32, sizeof(*list32)) ? true
                                                                     : false;
  }
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

// hybrid search: linear or binary16 or binary32
static inline uint8_t
sc16_search(const uint32_t cp, const struct sc16 *sc_list16, const size_t len16,
            const struct sc *sc_list32, const size_t len32) {
  if (cp < 255) { // 14 ranges a 9 byte (126 byte, i.e cache loads)
    struct sc16 *s = (struct sc16 *)sc_list16;
    for (size_t i = 0; i < len16; i++) {
      if (((uint16_t)cp - s->from) <=
          (s->to - s->from)) // faster in-between trick
        return s->scr;
      if (cp <= s->to) // s is sorted. not found
        return 255;
      s++;
    }
    return 255;
  } else if (cp <= 0xffff) {
    const struct sc16 *sc = (struct sc16 *)binary_search(
        cp, (char *)sc_list16, len16, sizeof(*sc_list16));
    return sc ? sc->scr : 255;
  } else {
    const struct sc *sc = (struct sc *)binary_search(cp, (char *)sc_list32,
                                                     len32, sizeof(*sc_list32));
    return sc ? sc->scr : 255;
  }
}

static inline uint8_t sc_eytzinger_search(const uint32_t cp,
                                          const struct sc *list,
                                          const size_t len) {
  if (cp < 127) {
    // linear search
    struct sc *s = (struct sc *)list;
    for (size_t i = 0; i < len; i++) {
      if ((cp - s->from) <= (s->to - s->from)) // faster in-between trick
        return s->scr;
      if (cp <= s->to) // s is sorted. not found
        return 255;
      s++;
    }
    return 255;
  } else {
    struct sc *s = eytzinger_search(cp, (char *)list, len, sizeof(*list));
    return s ? s->scr : 255;
  }
}

static inline bool range_bool_eytzinger_search(const uint32_t cp,
                                               const struct range_bool *list,
                                               const size_t len) {
  if (cp < 127) {
    // linear search
    struct range_bool *s = (struct range_bool *)list;
    for (size_t i = 0; i < len; i++) {
      if ((cp - s->from) <= (s->to - s->from)) // faster in-between trick
        return true;
      if (cp <= s->to) // s is sorted. not found
        return false;
      s++;
    }
    return false;
  } else {
    return eytzinger_search(cp, (char *)list, len, sizeof(struct range_bool))
               ? true
               : false;
  }
}

#define PERC(fast, slow) (100.0 * (slow - fast) / (double)fast)
#define LOOPS (100 * (128 - 20)) + (0x11000 - 20)
// favor ASCII 100x over unicode char coverage
#define DO_LOOP(t1, boolfunc)                                                  \
  /* warmup */                                                                 \
  for (uint32_t cp = 0x10000; cp > 20; cp -= 4) {                              \
    bool ret = boolfunc;                                                       \
    gret |= ret;                                                               \
  }                                                                            \
  begin = timer_start();                                                       \
  for (int i = 0; i < 100; i++) {                                              \
    for (uint32_t cp = 20; cp < 128; cp++) {                                   \
      bool ret = boolfunc;                                                     \
      gret |= ret;                                                             \
    }                                                                          \
  }                                                                            \
  for (uint32_t cp = 20; cp < 0x11000; cp++) {                                 \
    bool ret = boolfunc;                                                       \
    gret |= ret;                                                               \
  }                                                                            \
  end = timer_end();                                                           \
  uint64_t t1 = ((end - begin) - tbase) / LOOPS

#define DO_LOOP_NM(t1, boolfunc, NFPRE)                                        \
  /* warmup */                                                                 \
  for (uint32_t cp = 0x10000; cp > 20; cp -= 4) {                              \
    bool ret =                                                                 \
        boolfunc(cp, JOIN(NFPRE, N_list), ARRAY_SIZE(JOIN(NFPRE, N_list)));    \
    gret |= ret;                                                               \
  }                                                                            \
  begin = timer_start();                                                       \
  for (int i = 0; i < 100; i++) {                                              \
    for (uint32_t cp = 20; cp < 128; cp++) {                                   \
      bool ret;                                                                \
      if (boolfunc(cp, JOIN(NFPRE, N_list), ARRAY_SIZE(JOIN(NFPRE, N_list))))  \
        ret = true;                                                            \
      else                                                                     \
        ret = boolfunc(cp, JOIN(NFPRE, M_list),                                \
                       ARRAY_SIZE(JOIN(NFPRE, M_list)));                       \
      gret |= ret;                                                             \
    }                                                                          \
  }                                                                            \
  for (uint32_t cp = 20; cp < 0x11000; cp++) {                                 \
    bool ret;                                                                  \
    if (boolfunc(cp, JOIN(NFPRE, N_list), ARRAY_SIZE(JOIN(NFPRE, N_list))))    \
      ret = true;                                                              \
    else                                                                       \
      ret =                                                                    \
          boolfunc(cp, JOIN(NFPRE, M_list), ARRAY_SIZE(JOIN(NFPRE, M_list)));  \
    gret |= ret;                                                               \
  }                                                                            \
  end = timer_end();                                                           \
  uint64_t t1 = ((end - begin) - tbase) / LOOPS

bool empty_basefunc(uint32_t cp, uint32_t *arr, size_t len) {
  arr[len - 1] = cp;
  return true;
}

void measure_baseline(void) {
  uint64_t begin, end;
  uint32_t arr[10];
  DO_LOOP(_tbase, empty_basefunc(32, arr, 10));
  tbase = _tbase;
#ifdef DEBUG
  printf("empty loop: %lu\n", tbase);
#endif
}

// with t1 being the slowest, t3 usually the fastest
#define RESULT(name, t1, t2, t3)                                               \
  printf("%-10s: %-10lu %-10lu %-9lu|\t\t\t\tlast %0.2f%% %s\n", name, t1, t2, \
         t3, t3 < t2 ? PERC(t3, t2) : PERC(t2, t3),                            \
         t3 < t2 ? "faster" : "slower")
// with t1 being the slowest, t4 usually the fastest, compare to t3
/*#define RESULT4(name, t1, t2, t3, t4)                                 \
  printf("%-10s: %-10lu %-10lu %-10lu %-9lu|\tlast %0.2f%% %s\n", name, \
         t1, t2, t3, t4,                                                \
         t4 < t3 ? PERC(t4,t3) : PERC(t3,t4),                           \
         t4 < t3 ? "faster" : "slower")
*/
#define RESULT5(name, t1, t2, t3, t4, t5)                                      \
  printf("%-10s: %-10lu %-10lu %-10lu %-10lu %-9lu|\tlast %0.2f%% %s\n", name, \
         t1, t2, t3, t4, t5,                                                   \
         t4 ? (t5 < t4 ? PERC(t5, t4) : PERC(t4, t5))                          \
            : (t5 < t3 ? PERC(t5, t3) : PERC(t3, t5)),                         \
         t5 < (t4 ? t4 : t3) ? "faster" : "slower")

// this is the only one without ranges, thus croaring is fastest
void perf_confus(void) {
  uint64_t begin, end;

  // just a uint32_t[] array. not from,to pairs
  DO_LOOP(t1, bsearch(&cp, confusables, ARRAY_SIZE(confusables), 4, compar32));
  DO_LOOP(t2, u8ident_is_confusable(cp)); // croaring
  DO_LOOP(t3, array_search_hybr(cp, confusables, ARRAY_SIZE(confusables)));

  printf("%-10s: %-10lu %-10lu %-9lu|\t\t\t\tlast %0.2f%% %s\n", "confus", t1,
         t2, t3, t3 < t1 ? PERC(t3, t1) : PERC(t1, t3),
         t3 < t1 ? "faster" : "slower");
  // RESULT("confus", t1,t2,t3);
}

void perf_scripts(void) {
  uint64_t begin, end;
  const size_t len = ARRAY_SIZE(xid_script_list);

  // DO_LOOP(t1, u8ident_roar_has_uncommonscript(cp));
  uint64_t t1 = 0;
  DO_LOOP(t2, binary_search(cp, (const char *)xid_script_list, len,
                            sizeof(struct sc)));
  DO_LOOP(t3, sc_search(cp, xid_script_list, len));
  DO_LOOP(t4, sc16_search(cp, xid_script_list16, ARRAY_SIZE(xid_script_list16),
                          xid_script_list32, ARRAY_SIZE(xid_script_list32)));

  struct sc *eytz_list = malloc((len + 1) * sizeof(*xid_script_list));
  sc_eytzinger_sort(xid_script_list, eytz_list, len, 0, 1);
  DO_LOOP(t5, sc_eytzinger_search(cp, eytz_list, len));
  free(eytz_list);

  RESULT5("scripts", t1, t2, t3, t4, t5);
}

void perf_allowed_id(void) {
  uint64_t begin, end;
  const size_t len = ARRAY_SIZE(allowed_id_list);

  DO_LOOP(t1, u8ident_roar_is_allowed(cp));
  DO_LOOP(t2, range_bool_search(cp, allowed_id_list, len));
  DO_LOOP(t3, range_bool_search_hybr(cp, allowed_id_list, len));
  // DO_LOOP(t4, faster_search(cp, allowed_id_list, len));
  DO_LOOP(t4,
          rb16_search_hybr(cp, allowed_id_list16, ARRAY_SIZE(allowed_id_list16),
                           allowed_id_list32, ARRAY_SIZE(allowed_id_list32)));

  struct range_bool *eytz_list = malloc((len + 1) * sizeof(*allowed_id_list));
  range_bool_eytzinger_sort(allowed_id_list, eytz_list, len, 0, 1);
  DO_LOOP(t5, range_bool_eytzinger_search(cp, eytz_list, len));
  free(eytz_list);

  RESULT5("allowed_id", t1, t2, t3, t4, t5);
}

void perf_mark(void) {
  uint64_t begin, end;
  const size_t len = ARRAY_SIZE(mark_list);

  DO_LOOP(t1, u8ident_roar_is_mark(cp));
  DO_LOOP(t2, range_bool_search(cp, mark_list, len));
  DO_LOOP(t3, range_bool_search_hybr(cp, mark_list, len));

  struct range_bool *eytz_list = malloc((len + 1) * sizeof(*mark_list));
  range_bool_eytzinger_sort(mark_list, eytz_list, len, 0, 1);
  DO_LOOP(t5, range_bool_eytzinger_search(cp, eytz_list, len));
  free(eytz_list);

  RESULT5("mark", t1, t2, t3, t3, t5);
}

void perf_nfkc(void) {
  uint64_t begin, end;
#undef NFKC
  DO_LOOP(t1, u8ident_roar_maybe_nfkc(cp));
  DO_LOOP_NM(t2, range_bool_search, NFKC);
  DO_LOOP_NM(t3, range_bool_search_hybr, NFKC);

  RESULT("nfkc", t1, t2, t3);
}

void perf_nfc(void) {
  uint64_t begin, end;
#undef NFC
  DO_LOOP(t1, u8ident_roar_maybe_nfc(cp));
  DO_LOOP_NM(t2, range_bool_search, NFC);
  DO_LOOP_NM(t3, range_bool_search_hybr, NFC);

  RESULT("nfc", t1, t2, t3);
}

void perf_nfkd(void) {
  uint64_t begin, end;
  const size_t len = ARRAY_SIZE(NFKD_N_list);
#undef NFKD

  DO_LOOP(t1, u8ident_roar_maybe_nfkd(cp));
  DO_LOOP(t2, range_bool_search(cp, NFKD_N_list, len));
  DO_LOOP(t3, range_bool_search_hybr(cp, NFKD_N_list, len));
  DO_LOOP(t4, rb16_search_hybr(cp, NFKD_N_list16, ARRAY_SIZE(NFKD_N_list16),
                               NFKD_N_list32, ARRAY_SIZE(NFKD_N_list32)));

  struct range_bool *eytz_list = malloc((len + 1) * sizeof(*NFKD_N_list));
  range_bool_eytzinger_sort(NFKD_N_list, eytz_list, len, 0, 1);
  DO_LOOP(t5, range_bool_eytzinger_search(cp, NFKD_N_list, len));
  free(eytz_list);

  RESULT5("nfkd", t1, t2, t3, t4, t5);
}

void perf_nfd(void) {
  uint64_t begin, end;
  const size_t len = ARRAY_SIZE(NFD_N_list);

#undef NFD
  DO_LOOP(t1, u8ident_roar_maybe_nfd(cp));
  DO_LOOP(t2, range_bool_search(cp, NFD_N_list, len));
  DO_LOOP(t3, range_bool_search_hybr(cp, NFD_N_list, len));
  DO_LOOP(t4, rb16_search_hybr(cp, NFD_N_list16, ARRAY_SIZE(NFD_N_list16),
                               NFD_N_list32, ARRAY_SIZE(NFD_N_list32)));

  struct range_bool *eytz_list = malloc((len + 1) * sizeof(*NFD_N_list));
  range_bool_eytzinger_sort(NFD_N_list, eytz_list, len, 0, 1);
  DO_LOOP(t5, range_bool_eytzinger_search(cp, NFD_N_list, len));
  free(eytz_list);

  RESULT5("nfd", t1, t2, t3, t4, t5);
}

int main(void) {
  u8ident_roar_init();
  printf("times in rdtsc cycles per lookup, less is better.\n");
  measure_baseline();
  printf("%-10s| %-8s | %-8s | %-8s | %-8s | %-8s |\n", "", "croaring",
         "bsearch", "hybrid", "hybrid16", "eytzinger");
  perf_confus();
  perf_scripts();
  perf_allowed_id();
  perf_mark();
  perf_nfkd();
  perf_nfd();
  perf_nfkc();
  perf_nfc();

  u8ident_roar_free();
}
