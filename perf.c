/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   Measure binary_search in array vs croaring for confusables[] and
   some range_bool sets, like allowed_id_list[] and the NORM lists.
   croaring is 10-100% faster only for confusables,
   and 70-100% slower for the range_bool sets.
   A hybrid linear and bsearch is the fastest for most.
   TODO: branch-free bsearch, eytzinger layout.

   confus:
   croaring: 351442	bsearch: 517036          47.12% faster
             | croaring | bsearch  | hybrid   |
   allowed_id: 3265730    1962740    1617538  |	last 21.34% faster
   mark      : 11379602   3276052    1867788  |	last 75.40% faster
   nfkd      : 2834130    4376008    2395458  |	last 82.68% faster
   nfd       : 2703714    1724918    1621802  |	last 6.36% faster
   nfkc      : 5072808    4014738    4248660  |	last 5.83% slower
   nfc       : 12601550   2960984    3304444  |	last 11.60% slower

   with the scripts1.h variant: (first search range, then singles, see branch
   scripts1)
   nfkd:
   bsearch: 3326908 	2x bsearch: 4575870 	 37.54% faster
   nfd:
   bsearch: 2575716 	2x bsearch: 4131504 	 60.40% faster
   nfkc:
   bsearch: 5633134 	2x bsearch: 7809620 	 38.64% faster
   nfc:
   bsearch: 3747484 	2x bsearch: 7600398 	 102.81% faster
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
#include "confus.h"
#define EXT_SCRIPTS
#include "mark.h"

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)

volatile bool gret = false;

#if defined(_MSC_VER)
#  define timer_start() __rdtsc()
#  define timer_end() __rdtsc()
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

static struct sc *binary_search(const uint32_t cp, const char *list,
                                const size_t len, const size_t size) {
  int n = (int)len;
  const char *p = list;
  struct sc *pos;
  while (n > 0) {
    pos = (struct sc *)(p + size * (n / 2));
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

#if 0
static struct sc *binary_search_fast(const uint32_t cp, const char *list,
                                     const size_t len, const size_t size)
{
  int n = (int)len;
  const char *p = list;
  struct sc *pos;
  while (n > 0) {
    pos = (struct sc *)(p + size * (n / 2));
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

static struct sc *eytzinger_search(const uint32_t cp, const char *list,
                                   const size_t len, const size_t size)
{
  size_t k = 1;
  const char *p = list;
  struct sc *pos;
  while (k <= len) {
    pos = (struct sc *)(p + (size * k));
    if (cp >= pos->to)
      k = 2 * k;
    else
      k = 2 * k + 1;
  }
  k >>= __builtin_ffs(~k);
  return (struct sc *)(p + (size * k));
}
#endif

static inline bool range_bool_search(const uint32_t cp,
                                     const struct range_bool *list,
                                     const size_t len) {
  const char *r = (char *)binary_search(cp, (char *)list, len, sizeof(*list));
  return r ? true : false;
}

static inline bool range_bool_search_hybr(const uint32_t cp,
                                          const struct range_bool *list,
                                          const size_t len) {
  if (cp < 127) {
    struct range_bool *s = (struct range_bool *)list;
    for (size_t i = 0; i < len; i++) {
      if ((cp - s->from) <= (s->to - s->from))
        return true;
      if (cp <= s->to) // s is sorted. not found
        return false;
      s++;
    }
    return false;
  }
  else {
    const char *r = (char *)binary_search(cp, (char *)list, len, sizeof(*list));
    return r ? true : false;
  }
}

// without croaring
static int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}

#define PERC(fast,slow) (100.0 * (slow - fast) / (double)fast)
// favor ASCII 100x over unicode char coverage
#define DO_LOOP(t1,boolfunc) \
  begin = timer_start(); \
  for (int i = 0; i < 100; i++) { \
    for (uint32_t cp = 20; cp < 128; cp++) { \
      bool ret = boolfunc; \
      gret |= ret; \
    } \
  } \
  for (uint32_t cp = 20; cp < 0x11000; cp++) { \
    bool ret = boolfunc; \
    gret |= ret; \
  } \
  end = timer_end(); \
  uint64_t t1 = end - begin

#define DO_LOOP_NM(t1,boolfunc,NFPRE)           \
  begin = timer_start(); \
  for (int i = 0; i < 100; i++) { \
    for (uint32_t cp = 20; cp < 128; cp++) { \
    bool ret; \
    if (boolfunc(cp, JOIN(NFPRE,N_list), ARRAY_SIZE(JOIN(NFPRE,N_list)))) \
      ret = true; \
    else \
      ret = boolfunc(cp, JOIN(NFPRE,M_list), ARRAY_SIZE(JOIN(NFPRE,M_list))); \
    gret |= ret; \
    } \
  } \
  for (uint32_t cp = 20; cp < 0x11000; cp++) { \
    bool ret; \
    if (boolfunc(cp, JOIN(NFPRE,N_list), ARRAY_SIZE(JOIN(NFPRE,N_list)))) \
      ret = true; \
    else \
      ret = boolfunc(cp, JOIN(NFPRE,M_list), ARRAY_SIZE(JOIN(NFPRE,M_list))); \
    gret |= ret; \
  } \
  end = timer_end(); \
  uint64_t t1 = end - begin

void perf_confus(void) {
  printf("confus:\n");
  uint64_t begin, end;

  // just a uint32_t[] array. not from, to pairs
  DO_LOOP(t1, u8ident_is_confusable(cp));
  DO_LOOP(t2, bsearch(&cp, confusables, ARRAY_SIZE(confusables), 4, compar32));
  //DO_LOOP(t3, search_hybr(cp, confusables, ARRAY_SIZE(confusables)));

  if (t1 < t2)
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% faster\n", t1, t2, PERC(t1,t2));
  else
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% slower\n", t1, t2, PERC(t2,t1));
}

// with t1 being the slowest, t3 usually the fastest
#define RESULT(name, t1, t2, t3)                                 \
  printf("%-10s: %-10lu %-10lu %-9lu|\tlast %0.2f%% %s\n", name, \
         t1, t2, t3,                                             \
         t3 < t2 ? PERC(t3,t2) : PERC(t2,t3),                    \
         t3 < t2 ? "faster" : "slower")

void perf_allowed_id(void) {
  uint64_t begin, end;

  DO_LOOP(t1, u8ident_roar_is_allowed(cp));
  DO_LOOP(t2, range_bool_search(cp, allowed_id_list, ARRAY_SIZE(allowed_id_list)));
  DO_LOOP(t3, range_bool_search_hybr(cp, allowed_id_list, ARRAY_SIZE(allowed_id_list)));

  RESULT("allowed_id", t1,t2,t3);
}

void perf_mark(void) {
  uint64_t begin, end;

  DO_LOOP(t1, u8ident_roar_is_mark(cp));
  DO_LOOP(t2, range_bool_search(cp, mark_list, ARRAY_SIZE(mark_list)));
  DO_LOOP(t3, range_bool_search_hybr(cp, allowed_id_list, ARRAY_SIZE(mark_list)));

  RESULT("mark", t1,t2,t3);
}

void perf_nfkc(void) {
  uint64_t begin, end;
#undef NFKC
  DO_LOOP(t1, u8ident_roar_maybe_nfkc(cp));
  DO_LOOP_NM(t2, range_bool_search, NFKC);
  DO_LOOP_NM(t3, range_bool_search_hybr, NFKC);

  RESULT("nfkc", t1,t2,t3);
}

void perf_nfc(void) {
  uint64_t begin, end;
#undef NFC
  DO_LOOP(t1, u8ident_roar_maybe_nfc(cp));
  DO_LOOP_NM(t2, range_bool_search, NFC);
  DO_LOOP_NM(t3, range_bool_search_hybr, NFC);

  RESULT("nfc", t1,t2,t3);
}

void perf_nfkd(void) {
  uint64_t begin, end;
#undef NFKD
  DO_LOOP(t1, u8ident_roar_maybe_nfkd(cp));
  DO_LOOP(t2, range_bool_search(cp, NFKD_N_list, ARRAY_SIZE(NFKD_N_list)));
  DO_LOOP(t3, range_bool_search_hybr(cp, NFKD_N_list, ARRAY_SIZE(NFKD_N_list)));

  RESULT("nfkd", t1,t2,t3);
}

void perf_nfd(void) {
  uint64_t begin, end;
#undef NFD
  DO_LOOP(t1, u8ident_roar_maybe_nfd(cp));
  DO_LOOP(t2, range_bool_search(cp, NFD_N_list, ARRAY_SIZE(NFD_N_list)));
  DO_LOOP(t3, range_bool_search_hybr(cp, NFD_N_list, ARRAY_SIZE(NFD_N_list)));

  RESULT("nfd", t1,t2,t3);
}

int main(void) {
  u8ident_roar_init();
  perf_confus();
  printf("\n%-10s| %-8s | %-8s | %-8s |\n", "", "croaring", "bsearch", "hybrid");
  perf_allowed_id();
  perf_mark();
  perf_nfkd();
  perf_nfd();
  perf_nfkc();
  perf_nfc();
  u8ident_roar_free();
}
