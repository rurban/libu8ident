/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   Measure binary_search in array vs croaring for confusables[] and
   some range_bool sets, like allowed_id_list[] and the NORM lists.
   croaring is 10-100% faster only for confusables,
   and 70-100% slower for the range_bool sets.

   confus:
   croaring: 351442	bsearch: 517036          47.12% faster
   nfkd:
   croaring: 3193632	bsearch: 1829178 	 74.59% slower
   nfd:
   croaring: 3376412	bsearch: 1876160 	 79.96% slower
   nfkc:
   croaring: 4980066	bsearch: 3699228 	 34.62% slower
   nfc:
   croaring: 4497194	bsearch: 2139826 	 110.17% slower
   allowed_id:
   croaring: 4333056	bsearch: 2439034         77.65% slower

   with the scripts1.h variant: (first search range, then singles, see branch scripts1)
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

static inline bool range_bool_search(const uint32_t cp,
                                     const struct range_bool *list,
                                     const size_t len) {
  const char *r = (char *)binary_search(cp, (char *)list, len, sizeof(*list));
  return r ? true : false;
}

// without croaring
static int compar32(const void *a, const void *b) {
  const uint32_t ai = *(const uint32_t *)a;
  const uint32_t bi = *(const uint32_t *)b;
  return ai < bi ? -1 : ai == bi ? 0 : 1;
}

void perf_confus(void) {
  printf("confus:\n");
  uint64_t begin = timer_start();
  for (size_t i = 0; i < ARRAY_SIZE(confusables); i++) {
    const uint32_t cp = confusables[i];
    bool ret = u8ident_is_confusable(cp);
    gret |= ret;
  }
  uint64_t end = timer_end();
  uint64_t t1 = end - begin;

  begin = timer_start();
  for (size_t i = 0; i < ARRAY_SIZE(confusables); i++) {
    const uint32_t cp = confusables[i];
    void *ret =
        bsearch(&cp, confusables, ARRAY_SIZE(confusables), 4, compar32);
    gret |= ret ? true : false;
  }
  end = timer_end();
  uint64_t t2 = end - begin;
  if (t1 < t2)
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% faster\n", t1, t2,
           100.0 * (t2 - t1) / (double)t1);
  else
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% slower\n", t1, t2,
           100.0 * (t1 - t2) / (double)t2);
}

void perf_nfkc(void) {
  printf("nfkc:\n");
  uint64_t begin = timer_start();
  for (uint32_t cp = 128; cp < 0x11000; cp++) {
    gret |= u8ident_roar_maybe_nfkc(cp);
  }
  uint64_t end = timer_end();
  uint64_t t1 = end - begin;

  begin = timer_start();
  for (uint32_t cp = 128; cp < 0x11000; cp++) {
    bool ret;
    if (range_bool_search(cp, NFKC_N_list, ARRAY_SIZE(NFKC_N_list)))
      ret = true;
    else
      ret = range_bool_search(cp, NFKC_M_list, ARRAY_SIZE(NFKC_M_list));
    gret |= ret;
  }
  end = timer_end();
  uint64_t t2 = end - begin;
  if (t1 < t2)
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% faster\n", t1, t2,
           100.0 * (t2 - t1) / (double)t1);
  else
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% slower\n", t1, t2,
           100.0 * (t1 - t2) / (double)t2);
}

void perf_nfc(void) {
  printf("nfc:\n");
  uint64_t begin = timer_start();
  for (uint32_t cp = 128; cp < 0x11000; cp++) {
    bool ret = u8ident_roar_maybe_nfc(cp);
    gret |= ret;
  }
  uint64_t end = timer_end();
  uint64_t t1 = end - begin;

  begin = timer_start();
  for (uint32_t cp = 128; cp < 0x11000; cp++) {
    bool ret;
    if (range_bool_search(cp, NFC_N_list, ARRAY_SIZE(NFC_N_list)))
      ret = true;
    else
      ret = range_bool_search(cp, NFC_M_list, ARRAY_SIZE(NFC_M_list));
    gret |= ret;
  }
  end = timer_end();
  uint64_t t2 = end - begin;
  if (t1 < t2)
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% faster\n", t1, t2,
           100.0 * (t2 - t1) / (double)t1);
  else
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% slower\n", t1, t2,
           100.0 * (t1 - t2) / (double)t2);
}

void perf_nfkd(void) {
  printf("nfkd:\n");
  uint64_t begin = timer_start();
  for (uint32_t cp = 128; cp < 0x11000; cp++) {
    bool ret = u8ident_roar_maybe_nfkd(cp);
    gret |= ret;
  }
  uint64_t end = timer_end();
  uint64_t t1 = end - begin;

  begin = timer_start();
  for (uint32_t cp = 128; cp < 0x11000; cp++) {
    bool ret = range_bool_search(cp, NFKD_N_list, ARRAY_SIZE(NFKD_N_list));
    gret |= ret;
  }
  end = timer_end();
  uint64_t t2 = end - begin;
  if (t1 < t2)
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% faster\n", t1, t2,
           100.0 * (t2 - t1) / (double)t1);
  else
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% slower\n", t1, t2,
           100.0 * (t1 - t2) / (double)t2);
}

void perf_nfd(void) {
  printf("nfd:\n");
  uint64_t begin = timer_start();
  for (uint32_t cp = 128; cp < 0x11000; cp++) {
    bool ret = u8ident_roar_maybe_nfd(cp);
    gret |= ret;
  }
  uint64_t end = timer_end();
  uint64_t t1 = end - begin;

  begin = timer_start();
  for (uint32_t cp = 128; cp < 0x11000; cp++) {
    bool ret = range_bool_search(cp, NFD_N_list, ARRAY_SIZE(NFD_N_list));
    gret |= ret;
  }
  end = timer_end();
  uint64_t t2 = end - begin;
  if (t1 < t2)
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% faster\n", t1, t2,
           100.0 * (t2 - t1) / (double)t1);
  else
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% slower\n", t1, t2,
           100.0 * (t1 - t2) / (double)t2);
}

void perf_allowed_id(void) {
  printf("allowed_id:\n");
  uint64_t begin = timer_start();
  for (size_t i = 0; i < ARRAY_SIZE(allowed_id_list); i++) {
    for (uint32_t cp = allowed_id_list[i].from; cp <= allowed_id_list[i].to;
         cp++) {
      bool ret = u8ident_roar_is_allowed(cp);
      gret |= ret;
    }
  }
  uint64_t end = timer_end();
  uint64_t t1 = end - begin;

  begin = timer_start();
  for (size_t i = 0; i < ARRAY_SIZE(allowed_id_list); i++) {
    for (uint32_t cp = allowed_id_list[i].from; cp <= allowed_id_list[i].to;
         cp++) {
      bool ret =
          range_bool_search(cp, allowed_id_list,
                            sizeof(allowed_id_list) / sizeof(*allowed_id_list));
      gret |= ret;
    }
  }
  end = timer_end();
  uint64_t t2 = end - begin;
  if (t1 < t2)
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% faster\n", t1, t2,
           100.0 * (t2 - t1) / (double)t1);
  else
    printf("croaring: %lu\tbsearch: %lu \t %0.2f%% slower\n", t1, t2,
           100.0 * (t1 - t2) / (double)t2);
}

int main(void) {
  u8ident_roar_init();
  perf_confus();
  perf_nfkd();
  perf_nfd();
  perf_nfkc();
  perf_nfc();
  perf_allowed_id();
  u8ident_roar_free();
}
