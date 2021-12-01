#pragma once
#include "config.h"
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#define EXTERN extern

#if __GNUC__ >= 3
#define _expect(expr, value) __builtin_expect((expr), (value))
#define INLINE static inline
#else
#define _expect(expr, value) (expr)
#define INLINE static
#endif
#ifndef likely
#define likely(expr) _expect((long)((expr) != 0), 1)
#define unlikely(expr) _expect((long)((expr) != 0), 0)
#endif

#define U8ID_CTX_TRESH 5
#define U8ID_SCR_TRESH 8
struct ctx_t {
  uint8_t count;
  uint8_t is_japanese :1;
  uint8_t is_chinese :1;
  uint8_t is_korean :1;
  uint8_t has_han :1;
  uint32_t last_cp; // only set on errors
  union {
    uint64_t scr64;   // room for 8 scripts
    uint8_t  scr8[U8ID_SCR_TRESH];
    uint8_t  *u8p;    // or if count > 8 
  };
};
