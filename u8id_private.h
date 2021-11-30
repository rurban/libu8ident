#pragma once
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

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

struct ctx_t {
  uint8_t count;
  union {
    uint64_t scr64;   // room for 8 scripts
    uint8_t  scr8[8];
    uint8_t  *u8p;    // or if count > 8 
  };
};
