#pragma once
#include <stddef.h>
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

