#pragma once
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#define EXTERN extern

#if __GNUC__ >= 3
#  define _expect(expr, value) __builtin_expect((expr), (value))
#  define INLINE static inline
#else
#  define _expect(expr, value) (expr)
#  define INLINE static
#endif
#ifndef likely
#  define likely(expr) _expect((long)((expr) != 0), 1)
#  define unlikely(expr) _expect((long)((expr) != 0), 0)
#endif

#define NFKC 0
#define NFD 1
#define NFC 2
#define NFKD 3
#define FCD 4
#define FCC 5
#define _XSTR(s) _STR(s)
#define _STR(s) #s

#ifdef U8ID_NORM
#  if U8ID_NORM == NFKC
#    define U8ID_NORM_DEFAULT U8ID_NFKC
#  elif U8ID_NORM == NFKD
#    define U8ID_NORM_DEFAULT U8ID_NFKD
#  elif U8ID_NORM == NFD
#    define U8ID_NORM_DEFAULT U8ID_NFD
#  elif U8ID_NORM == NFC
#    define U8ID_NORM_DEFAULT U8ID_NFC
#  elif U8ID_NORM == FCC
#    define U8ID_NORM_DEFAULT U8ID_FCC
#  elif U8ID_NORM == FCD
#    define U8ID_NORM_DEFAULT U8ID_FCD
#  else
#    error "Invalid U8ID_NORM "_XSTR(U8ID_NORM)
#  endif
#else
#  define U8ID_NORM_DEFAULT U8ID_NFKC
#endif

#ifdef U8ID_PROFILE
#  if U8ID_PROFILE == 2
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_2
#  elif U8ID_PROFILE == 3
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_3
#  elif U8ID_PROFILE == 4
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_4
#  elif U8ID_PROFILE == 5
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_5
#  elif U8ID_PROFILE == 6
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_6
#  else
#    error "Invalid U8ID_PROFILE "_XSTR(U8ID_PROFILE)
#  endif
#else
// Moderately Restrictive
#  define U8ID_PROFILE_DEFAULT U8ID_PROFILE_4
#endif

#define U8ID_CTX_TRESH 5
#define U8ID_SCR_TRESH 8
struct ctx_t {
  uint8_t count;
  uint8_t has_han : 1;
  uint8_t is_japanese : 1;
  uint8_t is_chinese : 1;
  uint8_t is_korean : 1;
  uint32_t last_cp; // only set on errors
  union {
    uint64_t scr64; // room for 8 scripts
    uint8_t scr8[U8ID_SCR_TRESH];
    // TODO check if we really need more than 8. Very unlikely.
    // Only if we manually add extra scripts.
    uint8_t *u8p; // or if count > 8
  };
};

// clang-format off
#if (defined(__GNUC__) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 480)
#  define GCC_DIAG_PRAGMA(x) _Pragma (#x)
#  define GCC_DIAG_IGNORE(x)                                                  \
    _Pragma ("GCC diagnostic push") GCC_DIAG_PRAGMA (GCC diagnostic ignored #x)
#  define GCC_DIAG_POP _Pragma ("GCC diagnostic pop")
#else
#  define GCC_DIAG_IGNORE(w)
#  define GCC_DIAG_POP
#endif
