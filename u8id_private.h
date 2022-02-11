#ifndef _U8ID_PRIVATE_H
#define _U8ID_PRIVATE_H

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#if defined _WIN32 || defined __CYGWIN__
#  define EXTERN __declspec(dllexport)
#  define LOCAL
#elif __GNUC__ >= 4
#  define EXTERN __attribute__((visibility("default")))
#  define LOCAL __attribute__((visibility("hidden")))
#else
#  define EXTERN
#  define LOCAL
#endif

#ifndef PERF_TEST
// they are all too slow
#  undef USE_ALLOWED_CROAR
#  undef USE_MARK_CROAR
#  undef USE_NORM_CROAR
#else
#  define USE_ALLOWED_CROAR
#  define USE_MARK_CROAR
#  define USE_NORM_CROAR
#endif

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

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)
#define strEQ(s1, s2) !strcmp((s1), (s2))
#define strEQc(s1, s2) !strcmp((s1), s2 "")

#define NFC 0
#define NFD 1
#define NFKC 2
#define NFKD 3
#define FCD 4
#define FCC 5
#define C11_6 7
#define C26_4 8

// allowed set of identifiers. TR31 --xid tokenizer options
// we need XID, the default, as first for uninitialized options.
enum xid_e {
  XID, // ID plus NFKC quirks, labelled stable, the default
  ID,  // all letters, plus numbers, punctuation and marks. With exotic scripts.
  ALLOWED, // TR39 ID with only recommended scripts. Allowed IdentifierStatus.
  SAFEC26, // practical XID with TR39 security measures, see P2528R1
  C11,     // the stable insecure AltId ranges from the C11 standard, Annex D
  ALLUTF8, // all > 128, e.g. D, php, nim, crystal
  ASCII,   // only ASCII letters
};
#define XID 0
#define ID 1
#define ALLOWED 2
#define SAFEC26 3
#define C11 4
#define ALLUTF8 5
#define ASCII 6
#define NONE 7
#define FIRST_XID_E XID
#define LAST_XID_E ASCII

#define _XSTR(s) _STR(s)
#define _STR(s) #s
#define CAT(a, b) a##b
#define PASTE(a, b) CAT(a, b)
#define JOIN(prefix, name) PASTE(prefix, PASTE(_, name))

#ifdef U8ID_NORM
#  if U8ID_NORM == NFC
#    define U8ID_NORM_DEFAULT U8ID_NFC
#  elif U8ID_NORM == NFD
#    define U8ID_NORM_DEFAULT U8ID_NFD
#  elif U8ID_NORM == NFKD
#    define U8ID_NORM_DEFAULT U8ID_NFKD
#  elif U8ID_NORM == NFKC
#    define U8ID_NORM_DEFAULT U8ID_NFKC
#  elif U8ID_NORM == FCC
#    define U8ID_NORM_DEFAULT U8ID_FCC
#  elif U8ID_NORM == FCD
#    define U8ID_NORM_DEFAULT U8ID_FCD
#  else
#    error "Invalid U8ID_NORM "_XSTR(U8ID_NORM)
#  endif
#else
#  define U8ID_NORM_DEFAULT U8ID_NFC
#endif

#ifdef U8ID_PROFILE
#  if U8ID_PROFILE == 1
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_1
#  elif U8ID_PROFILE == 2
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_2
#  elif U8ID_PROFILE == 3
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_3
#  elif U8ID_PROFILE == 4
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_4
#  elif U8ID_PROFILE == 5
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_5
#  elif U8ID_PROFILE == 6
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_6
#  elif U8ID_PROFILE == C26_4
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_C26_4
#    define U8ID_PROFILE_SAFEC26
#  elif U8ID_PROFILE == C11_6
#    define U8ID_PROFILE_DEFAULT U8ID_PROFILE_C11_6
#    define U8ID_PROFILE_C11STD
#  else
#    error "Invalid U8ID_PROFILE "_XSTR(U8ID_PROFILE)
#  endif
#elif defined U8ID_PROFILE_SAFEC26
#  define U8ID_PROFILE_DEFAULT U8ID_PROFILE_C26_4
#  define U8ID_PROFILE C26_4
#elif defined U8ID_PROFILE_C11STD
#  define U8ID_PROFILE_DEFAULT U8ID_PROFILE_C11_6
#  define U8ID_PROFILE C11_6
#else
// Moderately Restrictive
#  define U8ID_PROFILE_DEFAULT U8ID_PROFILE_4
#endif

#ifdef DISABLE_U8ID_TR31
#  define DISABLE_CHECK_XID
#  define U8ID_TR31_DEFAULT 0
#  undef U8ID_TR31
#  undef ENABLE_CHECK_XID
#endif
#ifdef U8ID_TR31
//#  pragma message("U8ID_TR31=" _XSTR(U8ID_TR31))
#  if U8ID_TR31 == NONE
#    define DISABLE_CHECK_XID
#    define U8ID_TR31_DEFAULT 0
#  else
#    define ENABLE_CHECK_XID
#    if U8ID_TR31 == ALLOWED
#      define U8ID_TR31_DEFAULT U8ID_TR31_ALLOWED
#    elif U8ID_TR31 == ASCII
#      define U8ID_TR31_DEFAULT U8ID_TR31_ASCII
#    elif U8ID_TR31 == SAFEC26
#      define U8ID_TR31_DEFAULT U8ID_TR31_SAFEC26
#    elif U8ID_TR31 == ID
#      define U8ID_TR31_DEFAULT U8ID_TR31_ID
#    elif U8ID_TR31 == XID
#      define U8ID_TR31_DEFAULT U8ID_TR31_XID
#    elif U8ID_TR31 == C11
#      define U8ID_TR31_DEFAULT U8ID_TR31_C11
#    elif U8ID_TR31 == ALLUTF8
#      define U8ID_TR31_DEFAULT U8ID_TR31_ALLUTF8
#    endif
#  endif
#else
#  define U8ID_TR31_DEFAULT U8ID_TR31_XID
#endif

#define U8ID_CTX_TRESH 5
#define U8ID_SCR_TRESH 8
struct ctx_t {
  uint8_t count;
  uint8_t has_han : 1;
  uint8_t is_japanese : 1;
  uint8_t is_chinese : 1;
  uint8_t is_korean : 1;
  uint8_t is_rtl : 1; // Hebrew or Arabic
  uint32_t last_cp;   // only set on errors
  union {
    uint64_t scr64; // room for 8 scripts
    uint8_t scr8[U8ID_SCR_TRESH];
    // we need more than 8 only with insecure
    // profiles, or when we manually add extra scripts.
    uint8_t *u8p; // or if count > 8
  };
};

// clang-format off
#if (defined(__GNUC__) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 480)
#  define GCC_DIAG_PRAGMA(x) _Pragma (#x)
#  define GCC_DIAG_IGNORE(x)                                                  \
    GCC_DIAG_PRAGMA (GCC diagnostic ignored #x)
#else
#  define GCC_DIAG_IGNORE(w)
#endif

LOCAL enum u8id_norm u8ident_norm(void);
LOCAL enum u8id_profile u8ident_profile(void);
LOCAL enum u8id_options u8ident_tr31(void);
LOCAL unsigned u8ident_options(void);
LOCAL unsigned u8ident_maxlength(void);
LOCAL const char *u8ident_errstr(int errcode);
// from u8idnorm.c
LOCAL uint32_t dec_utf8(char **strp);
LOCAL char *enc_utf8(char *dest, size_t *lenp, const uint32_t cp);

#endif // _U8ID_PRIVATE_H
