// SPDX-License-Identifier: LGPL-2.1-or-later
// Simplified public API header for libu8ident_c (TR39 amalgam)
#ifndef _U8IDENT_C_H
#define _U8IDENT_C_H

#include <stdint.h>
#include <stdbool.h>

#define U8ID_TR31 3

#if __GNUC__ >= 3
#ifndef likely
#define likely(expr) __builtin_expect((long)((expr) != 0), 1)
#define unlikely(expr) __builtin_expect((long)((expr) != 0), 0)
#endif
#else
#ifndef likely
#define likely(expr) (expr)
#define unlikely(expr) (expr)
#endif
#endif

#define ARRAY_SIZE(x) sizeof(x) / sizeof(*x)
#define strEQc(s1, s2) !strcmp((s1), s2 "")

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

typedef unsigned u8id_ctx_t;

enum u8id_errors {
    U8ID_EOK = 0,             /* valid without need to normalize */
    U8ID_EOK_NORM = 1,        /* valid with need to normalize */
    U8ID_EOK_WARN_CONFUS = 2, /* warn about confusable */
    U8ID_EOK_NORM_WARN_CONFUS =
        3,                  /* warn about confusable and need to normalize */
    U8ID_ERR_XID = -1,      /* invalid xid, disallowed via IdentifierStatus.txt */
    U8ID_ERR_SCRIPT = -2,   /* invalid script */
    U8ID_ERR_SCRIPTS = -3,  /* invalid mixed scripts */
    U8ID_ERR_ENCODING = -4, /* invalid encoding */
    U8ID_ERR_COMBINE = -5,  /* invalid combination of codepoints */
    U8ID_ERR_CONFUS = -6,   /* invalid because confusable */
};

enum u8id_norm {
    U8ID_NFC = 0,
    U8ID_NFD = 1,
    U8ID_NFKC = 2,
    U8ID_NFKD = 3,
    U8ID_FCD = 4,
    U8ID_FCC = 5
};

#undef U8ID_PROFILE_TR39
enum u8id_profile {
    U8ID_PROFILE_1 = 1,
    U8ID_PROFILE_2 = 2,
    U8ID_PROFILE_3 = 3,
    U8ID_PROFILE_4 = 4,
    U8ID_PROFILE_5 = 5,
    U8ID_PROFILE_6 = 6,
    U8ID_PROFILE_TR39 = 7,
    U8ID_PROFILE_TR39_4 = 8,
    U8ID_PROFILE_C11 = 9,
    U8ID_PROFILE_C11_6 = 10
};

enum u8id_options {
    U8ID_TR31_XID = 0,
    U8ID_TR31_ID = 1,
    U8ID_TR31_ALLOWED = 2,
    U8ID_TR31_TR39 = 3,
    U8ID_TR31_C23 = 4,
    U8ID_TR31_C11 = 5,
    U8ID_TR31_ALLUTF8 = 6,
    U8ID_TR31_ASCII = 7,
};

#define U8ID_TR31_DEFAULT U8ID_TR31_TR39
#define U8ID_TR31_MASK 0x7F
#define U8ID_NORM_DEFAULT U8ID_NFC
#define U8ID_PROFILE_DEFAULT U8ID_PROFILE_TR39_4

extern int u8ident_init(enum u8id_profile profile, enum u8id_norm norm,
                        unsigned options);
extern enum u8id_norm u8ident_norm(void);
extern enum u8id_profile u8ident_profile(void);
extern enum u8id_options u8ident_tr31(void);
extern void u8ident_set_maxlength(unsigned maxlen);
extern unsigned u8ident_maxlength(void);
extern u8id_ctx_t u8ident_new_ctx(void);
extern int u8ident_set_ctx(u8id_ctx_t i);
extern int u8ident_add_script(uint8_t script);
extern int u8ident_free_ctx(u8id_ctx_t ctx);
extern void u8ident_free(void);
extern enum u8id_errors u8ident_check_buf(const char *buf, const int len,
                                          char **outnorm);
extern enum u8id_errors u8ident_check(const uint8_t *string, char **outnorm);
extern uint32_t u8ident_failed_char(const u8id_ctx_t ctx);
extern const char *u8ident_failed_script_name(const u8id_ctx_t ctx);
extern const char *u8ident_existing_scripts(const u8id_ctx_t ctx);
extern uint8_t u8ident_get_script(const uint32_t cp);
extern const char *u8ident_script_name(const int scr);
extern char *u8ident_normalize(const char *src, int srcsz);

#endif /* _U8IDENT_C_H */
