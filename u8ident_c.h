/* libu8ident - C compiler integration header.
   Copyright 2022,2025 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   Simplified public API for the TR39 profile (libu8ident_c).
   No private headers needed — just include this and link.
*/
#ifndef _U8IDENT_C_H
#define _U8IDENT_C_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __GNUC__
#  define U8ID_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#  define U8ID_LIKELY(expr)   __builtin_expect(!!(expr), 1)
#else
#  define U8ID_UNLIKELY(expr) (expr)
#  define U8ID_LIKELY(expr)   (expr)
#endif

#define U8ID_TR31 3
#define U8ID_CTX_TRESH 5
#define U8ID_SCR_TRESH 8

#define unlikely U8ID_UNLIKELY
#define likely   U8ID_LIKELY

typedef unsigned u8id_ctx_t;

enum u8id_profile {
  U8ID_PROFILE_1 = 0,
  U8ID_PROFILE_TR39_4 = 8,
};

enum u8id_norm {
  U8ID_NFC = 0,
};

enum u8id_errors {
  U8ID_ERR_CONFUS = -6,
  U8ID_ERR_COMBINE = -5,
  U8ID_ERR_ENCODING = -4,
  U8ID_ERR_SCRIPTS = -3,
  U8ID_ERR_SCRIPT = -2,
  U8ID_ERR_XID = -1,
  U8ID_EOK = 0,
};

struct ctx_t {
  unsigned count;
  u8id_ctx_t id;
  uint32_t last_cp;
  uint8_t has_han : 1;
  uint8_t is_chinese : 1;
  uint8_t is_japanese : 1;
  uint8_t is_korean : 1;
  uint8_t is_rtl : 1;
  uint8_t scr8[U8ID_SCR_TRESH];
  uint8_t *u8p;
};

extern int u8ident_init(enum u8id_profile profile, enum u8id_norm norm,
                        unsigned options);
extern u8id_ctx_t u8ident_new_ctx(void);
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

#endif /* _U8IDENT_C_H */
