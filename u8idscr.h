#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "u8id_private.h"
#define EXT_SCRIPTS
#include "scripts.h"

uint32_t dec_utf8(char **strp);
bool u8ident_has_script(const uint8_t scr);
bool u8ident_has_script_ctx(const uint8_t scr, const struct ctx_t *ctx);
int u8ident_add_script_ctx(const uint8_t scr, struct ctx_t *ctx);
struct ctx_t *u8ident_ctx(void);
uint8_t u8ident_get_script(const uint32_t cp);
/* list of script indices */
const char *u8ident_get_scx(const uint32_t cp);
bool u8ident_is_allowed(const uint32_t cp);
// bitmask of u8id_idtypes
uint16_t u8ident_get_idtypes(const uint32_t cp);
const char *u8ident_script_name(const int scr);
//bool u8ident_is_decomposed(const uint32_t cp, const uint8_t scr);
bool u8ident_maybe_normalized(const uint32_t cp);
