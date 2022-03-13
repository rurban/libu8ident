#ifndef _U8IDSCR_H
#define _U8IDSCR_H

#include <stdint.h>
#include <stdbool.h>
#include "u8id_private.h"
#define EXTERN_SCRIPTS
#include "u8id_gc.h"
#include "scripts.h"

bool u8ident_has_script(const uint8_t scr);
bool u8ident_has_script_ctx(const uint8_t scr, const struct ctx_t *ctx);
int u8ident_add_script_ctx(const uint8_t scr, struct ctx_t *ctx);
struct ctx_t *u8ident_ctx(void);
uint8_t u8ident_get_script(const uint32_t cp);
/* list of script indices */
const struct scx *u8ident_get_scx(const uint32_t cp);
/* search for safec23 XID entry, in start or cont lists */
const struct sc_c23 *u8ident_get_safec23(const uint32_t cp);
bool u8ident_is_MARK(const uint32_t cp);
bool u8ident_is_MEDIAL(const uint32_t cp);
// member or bidi formatting characters for reordering attacks.
// Only valid with RTL scripts, such as Hebrew and Arabic.
bool u8ident_is_bidi(const uint32_t cp);
// Greek letters confusable with Latin
bool u8ident_is_greek_latin_confus(const uint32_t cp);
// bitmask of u8id_idtypes
uint16_t u8ident_get_idtypes(const uint32_t cp);
const char *u8ident_script_name(const int scr);
// bool u8ident_is_decomposed(const uint32_t cp, const uint8_t scr);
bool u8ident_maybe_normalized(const uint32_t cp);

typedef bool func_tr31(const uint32_t cp);
struct func_tr31_s {
  func_tr31 *start;
  func_tr31 *cont;
};
bool isASCII_start(const uint32_t cp);
bool isASCII_cont(const uint32_t cp);
bool isALLOWED_start(const uint32_t cp);
bool isALLOWED_cont(const uint32_t cp);
bool isSAFEC26_start(const uint32_t cp);
bool isSAFEC26_cont(const uint32_t cp);
bool isID_start(const uint32_t cp);
bool isID_cont(const uint32_t cp);
bool isXID_start(const uint32_t cp);
bool isXID_cont(const uint32_t cp);
bool isC11_start(const uint32_t cp);
bool isC11_cont(const uint32_t cp);
bool isC23_start(const uint32_t cp);
bool isC23_cont(const uint32_t cp);
bool isALLUTF8_start(const uint32_t cp);
bool isALLUTF8_cont(const uint32_t cp);

enum u8id_gc u8ident_get_gc(const uint32_t cp);
const char *u8ident_gc_name(const enum u8id_gc);

#endif // _U8IDSCR_H
