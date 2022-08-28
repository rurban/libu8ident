/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   use roaring bitmaps for some sets.
*/

#include "u8id_private.h"
#include <stdbool.h>
int u8ident_roar_init(void);
int u8ident_roar_free(void);
EXTERN bool u8ident_is_confusable(const uint32_t cp);

#ifdef USE_ALLOWED_CROAR
bool u8ident_roar_is_allowed(const uint32_t cp);
#endif

#ifdef USE_MARK_CROAR
bool u8ident_roar_is_mark(const uint32_t cp);
#endif

#ifdef USE_NORM_CROAR
bool u8ident_roar_maybe_nfkc(const uint32_t cp);
bool u8ident_roar_maybe_nfc(const uint32_t cp);
bool u8ident_roar_maybe_nfkd(const uint32_t cp);
bool u8ident_roar_maybe_nfd(const uint32_t cp);
#endif
