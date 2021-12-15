/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   use roaring bitmaps for some sets.
*/
#include "config.h"

int u8ident_roar_init (void);
int u8ident_roar_free (void);
//bool u8ident_is_allowed(const uint32_t cp);
EXTERN bool u8ident_is_confusable(const uint32_t cp);
bool u8ident_roar_is_allowed(const uint32_t cp);
