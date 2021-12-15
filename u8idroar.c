/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   use roaring bitmaps for some sets.
*/
#include "config.h"
#ifdef HAVE_CROARING

#  include <stdio.h>
#  include <stdint.h>
#  include <stdbool.h>
#  include "u8id_private.h"
#  include "roaring.c"
#  include "confus_croar.h"
#  include "allowed_croar.h"

static roaring_bitmap_t *ra = NULL, *rc = NULL;

int u8ident_roar_init(void) {
  if (!rc)
    rc = roaring_bitmap_portable_deserialize_safe((char *)confus_croar_bin,
                                                  confus_croar_bin_len);
  if (!ra)
    ra = roaring_bitmap_portable_deserialize_safe((char *)allowed_croar_bin,
                                                  allowed_croar_bin_len);
  return (rc && ra) ? 0 : -1;
}

void u8ident_roar_free(void) {
  if (rc)
    roaring_bitmap_free(rc);
  if (ra)
    roaring_bitmap_free(ra);
  rc = NULL;
  ra = NULL;
}

bool u8ident_roar_is_allowed(const uint32_t cp) {
  return roaring_bitmap_contains(ra, cp);
}

EXTERN bool u8ident_is_confusable(const uint32_t cp) {
  return roaring_bitmap_contains(rc, cp);
}

#endif
