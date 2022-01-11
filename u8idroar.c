/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   use roaring bitmaps for some sets.
   Currently only confus_croar is faster than binary search in our ranges lists.
*/

#include "u8id_private.h"
#ifdef HAVE_CROARING
#  include <stdio.h>
#  include <stdbool.h>
#  include "roaring.c"
#  include "confus_croar.h"

static roaring_bitmap_t *rc = NULL;

#  ifdef USE_ALLOWED_CROAR
#    include "allowed_croar.h"
static roaring_bitmap_t *ra = NULL;
#  endif

#  ifdef USE_MARK_CROAR
#    define EXTERN_SCRIPTS
#    include "scripts.h"
#    undef EXTERN_SCRIPTS
#    include "mark.h"
static roaring_bitmap_t *rm = NULL;
#  endif

#  ifdef USE_NORM_CROAR
#    include "nfkc_croar.h"
#    include "nfc_croar.h"
#    include "nfkd_croar.h"
#    include "nfd_croar.h"
static roaring_bitmap_t *rnfkc_m = NULL;
static roaring_bitmap_t *rnfc_m = NULL;
static roaring_bitmap_t *rnfkc_n = NULL;
static roaring_bitmap_t *rnfc_n = NULL;
static roaring_bitmap_t *rnfkd_n = NULL;
static roaring_bitmap_t *rnfd_n = NULL;
#  endif

int u8ident_roar_init(void) {
  if (!rc) {
    rc = roaring_bitmap_portable_deserialize_safe((char *)confus_croar_bin,
                                                  confus_croar_bin_len);
    if (!rc)
      return -1;
  }

  // These are disabled by default. Only used by perf
#  ifdef USE_NORM_CROAR

#    define DEF_DESERIALIZE_SAFE(rn, n)                                        \
      if (!rn) {                                                               \
        rn = roaring_bitmap_portable_deserialize_safe(                         \
            (char *)JOIN(n, croar_bin), JOIN(n, croar_bin_len));               \
        if (!rn)                                                               \
          return -1;                                                           \
      }

  DEF_DESERIALIZE_SAFE(rnfkc_m, nfkc_m)
  DEF_DESERIALIZE_SAFE(rnfkc_n, nfkc_n)
  DEF_DESERIALIZE_SAFE(rnfc_m, nfc_m)
  DEF_DESERIALIZE_SAFE(rnfc_n, nfc_n)
  DEF_DESERIALIZE_SAFE(rnfkd_n, nfkc_n)
  DEF_DESERIALIZE_SAFE(rnfd_n, nfd_n)
#  endif
#  ifdef USE_ALLOWED_CROAR
  DEF_DESERIALIZE_SAFE(ra, allowed)
#  endif
#  ifdef USE_MARK_CROAR
  DEF_DESERIALIZE_SAFE(rm, mark)
#  endif
#  undef DEF_DESERIALIZE_SAFE
  return 0;
}

void u8ident_roar_free(void) {

#  define FREE_R(rc)                                                           \
    if (rc)                                                                    \
      roaring_bitmap_free(rc);                                                 \
    rc = NULL

  FREE_R(rc);

#  ifdef USE_ALLOWED_CROAR
  FREE_R(ra);
#  endif
#  ifdef USE_MARK_CROAR
  FREE_R(rm);
#  endif
#  ifdef USE_NORM_CROAR
  FREE_R(rnfkc_m);
  FREE_R(rnfkc_n);
  FREE_R(rnfc_m);
  FREE_R(rnfc_n);
  FREE_R(rnfkd_n);
  FREE_R(rnfd_n);
#  endif
#  undef FREE_R
}

EXTERN bool u8ident_is_confusable(const uint32_t cp) {
  return roaring_bitmap_contains(rc, cp);
}

#  ifdef USE_ALLOWED_CROAR
bool u8ident_roar_is_allowed(const uint32_t cp) {
  return roaring_bitmap_contains(ra, cp);
}
#  endif

#  ifdef USE_MARK_CROAR
bool u8ident_roar_is_mark(const uint32_t cp) {
  return roaring_bitmap_contains(rm, cp);
}
#  endif

#  ifdef USE_NORM_CROAR
bool u8ident_roar_maybe_nfkc(const uint32_t cp) {
  if (roaring_bitmap_contains(rnfkc_n, cp))
    return true;
  return roaring_bitmap_contains(rnfkc_m, cp);
}
bool u8ident_roar_maybe_nfc(const uint32_t cp) {
  if (roaring_bitmap_contains(rnfc_n, cp))
    return true;
  return roaring_bitmap_contains(rnfc_m, cp);
}
bool u8ident_roar_maybe_nfkd(const uint32_t cp) {
  return roaring_bitmap_contains(rnfkd_n, cp);
}
bool u8ident_roar_maybe_nfd(const uint32_t cp) {
  return roaring_bitmap_contains(rnfd_n, cp);
}
#  endif

#endif
