/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   generate roaring bitmaps for some sets.
*/

#include <stdio.h>
#include "roaring.c"
#include "u8id_private.h"
#include "u8id_gc.h"
#include "scripts.h"
#include "confus.h"
#include "mark.h"

enum what_list {
  ALLOWED_ID_LIST,
  CONFUSABLES,
  MARK,
  NFD_N,
  NFC_N,
  NFC_M,
  NFKD_N,
  NFKC_N,
  NFKC_M
};

int serialize(size_t size, const uint32_t *list, enum what_list what) {
  FILE *f;
  roaring_bitmap_t *rb = roaring_bitmap_create_with_capacity(size);
  roaring_statistics_t stat;
  const char *file;
  if (what == CONFUSABLES) { // simple uint32_t[]
    for (uint32_t i = 0; i < size; i++)
      roaring_bitmap_add(rb, list[i]);
  } else /* if (what == ALLOWED_ID_LIST) */ { // struct range_bool
    const struct range_bool *blist = (const struct range_bool *)list;
    for (uint32_t i = 0; i < size; i++) {
      for (uint32_t cp = blist[i].from; cp <= blist[i].to; cp++) {
        roaring_bitmap_add(rb, cp);
      }
    }
  }
  switch (what) {
  case ALLOWED_ID_LIST:
    file = "allowed_croar.bin";
    break;
  case CONFUSABLES:
    file = "confus_croar.bin";
    break;
  case MARK:
    file = "mark_croar.bin";
    break;
    /* NFD_N, NFC_N, NFC_M, NFKD_N, NFKC_N, NFKC_M */
  case NFD_N:
    file = "nfd_n_croar.bin";
    break;
  case NFC_N: // this might be slower than binary search
    file = "nfc_n_croar.bin";
    break;
  case NFC_M:
    file = "nfc_m_croar.bin";
    break;
  case NFKD_N:
    file = "nfkd_n_croar.bin";
    break;
  case NFKC_N:
    file = "nfkc_n_croar.bin";
    break;
  case NFKC_M:
    file = "nfkc_m_croar.bin";
    break;
  default:
    fprintf(stderr, "Unhandled case %d\n", what);
    exit(1);
  }

  f = fopen(file, "w");
  uint32_t sizebefore = roaring_bitmap_portable_size_in_bytes(rb);
  roaring_bitmap_run_optimize(rb);

  uint32_t sizeafter = roaring_bitmap_portable_size_in_bytes(rb);
  char *serializedbytes = malloc(sizeafter);
  roaring_bitmap_portable_serialize(rb, serializedbytes);
  fwrite(serializedbytes, 1, sizeafter, f);
  fclose(f);
  free(serializedbytes);
  printf("\nwrote %u serialized bytes to %s\n", sizeafter, file);

  printf("cardinality = %d\n", (int)roaring_bitmap_get_cardinality(rb));
  printf("size before/after optim: %u/%u\n", sizebefore, sizeafter);
  roaring_bitmap_statistics(rb, &stat);
  printf("n_bitset_containers = %u\n", stat.n_bitset_containers);
  printf("n_values_bitset_containers = %u\n", stat.n_values_bitset_containers);
  printf("n_bytes_bitset_containers = %u\n", stat.n_bytes_bitset_containers);
  printf("n_array_containers = %u\n", stat.n_array_containers);
  printf("n_values_array_containers = %u\n", stat.n_values_array_containers);
  printf("n_bytes_array_containers = %u\n", stat.n_bytes_array_containers);
  printf("n_run_containers = %u\n", stat.n_run_containers);
  printf("n_values_run_containers = %u\n", stat.n_values_run_containers);
  printf("n_bytes_run_containers = %u\n", stat.n_bytes_run_containers);
  roaring_bitmap_free(rb);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2 || strcmp(argv[1], "confus") == 0)
    serialize(ARRAY_SIZE(confusables), confusables, CONFUSABLES);
  if (argc > 1 && strcmp(argv[1], "confus") == 0)
    exit(0);

  if (argc < 2 || strcmp(argv[1], "mark") == 0)
    serialize(ARRAY_SIZE(mark_list), (const uint32_t *)mark_list, MARK);
  if (argc > 1 && strcmp(argv[1], "mark") == 0)
    exit(0);

  serialize(ARRAY_SIZE(allowed_id_list), (const uint32_t *)allowed_id_list,
            ALLOWED_ID_LIST);
  /* NFD_N, NFC_N, NFC_M, NFKD_N, NFKC_N, NFKC_M */
  serialize(ARRAY_SIZE(NFD_N_list), (const uint32_t *)NFD_N_list, NFD_N);
  serialize(ARRAY_SIZE(NFC_N_list), (const uint32_t *)NFC_N_list, NFC_N);
  serialize(ARRAY_SIZE(NFC_M_list), (const uint32_t *)NFC_M_list, NFC_M);
  serialize(ARRAY_SIZE(NFKD_N_list), (const uint32_t *)NFKD_N_list, NFKD_N);
  serialize(ARRAY_SIZE(NFKC_N_list), (const uint32_t *)NFKC_N_list, NFKC_N);
  serialize(ARRAY_SIZE(NFKC_M_list), (const uint32_t *)NFKC_M_list, NFKC_M);

  return 0;
}
