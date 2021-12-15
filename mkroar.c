/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2021 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   generate roaring bitmaps for some sets.
*/

#include <stdio.h>
#include "roaring.c"
#include "scripts.h"
#include "confus.h"

#define ARR_SIZE(x) sizeof(x) / sizeof(*x)
enum what_list {
  ALLOWED_ID_LIST,
  CONFUSABLES
};

int serialize(size_t size, const uint32_t *list, enum what_list what) {
  FILE *f;
  roaring_bitmap_t *rb = roaring_bitmap_create_with_capacity(size);
  roaring_statistics_t stat;
  const char *file;
  if (what == CONFUSABLES) { // simple confusables uint32_t confusable[]
    for (uint32_t i = 0; i < size; i++)
      roaring_bitmap_add(rb, list[i]);
    file = "confus_croar.bin";
  } else if (what == ALLOWED_ID_LIST) { // struct range_bool allowed_id_list[]
    const struct range_bool *blist = (const struct range_bool *)list;;
    for (uint32_t i = 0; i < size; i++) {
      for (uint32_t cp = blist[i].from; cp <= blist[i].to; cp++) {
        roaring_bitmap_add(rb, cp);
      }
    }
    file = "allowed_croar.bin";
  }
  f = fopen(file, "w");
  uint32_t sizebefore = roaring_bitmap_portable_size_in_bytes(rb);
  roaring_bitmap_run_optimize(rb);

  uint32_t sizeafter = roaring_bitmap_portable_size_in_bytes(rb);
  char *serializedbytes = malloc(sizeafter);
  roaring_bitmap_portable_serialize(rb, serializedbytes);
  fwrite(serializedbytes, 1, sizeafter, f);
  fclose(f);
  free (serializedbytes);
  printf("\nwrote %u serialized bytes to %s\n", sizeafter, file);

  printf("cardinality = %d\n", (int) roaring_bitmap_get_cardinality(rb));
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

int main() {
  serialize(ARR_SIZE(allowed_id_list), (const uint32_t *)allowed_id_list, ALLOWED_ID_LIST);
  serialize(ARR_SIZE(confusables), confusables, CONFUSABLES);
  return 0;
}
