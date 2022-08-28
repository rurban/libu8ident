/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

   A simple open-addressing string hash table for the confusables check.
   No deletions needed.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "htable.h"

struct htable * new_htab(unsigned cap) {
  struct htable *ht = malloc(sizeof(struct htable));
  assert(cap % 2 == 0);
  ht->keys = calloc(cap, sizeof(char*));
  ht->values = calloc(cap, sizeof(char*));
  ht->cap = cap;
  ht->size = 0;
  return ht;
}

void free_htab(struct htable *htab) {
  for (unsigned i=0; i < htab->cap; i++) {
    if (htab->keys[i]) {
      free(htab->keys[i]);
      free(htab->values[i]);
    }
  }
  free(htab->keys);
  free(htab->values);
  htab->cap = htab->size = 0;
  return;
}

static inline float fill_htab(struct htable *htab) {
  return htab->size / htab->cap;
}

static inline uint32_t hash(const char *key) {
  uint32_t h = 2166136261;
  uint8_t *p = (uint8_t *)key;
  uint8_t c;
  while ((c = *p++)) {
    h ^= c;
    h *= 16777619;
  }
  return h;
}

void add_htab(struct htable *htab, const char *key, const char *value) {
  assert(htab);
  uint32_t h = hash(key) & (htab->cap - 1);
  uint32_t oh = h;
  assert(key);
  if (fill_htab(htab) > 0.75f) {
    struct htable *ht2;
  resize:
    ht2 = new_htab(htab->cap * 2);
    //fprintf(stderr, "resize %p[%lu] to %lu\n", htab, htab->size, htab->cap * 2);
    for (unsigned i=0; i < htab->cap; i++) {
      if (htab->keys[h]) {
        add_htab(ht2, htab->keys[h], htab->values[h]);
      }
    }
    free_htab(htab);
    memcpy(htab, ht2, sizeof *htab); // copy all over, and start again.
    free(ht2);
    oh = h = hash(key) & (htab->cap - 1);
  }
  while (htab->keys[h] && strcmp(htab->keys[h], key)) { // not found
    h++;
    if (h >= htab->cap) // wraparound
      h = 0;
    if (h == oh)
      goto resize;
  }
  if (!htab->keys[h]) { // found a free slot
    //fprintf(stderr, "add %s key to %p[%lu]\n", key, htab, htab->size+1);
    htab->keys[h] = strdup(key);
    htab->values[h] = strdup(value);
    htab->size++;
  } // else already exists, ignore
  return;
}

char * find_htab(struct htable *htab, const char *key) {
  assert(htab);
  if (!htab->size)
    return false;
  uint32_t h = hash(key) & (htab->cap - 1);
  const uint32_t oh = h;
  assert(key);
  while (htab->keys[h] && strcmp(htab->keys[h], key)) { // not found
    h++;
    if (h >= htab->cap) // wraparound
      h = 0;
    if (h == oh)
      return false;
  }
  //if (htab->keys[h])
  //  fprintf(stderr, "find %s -> %s in %p[%lu]\n", htab->keys[h], htab->values[h], htab, htab->size);
  return htab->keys[h] ? htab->values[h] : NULL;
}
