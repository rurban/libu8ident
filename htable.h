/* libu8ident - Check unicode security guidelines for identifiers.
   Copyright 2022 Reini Urban
   SPDX-License-Identifier: Apache-2.0

   A simple open-addressing string hash table for the confusables check.
   No deletion needed.
*/

#pragma once
#include <stdbool.h>
#include <stddef.h>

struct htable {
  unsigned size;
  unsigned cap;
  char **keys;
  char **values;
};

struct htable * new_htab(unsigned cap);
void free_htab(struct htable *htab);
// adds a copy to the htable
void add_htab(struct htable *htab, const char *key, const char *value);
// return value
char * find_htab(struct htable *htab, const char *key);
