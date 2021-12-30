#include <stdio.h>
#include <stdbool.h>
// RLO U+202E, LRE U+202A, PDI U+2069, LRI U+2066

int main() {
  bool isAdmin = false;
  /*‮ } ⁦if (isAdmin)⁩ ⁦ begin admins only */
     printf("You are an admin.\n");
  /* end admins only ‮ { ⁦*/
  return 0;
}
