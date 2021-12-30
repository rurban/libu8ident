#include <stdio.h>
#define USER  0‮⁦
#define ADMIN 1
// RLO U+202E, LRE U+202A, PDI U+2069, LRI U+2066

int main() {
  int accessLevel = USER;
  if (accessLevel != USER‮⁦// Check if admin⁩⁦)
     printf("You are an admin.\n");
  return 0;
}
