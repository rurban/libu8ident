#include <assert.h>
int main() {
  int a = 2; // which is which?
  int а = 3;
  assert(a == 2);  // OK
  assert(а == 3);  // OK
  return 0;
}
