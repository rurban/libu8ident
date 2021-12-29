#include <assert.h>
int main() {
  int Café = 1;      // with Mn. Cafe\u0301 is not in NFC -Wnormalized
  assert(Café == 1); // Caf\u00e9 without Mn, same NFC
  return 0;
}
