#include <string.h>

int CHECK (const char *arg) {
  return strcmp(arg, "check") == 0;
}
int СНЕСК (const char *arg) {
  return strcmp(arg, "сhесk") == 0;
}

int main () {
  return СНЕСК("check");
}
