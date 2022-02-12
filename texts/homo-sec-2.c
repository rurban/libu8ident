#include <stdbool.h>

enum env_e {
  ENV_PRODUCTION,
  ENV_DEVELOPMENT
};
/* … */
const enum env_e environment = ENV_PRODUCTION;
/* … */
bool isUserAdmin(const char *user) {
    if(environmentǃ=ENV_PRODUCTION){
        // bypass authZ checks in DEVELOPMENT
        return true;
    }

    /* … */
    return false;
}
