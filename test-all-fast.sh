#!/bin/sh
set -e
make -f makefile.gnu clean
echo "check -UU8ID_NORM -UU8ID_PROFILE"
make -f makefile.gnu check
make -f makefile.gnu check-asan
make -f makefile.gnu clean
for norm in NFKC NFC NFKD NFD FCC FCD; do
    for profile in 2 3 4 5 6; do
        echo "check -DU8ID_NORM=$norm -DU8ID_PROFILE=$profile"
        make -f makefile.gnu check CFLAGS="-Wall -Wextra -O2 -DU8ID_NORM=$norm -DU8ID_PROFILE=$profile"
        make -f makefile.gnu check-asan CFLAGS="-Wall -Wextra -O2 -DU8ID_NORM=$norm -DU8ID_PROFILE=$profile"
        make -f makefile.gnu clean
    done
done

