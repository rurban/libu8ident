#!/bin/sh
make clean
echo "check -UU8ID_NORM -UU8ID_PROFILE"
./configure && make check
make check-asan
make clean
for norm in NFKC NFC NFKD NFD FCC FCD; do
    for profile in 2 3 4 5 6; do
        echo "check -DU8ID_NORM=$norm -DU8ID_PROFILE=$profile"
        ./configure --with-norm=$norm --with-profile=$profile && make check
        make check-asan
        make clean
    done
done

