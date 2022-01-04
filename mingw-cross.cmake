# from linux or a bsd:
# cmake . -DCMAKE_TOOLCHAIN_FILE=mingw-cross.cmake
# from windows: cmake . -G "MinGW Makefiles"
set(CMAKE_SYSTEM_NAME Windows)

set(TOOLCHAIN_PREFIX   x86_64-w64-mingw32)
set(CMAKE_C_COMPILER   ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH  /usr/${TOOLCHAIN_PREFIX})

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
