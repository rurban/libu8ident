project(libu8ident C)
cmake_minimum_required(VERSION 2.9)
# Supported options -DU8ID_NORM=NFC,NFKC,NFD,NFKD
#                   -DU8ID_PROFILE=2,3,4,5,6,C11_4,C11_6
#                   -DU8ID_CHECK_XID=On,Off
# for smaller builds and lib.

if(MSVC)
    # Disable some overly strict MSVC warnings.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -wd4244 -wd4800 -wd4805 -D_CRT_SECURE_NO_WARNINGS")
endif()

if (EXISTS ".version")
    file(READ .version NL_PACKAGE_VERSION)
else()
    find_package(Git)
    set(PACKAGE_VERSION "")
    execute_process(COMMAND ${GIT_EXECUTABLE} describe --long --tags --always
                    OUTPUT_VARIABLE NL_PACKAGE_VERSION)
endif()
string(STRIP "${NL_PACKAGE_VERSION}" PACKAGE_VERSION)

include(CheckIncludeFile)
CHECK_INCLUDE_FILE("dlfcn.h" HAVE_DLFCN_H)
CHECK_INCLUDE_FILE("dirent.h" HAVE_DIRENT_H)
CHECK_INCLUDE_FILE("getopt.h" HAVE_GETOPT_H)
CHECK_INCLUDE_FILE("inttypes.h" HAVE_INTTYPES_H)
CHECK_INCLUDE_FILE("malloc.h" HAVE_MALLOC_H)
CHECK_INCLUDE_FILE("memory.h" HAVE_MEMORY_H)
CHECK_INCLUDE_FILE("stdbool.h" HAVE_STDBOOL_H)
CHECK_INCLUDE_FILE("stddef.h" HAVE_STDDEF_H)
CHECK_INCLUDE_FILE("stdint.h" HAVE_STDINT_H)
CHECK_INCLUDE_FILE("stdlib.h" HAVE_STDLIB_H)
CHECK_INCLUDE_FILE("string.h" HAVE_STRING_H)
CHECK_INCLUDE_FILE("strings.h" HAVE_STRINGS_H)
CHECK_INCLUDE_FILE("sys/stat.h" HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILE("sys/types.h" HAVE_SYS_TYPES_H)
include(CheckFunctionExists)
check_function_exists(getopt_long HAVE_GETOPT_LONG)
include(CheckCSourceCompiles)
# Returns one plus the index of the least significant 1-bit of x, or if x is zero, returns zero.
check_c_source_compiles("
int main() { (void)__builtin_ffs(0); return 0; }
" HAVE___BUILTIN_FFS)
#check_function_exists(__builtin_ffs HAVE___BUILTIN_FFS)
#check_function_exists(strcmp HAVE_STRCMP)
#check_function_exists(strcasestr HAVE_STRCASESTR)
include(CheckTypeSize)
check_type_size(size_t SIZE_T)
#check_type_size(wchar_t WCHAR_T)
#include(CheckCCompilerFlag)
configure_file(cmakeconfig.h.in config.h)
if(CMAKE_MAJOR_VERSION GREATER 2)
  include(TestBigEndian)
  test_big_endian(IS_BIG_ENDIAN)
  if(IS_BIG_ENDIAN)
    message(ERROR "Big Endian not supported: <${error}>")
    add_definitions(-DBIG_ENDIAN)
  endif()
endif()
add_definitions(-DHAVE_CONFIG_H)

# Supported options:
#  -DBUILD_SHARED_LIBS=ON,OFF
#  -DLIBU8IDENT_NORM=NFC,NFKC,NFD,NFKD
#  -DLIBU8IDENT_PROFILE=2,3,4,5,6,C23_4,C11_6
#  -DENABLE_CHECK_XID=On
#  -DDISABLE_CHECK_XID=On
#  -DHAVE_CONFUS=ON
#  -DHAVE_CROARING=ON
option(BUILD_SHARED_LIBS "shared libu8ident library" ON)
option(LIBU8IDENT_NORM "force a single normalization: NFC,NFKC,NFD,NFKD,FCC,FCD" OFF)
option(LIBU8IDENT_PROFILE "force a single profile: 2-6,C23_4,C11_6" OFF)
option(ENABLE_CHECK_XID "en- or disabled check_xid" OFF)
option(DISABLE_CHECK_XID "en- or disabled check_xid" OFF)
option(HAVE_CONFUS "add confus.h set" OFF)
option(HAVE_CROARING "use CRoaring bitsets" ON)

if (HAVE_CONFUS)
  if (HAVE_CROARING)
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")
    find_package(CRoaring)
    if (CRoaring_FOUND)
      add_definitions(-DHAVE_CROARING)
      add_definitions(-DCROARING_PATH="${CROARING_LIBRARY}")
    else()
      unset(HAVE_CROARING)
    endif()
  endif()
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release"
      CACHE STRING "Choose the type of build, options are: Debug Release
  RelWithDebInfo MinSizeRel Asan." FORCE)
endif()

if((CMAKE_MAJOR_VERSION EQUAL 3 AND CMAKE_MINOR_VERSION GREATER_EQUAL 9)
   AND (CMAKE_BUILD_TYPE STREQUAL "Release"))
  cmake_policy(SET CMP0069 NEW)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported OUTPUT error)
endif()
if(ipo_supported)
  message(STATUS "IPO / LTO enabled")
  set_property(GLOBAL PROPERTY INTERPROCEDURAL_OPTIMIZATION True)
  add_definitions(-DLTO)
else()
  message(STATUS "IPO / LTO not supported: <${error}>")
endif()

set(libu8ident_DOCS
    README.md c11.md NOTICE LICENSE)

set(libu8ident_HEADERS
    include/u8ident.h)

set(libu8ident_SOURCES
    u8ident.c
    u8idnorm.c
    u8idscr.c
    u8idroar.c)

if (CRoaring_FOUND)
  set(roaring_HEADERS
      confus_croar.h)
endif()

set(private_HEADERS
  scripts.h
  config.h
  u8idscr.h
  u8idroar.h
  u8id_private.h
  un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h hangul.h
  mark.h unic11.h confus.h ${roaring_HEADERS})

if(MSVC)
  if (BUILD_SHARED_LIBS)
    add_library(u8ident_static STATIC
      ${libu8ident_HEADERS}
      ${libu8ident_SOURCES}
      ${private_HEADERS})
    add_library(u8ident SHARED
      ${libu8ident_HEADERS}
      ${libu8ident_SOURCES}
      ${private_HEADERS})
    # FIXME cmake bug:
    # need full path. u8idlint only gets Release\u8ident.lib, but is in a seperate path.
    # This is ignored because the target is built, not imported.
    #set_target_properties(u8ident PROPERTIES
    #  IMPORTED_IMPLIB_DEBUG "${CMAKE_CURRENT_BINARY_DIR}\\Debug\\u8ident.lib")
    #set_target_properties(u8ident PROPERTIES
    #  IMPORTED_IMPLIB_RELEASE "${CMAKE_CURRENT_BINARY_DIR}\\Release\\u8ident.lib")
    # this is the default already
    #if (CMAKE_BUILD_TYPE STREQUAL "Debug")
      #set(LIBPATH "${CMAKE_CURRENT_BINARY_DIR}/Debug")
      #set_target_properties(u8ident PROPERTIES
      #  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Debug")
    #else()
      #set(LIBPATH "${CMAKE_CURRENT_BINARY_DIR}/Release")
      #set_target_properties(u8ident PROPERTIES
      #  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Release")
    #endif()
  else(BUILD_SHARED_LIBS)
    add_library(u8ident
      ${libu8ident_HEADERS}
      ${libu8ident_SOURCES}
      ${private_HEADERS})
  endif(BUILD_SHARED_LIBS)
else(MSVC)
  add_library(u8ident
    ${libu8ident_HEADERS}
    ${libu8ident_SOURCES}
    ${private_HEADERS})
endif(MSVC)
#set_target_properties(${libu8ident_HEADERS} PROPERTIES PUBLIC_HEADER)
set_target_properties(u8ident PROPERTIES PUBLIC_HEADER include/u8ident.h)
target_include_directories(u8ident PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(u8ident PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (CRoaring_FOUND)
  add_executable(perf perf.c u8idroar.c)
  set_source_files_properties(perf.c
      PROPERTIES COMPILE_FLAGS "-DPERF_TEST -DHAVE___BUILTIN_FFS")
endif()

# cmake bug: u8idlint only gets Release\u8ident.lib, but is in a subdir
if (NOT MSVC)
  link_libraries(u8ident)
endif()
add_executable(u8idlint u8idlint.c)
if (MSVC)
  #target_link_directories(u8idlint PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(u8idlint ${CMAKE_CURRENT_BINARY_DIR}/u8ident.lib)
endif()
include_directories(BEFORE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR})

if(NOT CMAKE_CROSSCOMPILING)
  enable_testing()
  add_executable(u8idtest test.c)
  add_test(test ./u8idtest)
  if (NOT MSVC)
    add_test(u8idlint.test "${CMAKE_CURRENT_SOURCE_DIR}/u8idlint.test")
    set(ENV{U8IDTEST_TEXTS} "${CMAKE_CURRENT_SOURCE_DIR}/texts")
    add_executable(test-texts test-texts.c)
    add_test(test-texts ./test-texts)
    add_executable(mkc23 mkc23.c)
    set_source_files_properties(mkc23
      PROPERTIES COMPILE_FLAGS -DU8ID_PROFILE_SAFEC23)
    add_test(mkc23 ./mkc23)
  else()
    # cmake bug: u8idlint only gets Release\u8ident.lib, but is in a subdir
    #target_link_directories(u8idtest PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(u8idtest ${CMAKE_CURRENT_BINARY_DIR}/u8ident.lib)
    #target_link_directories(test-texts PRIVATE ${LIBPATH})
    #target_link_directories(mkc23 PRIVATE ${LIBPATH})
    #target_link_libraries(test-texts u8ident.lib)
    #target_link_libraries(mkc23 u8ident.lib)
  endif(NOT MSVC)
endif(NOT CMAKE_CROSSCOMPILING)

add_custom_target(
  clang-format
  COMMAND clang-format -i ${CMAKE_CURRENT_SOURCE_DIR}/*.c ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/scripts.h ${CMAKE_CURRENT_SOURCE_DIR}/u8id*.h)

add_custom_target(
  regen-scripts
  COMMAND wget -N https://www.unicode.org/Public/UNIDATA/Scripts.txt
  COMMAND wget -N https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt
  COMMAND wget -N https://www.unicode.org/Public/UNIDATA/PropertyValueAliases.txt
  COMMAND perl mkscripts.pl
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_custom_target(
  regen-confus
  COMMAND wget -N https://www.unicode.org/Public/security/latest/confusables.txt
  COMMAND perl mkconfus.pl
  #BYPRODUCTS confus.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_custom_target(
  regen-all
  MAIN_DEPENDENCY regen-scripts
  DEPENDS regen-confus
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_custom_target(
  TAGS
  COMMAND etags --language=c++ *.c *.h include/*.h
  DEPENDS *.c *.h include/*.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# make install
# make install/local
# make install/strip
if(MSVC)
  #untested
  install(TARGETS u8ident RUNTIME PUBLIC_HEADER
          DESTINATION libu8ident-${PACKAGE_VERSION})
else()
  include(GNUInstallDirs)
endif()
install(TARGETS u8ident
  LIBRARY
  COMPONENT u8ident)
install(TARGETS RUNTIME)
install(TARGETS u8idlint)

if(MSVC)
  #untested
  add_custom_target(dist
    COMMAND zip libu8ident-${PACKAGE_VERSION}.zip libu8ident-*.dll
            include/u8ident.h ${libu8ident_DOCS}
    DEPENDS u8ident)
endif()

# make package
# make package_source (only after distclean or git clean -dxf)
set(CPACK_PACKAGE_VENDOR "Reini Urban")
set(CPACK_PACKAGE_CONTACT "rurban@cpan.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Check unicode security guidelines for identifiers")
#set(CPACK_PACKAGE_VERSION_MAJOR ${PACKAGE_VERSION_MAJOR})
#set(CPACK_PACKAGE_VERSION_MINOR ${PACKAGE_VERSION_MINOR})
#set(CPACK_PACKAGE_VERSION_PATCH ${PACKAGE_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

set(CPACK_RPM_PACKAGE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
include(CPack)
