project(libu8ident C)
cmake_minimum_required(VERSION 3.5)
# Supported options:
#  -DBUILD_SHARED_LIBS=ON,OFF
#  -DU8ID_NORM=NFC,NFKC,NFD,NFKD
#  -DU8ID_PROFILE=2,3,4,5,6,TR39_4,C11_6
#  -DU8ID_TR31=ALLOWED,TR39,ID,XID,C11,ALLUTF8,NONE
#  -DHAVE_CONFUS=ON
#  -DHAVE_CROARING=ON
#  -DALLOW_DOLLAR=OFF
# for smaller builds and lib.

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
if(CMAKE_MAJOR_VERSION GREATER 2)
  include(TestBigEndian)
  test_big_endian(IS_BIG_ENDIAN)
  if(IS_BIG_ENDIAN)
    message(ERROR "Big Endian not supported: <${error}>")
    add_definitions(-DBIG_ENDIAN)
  endif()
endif()
add_definitions(-DHAVE_CONFIG_H)

if(MSVC)
    # Disable some overly strict MSVC warnings.
    add_compile_options(-wd4244 -wd4800 -wd4805 -D_CRT_SECURE_NO_WARNINGS)
endif()
if(MINGW) # WINDOWS AND CMAKE_COMPILER_IS_GNUCC
    add_compile_options(-fstack-protector)
    add_link_options(-fstack-protector)
endif()

option(BUILD_SHARED_LIBS "shared libu8ident library" ON)
option(U8ID_NORM "force a single normalization: NFC,NFKC,NFD,NFKD,FCC,FCD" OFF)
option(U8ID_PROFILE "force a single profile: 2-6,TR39_4,C11_6" OFF)
option(U8ID_TR31 "force TR31 charset: ALLOWED,TR39,ID,XID,C11,ALLUTF8,NONE" OFF)
option(HAVE_CONFUS "add confusables API" OFF)
option(HAVE_CROARING "use CRoaring bitsets" ON)
option(ALLOW_DOLLAR "allow the dollar sign in our profiles" ON)

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
if (WITH_DOLLAR)
  add_definitions(-DALLOW_DOLLAR)
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

configure_file(cmakeconfig.h.in config.h)

set(libu8ident_DOCS
  README.md doc/c11.md doc/n2916.md doc/P2528R0.md doc/P2528R1.md
  doc/tr31-bugs.md doc/n2916.patch
  NOTICE LICENSE)

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
  config.h.in
  u8idscr.h
  u8idroar.h
  u8id_private.h
  un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h hangul.h
  mark.h unic11.h confus.h ${roaring_HEADERS})

add_library(u8ident_static STATIC
  ${libu8ident_HEADERS}
  ${libu8ident_SOURCES}
  ${private_HEADERS})
add_library(u8ident SHARED
  ${libu8ident_HEADERS}
  ${libu8ident_SOURCES}
  ${private_HEADERS})
if(MSVC)
  if (BUILD_SHARED_LIBS)
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
  endif(BUILD_SHARED_LIBS)
endif(MSVC)
#set_target_properties(${libu8ident_HEADERS} PROPERTIES PUBLIC_HEADER)
set_target_properties(u8ident PROPERTIES PUBLIC_HEADER include/u8ident.h)
if (U8ID_NORM)
  set_target_properties(u8ident u8ident_static PROPERTIES
    COMPILE_DEFINITIONS U8ID_NORM=${U8ID_NORM})
endif()
if (U8ID_PROFILE)
  get_target_property(DEF u8ident COMPILE_DEFINITIONS)
  if (DEF)
    set_target_properties(u8ident u8ident_static PROPERTIES
      COMPILE_DEFINITIONS "${DEF};U8ID_PROFILE=${U8ID_PROFILE}")
  else()
    set_target_properties(u8ident u8ident_static PROPERTIES
      COMPILE_DEFINITIONS U8ID_PROFILE=${U8ID_PROFILE})
  endif()
endif()
if (U8ID_TR31)
  get_target_property(DEF u8ident COMPILE_DEFINITIONS)
  if (DEF)
    set_target_properties(u8ident u8ident_static PROPERTIES
      COMPILE_DEFINITIONS "${DEF};U8ID_TR31=${U8ID_TR31}")
  else()
    set_target_properties(u8ident u8ident_static PROPERTIES
      COMPILE_DEFINITIONS U8ID_TR31=${U8ID_TR31})
  endif()
endif()

target_include_directories(u8ident PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(u8ident PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (CRoaring_FOUND)
  add_executable(perf perf.c u8idroar.c)
  set_source_files_properties(perf.c
      PROPERTIES COMPILE_FLAGS "-DPERF_TEST")
endif()

add_executable(u8idlint u8idlint.c ${libu8ident_SOURCES})
# cmake MSVC bug: u8idlint only gets Release\u8ident.lib, but is in a subdir
# target_link_directories(u8idlint PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
# target_link_libraries(u8idlint ${CMAKE_CURRENT_BINARY_DIR}/u8ident.lib)
include_directories(BEFORE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR})

if(NOT CMAKE_CROSSCOMPILING)
  enable_testing()
  add_executable(u8idtest test.c ${libu8ident_SOURCES})
  add_test(test ./u8idtest)
  if (NOT MSVC)
    add_test(u8idlint.test "${CMAKE_CURRENT_SOURCE_DIR}/u8idlint.test")
  endif()
  set(ENV{U8IDTEST_TEXTS} "${CMAKE_CURRENT_SOURCE_DIR}/texts")
  add_executable(test-texts test-texts.c ${libu8ident_SOURCES})
  add_test(test-texts ./test-texts)
  add_executable(mktr39 mktr39.c ${libu8ident_SOURCES})
  set_source_files_properties(mktr39
    PROPERTIES COMPILE_FLAGS -DU8ID_PROFILE_TR39)
  add_test(mktr39 ./mktr39)
endif(NOT CMAKE_CROSSCOMPILING)

add_custom_target(
  clang-format
  COMMAND clang-format -i
      ${CMAKE_CURRENT_SOURCE_DIR}/*.c
      ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts.h
      ${CMAKE_CURRENT_SOURCE_DIR}/confus.h
      ${CMAKE_CURRENT_SOURCE_DIR}/u8id*.h)

add_custom_target(
  regen-scripts
  COMMAND wget -N https://www.unicode.org/Public/UNIDATA/Scripts.txt
  COMMAND wget -N https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt
  COMMAND wget -N https://www.unicode.org/Public/UNIDATA/PropertyValueAliases.txt
  COMMAND wget -N https://www.unicode.org/Public/UNIDATA/DerivedCoreProperties.txt
  COMMAND wget -N https://www.unicode.org/Public/UNIDATA/DerivedNormalizationProps.txt
  COMMAND wget -N https://www.unicode.org/Public/security/latest/IdentifierType.txt
  COMMAND wget -N https://www.unicode.org/Public/security/latest/IdentifierStatus.txt
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
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Check unicode TR39 security guidelines for identifiers")
#set(CPACK_PACKAGE_VERSION_MAJOR ${PACKAGE_VERSION_MAJOR})
#set(CPACK_PACKAGE_VERSION_MINOR ${PACKAGE_VERSION_MINOR})
#set(CPACK_PACKAGE_VERSION_PATCH ${PACKAGE_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

set(CPACK_RPM_PACKAGE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
if(MSVC)
  set(CPACK_GENERATOR "ZIP")
endif()
include(CPack)
