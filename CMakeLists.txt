project(libu8ident C)
cmake_minimum_required(VERSION 2.9)
# Supported options -DU8ID_NORM=NFC,NFKC,NFD,NFKD
#                   -DU8ID_PROFILE=2,3,4,5,6
#                   -DU8ID_CHECK_XID=On,Off
# for smaller builds and lib.

if(MSVC)
    # Disable some overly strict MSVC warnings.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -wd4244 -wd4800 -wd4805")
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

# Supported options:
#  -DBUILD_SHARED_LIBS=ON,OFF
#  -DLIBU8IDENT_NORM=NFC,NFKC,NFD,NFKD
#  -DLIBU8IDENT_PROFILE=2,3,4,5,6
#  -DENABLE_CHECK_XID=On
#  -DDISABLE_CHECK_XID=On
#  -DHAVE_CONFUS=ON
#  -DHAVE_CROARING=ON
option(BUILD_SHARED_LIBS "shared libu8ident library" ON)
option(LIBU8IDENT_NORM "force a single normalization: NFC,NFKC,NFD,NFKD,FCC,FCD" OFF)
option(LIBU8IDENT_PROFILE "force a single profile: 2-6" OFF)
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

set(libu8ident_DOCS
    README.md NOTICE LICENSE)

set(libu8ident_HEADERS
    include/u8ident.h)

set(libu8ident_SOURCES
    u8ident.c
    u8idnorm.c
    u8idscr.c)

set(private_HEADERS
  scripts.h
  config.h
  u8idscr.h
  u8id_private.h
  un8ifcan.h un8ifcmb.h un8ifcmp.h un8ifcpt.h un8ifexc.h hangul.h)
  
add_library(u8ident
    ${libu8ident_HEADERS}
    ${libu8ident_SOURCES}
    ${private_HEADERS})
#set_target_properties(${libu8ident_HEADERS} PROPERTIES PUBLIC_HEADER)
set_target_properties(u8ident PROPERTIES PUBLIC_HEADER include/u8ident.h)
target_include_directories(u8ident PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(u8ident PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

#link_libraries(u8ident)

if(ipo_supported)
  message(STATUS "IPO / LTO enabled")
  set_property(GLOBAL PROPERTY INTERPROCEDURAL_OPTIMIZATION True)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLTO")
else()
  message(STATUS "IPO / LTO not supported: <${error}>")
endif()

include_directories(BEFORE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR})

if(NOT CMAKE_CROSSCOMPILING)
  enable_testing()
  add_executable(u8idtest
    test.c
    ${libu8ident_SOURCES}
    ${libu8ident_HEADERS})
  add_test(test ./u8idtest)
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
  BYPRODUCTS confus.h
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

if(MSVC)
  #untested
  add_custom_target(dist
    COMMAND zip libu8ident-${PACKAGE_VERSION}.zip libu8ident-*.dll
            include/u8ident.h ${libu8ident_DOCS}
    DEPENDS u8ident)
endif()
