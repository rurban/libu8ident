# - Try to find CRoaring
# Once done this will define
#  CROARING_FOUND - System has roaring.c
#  CROARING_INCLUDE_DIRS - The roaring.h include directories
#  CROARING_DEFINITIONS - Compiler switches required for using roaring.c

find_package(PkgConfig)
pkg_check_modules(PC_CROARING QUIET roaring)
set(CROARING_DEFINITIONS ${PC_CROARING_CFLAGS})

find_path(CROARING_INCLUDE_DIR roaring.h
          HINTS ${PC_CROARING_INCLUDEDIR} ${PC_CROARING_INCLUDE_DIRS}
          PATH_SUFFIXES CRoaring )

find_library(CROARING_LIBRARY NAMES CRoaring libroaring
             HINTS ${PC_CROARING_LIBDIR} ${PC_CROARING_LIBRARY_DIRS} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set CROARING_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(CRoaring DEFAULT_MSG
                                  CROARING_LIBRARY CROARING_INCLUDE_DIR)

mark_as_advanced(CROARING_INCLUDE_DIR CROARING_LIBRARY )

set(CROARING_LIBRARIES ${CROARING_LIBRARY} )
set(CROARING_INCLUDE_DIRS ${CROARING_INCLUDE_DIR} )
