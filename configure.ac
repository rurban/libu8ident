# Autoconf requirements
AC_PREREQ([2.69])
AC_INIT([libu8ident],
        [0.1],
        [https://github.com/rurban/libu8ident/issues],[libu8ident],[http://github.com/rurban/libu8ident/])
AC_CONFIG_SRCDIR([u8ident.c])
AC_SUBST([LIBU8IDENT_SO_VERSION], [0:0:0])

AM_INIT_AUTOMAKE([1.10 no-define foreign dist-xz])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CHECK_TOOLS([AR], [gcc-ar ar])
AC_CHECK_TOOLS([RANLIB], [gcc-ranlib ranlib])
AC_CHECK_TOOLS([NM], [gcc-nm nm])
LT_INIT
# Initialize pkg-config since we are installing a .pc file
PKG_INSTALLDIR
AM_CPPFLAGS="-I\$(top_srcdir)/include"

AC_CANONICAL_HOST
AC_MSG_NOTICE([Check programs])
# ===============================================
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AM_PROG_CC_C_O
AC_PROG_CC_C99
#AC_PROG_CC_C11
if test "x$ac_cv_prog_cc_c11" != "xno"; then
   AC_DEFINE([HAVE_C11], 1,
        [Defined to 1 when the compiler supports c11])
   if test "x$ac_cv_prog_cc_c11" != "x"; then
      AC_MSG_RESULT([added $ac_cv_prog_cc_c11 to CFLAGS])
      AM_CFLAGS="$AM_CFLAGS $ac_cv_prog_cc_c11"
   fi
fi
AC_SUBST(HAVE_C11)

AC_MSG_NOTICE([Check header files])
# ===============================================
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_HEADER_TIME
AC_CHECK_HEADERS([stdlib.h	\
                  malloc.h	\
                  string.h	\
                  stddef.h	\
                  unistd.h	\
                  sys/types.h	\
                  inttypes.h	\
                  stdint.h	\
                  ])

AC_MSG_NOTICE([Check typedefs, structures, and compiler characteristics])
# ===============================================
AC_C_CONST
AC_C_INLINE
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_INT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
#AC_TYPE_UINTPTR_T
AC_CHECK_SIZEOF(size_t)

AC_CHECK_FUNCS([ memset strcmp ])

AC_CHECK_TOOLS([PERL], [cperl perl])
AC_CHECK_TOOLS([WGET], [wget])

AH_TOP([
#ifndef __U8ID_CONF_H__
#define __U8ID_CONF_H__
])

AH_BOTTOM([
#endif /* __U8ID_CONF_H__ */
])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([libu8ident.pc
                 Makefile])
AC_OUTPUT
