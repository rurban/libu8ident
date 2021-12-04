# configure.ac - Process with autoconf to produce a configure script
# (C) 2021  Reini Urban <rurban@cpan.org>
# See LICENSE
AC_PREREQ([2.69])
AC_INIT([libu8ident],
        [0.1],
        [https://github.com/rurban/libu8ident/issues],[libu8ident],[http://github.com/rurban/libu8ident/])
AC_CONFIG_SRCDIR([u8ident.c])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([LIBU8IDENT_SO_VERSION], [0:0:0])

AM_INIT_AUTOMAKE([1.10 no-define foreign dist-xz])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
#dnl m4_pattern_allow
AC_CHECK_TOOLS([AR], [gcc-ar ar])
AC_CHECK_TOOLS([RANLIB], [gcc-ranlib ranlib])
AC_CHECK_TOOLS([NM], [gcc-nm nm])
LT_INIT
#dnl Initialize pkg-config since we are installing a .pc file
PKG_INSTALLDIR
AM_CPPFLAGS="-I\$(top_srcdir)/include"

AC_MSG_NOTICE([

Check options])
# ===============================================
# hardcode certain options, to creater smaller and faster binaries
# Recommended: --with-norm=NFKC
AC_MSG_CHECKING([for --with-norm=])
AC_ARG_WITH([norm],
	[AS_HELP_STRING([--with-norm=NF{K,}{C,D}],
		[support only this normalization method. @<:@default=@:>@
		 Recommended: --with-norm=NFKC])],
	[case "${with_norm}" in
	NFKD|NFKC|NFC|NFD) U8ID_NORM=${with_norm}; AC_MSG_RESULT([$with_norm]) ;;
	FCD|FCD)           U8ID_NORM=${with_norm}; AC_MSG_RESULT([$with_norm]) ;;
	*)    AC_MSG_RESULT([invalid ${with_norm}: only NFC,NFKC,NFD,NFKD,FCC,FCD]) ;;
	esac],
        [ U8ID_NORM=; AC_MSG_RESULT([none. support all (default). Recommended: NFKC]) ]
	)
if test -n "$U8ID_NORM"; then
  CFLAGS="$CFLAGS -DU8ID_NORM=$U8ID_NORM"
  dnl AC_DEFINE([U8ID_NORM],[$U8ID_NORM],[Define to NF{K,}{C,D} to support only this Unicode normalization])
fi
AC_SUBST([U8ID_NORM])

# Recommended: --with-profile=4
AC_MSG_CHECKING([for --with-profile=])
AC_ARG_WITH([profile],
	[AS_HELP_STRING([--with-profile={2,3,4,5,6}],
		[support only this Unicode security profile. @<:@default=4@:>@
		 Recommended: --with-profile=4])],
	[case "${with_profile}" in
	2|3|4|5|6) U8ID_PROFILE=${with_profile}; AC_MSG_RESULT([$with_profile]) ;;
	*)    AC_MSG_RESULT([invalid ${with_profile}: only 2,3,4,5,6]) ;;
	esac],
        [ U8ID_PROFILE=; AC_MSG_RESULT([none. support all (default). Recommended: 4]) ]
	)
if test -n "$U8ID_PROFILE"; then
  CFLAGS="$CFLAGS -DU8ID_PROFILE=$U8ID_PROFILE"
  dnl AC_DEFINE([U8ID_PROFILE],[$U8ID_PROFILE],[Define to 2-6 to support only this Unicode security profile])
fi
AC_SUBST([U8ID_PROFILE])

AC_MSG_CHECKING([for --{dis,en}able-check-xid])
AC_ARG_ENABLE([check_xid],
        [AS_HELP_STRING([--enable-check-xid],
	  [en- or disable checking for valid XID's, i.e Allowed IdentifierStatus. @<:@default=none@:>@])],
	[case "${enableval}" in
	yes) enable_check_xid=yes; AC_MSG_RESULT([enable]); CFLAGS="$CFLAGS -DENABLE_CHECK_XID" ;;
	no)  enable_check_xid=no ; AC_MSG_RESULT([disable]); CFLAGS="$CFLAGS -DDISABLE_CHECK_XID" ;; 
	*)   ;;
	esac], [enable_check_xid= ])
if test -z "$enable_check_xid"; then
  AC_MSG_RESULT([none])
fi

AC_MSG_NOTICE([

Check programs])
# ===============================================
AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AM_PROG_CC_C_O
AC_PROG_CC_C99
dnl AC_PROG_CC_C11
dnl optional for packaging or maintainance
AC_CHECK_TOOLS([WGET], [wget2 wget])
# dnf install rubygem-ronn-ng
AC_CHECK_TOOLS([RONN], [ronn])
AC_CHECK_TOOLS([PERL], [cperl perl])

if test "x$ac_cv_prog_cc_c11" != "xno"; then
   AC_DEFINE([HAVE_C11], 1,
        [Defined to 1 when the compiler supports c11])
   if test "x$ac_cv_prog_cc_c11" != "x"; then
      AC_MSG_RESULT([added $ac_cv_prog_cc_c11 to CFLAGS])
      AM_CFLAGS="$AM_CFLAGS $ac_cv_prog_cc_c11"
   fi
fi
AC_SUBST(HAVE_C11)

if test x$ac_compiler_gnu = xyes; then
  WARN_CFLAGS="-Wall -Wextra -Werror"
  # -Wno-return-local-addr
else
  WARN_CFLAGS="-Wall -Wextra"
fi
dnl older non-c99 g++ complain about __VA_ARGS__, for();
if test "x$ac_cv_prog_cc_c99" = "xno"; then
    WARN_CFLAGS=`echo $WARN_CFLAGS | sed -e"s,-Werror ,,"`
fi
AC_SUBST(WARN_CFLAGS)

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
dnl AC_TYPE_UINTPTR_T
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
