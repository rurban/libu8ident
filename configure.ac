# configure.ac - Process with autoconf to produce a configure script
# (C) 2021-2022  Reini Urban <rurban@cpan.org>
# See LICENSE
AC_PREREQ([2.69])
AC_INIT([libu8ident],
        m4_esyscmd([build-aux/git-version-gen .version]),
	[https://github.com/rurban/libu8ident/issues],,
	[http://github.com/rurban/libu8ident/])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([u8ident.c])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([LIBU8IDENT_SO_VERSION], [1:0:0])
VERSION_FILE=".version"
AC_SUBST([VERSION_FILE])
AC_MSG_CHECKING([git version])
AC_MSG_RESULT($PACKAGE_VERSION)
AC_MSG_CHECKING([so version-info])
AC_MSG_RESULT($LIBU8IDENT_SO_VERSION)

AM_INIT_AUTOMAKE([1.10 no-define foreign dist-xz])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
#dnl m4_pattern_allow
LT_INIT
AC_CHECK_TOOLS([AR], [gcc-ar ar])
AC_CHECK_TOOLS([RANLIB], [gcc-ranlib ranlib])
AC_CHECK_TOOLS([NM], [gcc-nm nm])
#dnl Initialize pkg-config since we are installing a .pc file
PKG_INSTALLDIR
AM_CPPFLAGS="-I\$(top_srcdir)/include"

AC_MSG_NOTICE([

Check options])
# ===============================================
# hardcode certain options, to creater smaller and faster binaries

# TR31 charset profile for identifiers
# Recommended: --with-tr31=allowed or none
AC_MSG_CHECKING([for --with-tr31=])
AC_ARG_WITH([tr31],
      [AS_HELP_STRING([--with-tr31={ALLOWED,SAFEC26,ID,XID,C11,C23,ALLUTF8,NONE}],
      	[support only this TR31 identifier profile. @<:@default=xid@:>@
      	 Recommended: --with-tr31=allowed])],
      [case "${with_tr31}" in
      ALLOWED|SAFEC26|ID|XID|C11|C23|ALLUTF8) U8ID_TR31=${with_tr31}; AC_MSG_RESULT([$with_tr31]) ;;
      NONE) CFLAGS="$CFLAGS -DDISABLE_U8ID_TR31"; AC_MSG_RESULT([$with_tr31]) ;;
      *)    AC_MSG_ERROR([invalid ${with_tr31}: only ALLOWED,SAFEC26,ID,XID,C11,C23,ALLUTF8,NONE]) ;;
      esac],
      [ U8ID_TR31=; AC_MSG_RESULT([none. support all (default). Recommended: ALLOWED]) ]
      )
if test -n "$U8ID_TR31"; then
  CFLAGS="$CFLAGS -DU8ID_TR31=$U8ID_TR31"
  dnl AC_DEFINE([U8IDP_TR31],[$U8ID_TR31],[Define to ALLOWED,SAFEC26,ID,XID,C11,C23,ALLUTF8 to support only this TR31 identifier charset])
fi
AC_SUBST([U8ID_TR31])

# TR39 Mixed-script security profile for identifiers
# Recommended: --with-profile=4
AC_MSG_CHECKING([for --with-profile=])
AC_ARG_WITH([profile],
	[AS_HELP_STRING([--with-profile={2,3,4,5,6,C26_4,C11_6}],
		[support only this TR39 Unicode security profile. @<:@default=4@:>@
		 Recommended: --with-profile=4])],
	[case "${with_profile}" in
	2|3|4|5|6|C26_4|C11_6) U8ID_PROFILE=${with_profile}; AC_MSG_RESULT([$with_profile]) ;;
	*)    AC_MSG_ERROR([invalid ${with_profile}: only 2,3,4,5,6,C26_4,C11_6]) ;;
	esac],
        [ U8ID_PROFILE=; AC_MSG_RESULT([none. support all (default). Recommended: 4]) ]
	)
if test -n "$U8ID_PROFILE"; then
  CFLAGS="$CFLAGS -DU8ID_PROFILE=$U8ID_PROFILE"
  dnl AC_DEFINE([U8ID_PROFILE],[$U8ID_PROFILE],[Define to 2-6,C26_4,C11_6 to support only this Unicode security profile])
fi
AC_SUBST([U8ID_PROFILE])

# Recommended: --with-norm=NFC
AC_MSG_CHECKING([for --with-norm=])
AC_ARG_WITH([norm],
	[AS_HELP_STRING([--with-norm=NF{K,}{C,D}],
		[support only this normalization method. @<:@default=@:>@
		 Recommended: --with-norm=NFC])],
	[case "${with_norm}" in
	NFKD|NFKC|NFC|NFD) U8ID_NORM=${with_norm}; AC_MSG_RESULT([$with_norm]) ;;
	FCD|FCD)           U8ID_NORM=${with_norm}; AC_MSG_RESULT([$with_norm]) ;;
	*)    AC_MSG_ERROR([invalid ${with_norm}: only NFC,NFKC,NFD,NFKD,FCC,FCD]) ;;
	esac],
        [ U8ID_NORM=; AC_MSG_RESULT([none. support all (default). Recommended: NFC]) ]
	)
if test -n "$U8ID_NORM"; then
  if test x$U8ID_NORM != xNFC && test x$U8ID_PROFILE = xC26_4 -o x$U8ID_TR31 = xSAFEC26 -o x$U8ID_TR31 = xC23
  then
    AC_MSG_ERROR([Profile $U8ID_PROFILE or TR31 $U8ID_TR31 requires NFC])
  else
    CFLAGS="$CFLAGS -DU8ID_NORM=$U8ID_NORM"
    dnl AC_DEFINE([U8ID_NORM],[$U8ID_NORM],[Define to NF{K,}{C,D} to support only this Unicode normalization])
  fi
fi
AC_SUBST([U8ID_NORM])

AC_MSG_CHECKING([for --enable-confus])
AC_ARG_ENABLE([confus],
        [AS_HELP_STRING([--enable-confus],
	  [add the confusables set @<:@default=no@:>@])],
	[case "${enableval}" in
	yes) HAVE_CONFUS=1;
             AC_DEFINE([HAVE_CONFUS], 1,
               [Defined to 1 to add the confusable API])
             AC_MSG_RESULT([yes])
             ;;
	*)  AC_MSG_RESULT([no]) ;;
	esac], [HAVE_CONFUS= ])
if test -z "$HAVE_CONFUS"; then
  AC_MSG_RESULT([no])
fi
AC_SUBST([HAVE_CONFUS])

download_croaring() {
  git clone https://github.com/RoaringBitmap/CRoaring
}

AC_MSG_CHECKING([for --with-croaring])
AC_ARG_WITH([croaring],
	[AS_HELP_STRING([--with-croaring=optional_path],
		[Use the CRoaring library.])],
	[case "${with_croaring}" in
        yes) HAVE_CROARING=1
             AC_MSG_RESULT([$with_croaring])
             AC_CHECK_TOOLS([XXD], [xxd])
             # in a parallel dir?
             with_croaring="$srcdir/../CRoaring"
             if test -d "${with_croaring}" && \
                test -e "${with_croaring}/roaring.c" && \
                test -e "${with_croaring}/roaring.h"
             then
               CROARING_PATH="\"$srcdir/../CRoaring\""
               AC_MSG_RESULT([found "$srcdir/../CRoaring"])
             else
               download_croaring && CROARING_PATH="CRoaring"
             fi
             ;;
        *)   if test -d "${with_croaring}" && \
                test -e "${with_croaring}/roaring.c" && \
                test -e "${with_croaring}/roaring.h"
             then
                HAVE_CROARING=1
                CROARING_PATH="\"${with_croaring}\""
                AC_MSG_RESULT(["$with_croaring"])
             else
                AC_MSG_ERROR([invalid ${with_profile} path])
             fi
             ;;
	esac],
        [ HAVE_CROARING=; AC_MSG_RESULT([no]) ]
	)

if test -n "$HAVE_CROARING"; then
   AC_DEFINE([HAVE_CROARING], 1,
        [Defined to 1 when to use the CRoaring library])
fi
AC_SUBST([HAVE_CROARING])
AC_SUBST([CROARING_PATH])
if test -n "$CROARING_PATH"; then
   AC_DEFINE_UNQUOTED([CROARING_PATH], $CROARING_PATH,
        [Defined to the path to the CRoaring library])
fi
AM_CONDITIONAL([HAVE_CONFUS], [test x$HAVE_CONFUS = x1])
AM_CONDITIONAL([HAVE_CROARING], [test x$HAVE_CROARING = x1])

AC_MSG_NOTICE([

Check programs])
# ===============================================
AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AM_PROG_CC_C_O
AC_PROG_CC
dnl AC_PROG_CC_C11
if test "x$ac_cv_prog_cc_c11" != "xno"; then
   AC_DEFINE([HAVE_C11], 1,
        [Defined to 1 when the compiler supports c11])
   if test "x$ac_cv_prog_cc_c11" != "x"; then
      AC_MSG_RESULT([added $ac_cv_prog_cc_c11 to CFLAGS])
      AM_CFLAGS="$AM_CFLAGS $ac_cv_prog_cc_c11"
   fi
fi
AC_SUBST(HAVE_C11)
AC_CACHE_CHECK([if compiling with clang], [ax_cv_cc_target_clang],
[
    CFLAGS="$TARGET_CFLAGS"
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([], [[
#ifdef __clang__
#error "is clang"
#endif
        ]])],
        [ax_cv_cc_target_clang=no], [ax_cv_cc_target_clang=yes])])

# clang has no broken return-local-addr detection
if test x$ac_cv_c_compiler_gnu = xyes -a $ax_cv_cc_target_clang = xno; then
   case $host_os in
     mingw*|cygwin*|msys*)
        WARN_CFLAGS="-Wall -Wextra" ;;
     *) dnl older non-c99 g++ complain about __VA_ARGS__, for();
        if test "x$ac_cv_prog_cc_c99" = "xno"; then
          WARN_CFLAGS="-Wall -Wextra"
        else
          WARN_CFLAGS="-Wall -Wextra -Werror -Wno-return-local-addr"
        fi
        ;;
     esac
elif test $ax_cv_cc_target_clang = xyes; then
  WARN_CFLAGS="-Wall -Wextra -Werror"
else
  WARN_CFLAGS="-Wall -Wextra"
fi
AC_SUBST(WARN_CFLAGS)

dnl optional for packaging or maintainance
AC_CHECK_TOOLS([WGET], [wget2 wget])
# dnf install rubygem-ronn-ng
AC_CHECK_TOOLS([RONN], [ronn])
AC_CHECK_TOOLS([PERL], [cperl perl])
AC_CHECK_TOOLS([PANDOC], [pandoc])
AM_CONDITIONAL([HAVE_PANDOC], [test -n "$PANDOC"])
AC_CHECK_TOOLS([GPERF], [gperf])

AC_MSG_NOTICE([Check header files])
# ===============================================
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([stdlib.h	\
                  malloc.h	\
                  string.h	\
                  stddef.h	\
                  inttypes.h	\
                  stdint.h	\
                  assert.h	\
                  unistd.h	\
                  getopt.h      \
                  sys/types.h	\
                  sys/stat.h	\
                  dirent.h	\
                  libgen.h	\
                  uniwbrk.h     \
                  ])
AC_CHECK_LIB([unistring],[u8_wordbreaks],
  [have_libunistring=yes;
   u8idlint_LIBS=-lunistring;
   AC_SUBST([u8idlint_LIBS])
   ],
  [if pkg-config --exists libunistring; then
    have_libunistring=yes;
    U8IDLINT_CFLAGS=`pkg-config libunistring --cflags`
    u8idlint_LIBS=`pkg-config libunistring --libs`
    AC_SUBST([U8IDLINT_CFLAGS])
    AC_SUBST([u8idlint_LIBS])
  else
    AC_MSG_WARN([libunistring for u8idlint not found])
  fi])
AM_CONDITIONAL([HAVE_LIBUNISTRING], [test x$have_libunistring = xyes])

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
dnl AC_CHECK_FUNCS([ memset strcmp ])
AC_CHECK_FUNCS([getopt_long],[],
  AC_MSG_WARN([getopt_long not found. u8idlint will not accept long options.]))
AX_GCC_BUILTIN(__builtin_ffs)

case $host_os in
  mingw*|cygwin*|msys*)
        have_windows=1
        CFLAGS="$CFLAGS -fstack-protector"
        ;;
esac
AM_CONDITIONAL([HAVE_WINDOWS], [test x1 = x$have_windows])

AC_CHECK_TOOLS([PERL], [cperl perl])
AC_CHECK_TOOLS([WGET], [wget])

AH_TOP([
#ifndef __U8ID_CONF_H__
#define __U8ID_CONF_H__
])

AH_BOTTOM([
#endif /* __U8ID_CONF_H__ */
])

LTEXEC="./libtool --mode=execute"
AC_SUBST(LTEXEC)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([libu8ident.pc
                 Makefile])
AC_CONFIG_FILES([test-texts.test], [chmod +x test-texts.test])
AC_OUTPUT
