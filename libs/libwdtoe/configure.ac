#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([libwdtoe], [1.0.0], [julien@chelsio.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/libwdtoe.c])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

MYCFLAGS="-Wall -Werror -fno-strict-aliasing -D_GNU_SOURCE -D_BSD_SOURCE"
AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug], [turns debug output on]), \
	      MYCFLAGS="$MYCFLAGS -g", MYCFLAGS="$MYCFLAGS -O2 -DNDEBUG")
CFLAGS="$CFLAGS $MYCFLAGS"

AC_CANONICAL_HOST
AM_MAINTAINER_MODE

AC_DISABLE_STATIC
# automake versions >1.12 seems to require AM_PROG_AR
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_LIBTOOL

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_REPLACE_FNMATCH
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset socket strcasecmp strchr strdup strpbrk strrchr strtoul])

# Check OS.
case "${host}" in
i[[3456]]86-*-linux*) AC_DEFINE(LINUX_BUILD, 1, [OS is linux]) ac_cv_linux_build="yes" ;;
esac

AM_CONDITIONAL(LINUX_BUILD, test "$ac_cv_linux_build" = "yes")

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
