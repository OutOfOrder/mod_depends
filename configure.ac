dnl Required initializer
AC_INIT(mod_depends, 0.7.0)
OOO_CONFIG_NICE(config.nice)
AC_PREREQ(2.53)
AC_CONFIG_SRCDIR([src/mod_depends.c])
AM_MAINTAINER_MODE
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER([include/mod_depends_config.h:config.in])

AC_PROG_CC
AC_PROG_LD
AC_PROG_INSTALL
AM_PROG_LIBTOOL

AP_VERSION=2.0.40
CHECK_APACHE(,$AP_VERSION,
    :,:,
    AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])
)

MODULE_CFLAGS="${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES}"

AC_SUBST(MODULE_CFLAGS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

echo "---"
echo "Configuration summary for mod_depends"
echo ""
echo "   * Apache Dodules Directory:    $AP_LIBEXECDIR"
echo ""
echo "---"
