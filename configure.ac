AC_PREREQ(2.60)
AC_INIT(mod_authn_persona, 0.1, llyod@mozilla.com)
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_MACRO_DIR([build])

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_MACRO_DIR([m4])

AM_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([build/mod_authn_persona.spec])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AX_WITH_APXS(no, [$PATH:/sbin:/usr/sbin:/usr/local/sbin])

if test "$apxs_found" = no ; then
    AC_MSG_ERROR([apxs is required])
fi

LIBCURL_CHECK_CONFIG([],[],[],[
    AC_MSG_ERROR([libcurl is required])
])

PKG_CHECK_MODULES([YAJL], [yajl])

AC_PROG_PERL_VERSION(5.8.0)
AC_PERL_MODULE_VERSION(Apache::Test 0, , AC_MSG_ERROR(Need some Perl modules))
AC_C_CONST

AM_MAINTAINER_MODE

AC_OUTPUT(Makefile)
