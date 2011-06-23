AC_PREREQ(2.59)
AC_INIT(mod_badge, 1.0.2)
AM_INIT_AUTOMAKE(foreign)

AC_PROG_CC
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG

LT_INIT([win32-dll disable-static])

AX_PROG_APACHE

AC_HEADER_STDC
dnl AC_CHECK_HEADERS

#	Get Apache base directory.

apache_dir=`dirname "\`dirname \"${APACHE}\"\`"`

#	Get APXS configuration.

AC_PATH_PROG([APXS], [apxs], [], ["$apache_dir/bin:$apache_dir/sbin:$PATH"])

if test -z "${APXS}"
then	AC_PATH_PROG([APXS], [apxs2], [],
		["$apache_dir/bin:$apache_dir/sbin:$PATH"])

	if test -z "${APXS}"
	then	AC_MSG_ERROR([failed to find Apache apxs executable])
	fi
fi

APXS_CFLAGS=`"${APXS}" -q CFLAGS`
APXS_LDFLAGS=`"${APXS}" -q LDFLAGS_SHLIB`
APXS_INCLUDES=-I`"${APXS}" -q INCLUDEDIR`
APXS_libexecdir=`"${APXS}" -q LIBEXECDIR`
AC_SUBST(APXS_CFLAGS)
AC_SUBST(APXS_LDFLAGS)
AC_SUBST(APXS_INCLUDES)
AC_SUBST(APXS_libexecdir)

#	Get APR configuration.

APR_FIND_APR([], [], 1, [1 2])

if test "${apr_found}" != 'yes'
then	AC_MSG_ERROR([failed to find Apache Portable Runtime development files])
fi

APR_CPPFLAGS=`"${apr_config}" --cppflags`
APR_CFLAGS=`"${apr_config}" --cflags`
APR_LDFLAGS=`"${apr_config}" --ldflags`
APR_INCLUDES=`"${apr_config}" --includes`
AC_SUBST(APR_CPPFLAGS)
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_LDFLAGS)
AC_SUBST(APR_INCLUDES)

#	Get OpenSSL configuration.

PKG_CHECK_MODULES(SSL, [libssl], [],
	AC_MSG_ERROR([failed to find OpenSSL development files]))

AC_CONFIG_FILES([Makefile
		mod_badge.spec
		src/Makefile
		doc/Makefile])
AC_OUTPUT
