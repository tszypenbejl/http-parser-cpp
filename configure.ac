#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([http-parser-cpp], [0.0.0], [tomasz.szypenbejl@interia.pl])
AC_CONFIG_SRCDIR([HttpParser.hpp])
AC_LANG_CPLUSPLUS

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CXX

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_11([noext])

# Checks for libraries.
AC_CHECK_LIB([http_parser], [http_parser_init], [], [AC_MSG_ERROR([libhttp_parser not found])])
AC_CHECK_LIB([boost_system], [main], [HAVE_BOOST_SYSTEM=1],
		[AC_MSG_NOTICE([libboost_system (needed by example programs) not found])])

# Checks for header files.
AC_CHECK_HEADERS([http_parser.h], [], [AC_MSG_ERROR([http_parser.h header not found])])
AC_CHECK_HEADERS([strings.h], [], [AC_MSG_ERROR([strings.h header not found])])
AC_CHECK_HEADERS([boost/asio.hpp], [HAVE_BOOST_ASIO=1],
		[AC_MSG_NOTICE([boost/asio.hpp header (needed by example programs) not found])])

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp])

# Define automake conditionals
AM_CONDITIONAL([CAN_BUILD_EXAMPLES], [test x$HAVE_BOOST_SYSTEM = x1 && test x$HAVE_BOOST_ASIO = x1])

# We are not going to need all those -D options from the configure script.
echo -n > confdefs.h

AC_CONFIG_FILES([Makefile test/Makefile examples/Makefile])
AC_OUTPUT
