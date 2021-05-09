/* Macros for managing ABI-compatibility definitions using ELF symbol versions.
   Copyright (C) 2000-2016 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _SHLIB_COMPAT_H
#define _SHLIB_COMPAT_H	1

#ifdef SHARED

# include <abi-versions.h>

/* The file abi-versions.h (generated by scripts/abi-versions.awk) defines
   symbols like `ABI_libm_GLIBC_2_0' for each version set in the source
   code for each library.  For a version set that is subsumed by a later
   version set, the definition gives the subsuming set, i.e. if GLIBC_2_0
   is subsumed by GLIBC_2_1, then ABI_libm_GLIBC_2_0 == ABI_libm_GLIBC_2_1.
   Each version set that is to be distinctly defined in the output has an
   unique positive integer value, increasing with newer versions.  Thus,
   evaluating two ABI_* symbols reduces to integer values that differ only
   when the two version sets named are in fact two different ABIs we are
   supporting.  If these do not differ, then there is no need to compile in
   extra code to support this version set where it has been superseded by a
   newer version.  The compatibility code should be conditionalized with
   e.g. `#if SHLIB_COMPAT (libm, GLIBC_2_0, GLIBC_2_2)' for code introduced
   in the GLIBC_2.0 version and obsoleted in the GLIBC_2.2 version.  */

# define SHLIB_COMPAT(lib, introduced, obsoleted)			      \
  _SHLIB_COMPAT (lib, introduced, obsoleted)
# define _SHLIB_COMPAT(lib, introduced, obsoleted)			      \
  (IS_IN (lib)								      \
   && (!(ABI_##lib##_##obsoleted - 0)					      \
       || ((ABI_##lib##_##introduced - 0) < (ABI_##lib##_##obsoleted - 0))))

/* That header also defines symbols like `VERSION_libm_GLIBC_2_1' to
   the version set name to use for e.g. symbols first introduced into
   libm in the GLIBC_2.1 version.  Definitions of symbols with explicit
   versions should look like:
	versioned_symbol (libm, new_foo, foo, GLIBC_2_1);
   This will define the symbol `foo' with the appropriate default version,
   i.e. either GLIBC_2.1 or the "earliest version" specified in
   shlib-versions if that is newer.  */

# define versioned_symbol(lib, local, symbol, version) \
  versioned_symbol_1 (lib, local, symbol, version)
# define versioned_symbol_1(lib, local, symbol, version) \
  versioned_symbol_2 (local, symbol, VERSION_##lib##_##version)
# define versioned_symbol_2(local, symbol, name) \
  default_symbol_version (local, symbol, name)

# define compat_symbol(lib, local, symbol, version) \
  compat_symbol_1 (lib, local, symbol, version)
# define compat_symbol_1(lib, local, symbol, version) \
  compat_symbol_2 (local, symbol, VERSION_##lib##_##version)
# define compat_symbol_2(local, symbol, name) \
  symbol_version (local, symbol, name)

#else

/* Not compiling ELF shared libraries at all, so never any old versions.  */
# define SHLIB_COMPAT(lib, introduced, obsoleted)	0

/* No versions to worry about, just make this the global definition.  */
# define versioned_symbol(lib, local, symbol, version) \
  weak_alias (local, symbol)

/* This should not appear outside `#if SHLIB_COMPAT (...)'.  */
# define compat_symbol(lib, local, symbol, version) ...

#endif


# ifdef LINK_OBSOLETE_RPC
/* Export the symbol for both static and dynamic linking.  */
#  define libc_sunrpc_symbol(name, aliasname, version) \
  strong_alias (name, aliasname)
# else
/* Export the symbol only for shared-library compatibility.  */
#  define libc_sunrpc_symbol(name, aliasname, version) \
  compat_symbol (libc, name, aliasname, version);
# endif

#endif	/* shlib-compat.h */
