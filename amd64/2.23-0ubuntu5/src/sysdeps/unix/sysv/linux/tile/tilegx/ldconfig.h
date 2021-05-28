/* Copyright (C) 2011-2016 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Chris Metcalf <cmetcalf@tilera.com>, 2011.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */

#include <sysdeps/generic/ldconfig.h>

#define SYSDEP_KNOWN_INTERPRETER_NAMES \
  { "/lib/ld.so.1", FLAG_ELF_LIBC6 },	\
  { "/lib32/ld.so.1", FLAG_ELF_LIBC6 },
#define SYSDEP_KNOWN_LIBRARY_NAMES \
  { "libc.so.6", FLAG_ELF_LIBC6 },	\
  { "libm.so.6", FLAG_ELF_LIBC6 },