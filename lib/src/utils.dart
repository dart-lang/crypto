// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.utils;

/// A bitmask that limits an integer to 8 bits.
const MASK_8 = 0xff;

/// A bitmask that limits an integer to 32 bits.
const MASK_32 = 0xffffffff;

/// The number of bits in a byte.
const BITS_PER_BYTE = 8;

/// The number of bytes in a 32-bit word.
const BYTES_PER_WORD = 4;

/// Adds [x] and [y] with 32-bit overflow semantics.
int add32(x, y) => (x + y) & MASK_32;

/// Bitwise rotates [val] to the left by [shift], obeying 32-bit overflow
/// semantics.
int rotl32(int val, int shift) {
  var mod_shift = shift & 31;
  return ((val << mod_shift) & MASK_32) |
      ((val & MASK_32) >> (32 - mod_shift));
}
