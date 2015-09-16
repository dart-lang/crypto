// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.utils;

// Constants.
const MASK_8 = 0xff;
const MASK_32 = 0xffffffff;
const BITS_PER_BYTE = 8;
const BYTES_PER_WORD = 4;

// Helper methods.
int add32(x, y) => (x + y) & MASK_32;

int roundUp(val, n) => (val + n - 1) & -n;

// Helper functions used by more than one hasher.

// Rotate left limiting to unsigned 32-bit values.
int rotl32(int val, int shift) {
  var mod_shift = shift & 31;
  return ((val << mod_shift) & MASK_32) |
      ((val & MASK_32) >> (32 - mod_shift));
}
