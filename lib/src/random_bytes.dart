// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.
import 'dart:math';
import 'dart:typed_data';

/// Generates a cryptographically secure random UInt8List of [length] bytes
Uint8List randomBytes(int length) {
  final Random random = Random.secure();
  final Uint8List randomBytesArray = Uint8List(length);

  for (int i = 0; i < length; i++) {
    randomBytesArray[i] = random.nextInt(256);
  }

  return randomBytesArray;
}
