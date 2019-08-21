// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

void main() {
  group('randomBytes', () {
    test('returns an Uint8List of specified length', () {
      const int length = 8;
      Uint8List randomByteArray = randomBytes(length);

      expect(randomByteArray.length, equals(length));
    });
  });
}
