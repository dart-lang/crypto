// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'package:convert/convert.dart';

/// A message digest as computed by a [Hash] or [HMAC] function.
class Digest {
  /// The message digest as an array of bytes.
  final List<int> bytes;

  Digest(this.bytes);

  /// Returns whether this is equal to another digest.
  ///
  /// This should be used instead of manual comparisons to avoid leaking
  /// information via timing.
  bool operator ==(Object other) {
    if (other is! Digest) return false;

    var digest = other as Digest;
    if (digest.bytes.length != bytes.length) return false;

    var result = 0;
    for (var i = 0; i < bytes.length; i++) {
      result |= bytes[i] ^ digest.bytes[i];
    }
    return result == 0;
  }

  /// The message digest as a string of hexadecimal digits.
  String toString() => hex.encode(bytes);
}
