// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'base64.dart';

/// This class is deprecated.
@Deprecated("Will be removed in crypto 1.0.0.")
abstract class CryptoUtils {
  /// This is deprecated.
  ///
  /// Use `hex` from `package:convert` instead.
  static String bytesToHex(List<int> bytes) {
    var result = new StringBuffer();
    for (var part in bytes) {
      result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
    }
    return result.toString();
  }

  /// This is deprecated.
  ///
  /// Use `BASE64` from `dart:convert` instead.
  static String bytesToBase64(List<int> bytes,
          {bool urlSafe: false, bool addLineSeparator: false}) =>
      BASE64.encode(bytes,
          urlSafe: urlSafe, addLineSeparator: addLineSeparator);

  /// This is deprecated.
  ///
  /// Use `BASE64` from `dart:convert` instead.
  static List<int> base64StringToBytes(String input) => BASE64.decode(input);
}
