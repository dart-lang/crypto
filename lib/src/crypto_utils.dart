// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'base64.dart';

/// Utility methods for working with message digests.
abstract class CryptoUtils {
  /// Convert a list of bytes (for example a message digest) into a hexadecimal
  /// string.
  static String bytesToHex(List<int> bytes) {
    var result = new StringBuffer();
    for (var part in bytes) {
      result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
    }
    return result.toString();
  }

  /// Converts a list of bytes into a [Base64-encoded][rfc] string.
  ///
  /// [rfc]: https://tools.ietf.org/html/rfc4648
  ///
  /// The list can be any list of integers from 0 to 255 inclusive, for example
  /// a message digest.
  ///
  /// If [addLineSeparator] is true, the resulting string will  be
  /// broken into lines of 76 characters, separated by "\r\n".
  ///
  /// If [urlSafe] is true, the resulting string will be URL- and filename-
  /// safe.
  static String bytesToBase64(List<int> bytes,
          {bool urlSafe: false, bool addLineSeparator: false}) =>
      BASE64.encode(bytes,
          urlSafe: urlSafe, addLineSeparator: addLineSeparator);

  /// Converts a [Base64-encoded][rfc] String into list of bytes.
  ///
  /// [rfc]: https://tools.ietf.org/html/rfc4648
  ///
  /// This ignores "\r\n" sequences in [input]. It accepts both URL-safe and
  /// -unsafe Base 64 encoded strings.
  ///
  /// Throws a [FormatException] if [input] contains invalid characters.
  static List<int> base64StringToBytes(String input) => BASE64.decode(input);
}
