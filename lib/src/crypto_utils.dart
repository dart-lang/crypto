// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.crypto_utils;

import 'base64.dart';

/**
 * Utility methods for working with message digests.
 */
abstract class CryptoUtils {
  /**
   * Convert a list of bytes (for example a message digest) into a hex
   * string.
   */
  static String bytesToHex(List<int> bytes) {
    var result = new StringBuffer();
    for (var part in bytes) {
      result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
    }
    return result.toString();
  }

  /**
   * Converts a list of bytes into a Base 64 encoded string.
   *
   * The list can be any list of integers in the range 0..255,
   * for example a message digest.
   *
   * If [addLineSeparator] is true, the resulting string will  be
   * broken into lines of 76 characters, separated by "\r\n".
   *
   * If [urlSafe] is true, the result is URL and filename safe.
   *
   * Based on [RFC 4648](http://tools.ietf.org/html/rfc4648)
   *
   */
  static String bytesToBase64(List<int> bytes,
      [bool urlSafe = false, bool addLineSeparator = false]) {
    return BASE64.encode(bytes,
        urlSafe: urlSafe, addLineSeparator: addLineSeparator);
  }

  /**
   * Converts a Base 64 encoded String into list of bytes.
   *
   * Decoder ignores "\r\n" sequences from input.
   *
   * Accepts both URL safe and unsafe Base 64 encoded strings.
   *
   * Throws a FormatException exception if input contains invalid characters.
   *
   * Based on [RFC 4648](http://tools.ietf.org/html/rfc4648)
   */
  static List<int> base64StringToBytes(String input) {
    return BASE64.decode(input);
  }
}
