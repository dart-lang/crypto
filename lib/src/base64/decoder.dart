// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:charcode/ascii.dart';

import 'decoder_sink.dart';

/// A mapping from ASCII character codes to their corresponding Base64 values.
///
/// Characters with a value of `null` can't be decoded directly. This includes
/// special values like CR, LF, `=`, and `%`.
const _decodeTable = const [
  null, null, null, null, null, null, null, null, null, null, null, null, null,
  null, null, null, null, null, null, null, null, null, null, null, null, null,
  null, null, null, null, null, null, null, null, null, null, null, null, null,
  null, null, null, null, 62, null, 62, null, 63, 52, 53, 54, 55, 56, 57, 58,
  59, 60, 61, null, null, null, null, null, null, null, 0, 1, 2, 3, 4, 5, 6, 7,
  8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, null,
  null, null, null, 63, null, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
  38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
];

/// This is deprecated.
///
/// Use the `Base64Decoder` class in `dart:convert` instead.
@Deprecated("Will be removed in crypto 1.0.0.")
class Base64Decoder extends Converter<String, List<int>> {
  const Base64Decoder();

  List<int> convert(String input) {
    if (input.length == 0) return new Uint8List(0);

    // The length of the actual data sections in the input (not CRLFs).
    var dataLength = 0;

    // Count the data, and fail for invalid characters.
    for (var i = 0; i < input.length; i++) {
      var codeUnit = input.codeUnitAt(i);

      if (codeUnit == $cr || codeUnit == $lf) continue;

      if (codeUnit == $percent &&
          i < input.length - 2 &&
          input.codeUnitAt(i + 1) == $3 &&
          input.codeUnitAt(i + 2) == $D) {
        dataLength++;
        i += 2;
        continue;
      }

      if (codeUnit != $equal &&
          (codeUnit >= _decodeTable.length || _decodeTable[codeUnit] == null)) {
        throw new FormatException('Invalid character', input, i);
      }

      dataLength++;
    }

    if (dataLength % 4 != 0) {
      throw new FormatException(
          'Base64 input must encode a multiple of 4 bytes.',
          input,
          dataLength);
    }

    // Count the trailing pad characters.
    var padLength = 0;
    for (var i = input.length - 1; i >= 0; i--) {
      var codeUnit = input.codeUnitAt(i);
      if (codeUnit == $D &&
          i >= 2 &&
          input.codeUnitAt(i - 2) == $percent &&
          input.codeUnitAt(i - 1) == $3) {
        padLength++;
        i -= 2;
      } else if (codeUnit == $equal) {
        padLength++;
      } else if (codeUnit != $cr && codeUnit != $lf) {
        break;
      }
    }
    var outputLength = ((dataLength * 6) >> 3) - padLength;
    var out = new Uint8List(outputLength);

    var inputIndex = 0;
    var outputIndex = 0;
    while (outputIndex < outputLength) {
      // Accumulate four 6-bit Base64 characters into a 32-bit chunk.
      var chunk = 0;
      for (var i = 0; i < 4; i++) {
        var codeUnit = input.codeUnitAt(inputIndex++);

        if (codeUnit == $equal || codeUnit == $percent) {
          // We've reached the end of the source. Pad out the rest of the chunk
          // with zeroes.
          chunk <<= (4 - i) * 6;
          break;
        }

        if (codeUnit == $cr || codeUnit == $lf) {
          i--;
        } else {
          chunk = (chunk << 6) | _decodeTable[codeUnit];
        }
      }

      // Emit 8-bit pieces of the chunk to the output buffer.
      out[outputIndex++] = chunk >> 16;
      if (outputIndex >= outputLength) break;

      out[outputIndex++] = (chunk >> 8) & 0xFF;
      if (outputIndex >= outputLength) break;

      out[outputIndex++] = chunk & 0xFF;
    }

    return out;
  }

  Base64DecoderSink startChunkedConversion(Sink<List<int>> sink) {
    if (sink is! ByteConversionSink) sink = new ByteConversionSink.from(sink);
    return new Base64DecoderSink(sink);
  }
}
