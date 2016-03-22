// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'package:charcode/ascii.dart';

import 'encoder_sink.dart';

/// A String representing a mapping from numbers between 0 and 63, inclusive, to
/// their corresponding encoded character.
///
/// This is the table for URL-safe encodings.
const _encodeTableUrlSafe =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A String representing a mapping from numbers between 0 and 63, inclusive, to
/// their corresponding encoded character.
///
/// This is the table for URL-unsafe encodings.
const _encodeTable =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The line length for Base64 strings with line separators.
const _lineLength = 76;

/// This is deprecated.
///
/// Use the `Base64Encoder` class in `dart:convert` instead.
@Deprecated("Will be removed in crypto 1.0.0.")
class Base64Encoder extends Converter<List<int>, String> {
  /// Whether this encoder generates URL-safe strings.
  final bool _urlSafe;

  /// Whether this encoder adds line breaks to the output.
  final bool _addLineSeparator;

  /// The sequence of bytes to use as a padding character.
  final List<int> _pad;

  /// Creates a new [Base64Encoder].
  ///
  /// The default [BASE64.encoder] will be good enough for most cases. A new
  /// codec only needs to be instantiated when you want to do multiple
  /// conversions with the same configuration.
  ///
  /// If [urlSafe] is `true`, a URL-safe alphabet will be used. Specifically,
  /// the characters `-` and `_` will be used instead of `+` and `/`.
  ///
  /// If [addLineSeparator] is `true`, `\r\n` line separators will be added
  /// every 76 characters.
  ///
  /// If [encodePaddingCharacter] is `true`, the padding character `=` will be
  /// written as `%3D`.
  const Base64Encoder(
      {bool urlSafe: false,
      bool addLineSeparator: false,
      bool encodePaddingCharacter: false})
      : _urlSafe = urlSafe,
        _addLineSeparator = addLineSeparator,
        _pad = encodePaddingCharacter
            ? const [$percent, $3, $D]
            : const [$equal];

  /// Converts [bytes] to Base64.
  ///
  /// If [start] and [end] are provided, only the sublist `bytes.sublist(start,
  /// end)` is converted.
  String convert(List<int> bytes, [int start = 0, int end]) {
    RangeError.checkValidRange(start, end, bytes.length);
    if (end == null) end = bytes.length;

    var length = end - start;
    if (length == 0) return "";

    var lookup = _urlSafe ? _encodeTableUrlSafe : _encodeTable;

    // The total length of the 24-bit chunks.
    var remainderLength = length.remainder(3);
    var chunkLength = length - remainderLength;

    // The size of the base output.
    var baseOutputLength = (length ~/ 3) * 4;
    var remainderOutputLength = remainderLength > 0 ? 3 + _pad.length : 0;

    var outputLength = baseOutputLength + remainderOutputLength;
    if (_addLineSeparator) {
      // Add extra expected length to account for line separators.
      outputLength += ((outputLength - 1) ~/ _lineLength) * 2;
    }
    var out = new List<int>(outputLength);

    // Encode 24 bit chunks.
    var input = start;
    var output = 0;
    var chunks = 0;
    while (input < chunkLength) {
      // Get a 24-bit chunk from the next three input bytes. Mask each byte to
      // make sure we don't do something bad if the user passes in non-byte
      // ints.
      var chunk = (bytes[input++] << 16) & 0x00FF0000;
      chunk    |= (bytes[input++] << 8)  & 0x0000FF00;
      chunk    |=  bytes[input++]        & 0x000000FF;

      // Split the 24-bit chunk into four 6-bit sections to encode as
      // characters.
      out[output++] = lookup.codeUnitAt(chunk >> 18);
      out[output++] = lookup.codeUnitAt((chunk >> 12) & 0x3F);
      out[output++] = lookup.codeUnitAt((chunk >> 6) & 0x3F);
      out[output++] = lookup.codeUnitAt(chunk & 0x3F);

      // Add an optional line separator for every 76 characters we emit; that
      // is, every 19 chunks.
      chunks++;
      if (_addLineSeparator && chunks == 19 && output < outputLength - 2) {
        out[output++] = $cr;
        out[output++] = $lf;
        chunks = 0;
      }
    }

    // If the input length isn't a multiple of 3, encode the remaining bytes and
    // add padding.
    if (remainderLength == 1) {
      var byte = bytes[input];
      out[output++] = lookup.codeUnitAt(byte >> 2);
      out[output++] = lookup.codeUnitAt((byte << 4) & 0x3F);
      out.setRange(output, output + _pad.length, _pad);
      out.setRange(output + _pad.length, output + 2 * _pad.length, _pad);
    } else if (remainderLength == 2) {
      var byte1 = bytes[input++];
      var byte2 = bytes[input];
      out[output++] = lookup.codeUnitAt(byte1 >> 2);
      out[output++] = lookup.codeUnitAt(((byte1 << 4) | (byte2 >> 4)) & 0x3F);
      out[output++] = lookup.codeUnitAt((byte2 << 2) & 0x3F);
      out.setRange(output, output + _pad.length, _pad);
    }

    return new String.fromCharCodes(out);
  }

  Base64EncoderSink startChunkedConversion(Sink<String> sink) {
    StringConversionSink stringSink = sink is StringConversionSink
        ? sink
        : new StringConversionSink.from(sink);

    return new Base64EncoderSink(stringSink, _urlSafe, _addLineSeparator);
  }
}
