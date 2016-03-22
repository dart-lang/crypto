// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'decoder.dart';

/// This is deprecated.
///
/// Use the `Base64Decoder` class in `dart:convert` instead.
@Deprecated("Will be removed in crypto 1.0.0.")
class Base64DecoderSink extends ChunkedConversionSink<String> {
  /// The encoder used to decode each chunk.
  final Base64Decoder _decoder = new Base64Decoder();

  /// The underlying sink to which to emit the decoded strings.
  final ChunkedConversionSink<List<int>> _outSink;

  /// The as-yet-unconverted text.
  ///
  /// This is used to handle text stopping partway through a four-character
  /// 32-bit chunk.
  String _unconverted = "";

  Base64DecoderSink(this._outSink);

  void add(String chunk) {
    if (chunk.isEmpty) return;
    if (_unconverted.isNotEmpty) chunk = _unconverted + chunk;
    chunk = chunk.replaceAll("%3D", "=");

    // The decodable length is the length of the initial substring comprising
    // full four-character 32-bit chunks. Any leftovers are handled when [add]
    // or [close] are next called.
    var decodableLength = chunk.length;
    if (chunk.length > 3 && chunk.contains("%", chunk.length - 2)) {
      decodableLength = chunk.lastIndexOf("%");
    }
    decodableLength -= decodableLength % 4;

    _unconverted = chunk.substring(decodableLength);
    if (decodableLength > 0) {
      _outSink.add(_decoder.convert(chunk.substring(0, decodableLength)));
    }
  }

  void close() {
    if (_unconverted.isNotEmpty) _outSink.add(_decoder.convert(_unconverted));
    _outSink.close();
  }
}
