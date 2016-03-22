// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'encoder.dart';

/// This is deprecated.
///
/// Use the `Base64Encoder` class in `dart:convert` instead.
@Deprecated("Will be removed in crypto 1.0.0.")
class Base64EncoderSink extends ChunkedConversionSink<List<int>> {
  /// The encoder used to encode each chunk.
  final Base64Encoder _encoder;

  /// The underlying sink to which to emit the encoded strings.
  final ChunkedConversionSink<String> _outSink;

  /// The buffer of as-yet-unconverted bytes.
  ///
  /// This is used to ensure that we don't generate interstitial padding
  /// characters.
  final _buffer = new List<int>();

  /// The length of [_buffer]; that is, the number of unconverted bytes.
  var _bufferCount = 0;

  Base64EncoderSink(this._outSink, urlSafe, addLineSeparator)
      : _encoder = new Base64Encoder(
            urlSafe: urlSafe, addLineSeparator: addLineSeparator);

  void add(List<int> chunk) {
    var nextBufferCount = (chunk.length + _bufferCount) % 3;
    var decodableLength = _bufferCount + chunk.length - nextBufferCount;

    if (_bufferCount + chunk.length > _buffer.length) {
      _buffer.replaceRange(_bufferCount, _buffer.length,
          chunk.sublist(0, _buffer.length - _bufferCount));
      _buffer.addAll(chunk.sublist(_buffer.length - _bufferCount));
    } else {
      _buffer.replaceRange(_bufferCount, _bufferCount + chunk.length, chunk);
    }

    _outSink.add(_encoder.convert(_buffer, 0, decodableLength));
    _buffer.removeRange(0, decodableLength);
    _bufferCount = nextBufferCount;
  }

  void close() {
    if (_bufferCount > 0) {
      _outSink.add(_encoder.convert(_buffer.sublist(0, _bufferCount)));
    }
    _outSink.close();
  }
}

