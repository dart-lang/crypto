// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'digest.dart';
import 'digest_sink.dart';

/// An interface for cryptographic hash functions.
///
/// Every hash is a converter that takes a list of ints and returns a single
/// digest. When used in chunked mode, it will only ever add one digest to the
/// inner [Sink].
abstract class Hash extends Converter<List<int>, Digest> {
  /// The internal block size of the hash in bytes.
  ///
  /// This is exposed for use by the [HMAC] class, which needs to know the block
  /// size for the [Hash] it uses.
  int get blockSize;

  /// The sink for implementing the deprecated APIs that involved adding data
  /// directly to the [Hash] instance.
  ByteConversionSink _sink;

  /// The sink that [_sink] sends the [Digest] to once it finishes hashing.
  final DigestSink _innerSink = new DigestSink();

  Hash() {
    _sink = startChunkedConversion(_innerSink);
  }

  Digest convert(List<int> data) {
    var innerSink = new DigestSink();
    var outerSink = startChunkedConversion(innerSink);
    outerSink.add(data);
    outerSink.close();
    return innerSink.value;
  }

  ByteConversionSink startChunkedConversion(Sink<Digest> sink);

  /// Returns a new instance of this hash function.
  @Deprecated("Expires in 1.0.0. Use Hash.startChunkedConversion() instead.")
  Hash newInstance();

  /// Add a list of bytes to the hash computation.
  ///
  /// If [this] has already been closed, throws a [StateError].
  @Deprecated("Expires in 1.0.0. Use Hash.convert() or "
      "Hash.startChunkedConversion() instead.")
  void add(List<int> data) => _sink.add(data);

  /// Finish the hash computation and extract the message digest as a list of
  /// bytes.
  @Deprecated("Expires in 1.0.0. Use Hash.convert() or "
      "Hash.startChunkedConversion() instead.")
  List<int> close() {
    _sink.close();
    return _innerSink.value.bytes;
  }
}
