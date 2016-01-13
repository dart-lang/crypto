// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:typed_data/typed_data.dart';

import 'digest.dart';
import 'digest_sink.dart';
import 'hash.dart';

/// An implementation of [keyed-hash method authentication codes][rfc].
///
/// [rfc]: https://tools.ietf.org/html/rfc2104
///
/// HMAC allows messages to be cryptographically authenticated using any
/// iterated cryptographic hash function.
class HMAC extends Converter<List<int>, Digest> {
  /// The hash function used to compute the authentication digest.
  final Hash _hash;

  /// The secret key shared by the sender and the receiver.
  final Uint8List _key;

  /// The bytes from the message so far.
  final _message = new Uint8Buffer();

  /// The sink for implementing the deprecated APIs that involved adding data
  /// directly to the [HMAC] instance.
  _HmacSink _sink;

  /// The sink that [_sink] sends the [Digest] to once it finishes hashing.
  DigestSink _innerSink;

  /// Create an [HMAC] object from a [Hash] and a binary key.
  ///
  /// The key should be a secret shared between the sender and receiver of the
  /// message.
  HMAC(Hash hash, List<int> key)
      : _hash = hash,
        _key = new Uint8List(hash.blockSize) {
    // Hash the key if it's longer than the block size of the hash.
    if (key.length > _hash.blockSize) key = _hash.convert(key).bytes;

    // If [key] is shorter than the block size, the rest of [_key] will be
    // 0-padded.
    _key.setRange(0, key.length, key);

    _innerSink = new DigestSink();
    _sink = startChunkedConversion(_innerSink);
  }

  Digest convert(List<int> data) {
    var innerSink = new DigestSink();
    var outerSink = startChunkedConversion(innerSink);
    outerSink.add(data);
    outerSink.close();
    return innerSink.value;
  }

  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      new _HmacSink(sink, _hash, _key);

  /// Adds a list of bytes to the message.
  ///
  /// If [this] has already been closed, throws a [StateError].
  @Deprecated("Expires in 1.0.0. Use HMAC.convert() or "
      "HMAC.startChunkedConversion() instead.")
  void add(List<int> data) {
    _message.addAll(data);
    _sink.add(data);
  }

  /// Closes [this] and returns the digest of the message as a list of bytes.
  ///
  /// Once closed, [add] may no longer be called.
  @Deprecated("Expires in 1.0.0. Use HMAC.convert() or "
      "HMAC.startChunkedConversion() instead.")
  List<int> close() {
    _sink.close();
    return _innerSink.value.bytes;
  }

  /// Returns the digest of the message so far, as a list of bytes.
  @Deprecated("Expires in 1.0.0. Use HMAC.convert() or "
      "HMAC.startChunkedConversion() instead.")
  List<int> get digest {
    if (_sink._isClosed) return _innerSink.value.bytes;

    // This may be called at any point while the message is being hashed, but
    // the [_HmacSink] only supports getting the value once. To make this work,
    // we just re-hash everything after we get the digest. It's redundant, but
    // this API is deprecated anyway.
    _sink.close();
    var bytes = _innerSink.value.bytes;

    _innerSink = new DigestSink();
    _sink = _hash.startChunkedConversion(_innerSink);
    _sink.add(_message);

    return bytes;
  }

  /// Returns whether the digest computed for the data so far matches the given
  /// [digest].
  ///
  /// This method should be used instead of iterative comparisons to avoid
  /// leaking information via timing.
  ///
  /// Throws an [ArgumentError] if the given digest does not have the same size
  /// as the digest computed by [this].
  @Deprecated("Expires in 1.0.0. Use Digest.==() instead.")
  bool verify(List<int> digest) {
    var computedDigest = this.digest;
    if (digest.length != computedDigest.length) {
      throw new ArgumentError(
          'Invalid digest size: ${digest.length} in HMAC.verify. '
          'Expected: ${_hash.blockSize}.');
    }

    var result = 0;
    for (var i = 0; i < digest.length; i++) {
      result |= digest[i] ^ computedDigest[i];
    }
    return result == 0;
  }
}

/// The concrete implementation of the HMAC algorithm.
class _HmacSink extends ByteConversionSink {
  /// The sink for the outer hash computation.
  final ByteConversionSink _outerSink;

  /// The sink that [_innerSink]'s result will be added to when it's available.
  final _innerResultSink = new DigestSink();

  /// The sink for the inner hash computation.
  ByteConversionSink _innerSink;

  /// Whether [close] has been called.
  bool _isClosed = false;

  _HmacSink(Sink<Digest> sink, Hash hash, List<int> key)
      : _outerSink = hash.startChunkedConversion(sink) {
    _innerSink = hash.startChunkedConversion(_innerResultSink);

    // Compute outer padding.
    var padding = new Uint8List(key.length);
    for (var i = 0; i < padding.length; i++) {
      padding[i] = 0x5c ^ key[i];
    }
    _outerSink.add(padding);

    // Compute inner padding.
    for (var i = 0; i < padding.length; i++) {
      padding[i] = 0x36 ^ key[i];
    }
    _innerSink.add(padding);
  }

  void add(List<int> data) {
    if (_isClosed) throw new StateError("HMAC is closed");
    _innerSink.add(data);
  }

  void addSlice(List<int> data, int start, int end, bool isLast) {
    if (_isClosed) throw new StateError("HMAC is closed");
    _innerSink.addSlice(data, start, end, isLast);
  }

  void close() {
    if (_isClosed) return;
    _isClosed = true;

    _innerSink.close();
    _outerSink.add(_innerResultSink.value.bytes);
    _outerSink.close();
  }
}
