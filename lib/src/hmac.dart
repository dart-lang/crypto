// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.hmac;

import 'hash.dart';

/// An implementation of [keyed-hash method authentication codes][rfc].
///
/// [rfc]: https://tools.ietf.org/html/rfc2104
///
/// HMAC allows messages to be cryptographically authenticated using any
/// iterated cryptographic hash function.
///
/// The message's data is added using [add]. Once it's been fully added, the
/// [digest] and [close] methods can be used to extract the message
/// authentication digest.
///
/// If an expected authentication digest is available, the [verify] method may
/// also be used to ensure that the message actually corresponds to that digest.
// TODO(floitsch): make HMAC implement Sink, EventSink or similar.
class HMAC {
  /// The bytes from the message so far.
  final List<int> _message;

  /// The hash function used to compute the authentication digest.
  Hash _hash;

  /// The secret key shared by the sender and the receiver.
  List<int> _key;

  /// Whether this is closed.
  bool _isClosed = false;

  /// Create an [HMAC] object from a [Hash] and a binary key.
  ///
  /// The key should be a secret shared between the sender and receiver of the
  /// message.
  HMAC(Hash this._hash, List<int> this._key) : _message = [];

  /// Adds a list of bytes to the message.
  ///
  /// If [this] has already been closed, throws a [StateError].
  void add(List<int> data) {
    if (_isClosed) throw new StateError("HMAC is closed");
    _message.addAll(data);
  }

  /// Returns the digest of the message so far, as a list of bytes.
  List<int> get digest {
    var blockSize = _hash.blockSize;

    // Hash the key if it is longer than the block size of the hash.
    if (_key.length > blockSize) {
      _hash = _hash.newInstance();
      _hash.add(_key);
      _key = _hash.close();
    }

    // Zero-pad the key until its size is equal to the block size of the hash.
    if (_key.length < blockSize) {
      var newKey = new List(blockSize);
      newKey.setRange(0, _key.length, _key);
      for (var i = _key.length; i < blockSize; i++) {
        newKey[i] = 0;
      }
      _key = newKey;
    }

    // Compute inner padding.
    var padding = new List(blockSize);
    for (var i = 0; i < blockSize; i++) {
      padding[i] = 0x36 ^ _key[i];
    }

    // Inner hash computation.
    _hash = _hash.newInstance();
    _hash.add(padding);
    _hash.add(_message);
    var innerHash = _hash.close();

    // Compute outer padding.
    for (var i = 0; i < blockSize; i++) {
      padding[i] = 0x5c ^ _key[i];
    }

    // Outer hash computation which is the result.
    _hash = _hash.newInstance();
    _hash.add(padding);
    _hash.add(innerHash);
    return _hash.close();
  }

  /// Closes [this] and returns the digest of the message as a list of bytes.
  ///
  /// Once closed, [add] may no longer be called.
  List<int> close() {
    _isClosed = true;
    return digest;
  }

  /// Returns whether the digest computed for the data so far matches the given
  /// [digest].
  ///
  /// This method should be used instead of iterative comparisons to avoid
  /// leaking information via timing.
  ///
  /// Throws an [ArgumentError] if the given digest does not have the same size
  /// as the digest computed by [this].
  bool verify(List<int> digest) {
    var computedDigest = this.digest;
    if (digest.length != computedDigest.length) {
      throw new ArgumentError(
          'Invalid digest size: ${digest.length} in HMAC.verify. '
          'Expected: ${_hash.blockSize}.');
    }
    int result = 0;
    for (var i = 0; i < digest.length; i++) {
      result |= digest[i] ^ computedDigest[i];
    }
    return result == 0;
  }
}
