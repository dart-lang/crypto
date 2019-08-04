// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:math';
import 'dart:typed_data';

import 'digest.dart';
import 'hash.dart';
import 'hash_sink.dart';
import 'hmac.dart';
import 'sha1.dart';

/// An instance of [PBKDF2].
///
/// This instance provides convenient access to the [PBKDF2][rfc] key derivation functions function
/// with sha1 as default hashing / Hmac algorithm.
///
/// [rfc]: https://tools.ietf.org/html/rfc2898
///
final pbkdf2 = PBKDF2._();

/// An implementation of the [PBKDF2][rfc] hash function.
///
/// [rfc]: https://tools.ietf.org/html/rfc1321
///
/// Note that it's almost always easier to use [pbkdf2] rather than creating a new
/// instance.
class PBKDF2 {
  Hash _prf;

  PBKDF2([Hash prf]) {
    this._prf = prf ?? sha1;
  }

  static PBKDF2 _() {
    return PBKDF2();
  }

  Digest process(List<int> password, List<int> salt, int rounds, int dkLen) {
    final int hLen = _prf.convert([]).bytes.length;

    if (dkLen > (pow(2, 32) - 1) * hLen) {
      throw UnsupportedError('Length of derived key too long');
    }

    final int l = (dkLen / hLen)
        .ceil(); // number of hLen-octet blocks in the derived key, rounding up
    final Hmac hash = Hmac(_prf, password);
    final Uint8List key = Uint8List(dkLen);
    final Uint8List inputBuffer = Uint8List(salt.length + 4)
      ..setRange(0, salt.length, salt);

    int offset = 0;
    for (var blockNumber = 1; blockNumber <= l; blockNumber++) {
      inputBuffer[salt.length] = blockNumber >> 24;
      inputBuffer[salt.length + 1] = blockNumber >> 16;
      inputBuffer[salt.length + 2] = blockNumber >> 8;
      inputBuffer[salt.length + 3] = blockNumber;

      Uint8List block = _PBKDF2DigestSink.generate(inputBuffer, rounds, hash);
      int blockLength = hLen;
      if (offset + blockLength > dkLen) {
        blockLength = dkLen - offset;
      }
      key.setRange(offset, offset + blockLength, block);

      offset += blockLength;
    }
    return Digest(key);
  }
}

/// The concrete implementation of [PBKDF2].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members.
class _PBKDF2DigestSink extends Sink<Digest> {
  Digest _value;
  Uint8List bytes;

  _PBKDF2DigestSink(Uint8List inputBuffer, Hmac hash) {
    _value = hash.convert(inputBuffer);
    bytes = Uint8List(_value.bytes.length)
      ..setRange(0, _value.bytes.length, _value.bytes);
  }

  static Uint8List generate(Uint8List inputBuffer, int rounds, Hmac hash) {
    _PBKDF2DigestSink innerSink = _PBKDF2DigestSink(inputBuffer, hash);

    // The first round runs in the constructor.
    for (int round = 1; round < rounds; round++) {
      var outerSink = hash.startChunkedConversion(innerSink);
      outerSink.add(innerSink._value.bytes);
      outerSink.close();
    }

    return innerSink.bytes.buffer.asUint8List();
  }

  /// The value added to the sink, if any.
  Digest get value {
    return _value;
  }

  @override
  void add(Digest value) {
    _value = value;
    for (var i = 0; i < value.bytes.length; i++) {
      bytes[i] = bytes[i] ^ _value.bytes[i];
    }
  }

  @override
  void close() {}
}
