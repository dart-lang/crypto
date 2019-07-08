// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'digest.dart';
import 'hash.dart';
import 'hash_sink.dart';
import 'utils.dart';

/// An instance of [Sha2Sha384].
///
/// This instance provides convenient access to the [Sha384][rfc] hash function.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
final sha384 = Sha384._();

/// An instance of [Sha2Sha512].
///
/// This instance provides convenient access to the [Sha512][rfc] hash function.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
final sha512 = Sha512._();

/// An implementation of the [SHA-384][rfc] hash function.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
///
/// Note that it's almost always easier to use [sha384] rather than creating a
/// new instance.
class Sha384 extends Hash {
  @override
  final int blockSize = 16 * bytesPerWord;

  Sha384._();

  Sha384 newInstance() => Sha384._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(_Sha384Sink(sink));
}

/// An implementation of the [SHA-512][rfc] hash function.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
///
/// Note that it's almost always easier to use [sha512] rather than creating a
/// new instance.
class Sha512 extends Sha384 {
  Sha512._() : super._();

  Sha512 newInstance() => Sha512._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(_Sha512Sink(sink));
}

BigInt _bigFromTwo(int high, int low) =>
    (BigInt.from(high) << 32) | BigInt.from(low);

/// Data from a non-linear function that functions as reproducible noise.
///
/// [rfc]: https://tools.ietf.org/html/rfc6234#section-5.2
final List<BigInt> _noise = [
  _bigFromTwo(0x428a2f98, 0xd728ae22), _bigFromTwo(0x71374491, 0x23ef65cd), //
  _bigFromTwo(0xb5c0fbcf, 0xec4d3b2f), _bigFromTwo(0xe9b5dba5, 0x8189dbbc),
  _bigFromTwo(0x3956c25b, 0xf348b538), _bigFromTwo(0x59f111f1, 0xb605d019),
  _bigFromTwo(0x923f82a4, 0xaf194f9b), _bigFromTwo(0xab1c5ed5, 0xda6d8118),
  _bigFromTwo(0xd807aa98, 0xa3030242), _bigFromTwo(0x12835b01, 0x45706fbe),
  _bigFromTwo(0x243185be, 0x4ee4b28c), _bigFromTwo(0x550c7dc3, 0xd5ffb4e2),
  _bigFromTwo(0x72be5d74, 0xf27b896f), _bigFromTwo(0x80deb1fe, 0x3b1696b1),
  _bigFromTwo(0x9bdc06a7, 0x25c71235), _bigFromTwo(0xc19bf174, 0xcf692694),
  _bigFromTwo(0xe49b69c1, 0x9ef14ad2), _bigFromTwo(0xefbe4786, 0x384f25e3),
  _bigFromTwo(0x0fc19dc6, 0x8b8cd5b5), _bigFromTwo(0x240ca1cc, 0x77ac9c65),
  _bigFromTwo(0x2de92c6f, 0x592b0275), _bigFromTwo(0x4a7484aa, 0x6ea6e483),
  _bigFromTwo(0x5cb0a9dc, 0xbd41fbd4), _bigFromTwo(0x76f988da, 0x831153b5),
  _bigFromTwo(0x983e5152, 0xee66dfab), _bigFromTwo(0xa831c66d, 0x2db43210),
  _bigFromTwo(0xb00327c8, 0x98fb213f), _bigFromTwo(0xbf597fc7, 0xbeef0ee4),
  _bigFromTwo(0xc6e00bf3, 0x3da88fc2), _bigFromTwo(0xd5a79147, 0x930aa725),
  _bigFromTwo(0x06ca6351, 0xe003826f), _bigFromTwo(0x14292967, 0x0a0e6e70),
  _bigFromTwo(0x27b70a85, 0x46d22ffc), _bigFromTwo(0x2e1b2138, 0x5c26c926),
  _bigFromTwo(0x4d2c6dfc, 0x5ac42aed), _bigFromTwo(0x53380d13, 0x9d95b3df),
  _bigFromTwo(0x650a7354, 0x8baf63de), _bigFromTwo(0x766a0abb, 0x3c77b2a8),
  _bigFromTwo(0x81c2c92e, 0x47edaee6), _bigFromTwo(0x92722c85, 0x1482353b),
  _bigFromTwo(0xa2bfe8a1, 0x4cf10364), _bigFromTwo(0xa81a664b, 0xbc423001),
  _bigFromTwo(0xc24b8b70, 0xd0f89791), _bigFromTwo(0xc76c51a3, 0x0654be30),
  _bigFromTwo(0xd192e819, 0xd6ef5218), _bigFromTwo(0xd6990624, 0x5565a910),
  _bigFromTwo(0xf40e3585, 0x5771202a), _bigFromTwo(0x106aa070, 0x32bbd1b8),
  _bigFromTwo(0x19a4c116, 0xb8d2d0c8), _bigFromTwo(0x1e376c08, 0x5141ab53),
  _bigFromTwo(0x2748774c, 0xdf8eeb99), _bigFromTwo(0x34b0bcb5, 0xe19b48a8),
  _bigFromTwo(0x391c0cb3, 0xc5c95a63), _bigFromTwo(0x4ed8aa4a, 0xe3418acb),
  _bigFromTwo(0x5b9cca4f, 0x7763e373), _bigFromTwo(0x682e6ff3, 0xd6b2b8a3),
  _bigFromTwo(0x748f82ee, 0x5defb2fc), _bigFromTwo(0x78a5636f, 0x43172f60),
  _bigFromTwo(0x84c87814, 0xa1f0ab72), _bigFromTwo(0x8cc70208, 0x1a6439ec),
  _bigFromTwo(0x90befffa, 0x23631e28), _bigFromTwo(0xa4506ceb, 0xde82bde9),
  _bigFromTwo(0xbef9a3f7, 0xb2c67915), _bigFromTwo(0xc67178f2, 0xe372532b),
  _bigFromTwo(0xca273ece, 0xea26619c), _bigFromTwo(0xd186b8c7, 0x21c0c207),
  _bigFromTwo(0xeada7dd6, 0xcde0eb1e), _bigFromTwo(0xf57d4f7f, 0xee6ed178),
  _bigFromTwo(0x06f067aa, 0x72176fba), _bigFromTwo(0x0a637dc5, 0xa2c898a6),
  _bigFromTwo(0x113f9804, 0xbef90dae), _bigFromTwo(0x1b710b35, 0x131c471b),
  _bigFromTwo(0x28db77f5, 0x23047d84), _bigFromTwo(0x32caab7b, 0x40c72493),
  _bigFromTwo(0x3c9ebe0a, 0x15c9bebc), _bigFromTwo(0x431d67c4, 0x9c100d4c),
  _bigFromTwo(0x4cc5d4be, 0xcb3e42b6), _bigFromTwo(0x597f299c, 0xfc657e2a),
  _bigFromTwo(0x5fcb6fab, 0x3ad6faec), _bigFromTwo(0x6c44198c, 0x4a475817),
];

/// The concrete implementation of [Sha384].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members.
class _Sha384Sink extends HashSink {
  @override
  Uint32List get digest {
    var ret = Uint32List(12);
    for (int i = 0; i < 6; i++) {
      ret[i * 2] = (_digest[i] >> 32).toUnsigned(32).toInt();
      ret[i * 2 + 1] = (_digest[i]).toUnsigned(32).toInt();
    }
    return ret;
  }

  // Initial value of the hash parts. First 64 bits of the fractional parts
  // of the square roots of the ninth through sixteenth prime numbers.
  final List<BigInt> _digest;

  /// The sixteen words from the original chunk, extended to 64 words.
  ///
  /// This is an instance variable to avoid re-allocating, but its data isn't
  /// used across invocations of [updateHash].
  final List<BigInt> _extended;

  _Sha384Sink(Sink<Digest> sink, {List<BigInt> digestInit})
      : _extended = List<BigInt>(80),
        _digest = digestInit ??
            [
              _bigFromTwo(0xcbbb9d5d, 0xc1059ed8),
              _bigFromTwo(0x629a292a, 0x367cd507),
              _bigFromTwo(0x9159015a, 0x3070dd17),
              _bigFromTwo(0x152fecd8, 0xf70e5939),
              _bigFromTwo(0x67332667, 0xffc00b31),
              _bigFromTwo(0x8eb44a87, 0x68581511),
              _bigFromTwo(0xdb0c2e0d, 0x64f98fa7),
              _bigFromTwo(0x47b5481d, 0xbefa4fa4),
            ],
        super(sink, 32);

  // The following helper functions are taken directly from
  // http://tools.ietf.org/html/rfc6234.

  static final _mask64 =
      (BigInt.from(0xFFFFFFFF) << 32) | BigInt.from(0xFFFFFFFF);

  BigInt _rotr64(int n, BigInt x) => (x >> n) | ((x << (64 - n)) & _mask64);
  BigInt _ch(BigInt x, BigInt y, BigInt z) => (x & y) ^ ((~x & _mask64) & z);
  BigInt _maj(BigInt x, BigInt y, BigInt z) => (x & y) ^ (x & z) ^ (y & z);
  BigInt _bsig0(BigInt x) => _rotr64(28, x) ^ _rotr64(34, x) ^ _rotr64(39, x);
  BigInt _bsig1(BigInt x) => _rotr64(14, x) ^ _rotr64(18, x) ^ _rotr64(41, x);
  BigInt _ssig0(BigInt x) => _rotr64(1, x) ^ _rotr64(8, x) ^ (x >> 7);
  BigInt _ssig1(BigInt x) => _rotr64(19, x) ^ _rotr64(61, x) ^ (x >> 6);

  BigInt _add64(BigInt x, BigInt y) => (x + y) & _mask64;

  @override
  void updateHash(Uint32List chunk) {
    assert(chunk.length == 32);

    // Prepare message schedule.
    for (var i = 0; i < 16; i++) {
      _extended[i] = _bigFromTwo(chunk[i * 2], chunk[i * 2 + 1]);
    }
    for (var i = 16; i < 80; i++) {
      _extended[i] = _add64(_add64(_ssig1(_extended[i - 2]), _extended[i - 7]),
          _add64(_ssig0(_extended[i - 15]), _extended[i - 16]));
    }

    // Shuffle around the bits.
    var a = _digest[0];
    var b = _digest[1];
    var c = _digest[2];
    var d = _digest[3];
    var e = _digest[4];
    var f = _digest[5];
    var g = _digest[6];
    var h = _digest[7];

    for (var i = 0; i < 80; i++) {
      var temp1 = _add64(_add64(h, _bsig1(e)),
          _add64(_ch(e, f, g), _add64(_noise[i], _extended[i])));
      var temp2 = _add64(_bsig0(a), _maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = _add64(d, temp1);
      d = c;
      c = b;
      b = a;
      a = _add64(temp1, temp2);
    }

    // Update hash values after iteration.
    _digest[0] = _add64(a, _digest[0]);
    _digest[1] = _add64(b, _digest[1]);
    _digest[2] = _add64(c, _digest[2]);
    _digest[3] = _add64(d, _digest[3]);
    _digest[4] = _add64(e, _digest[4]);
    _digest[5] = _add64(f, _digest[5]);
    _digest[6] = _add64(g, _digest[6]);
    _digest[7] = _add64(h, _digest[7]);
  }
}

/// The concrete implementation of [Sha512].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members.
class _Sha512Sink extends _Sha384Sink {
  _Sha512Sink(Sink<Digest> sink)
      : super(sink, digestInit: [
          // Initial value of the hash parts. First 64 bits of the fractional
          // parts of the square roots of the first eight prime numbers.
          _bigFromTwo(0x6a09e667, 0xf3bcc908),
          _bigFromTwo(0xbb67ae85, 0x84caa73b),
          _bigFromTwo(0x3c6ef372, 0xfe94f82b),
          _bigFromTwo(0xa54ff53a, 0x5f1d36f1),
          _bigFromTwo(0x510e527f, 0xade682d1),
          _bigFromTwo(0x9b05688c, 0x2b3e6c1f),
          _bigFromTwo(0x1f83d9ab, 0xfb41bd6b),
          _bigFromTwo(0x5be0cd19, 0x137e2179),
        ]);

  @override
  Uint32List get digest {
    var ret = Uint32List(16);
    for (int i = 0; i < 8; i++) {
      ret[i * 2] = (_digest[i] >> 32).toUnsigned(32).toInt();
      ret[i * 2 + 1] = (_digest[i]).toUnsigned(32).toInt();
    }
    return ret;
  }
}
