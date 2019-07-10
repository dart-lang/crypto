// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'digest.dart';
import 'hash.dart';
import 'hash_sink.dart';
import 'utils.dart';

/// How optimized do you want to be? Answer: yes.
final bool _isJavascript = () {
  try {
    Uint64List(1);
    return false;
  } catch (e) {
    return true;
  }
}();

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
      ByteConversionSink.from(
          _isJavascript ? _Sha384SinkSlow(sink) : _Sha384SinkFast(sink));
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
      ByteConversionSink.from(
          _isJavascript ? _Sha512SinkSlow(sink) : _Sha512SinkFast(sink));
}

/// Data from a non-linear function that functions as reproducible noise.
///
/// [rfc]: https://tools.ietf.org/html/rfc6234#section-5.2
final _noise32 = Uint32List.fromList([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, //
  0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
  0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
  0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
  0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
  0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
  0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
  0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
  0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
  0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
  0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
  0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
  0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
  0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
]);

abstract class _Sha64BitSinkSlow extends HashSink {
  int get digestBytes;

  @override
  Uint32List get digest {
    return Uint32List.view(_digest.buffer, 0, digestBytes);
  }

  // Initial value of the hash parts. First 64 bits of the fractional parts
  // of the square roots of the ninth through sixteenth prime numbers.
  final Uint32List _digest;

  /// The sixteen words from the original chunk, extended to 64 words.
  ///
  /// This is an instance variable to avoid re-allocating, but its data isn't
  /// used across invocations of [updateHash].
  final _extended = Uint32List(160);

  _Sha64BitSinkSlow(Sink<Digest> sink, this._digest) : super(sink, 32);
  // The following helper functions are taken directly from
  // http://tools.ietf.org/html/rfc6234.

  _shr(int bits, Uint32List word, int offset, Uint32List ret, int offsetR) {
    ret[0 + offsetR] =
        ((bits < 32) && (bits >= 0)) ? (word[0 + offset] >> (bits)) : 0;
    ret[1 + offsetR] = (bits > 32)
        ? (word[0 + offset] >> (bits - 32))
        : (bits == 32)
            ? word[0 + offset]
            : (bits >= 0)
                ? ((word[0 + offset] << (32 - bits)) |
                    (word[1 + offset] >> bits))
                : 0;
  }

  _shl(int bits, Uint32List word, int offset, Uint32List ret, int offsetR) {
    ret[0 + offsetR] = (bits > 32)
        ? (word[1 + offset] << (bits - 32))
        : (bits == 32)
            ? word[1 + offset]
            : (bits >= 0)
                ? ((word[0 + offset] << bits) |
                    (word[1 + offset] >> (32 - bits)))
                : 0;
    ret[1 + offsetR] =
        ((bits < 32) && (bits >= 0)) ? (word[1 + offset] << bits) : 0;
  }

  _or(Uint32List word1, int offset1, Uint32List word2, int offset2,
      Uint32List ret, int offsetR) {
    ret[0 + offsetR] = word1[0 + offset1] | word2[0 + offset2];
    ret[1 + offsetR] = word1[1 + offset1] | word2[1 + offset2];
  }

  _xor(Uint32List word1, int offset1, Uint32List word2, int offset2,
      Uint32List ret, int offsetR) {
    ret[0 + offsetR] = word1[0 + offset1] ^ word2[0 + offset2];
    ret[1 + offsetR] = word1[1 + offset1] ^ word2[1 + offset2];
  }

  _add(Uint32List word1, int offset1, Uint32List word2, int offset2,
      Uint32List ret, int offsetR) {
    ret[1 + offsetR] = (word1[1 + offset1] + word2[1 + offset2]);
    ret[0 + offsetR] = word1[0 + offset1] +
        word2[0 + offset2] +
        (ret[1 + offsetR] < word1[1 + offset1] ? 1 : 0);
  }

  _addTo2(Uint32List word1, int offset1, Uint32List word2, int offset2) {
    int _addTemp;
    _addTemp = word1[1 + offset1];
    word1[1 + offset1] += word2[1 + offset2];
    word1[0 + offset1] +=
        word2[0 + offset2] + (word1[1 + offset1] < _addTemp ? 1 : 0);
  }

  final _rotrTemp1 = Uint32List(2);
  final _rotrTemp2 = Uint32List(2);
  // SHA rotate   ((word >> bits) | (word << (64-bits)))
  _rotr(int bits, Uint32List word, int offset, Uint32List ret, int offsetR) {
    _shr(bits, word, offset, _rotrTemp1, 0);
    _shl(64 - bits, word, offset, _rotrTemp2, 0);
    _or(_rotrTemp1, 0, _rotrTemp2, 0, ret, offsetR);
  }

  final _sigma0Temp1 = Uint32List(2);
  final _sigma0Temp2 = Uint32List(2);
  final _sigma0Temp3 = Uint32List(2);
  final _sigma0Temp4 = Uint32List(2);
  _bsig0(Uint32List word, int offset, Uint32List ret, int offsetR) {
    _rotr(28, word, offset, _sigma0Temp1, 0);
    _rotr(34, word, offset, _sigma0Temp2, 0);
    _rotr(39, word, offset, _sigma0Temp3, 0);
    _xor(_sigma0Temp2, 0, _sigma0Temp3, 0, _sigma0Temp4, 0);
    _xor(_sigma0Temp1, 0, _sigma0Temp4, 0, ret, offsetR);
  }

  final _sigma1Temp1 = Uint32List(2);
  final _sigma1Temp2 = Uint32List(2);
  final _sigma1Temp3 = Uint32List(2);
  final _sigma1Temp4 = Uint32List(2);
  _bsig1(Uint32List word, int offset, Uint32List ret, int offsetR) {
    _rotr(14, word, offset, _sigma1Temp1, 0);
    _rotr(18, word, offset, _sigma1Temp2, 0);
    _rotr(41, word, offset, _sigma1Temp3, 0);
    _xor(_sigma1Temp2, 0, _sigma1Temp3, 0, _sigma1Temp4, 0);
    _xor(_sigma1Temp1, 0, _sigma1Temp4, 0, ret, offsetR);
  }

  final _lsigma0Temp1 = Uint32List(2);
  final _lsigma0Temp2 = Uint32List(2);
  final _lsigma0Temp3 = Uint32List(2);
  final _lsigma0Temp4 = Uint32List(2);
  _ssig0(Uint32List word, int offset, Uint32List ret, int offsetR) {
    _rotr(1, word, offset, _lsigma0Temp1, 0);
    _rotr(8, word, offset, _lsigma0Temp2, 0);
    _shr(7, word, offset, _lsigma0Temp3, 0);
    _xor(_lsigma0Temp2, 0, _lsigma0Temp3, 0, _lsigma0Temp4, 0);
    _xor(_lsigma0Temp1, 0, _lsigma0Temp4, 0, ret, offsetR);
  }

  final _lsigma1Temp1 = Uint32List(2);
  final _lsigma1Temp2 = Uint32List(2);
  final _lsigma1Temp3 = Uint32List(2);
  final _lsigma1Temp4 = Uint32List(2);
  _ssig1(Uint32List word, int offset, Uint32List ret, int offsetR) {
    _rotr(19, word, offset, _lsigma1Temp1, 0);
    _rotr(61, word, offset, _lsigma1Temp2, 0);
    _shr(6, word, offset, _lsigma1Temp3, 0);
    _xor(_lsigma1Temp2, 0, _lsigma1Temp3, 0, _lsigma1Temp4, 0);
    _xor(_lsigma1Temp1, 0, _lsigma1Temp4, 0, ret, offsetR);
  }

  _ch(Uint32List x, int offsetX, Uint32List y, int offsetY, Uint32List z,
      int offsetZ, Uint32List ret, int offsetR) {
    ret[0 + offsetR] =
        ((x[0 + offsetX] & (y[0 + offsetY] ^ z[0 + offsetZ])) ^ z[0 + offsetZ]);
    ret[1 + offsetR] =
        ((x[1 + offsetX] & (y[1 + offsetY] ^ z[1 + offsetZ])) ^ z[1 + offsetZ]);
  }

  _maj(Uint32List x, int offsetX, Uint32List y, int offsetY, Uint32List z,
      int offsetZ, Uint32List ret, int offsetR) {
    ret[0 + offsetR] = ((x[0 + offsetX] & (y[0 + offsetY] | z[0 + offsetZ])) |
        (y[0 + offsetY] & z[0 + offsetZ]));
    ret[1 + offsetR] = ((x[1 + offsetX] & (y[1 + offsetY] | z[1 + offsetZ])) |
        (y[1 + offsetY] & z[1 + offsetZ]));
  }

  final a = Uint32List(2);
  final b = Uint32List(2);
  final c = Uint32List(2);
  final d = Uint32List(2);
  final e = Uint32List(2);
  final f = Uint32List(2);
  final g = Uint32List(2);
  final h = Uint32List(2);

  @override
  void updateHash(Uint32List chunk) {
    assert(chunk.length == 32);

    // Prepare message schedule.
    for (var i = 0; i < 32; i++) {
      _extended[i] = chunk[i];
    }
    final tmp1 = Uint32List(2);
    final tmp2 = Uint32List(2);
    final tmp3 = Uint32List(2);
    final tmp4 = Uint32List(2);
    final tmp5 = Uint32List(2);

    for (var i = 32; i < 160; i += 2) {
      _ssig1(_extended, i - 2 * 2, tmp1, 0);
      _add(tmp1, 0, _extended, i - 7 * 2, tmp2, 0);
      _ssig0(_extended, i - 15 * 2, tmp1, 0);
      _add(tmp1, 0, _extended, i - 16 * 2, tmp3, 0);
      _add(tmp2, 0, tmp3, 0, _extended, i);
    }

    // Shuffle around the bits.
    a[0] = _digest[0];
    a[1] = _digest[1];
    b[0] = _digest[2];
    b[1] = _digest[3];
    c[0] = _digest[4];
    c[1] = _digest[5];
    d[0] = _digest[6];
    d[1] = _digest[7];
    e[0] = _digest[8];
    e[1] = _digest[9];
    f[0] = _digest[10];
    f[1] = _digest[11];
    g[0] = _digest[12];
    g[1] = _digest[13];
    h[0] = _digest[14];
    h[1] = _digest[15];

    for (var i = 0; i < 160; i += 2) {
      // temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
      _bsig1(e, 0, tmp1, 0);
      _add(h, 0, tmp1, 0, tmp2, 0);
      _ch(e, 0, f, 0, g, 0, tmp3, 0);
      _add(tmp2, 0, tmp3, 0, tmp4, 0);
      _add(_noise32, i, _extended, i, tmp5, 0);
      _add(tmp4, 0, tmp5, 0, tmp1, 0);

      // temp2 = SHA512_SIGMA0(A) + SHA_Maj(A,B,C);
      _bsig0(a, 0, tmp3, 0);
      _maj(a, 0, b, 0, c, 0, tmp4, 0);
      _add(tmp3, 0, tmp4, 0, tmp2, 0);
      h[0] = g[0];
      h[1] = g[1];
      g[0] = f[0];
      g[1] = f[1];
      f[0] = e[0];
      f[1] = e[1];
      _add(d, 0, tmp1, 0, e, 0);
      d[0] = c[0];
      d[1] = c[1];
      c[0] = b[0];
      c[1] = b[1];
      b[0] = a[0];
      b[1] = a[1];
      _add(tmp1, 0, tmp2, 0, a, 0);
    }

    // Update hash values after iteration.
    _addTo2(_digest, 0, a, 0);
    _addTo2(_digest, 2, b, 0);
    _addTo2(_digest, 4, c, 0);
    _addTo2(_digest, 6, d, 0);
    _addTo2(_digest, 8, e, 0);
    _addTo2(_digest, 10, f, 0);
    _addTo2(_digest, 12, g, 0);
    _addTo2(_digest, 14, h, 0);
  }
}

/// The concrete implementation of [Sha384].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members.
class _Sha384SinkSlow extends _Sha64BitSinkSlow {
  final digestBytes = 12;

  _Sha384SinkSlow(Sink<Digest> sink)
      : super(
            sink,
            Uint32List.fromList([
              0xcbbb9d5d,
              0xc1059ed8,
              0x629a292a,
              0x367cd507,
              0x9159015a,
              0x3070dd17,
              0x152fecd8,
              0xf70e5939,
              0x67332667,
              0xffc00b31,
              0x8eb44a87,
              0x68581511,
              0xdb0c2e0d,
              0x64f98fa7,
              0x47b5481d,
              0xbefa4fa4,
            ]));
}

/// The concrete implementation of [Sha512].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members.
class _Sha512SinkSlow extends _Sha64BitSinkSlow {
  final digestBytes = 16;

  _Sha512SinkSlow(Sink<Digest> sink)
      : super(
            sink,
            Uint32List.fromList([
              // Initial value of the hash parts. First 64 bits of the fractional
              // parts of the square roots of the first eight prime numbers.
              0x6a09e667, 0xf3bcc908,
              0xbb67ae85, 0x84caa73b,
              0x3c6ef372, 0xfe94f82b,
              0xa54ff53a, 0x5f1d36f1,
              0x510e527f, 0xade682d1,
              0x9b05688c, 0x2b3e6c1f,
              0x1f83d9ab, 0xfb41bd6b,
              0x5be0cd19, 0x137e2179,
            ]));
}

abstract class _Sha64BitSinkFast extends HashSink {
  int get digestBytes;

  @override
  Uint32List get digest {
    var unordered = _digest.buffer.asUint32List();
    var ordered = Uint32List(digestBytes);
    for (int i = 0; i < digestBytes; i++) {
      ordered[i] = unordered[i + (i.isEven ? 1 : -1)];
    }
    return ordered;
  }

  // Initial value of the hash parts. First 64 bits of the fractional parts
  // of the square roots of the ninth through sixteenth prime numbers.
  final Uint64List _digest;

  /// The sixteen words from the original chunk, extended to 64 words.
  ///
  /// This is an instance variable to avoid re-allocating, but its data isn't
  /// used across invocations of [updateHash].
  final _extended = Uint64List(80);

  _Sha64BitSinkFast(Sink<Digest> sink, this._digest) : super(sink, 32);
  // The following helper functions are taken directly from
  // http://tools.ietf.org/html/rfc6234.

  static int _rotr64(int n, int x) => _shr64(n, x) | (x << (64 - n));
  static int _shr64(int n, int x) => (x >> n) & ~(-1 << (64 - n));

  static int _ch(int x, int y, int z) => (x & y) ^ (~x & z);
  static int _maj(int x, int y, int z) => (x & y) ^ (x & z) ^ (y & z);
  static int _bsig0(int x) => _rotr64(28, x) ^ _rotr64(34, x) ^ _rotr64(39, x);
  static int _bsig1(int x) => _rotr64(14, x) ^ _rotr64(18, x) ^ _rotr64(41, x);
  static int _ssig0(int x) => _rotr64(1, x) ^ _rotr64(8, x) ^ _shr64(7, x);
  static int _ssig1(int x) => _rotr64(19, x) ^ _rotr64(61, x) ^ _shr64(6, x);

  @override
  void updateHash(Uint32List chunk) {
    assert(chunk.length == 32);

    // Prepare message schedule.
    for (var i = 0, x = 0; i < 32; i += 2, x++) {
      _extended[x] = (chunk[i] << 32) | chunk[i + 1];
    }

    for (var t = 16; t < 80; t++) {
      _extended[t] = _ssig1(_extended[t - 2]) +
          _extended[t - 7] +
          _ssig0(_extended[t - 15]) +
          _extended[t - 16];
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
      var temp1 = h + _bsig1(e) + _ch(e, f, g) + _noise64[i] + _extended[i];
      var temp2 = _bsig0(a) + _maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    // Update hash values after iteration.
    _digest[0] += a;
    _digest[1] += b;
    _digest[2] += c;
    _digest[3] += d;
    _digest[4] += e;
    _digest[5] += f;
    _digest[6] += g;
    _digest[7] += h;
  }
}

/// The concrete implementation of [Sha384].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members.
class _Sha384SinkFast extends _Sha64BitSinkFast {
  @override
  final digestBytes = 12;

  _Sha384SinkFast(Sink<Digest> sink)
      : super(
            sink,
            Uint64List.fromList([
              (0xcbbb9d5d << 32) | 0xc1059ed8,
              (0x629a292a << 32) | 0x367cd507,
              (0x9159015a << 32) | 0x3070dd17,
              (0x152fecd8 << 32) | 0xf70e5939,
              (0x67332667 << 32) | 0xffc00b31,
              (0x8eb44a87 << 32) | 0x68581511,
              (0xdb0c2e0d << 32) | 0x64f98fa7,
              (0x47b5481d << 32) | 0xbefa4fa4,
            ]));
}

/// The concrete implementation of [Sha512].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members.
class _Sha512SinkFast extends _Sha64BitSinkFast {
  @override
  final digestBytes = 16;

  _Sha512SinkFast(Sink<Digest> sink)
      : super(
            sink,
            Uint64List.fromList([
              // Initial value of the hash parts. First 64 bits of the fractional
              // parts of the square roots of the first eight prime numbers.
              (0x6a09e667 << 32) | 0xf3bcc908,
              (0xbb67ae85 << 32) | 0x84caa73b,
              (0x3c6ef372 << 32) | 0xfe94f82b,
              (0xa54ff53a << 32) | 0x5f1d36f1,
              (0x510e527f << 32) | 0xade682d1,
              (0x9b05688c << 32) | 0x2b3e6c1f,
              (0x1f83d9ab << 32) | 0xfb41bd6b,
              (0x5be0cd19 << 32) | 0x137e2179,
            ]));
}

final _noise64 = Uint64List.fromList([
  (0x428a2f98 << 32) | 0xd728ae22,
  (0x71374491 << 32) | 0x23ef65cd,
  (0xb5c0fbcf << 32) | 0xec4d3b2f,
  (0xe9b5dba5 << 32) | 0x8189dbbc,
  (0x3956c25b << 32) | 0xf348b538,
  (0x59f111f1 << 32) | 0xb605d019,
  (0x923f82a4 << 32) | 0xaf194f9b,
  (0xab1c5ed5 << 32) | 0xda6d8118,
  (0xd807aa98 << 32) | 0xa3030242,
  (0x12835b01 << 32) | 0x45706fbe,
  (0x243185be << 32) | 0x4ee4b28c,
  (0x550c7dc3 << 32) | 0xd5ffb4e2,
  (0x72be5d74 << 32) | 0xf27b896f,
  (0x80deb1fe << 32) | 0x3b1696b1,
  (0x9bdc06a7 << 32) | 0x25c71235,
  (0xc19bf174 << 32) | 0xcf692694,
  (0xe49b69c1 << 32) | 0x9ef14ad2,
  (0xefbe4786 << 32) | 0x384f25e3,
  (0x0fc19dc6 << 32) | 0x8b8cd5b5,
  (0x240ca1cc << 32) | 0x77ac9c65,
  (0x2de92c6f << 32) | 0x592b0275,
  (0x4a7484aa << 32) | 0x6ea6e483,
  (0x5cb0a9dc << 32) | 0xbd41fbd4,
  (0x76f988da << 32) | 0x831153b5,
  (0x983e5152 << 32) | 0xee66dfab,
  (0xa831c66d << 32) | 0x2db43210,
  (0xb00327c8 << 32) | 0x98fb213f,
  (0xbf597fc7 << 32) | 0xbeef0ee4,
  (0xc6e00bf3 << 32) | 0x3da88fc2,
  (0xd5a79147 << 32) | 0x930aa725,
  (0x06ca6351 << 32) | 0xe003826f,
  (0x14292967 << 32) | 0x0a0e6e70,
  (0x27b70a85 << 32) | 0x46d22ffc,
  (0x2e1b2138 << 32) | 0x5c26c926,
  (0x4d2c6dfc << 32) | 0x5ac42aed,
  (0x53380d13 << 32) | 0x9d95b3df,
  (0x650a7354 << 32) | 0x8baf63de,
  (0x766a0abb << 32) | 0x3c77b2a8,
  (0x81c2c92e << 32) | 0x47edaee6,
  (0x92722c85 << 32) | 0x1482353b,
  (0xa2bfe8a1 << 32) | 0x4cf10364,
  (0xa81a664b << 32) | 0xbc423001,
  (0xc24b8b70 << 32) | 0xd0f89791,
  (0xc76c51a3 << 32) | 0x0654be30,
  (0xd192e819 << 32) | 0xd6ef5218,
  (0xd6990624 << 32) | 0x5565a910,
  (0xf40e3585 << 32) | 0x5771202a,
  (0x106aa070 << 32) | 0x32bbd1b8,
  (0x19a4c116 << 32) | 0xb8d2d0c8,
  (0x1e376c08 << 32) | 0x5141ab53,
  (0x2748774c << 32) | 0xdf8eeb99,
  (0x34b0bcb5 << 32) | 0xe19b48a8,
  (0x391c0cb3 << 32) | 0xc5c95a63,
  (0x4ed8aa4a << 32) | 0xe3418acb,
  (0x5b9cca4f << 32) | 0x7763e373,
  (0x682e6ff3 << 32) | 0xd6b2b8a3,
  (0x748f82ee << 32) | 0x5defb2fc,
  (0x78a5636f << 32) | 0x43172f60,
  (0x84c87814 << 32) | 0xa1f0ab72,
  (0x8cc70208 << 32) | 0x1a6439ec,
  (0x90befffa << 32) | 0x23631e28,
  (0xa4506ceb << 32) | 0xde82bde9,
  (0xbef9a3f7 << 32) | 0xb2c67915,
  (0xc67178f2 << 32) | 0xe372532b,
  (0xca273ece << 32) | 0xea26619c,
  (0xd186b8c7 << 32) | 0x21c0c207,
  (0xeada7dd6 << 32) | 0xcde0eb1e,
  (0xf57d4f7f << 32) | 0xee6ed178,
  (0x06f067aa << 32) | 0x72176fba,
  (0x0a637dc5 << 32) | 0xa2c898a6,
  (0x113f9804 << 32) | 0xbef90dae,
  (0x1b710b35 << 32) | 0x131c471b,
  (0x28db77f5 << 32) | 0x23047d84,
  (0x32caab7b << 32) | 0x40c72493,
  (0x3c9ebe0a << 32) | 0x15c9bebc,
  (0x431d67c4 << 32) | 0x9c100d4c,
  (0x4cc5d4be << 32) | 0xcb3e42b6,
  (0x597f299c << 32) | 0xfc657e2a,
  (0x5fcb6fab << 32) | 0x3ad6faec,
  (0x6c44198c << 32) | 0x4a475817,
]);
