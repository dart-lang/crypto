// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.sha1;

import 'dart:typed_data';

import 'hash.dart';
import 'hash_base.dart';
import 'utils.dart';

/**
 * SHA1 hash function implementation.
 */
abstract class SHA1 implements Hash {
  factory SHA1() = _SHA1;

  SHA1 newInstance();
}

class _SHA1 extends HashBase implements SHA1 {
  final Uint32List _w;

  // Construct a SHA1 hasher object.
  _SHA1()
      : _w = new Uint32List(80),
        super(16, 5, true) {
    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;
  }

  // Returns a new instance of this Hash.
  SHA1 newInstance() {
    return new _SHA1();
  }

  // Compute one iteration of the SHA1 algorithm with a chunk of
  // 16 32-bit pieces.
  void updateHash(Uint32List m) {
    assert(m.length == 16);

    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];

    for (var i = 0; i < 80; i++) {
      if (i < 16) {
        _w[i] = m[i];
      } else {
        var n = _w[i - 3] ^ _w[i - 8] ^ _w[i - 14] ^ _w[i - 16];
        _w[i] = rotl32(n, 1);
      }
      var t = add32(add32(rotl32(a, 5), e), _w[i]);
      if (i < 20) {
        t = add32(add32(t, (b & c) | (~b & d)), 0x5A827999);
      } else if (i < 40) {
        t = add32(add32(t, (b ^ c ^ d)), 0x6ED9EBA1);
      } else if (i < 60) {
        t = add32(add32(t, (b & c) | (b & d) | (c & d)), 0x8F1BBCDC);
      } else {
        t = add32(add32(t, b ^ c ^ d), 0xCA62C1D6);
      }

      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = t & MASK_32;
    }

    h[0] = add32(a, h[0]);
    h[1] = add32(b, h[1]);
    h[2] = add32(c, h[2]);
    h[3] = add32(d, h[3]);
    h[4] = add32(e, h[4]);
  }
}
