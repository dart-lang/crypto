// Copyright (c) 2019, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'digest.dart';
import 'hash.dart';
// ignore: uri_does_not_exist
import 'sha512_fastsinks.dart' if (dart.library.js) 'sha512_slowsinks.dart';
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

/// An instance of [Sha2Sha512/224].
///
/// This instance provides convenient access to the [Sha512/224][FIPS] hash
/// function.
///
/// [FIPS]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
final sha512224 = Sha512224._();

/// An instance of [Sha2Sha512/256].
///
/// This instance provides convenient access to the [Sha512/256][FIPS] hash
/// function.
///
/// [FIPS]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
final sha512256 = Sha512256._();

/// An implementation of the [SHA-384][rfc] hash function.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
///
/// Note that it's almost always easier to use [sha384] rather than creating a
/// new instance.
class Sha384 extends Hash {
  @override
  final int blockSize = 32 * bytesPerWord;

  Sha384._();

  Sha384 newInstance() => Sha384._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(Sha384Sink(sink));
}

/// An implementation of the [SHA-512][rfc] hash function.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
///
/// Note that it's almost always easier to use [sha512] rather than creating a
/// new instance.
class Sha512 extends Sha384 {
  Sha512._() : super._();

  @override
  Sha512 newInstance() => Sha512._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(Sha512Sink(sink));
}

/// An implementation of the [SHA-512/224][FIPS] hash function.
///
/// [FIPS]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///
/// Note that it's almost always easier to use [sha512224] rather than creating
/// a new instance.
class Sha512224 extends Sha512 {
  Sha512224._() : super._();

  @override
  Sha512224 newInstance() => Sha512224._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(Sha512224Sink(sink));
}

/// An implementation of the [SHA-512/256][FIPS] hash function.
///
/// [FIPS]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///
/// Note that it's almost always easier to use [sha512256] rather than creating
/// a new instance.
class Sha512256 extends Sha512 {
  Sha512256._() : super._();

  @override
  Sha512256 newInstance() => Sha512256._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(Sha512256Sink(sink));
}
