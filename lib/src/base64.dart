// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'base64/decoder.dart';
import 'base64/encoder.dart';

/// This is deprecated.
///
/// Use the `BASE64` constant in `dart:convert` instead.
@Deprecated("Will be removed in crypto 1.0.0.")
const Base64Codec BASE64 = const Base64Codec();

/// This is deprecated.
///
/// Use the `Base64Codec` class in `dart:convert` instead.
@Deprecated("Will be removed in crypto 1.0.0.")
class Base64Codec extends Codec<List<int>, String> {
  final bool _urlSafe;
  final bool _addLineSeparator;
  final bool _encodePaddingCharacter;

  /// Creates a new [Base64Codec].
  ///
  /// The default [BASE64] codec will be good enough for most cases. A new codec
  /// only needs to be instantiated when you want to do multiple conversions
  /// with the same configuration.
  ///
  /// If [urlSafe] is `true`, a URL-safe alphabet will be used when encoding.
  /// Specifically, the characters `-` and `_` will be used instead of `+` and
  /// `/`.
  ///
  /// If [addLineSeparator] is `true`, `\r\n` line separators will be added
  /// every 76 characters when encoding.
  ///
  /// If [encodePaddingCharacter] is `true`, the padding character `=` will be
  /// written as `%3D` when encoding.
  const Base64Codec(
      {bool urlSafe: false,
      bool addLineSeparator: false,
      bool encodePaddingCharacter: false})
      : _urlSafe = urlSafe,
        _addLineSeparator = addLineSeparator,
        _encodePaddingCharacter = encodePaddingCharacter;

  String get name => "base64";

  /// Encodes [bytes] into a Base64 string.
  ///
  /// If [urlSafe] is `true`, a URL-safe alphabet will be used when encoding.
  /// Specifically, the characters `-` and `_` will be used instead of `+` and
  /// `/`.
  ///
  /// If [addLineSeparator] is `true`, `\r\n` line separators will be added
  /// every 76 characters when encoding.
  ///
  /// If [encodePaddingCharacter] is `true`, the padding character `=` will be
  /// written as `%3D` when encoding.
  ///
  /// Any flags passed to this method take precedence over the flags passed to
  /// the codec itself.
  String encode(List<int> bytes,
      {bool urlSafe, bool addLineSeparator, bool encodePaddingCharacter}) {
    if (urlSafe == null) urlSafe = _urlSafe;
    if (addLineSeparator == null) addLineSeparator = _addLineSeparator;
    if (encodePaddingCharacter == null) {
      encodePaddingCharacter = _encodePaddingCharacter;
    }

    return new Base64Encoder(
        urlSafe: urlSafe,
        addLineSeparator: addLineSeparator,
        encodePaddingCharacter: encodePaddingCharacter).convert(bytes);
  }

  Base64Encoder get encoder => new Base64Encoder(
      urlSafe: _urlSafe,
      addLineSeparator: _addLineSeparator,
      encodePaddingCharacter: _encodePaddingCharacter);

  Base64Decoder get decoder => const Base64Decoder();
}
