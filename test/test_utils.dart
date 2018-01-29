// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart' hide sha1;
import 'package:test/test.dart';

void testHash(Hash hash, List<List<int>> _inputs, List<String> _digests,
    String emptyResult) {
  group('with a chunked converter', () {
    test('add may not be called after close', () {
      var sink =
          hash.startChunkedConversion(new StreamController<Digest>().sink);
      sink.close();
      expect(() => sink.add([0]), throwsStateError);
    });

    test('close may be called multiple times', () {
      var sink =
          hash.startChunkedConversion(new StreamController<Digest>().sink);
      sink.close();
      sink.close();
      sink.close();
      sink.close();
    });

    test('close closes the underlying sink', () {
      var inner = new ChunkedConversionSink<Digest>.withCallback(
          expectAsync1((accumulated) {
        expect(accumulated.length, equals(1));
        expect(accumulated.first.toString(), equals(emptyResult));
      }));

      var outer = hash.startChunkedConversion(inner);
      outer.close();
    });
  });

  group('standard vector', () {
    for (var i = 0; i < _inputs.length; i++) {
      test(_digests[i], () {
        expect(hash.convert(_inputs[i]).toString(), equals(_digests[i]));
      });
    }
  });
}

void testHmac(Hash hash, List<List<int>> inputs, List<String> macs,
    List<List<int>> keys) {
  for (var i = 0; i < inputs.length; i++) {
    test(macs[i], () {
      _expectHmacEquals(hash, inputs[i], keys[i], macs[i]);
    });
  }
}

/// Asserts that an HMAC using [hash] returns [mac] for [input] and [key].
void _expectHmacEquals(Hash hash, List<int> input, List<int> key, String mac) {
  var hmac = new Hmac(hash, key);
  expect(hmac.convert(input).toString(), startsWith(mac));
}
