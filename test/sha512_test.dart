// Copyright (c) 2019, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';

import 'package:test/test.dart';
import 'package:crypto/crypto.dart';

void main() {
  group('SHA2-384', () {
    group('with a chunked converter', () {
      test('add may not be called after close', () {
        var sink =
            sha384.startChunkedConversion(StreamController<Digest>().sink);
        sink.close();
        expect(() => sink.add([0]), throwsStateError);
      });

      test('close may be called multiple times', () {
        var sink =
            sha384.startChunkedConversion(StreamController<Digest>().sink);
        sink.close();
        sink.close();
        sink.close();
        sink.close();
      });

      test('close closes the underlying sink', () {
        var inner = ChunkedConversionSink<Digest>.withCallback(
            expectAsync1((accumulated) {
          expect(accumulated.length, equals(1));
          expect(
              accumulated.first.toString(),
              equals(
                  '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'));
        }));

        var outer = sha384.startChunkedConversion(inner);
        outer.close();
      });
    });

    test('384 Vectors', () {
      expect('${sha384.convert('this is a test'.codeUnits)}',
          '43382a8cc650904675c9d62d785786e368f3a99db99aeaaa7b76b02530677154d09c0b6bd2e21b4329fd41543b9a785b');
    });
  });

  group('SHA2-512', () {
    group('with a chunked converter', () {
      test('add may not be called after close', () {
        var sink =
            sha512.startChunkedConversion(StreamController<Digest>().sink);
        sink.close();
        expect(() => sink.add([0]), throwsStateError);
      });

      test('close may be called multiple times', () {
        var sink =
            sha512.startChunkedConversion(StreamController<Digest>().sink);
        sink.close();
        sink.close();
        sink.close();
        sink.close();
      });

      test('close closes the underlying sink', () {
        var inner = ChunkedConversionSink<Digest>.withCallback(
            expectAsync1((accumulated) {
          expect(accumulated.length, equals(1));
          expect(
              accumulated.first.toString(),
              equals(
                  'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'));
        }));

        var outer = sha512.startChunkedConversion(inner);
        outer.close();
      });
    });

    test('512 Vectors', () {
      expect('${sha512.convert('this is a test'.codeUnits)}',
          '7d0a8468ed220400c0b8e6f335baa7e070ce880a37e2ac5995b9a97b809026de626da636ac7365249bb974c719edf543b52ed286646f437dc7f810cc2068375c');
    });
  });
}
