// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import "package:charcode/ascii.dart";
import "package:crypto/crypto.dart";
import "package:test/test.dart";

void main() {
  group("encoder", () {
    test("for simple inputs", () {
      expect(BASE64.encode([]), equals(''));
      expect(BASE64.encode([$f]), equals('Zg=='));
      expect(BASE64.encode([$f, $o]), equals('Zm8='));
      expect(BASE64.encode([$f, $o, $o]), equals('Zm9v'));
      expect(BASE64.encode([$f, $o, $o, $b]), equals('Zm9vYg=='));
      expect(BASE64.encode([$f, $o, $o, $b, $a]), equals('Zm9vYmE='));
      expect(BASE64.encode([$f, $o, $o, $b, $a, $r]), equals('Zm9vYmFy'));
    });

    test("for inputs with zeroes", () {
      expect(BASE64.encode([0]), equals('AA=='));
      expect(BASE64.encode([0, 0]), equals('AAA='));
      expect(BASE64.encode([0, 0, 0]), equals('AAAA'));
      expect(BASE64.encode([0, 0, 0, 0]), equals('AAAAAA=='));
    });

    test("for a large input with line separators", () {
      expect(
          BASE64.encode(
              UTF8.encode(
                  "Man is distinguished, not only by his reason, but by this "
                  "singular passion from other animals, which is a lust of the "
                  "mind, that by a perseverance of delight in the continued "
                  "and indefatigable generation of knowledge, exceeds the "
                  "short vehemence of any carnal pleasure."),
              addLineSeparator: true),
          equals(
              "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1"
                  "dCBieSB0aGlz\r\n"
              "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBh"
                  "IGx1c3Qgb2Yg\r\n"
              "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0"
                  "aGUgY29udGlu\r\n"
              "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBl"
                  "eGNlZWRzIHRo\r\n"
              "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="));
    });

    test("for a large input without line separators", () {
      expect(
          BASE64.encode(
              UTF8.encode(
                  "Man is distinguished, not only by his reason, but by this "
                  "singular passion from other animals, which is a lust of the "
                  "mind, that by a perseverance of delight in the continued "
                  "and indefatigable generation of knowledge, exceeds the "
                  "short vehemence of any carnal pleasure.")),
          equals(
              "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1"
              "dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3"
              "aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFu"
              "Y2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxl"
              "IGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhl"
              "bWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="));
    });

    test("for chunked input", () {
      expect(_encodeChunked([
        [102, 102],
        [111, 102],
        [
          111, 111, 102, 111, 111, 98, 102, 111, 111, 98, 97, 102, 111, 111,
          98, 97, 114
        ]
      ]), equals("ZmZvZm9vZm9vYmZvb2JhZm9vYmFy"));

      expect(_encodeChunked([[196, 16], [], [158], [196]]), equals("xBCexA=="));
      expect(_encodeChunked([[196, 16], [158, 196], [], []]),
          equals("xBCexA=="));
      expect(_encodeChunked([[196], [], [16], [], [], [158], [], [196]]),
          equals("xBCexA=="));
      expect(_encodeChunked([[196], [], [16], [158, 196], [], []]),
          equals("xBCexA=="));
      expect(_encodeChunked([[], [196], [], [], [16, 158], [], [196]]),
          equals("xBCexA=="));
      expect(_encodeChunked([[], [196], [16, 158, 196], []]),
          equals("xBCexA=="));
      expect(_encodeChunked([[196, 16, 158], [], [], [196]]),
          equals("xBCexA=="));
      expect(_encodeChunked([[196, 16, 158], [], [196], []]),
          equals("xBCexA=="));
      expect(_encodeChunked([[196, 16, 158, 196], [], [], []]),
          equals("xBCexA=="));
    });

    test('with a URL-safe alphabet', () {
      expect(BASE64.encode(BASE64.decode('+/A='), urlSafe: true),
          equals('-_A='));
    });

    test('with a percent-encoded padding character', () {
      expect(BASE64.encode([2, 8], encodePaddingCharacter: true),
          equals('Agg%3D'));
    });

    test('with the old API', () {
      expect(CryptoUtils.bytesToBase64([]), equals(''));
      expect(CryptoUtils.bytesToBase64([$f]), equals('Zg=='));
      expect(CryptoUtils.bytesToBase64([$f, $o]), equals('Zm8='));
      expect(CryptoUtils.bytesToBase64([$f, $o, $o]), equals('Zm9v'));
      expect(CryptoUtils.bytesToBase64([$f, $o, $o, $b]), equals('Zm9vYg=='));
      expect(CryptoUtils.bytesToBase64([$f, $o, $o, $b, $a]),
          equals('Zm9vYmE='));
      expect(CryptoUtils.bytesToBase64([$f, $o, $o, $b, $a, $r]),
          equals('Zm9vYmFy'));
    });
  });

  group("decoder", () {
    test("for simple inputs", () {
      expect(BASE64.decode(''), equals([]));
      expect(BASE64.decode('Zg=='), equals([$f]));
      expect(BASE64.decode('Zm8='), equals([$f, $o]));
      expect(BASE64.decode('Zm9v'), equals([$f, $o, $o]));
      expect(BASE64.decode('Zm9vYg=='), equals([$f, $o, $o, $b]));
      expect(BASE64.decode('Zm9vYmE='), equals([$f, $o, $o, $b, $a]));
      expect(BASE64.decode('Zm9vYmFy'), equals([$f, $o, $o, $b, $a, $r]));
    });

    test("for inputs with zeroes", () {
      expect(BASE64.decode('AA=='), equals([0]));
      expect(BASE64.decode('AAA='), equals([0, 0]));
      expect(BASE64.decode('AAAA'), equals([0, 0, 0]));
      expect(BASE64.decode('AAAAAA=='), equals([0, 0, 0, 0]));
    });

    test("for a large input with line separators", () {
      expect(
          BASE64.decode(
              "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1"
                  "dCBieSB0aGlz\r\n"
              "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBh"
                  "IGx1c3Qgb2Yg\r\n"
              "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0"
                  "aGUgY29udGlu\r\n"
              "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBl"
                  "eGNlZWRzIHRo\r\n"
              "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="),
          equals(UTF8.encode(
              "Man is distinguished, not only by his reason, but by this "
              "singular passion from other animals, which is a lust of the "
              "mind, that by a perseverance of delight in the continued and "
              "indefatigable generation of knowledge, exceeds the short "
              "vehemence of any carnal pleasure.")));
    });

    test("for a large input without line separators", () {
      expect(
          BASE64.decode(
              "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1"
              "dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3"
              "aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFu"
              "Y2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxl"
              "IGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhl"
              "bWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="),
          equals(UTF8.encode(
              "Man is distinguished, not only by his reason, but by this "
              "singular passion from other animals, which is a lust of the "
              "mind, that by a perseverance of delight in the continued and "
              "indefatigable generation of knowledge, exceeds the short "
              "vehemence of any carnal pleasure.")));
    });

    test("for chunked input", () {
      expect(_decodeChunked(['YmFz', 'ZTY', '0I', 'GRlY29kZXI=']), equals([
        98, 97, 115, 101, 54, 52, 32, 100, 101, 99, 111, 100, 101, 114
      ]));
    });

    test("for chunked input containing zeroes", () {
      expect(_decodeChunked(['AAAA', 'AAA=', 'AA==', '']),
          equals([0, 0, 0, 0, 0, 0]));

      expect(_decodeChunked(["A", "", "BCD"]), equals([0, 16, 131]));
      expect(_decodeChunked(["A", "BCD", "", ""]), equals([0, 16, 131]));
      expect(_decodeChunked(["A", "B", "", "", "CD", ""]),
          equals([0, 16, 131]));
      expect(_decodeChunked(["", "A", "BC", "", "D"]), equals([0, 16, 131]));
      expect(_decodeChunked(["", "AB", "C", "", "", "D"]),
          equals([0, 16, 131]));
      expect(_decodeChunked(["AB", "CD", ""]), equals([0, 16, 131]));
      expect(_decodeChunked(["", "ABC", "", "D"]), equals([0, 16, 131]));
      expect(_decodeChunked(["", "ABC", "D", ""]), equals([0, 16, 131]));
      expect(_decodeChunked(["", "", "ABCD", ""]), equals([0, 16, 131]));
      expect(_decodeChunked(["A", "B", "C", "D"]), equals([0, 16, 131]));
      expect(_decodeChunked(["", "A", "B", "C", "D", ""]),
          equals([0, 16, 131]));
      expect(_decodeChunked(["", "A", "B", "", "", "C", "", "D", ""]),
          equals([0, 16, 131]));
    });

    test("for chunked input with encoded padding", () {
      expect(_decodeChunked(['AA%', '3D', '%', '3', 'DEFGZ']),
          equals(BASE64.decode('AA==EFGZ')));
    });

    test('with a URL-safe alphabet', () {
      expect(BASE64.decode('-_A='), equals(BASE64.decode('+/A=')));
    });

    test('with a percent-encoded padding character', () {
      expect(BASE64.decode('Agg%3D'), equals([2, 8]));
    });

    test("with the old API", () {
      expect(CryptoUtils.base64StringToBytes(''), equals([]));
      expect(CryptoUtils.base64StringToBytes('Zg=='), equals([$f]));
      expect(CryptoUtils.base64StringToBytes('Zm8='), equals([$f, $o]));
      expect(CryptoUtils.base64StringToBytes('Zm9v'), equals([$f, $o, $o]));
      expect(CryptoUtils.base64StringToBytes('Zm9vYg=='),
          equals([$f, $o, $o, $b]));
      expect(CryptoUtils.base64StringToBytes('Zm9vYmE='),
          equals([$f, $o, $o, $b, $a]));
      expect(CryptoUtils.base64StringToBytes('Zm9vYmFy'),
          equals([$f, $o, $o, $b, $a, $r]));
    });

    group("rejects", () {
      test("input of the wrong length", () {
        expect(() => BASE64.decode('A'), throwsFormatException);
        expect(() => BASE64.decode('AB'), throwsFormatException);
        expect(() => BASE64.decode('ABz'), throwsFormatException);
        expect(() => BASE64.decode('ABzdE'), throwsFormatException);
        expect(() => BASE64.decode('ABzdEf'), throwsFormatException);
        expect(() => BASE64.decode('ABzdEfg'), throwsFormatException);
      });

      test("input with invalid characters", () {
        expect(() => BASE64.decode('AB~'), throwsFormatException);
      });

      test("chunked input of the wrong length", () {
        expect(() => _decodeChunked(['ABz']), throwsFormatException);
        expect(() => _decodeChunked(['AB', 'Lx', 'z', 'xx']),
            throwsFormatException);
      });

      test("input with the wrong padding", () {
        expect(() => BASE64.decode('A=='), throwsFormatException);
        expect(() => BASE64.decode('AB='), throwsFormatException);
        expect(() => BASE64.decode('ABz=='), throwsFormatException);
        expect(() => BASE64.decode('ABzdE='), throwsFormatException);
      });

      test("input with the wrong encoded padding", () {
        expect(() => BASE64.decode('A%3D%3D'), throwsFormatException);
        expect(() => BASE64.decode('AB%3D'), throwsFormatException);
        expect(() => BASE64.decode('ABz%3D%3D'), throwsFormatException);
        expect(() => BASE64.decode('ABzdE%3D'), throwsFormatException);
      });
    });
  });

  test('successfully round-trips data', () {
    for (var i = 0; i < 10; i++) {
      for (var j = 0; j < 256 - i; j++) {
        var data = new List.filled(i, j);
        expect(BASE64.decode(BASE64.encode(data)), equals(data));
      }
    }
  });
}

/// Performs chunked Base64 decoding of [chunks] and returns the result as a
/// byte array.
List<int> _decodeChunked(Iterable<String> chunks) {
  var bytes;
  var innerSink = new ByteConversionSink.withCallback(
      (result) => bytes = result);
  var sink = BASE64.decoder.startChunkedConversion(innerSink);

  for (var chunk in chunks) {
    sink.add(chunk);
  }
  sink.close();

  return bytes;
}

/// Performs chunked Base64 encoding of [chunks] and returns the result.
String _encodeChunked(Iterable<List<int>> chunks) {
  var string;
  var innerSink = new StringConversionSink.withCallback(
      (result) => string = result);
  var sink = BASE64.encoder.startChunkedConversion(innerSink);

  for (var chunk in chunks) {
    sink.add(chunk);
  }
  sink.close();

  return string;
}
