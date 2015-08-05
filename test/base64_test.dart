// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

// Library tag to allow the test to run on Dartium.
library base64_test;

import 'dart:math';
import 'dart:async';

import "package:crypto/crypto.dart";
import "package:test/test.dart";

void main() {
  test('encoder', _testEncoder);
  test('decoder', _testDecoder);
  test('decoder for malformed input', _testDecoderForMalformedInput);
  test('encode decode lists', _testEncodeDecodeLists);
  test('url safe encode-decode', _testUrlSafeEncodeDecode);
  test('percent-encoded padding character encode-decode',
       _testPaddingCharacter);
  test('streaming encoder', _testStreamingEncoder);
  test('streaming decoder', _testStreamingDecoder);
  test('streaming decoder for malformed input',
       _testStreamingDecoderForMalformedInput);
  test('streaming encoder for different decompositions of a list of bytes',
       _testStreamingEncoderForDecompositions);
  test('streaming decoder for different decompositions of a string',
       _testStreamingDecoderForDecompositions);
  test('streaming for encoded padding character',
       _testStreamingForEncodedPadding);
  test('old api', _testOldApi);
  test('url safe streaming encoder/decoder', _testUrlSafeStreaming);
  test('performance', _testPerformance);


}

// Data from http://tools.ietf.org/html/rfc4648.
const _INPUTS =
    const [ '', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar'];
const _RESULTS =
    const [ '', 'Zg==', 'Zm8=', 'Zm9v', 'Zm9vYg==', 'Zm9vYmE=', 'Zm9vYmFy'];

const _PADDING_INPUT = const [2, 8];

var _STREAMING_ENCODER_INPUT =
    [[102, 102], [111, 102],
     [111, 111, 102, 111, 111, 98, 102, 111,
      111, 98, 97, 102, 111, 111, 98, 97, 114]];

const _STREAMING_ENCODED = 'ZmZvZm9vZm9vYmZvb2JhZm9vYmFy';
const _STREAMING_DECODER_INPUT =
    const ['YmFz', 'ZTY', '0I', 'GRlY29kZXI='];
const _STREAMING_DECODED =
    const [98, 97, 115, 101, 54, 52, 32, 100, 101, 99, 111, 100, 101, 114];
const _STREAMING_DECODER_INPUT_FOR_ZEROES =
    const ['AAAA', 'AAA=', 'AA==', ''];
var _STREAMING_DECODED_ZEROES = [0, 0, 0, 0, 0, 0];

var _DECOMPOSITIONS_FOR_DECODING = [
    ["A", "", "BCD"], ["A", "BCD", "", ""], ["A", "B", "", "", "CD", ""],
    ["", "A", "BC", "", "D"], ["", "AB", "C", "", "", "D"], ["AB", "CD", ""],
    ["", "ABC", "", "D"], ["", "ABC", "D", ""], ["", "", "ABCD", ""],
    ["A", "B", "C", "D"], ["", "A", "B", "C", "D", ""],
    ["", "A", "B", "", "", "C", "", "D", ""]];

const _DECOMPOSITION_DECODED = const [0, 16, 131];

var _DECOMPOSITIONS_FOR_ENCODING = [
    [[196, 16], [], [158], [196]],
    [[196, 16], [158, 196], [], []],
    [[196], [], [16], [], [], [158], [], [196]],
    [[196], [], [16], [158, 196], [], []],
    [[], [196], [], [], [16, 158], [], [196]],
    [[], [196], [16, 158, 196], []],
    [[196, 16, 158], [], [], [196]],
    [[196, 16, 158], [], [196], []],
    [[196, 16, 158, 196], [], [], []]];

const _DECOMPOSITION_ENCODED = 'xBCexA==';

// Test data with only zeroes.
var inputsWithZeroes = [[0, 0, 0], [0, 0], [0], []];
const _RESULTS_WITH_ZEROS = const ['AAAA', 'AAA=', 'AA==', ''];

const _LONG_LINE =
    "Man is distinguished, not only by his reason, but by this singular "
    "passion from other animals, which is a lust of the mind, that by a "
    "perseverance of delight in the continued and indefatigable generation "
    "of knowledge, exceeds the short vehemence of any carnal pleasure.";

const _LONG_LINE_RESULT =
    "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbm"
    "x5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz\r\n"
    "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlci"
    "BhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg\r\n"
    "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcm"
    "FuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu\r\n"
    "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYX"
    "Rpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo\r\n"
    "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm"
    "5hbCBwbGVhc3VyZS4=";

const _LONG_LINE_RESULT_NO_BREAK =
    "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbm"
    "x5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz"
    "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlci"
    "BhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg"
    "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcm"
    "FuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu"
    "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYX"
    "Rpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo"
    "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm"
    "5hbCBwbGVhc3VyZS4=";

void _testEncoder() {
  for (var i = 0; i < _INPUTS.length; i++) {
    expect(BASE64.encode(_INPUTS[i].codeUnits), _RESULTS[i]);
  }
  for (var i = 0; i < inputsWithZeroes.length; i++) {
    expect(BASE64.encode(inputsWithZeroes[i]),
           _RESULTS_WITH_ZEROS[i]);
  }
  expect(BASE64.encode(_LONG_LINE.codeUnits, addLineSeparator : true),
         _LONG_LINE_RESULT);
  expect(BASE64.encode(_LONG_LINE.codeUnits),
         _LONG_LINE_RESULT_NO_BREAK);
}

void _testDecoder() {
  for (var i = 0; i < _RESULTS.length; i++) {
    expect(
        new String.fromCharCodes(BASE64.decode(_RESULTS[i])),
        _INPUTS[i]);
  }

  for (var i = 0; i < _RESULTS_WITH_ZEROS.length; i++) {
    expect(BASE64.decode(_RESULTS_WITH_ZEROS[i]),
        inputsWithZeroes[i]);
  }

  var longLineDecoded = BASE64.decode(_LONG_LINE_RESULT);
  expect(new String.fromCharCodes(longLineDecoded), _LONG_LINE);

  var longLineResultNoBreak = BASE64.decode(_LONG_LINE_RESULT);
  expect(new String.fromCharCodes(longLineResultNoBreak), _LONG_LINE);
}

void _testPaddingCharacter() {
  var encoded = BASE64.encode(_PADDING_INPUT, encodePaddingCharacter: true);
  expect(encoded, 'Agg%3D');
  expect(BASE64.decode(encoded), _PADDING_INPUT);
}

Future _testStreamingEncoder() async {
  expect(
      await new Stream.fromIterable(_STREAMING_ENCODER_INPUT)
                      .transform(BASE64.encoder)
                      .join(),
      _STREAMING_ENCODED);
}

Future _testStreamingDecoder() async {
  expect(
      await new Stream.fromIterable(_STREAMING_DECODER_INPUT)
                      .transform(BASE64.decoder)
                      .expand((l) => l)
                      .toList(),
      _STREAMING_DECODED);

  expect(
      await new Stream.fromIterable(_STREAMING_DECODER_INPUT_FOR_ZEROES)
                      .transform(BASE64.decoder)
                      .expand((l) => l)
                      .toList(),
      _STREAMING_DECODED_ZEROES);
}

Future _testStreamingDecoderForMalformedInput() async {
  expect(new Stream.fromIterable(['ABz'])
                   .transform(BASE64.decoder)
                   .toList(),
         throwsFormatException);

  expect(new Stream.fromIterable(['AB', 'Lx', 'z', 'xx'])
                   .transform(BASE64.decoder)
                   .toList(),
         throwsFormatException);
}

Future _testStreamingEncoderForDecompositions() async {
  for(var decomposition in _DECOMPOSITIONS_FOR_ENCODING) {
    expect(
        await new Stream.fromIterable(decomposition)
                        .transform(BASE64.encoder)
                        .join(),
        _DECOMPOSITION_ENCODED);
  }
}

Future _testStreamingDecoderForDecompositions() async {
  for(var decomposition in _DECOMPOSITIONS_FOR_DECODING) {
    expect(
        await new Stream.fromIterable(decomposition)
                        .transform(BASE64.decoder)
                        .expand((x) => x)
                        .toList(),
        _DECOMPOSITION_DECODED);
  }
}

void _testDecoderForMalformedInput() {
  expect(() {
    BASE64.decode('AB~');
  }, throwsFormatException);

  expect(() {
    BASE64.decode('A');
  }, throwsFormatException);
}

Future _testUrlSafeStreaming() async {
  String encUrlSafe = '-_A=';
  List<List<int>> dec = [BASE64.decode('+/A=')];
  var streamedResult = await new Stream.fromIterable(dec)
      .transform(new Base64Encoder(urlSafe: true)).join();

  expect(streamedResult, encUrlSafe);
}

Future _testStreamingForEncodedPadding() async {
  List<String> withEncodedPadding = ['AA%', '3D', '%', '3', 'DEFGZ'];
  List<int> decoded = BASE64.decode('AA==EFGZ');
  var streamedResult = await new Stream.fromIterable(withEncodedPadding)
      .transform(BASE64.decoder).expand((x) => x).toList();

  expect(streamedResult, decoded);
}

void _testUrlSafeEncodeDecode() {
  List<int> decUrlSafe = BASE64.decode('-_A=');
  List<int> dec = BASE64.decode('+/A=');
  expect(decUrlSafe, orderedEquals(dec));
  expect(BASE64.encode(dec, urlSafe: true), '-_A=');
  expect(BASE64.encode(dec), '+/A=');
}

void _testEncodeDecodeLists() {
  for (int i = 0; i < 10; i++) {
    for (int j = 0; j < 256 - i; j++) {
      List<int> x = new List<int>(i);
      for (int k = 0; k < i; k++) {
        x[k] = j;
      }
      var enc = BASE64.encode(x);
      var dec = BASE64.decode(enc);
      expect(dec, orderedEquals(x));
    }
  }
}

void _fillRandom(List<int> l) {
  var random = new Random(0xBABE);
  for (int j = 0; j < l.length; j++) {
    l[j] = random.nextInt(255);
  }
}

void _testOldApi() {
  for (int i = 0; i < _INPUTS.length; i++) {
    expect(CryptoUtils.bytesToBase64(_INPUTS[i].codeUnits), _RESULTS[i]);
    expect(CryptoUtils.base64StringToBytes(_RESULTS[i]), _INPUTS[i].codeUnits);
  }
}

void _testPerformance() {
    var l = new List<int>(1024);
    var iters = 5000;
    _fillRandom(l);
    String enc;
    var w = new Stopwatch()..start();
    for( int i = 0; i < iters; ++i ) {
      enc = BASE64.encode(l);
    }
    int ms = w.elapsedMilliseconds;
    int perSec = (iters * l.length) * 1000 ~/ ms;
    // print("Encode 1024 bytes for $iters times: $ms msec. $perSec b/s");
    w..reset();
    for( int i = 0; i < iters; ++i ) {
      BASE64.decode(enc);
    }
    ms = w.elapsedMilliseconds;
    perSec = (iters * l.length) * 1000 ~/ ms;
    // ('''Decode into ${l.length} bytes for $iters
    //     times: $ms msec. $perSec b/s''');
}
