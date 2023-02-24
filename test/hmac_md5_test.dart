// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

// ignore_for_file: lines_longer_than_80_chars

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('standard vector', () {
    for (var i = 0; i < _inputs.length; i++) {
      test(_macs[i], () {
        expectHmacEquals(md5, bytesFromHexString(_inputs[i]),
            bytesFromHexString(_keys[i]), _macs[i]);
      });
    }
  });
}

// Data from http://tools.ietf.org/html/rfc2202.

const List<String> _inputs = [
  '4869205468657265',
  '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
  'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
  '546573742057697468205472756e636174696f6e',
  '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
  '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461',
];

const List<String> _keys = [
  '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
  '4a656665',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  '0102030405060708090a0b0c0d0e0f10111213141516171819',
  '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
];

const List<String> _macs = [
  '9294727a3638bb1c13f48ef8158bfc9d',
  '750c783e6ab0b503eaa86e310a5db738',
  '56be34521d144c88dbb8c733f0e8b3f6',
  '697eaf0aca3a3aea3a75164746ffaa79',
  '56461ef2342edc00f9bab995690efd4c',
  '6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd',
  '6f630fad67cda0ee1fb1f562db3aa53e',
];
