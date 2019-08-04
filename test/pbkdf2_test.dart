// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.


import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

void main() {
  group('standard vector', () {
    for (var i = 0; i < _inputs.length; i++) {
      test(_inputs[i]['result'], () {
        expect(pbkdf2.process(
          _inputs[i]['password'] as Uint8List,
          _inputs[i]['salt'] as Uint8List,
          _inputs[i]['rounds'] as int,
          _inputs[i]['dkLen'] as int,
        ).toString(), equals(_inputs[i]['result']));
      });
    }
  });
  group('exception', () {
    test('dkLen may not be bigger than (pow(2, 32) - 1) * hLen', () {
      int tooBigDkLen = (pow(2, 32) - 1) * 20 + 1 as int;
      expect(() => pbkdf2.process(
        utf8.encode('password'),
        utf8.encode('salt'),
        2,
        tooBigDkLen,
      ), throwsA(TypeMatcher<UnsupportedError>()));
    });
  });
}

var _inputs = <Map<String, dynamic>>[
  {'password': utf8.encode('password'), 'salt': utf8.encode('salt'), 'rounds': 2, 'dkLen': 20, 'result': 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'},
  {'password': utf8.encode('password'), 'salt': utf8.encode('salt'), 'rounds': 4096, 'dkLen': 20, 'result': '4b007901b765489abead49d926f721d065a429c1'},
  //{'password': utf8.encode('password'), 'salt': utf8.encode('salt'), 'rounds': 16777216, 'dkLen': 20, 'result': 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'},
  {'password': utf8.encode('passwordPASSWORDpassword'), 'salt': utf8.encode('saltSALTsaltSALTsaltSALTsaltSALTsalt'), 'rounds': 4096, 'dkLen': 25, 'result': '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'},
  {'password': utf8.encode('pass\u0000word'), 'salt': utf8.encode('sa\u0000lt'), 'rounds': 4096, 'dkLen': 16, 'result': '56fa6aa75548099dcc37d7f03425e0c3'},
];
