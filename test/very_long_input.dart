library very_long_input_test;

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

veryLongInput(digester, int byteLength, String verify) {
  var nullCharacter = '\u0000'.codeUnitAt(0);
  var input = [nullCharacter];
  for (var i = 0; i < byteLength; i++) {
    digester.add(input);
  }
  var d = digester.close();
  expect(CryptoUtils.bytesToHex(d), verify);
}
