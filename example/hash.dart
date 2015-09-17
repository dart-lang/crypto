// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:io' show exit, File;
import 'package:crypto/crypto.dart' show MD5, SHA1, SHA256, CryptoUtils;

const USAGE = 'Usage: dart hash.dart <md5|sha1|sha256> <input_filename>';

main(List<String> args) async {
  if (args == null || args.length != 2) {
    print(USAGE);
    exit(1);
  }

  var hasher;

  switch (args[0]) {
    case 'md5':
      hasher = new MD5();
      break;
    case 'sha1':
      hasher = new SHA1();
      break;
    case 'sha256':
      hasher = new SHA256();
      break;
    default:
      print(USAGE);
      exit(1);
  }

  var filename = args[1];
  var input = new File(filename);

  if (!input.existsSync()) {
    print('File "$filename" does not exist.');
    exit(1);
  }

  await for (var bytes in input.openRead()) {
    hasher.add(bytes);
  }

  var hex = CryptoUtils.bytesToHex(hasher.close());

  print(hex);
}
