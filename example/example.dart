// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:io';

import 'package:crypto/crypto.dart';

final _usage = 'Usage: dart example.dart <md5|sha1|sha256> <input_filename>';

Future main(List<String> args) async {
  if (args == null || args.length != 2) {
    print(_usage);
    exit(1);
  }

  var hashInstance = _getHash(args[0]);

  if (hashInstance == null) {
    print(_usage);
    exitCode = 1;
    return;
  }

  var filename = args[1];
  var input = new File(filename);

  if (!input.existsSync()) {
    print('File "$filename" does not exist.');
    exitCode = 1;
    return;
  }

  var value = await input.openRead().transform(hashInstance).first;

  print(value);
}

Hash _getHash(String name) {
  switch (name) {
    case 'md5':
      return md5;
    case 'sha1':
      return sha1;
      break;
    case 'sha256':
      return sha256;
      break;
  }
  return null;
}
