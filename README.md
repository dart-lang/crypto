[![Build Status](https://travis-ci.org/dart-lang/crypto.svg?branch=master)](https://travis-ci.org/dart-lang/crypto)

A set of cryptographic hashing functions implemented in Dart.

The following hashing algorithms are supported:

* [SHA-1][SHA1]
* [SHA-256][SHA256]
* [MD5]
* [HMAC][Hmac] (i.e. HMAC-MD5, HMAC-SHA1, HMAC-SHA256)

## Usage

### Digest on a single input

To hash a list of bytes, invoke the [`convert`][convert] method on the
[`sha1`][sha1-obj], [`sha256`][sha256-obj] or [`md5`][md5-obj]
objects.

```dart
import 'dart:convert'; // for the utf8.encode method

import 'package:crypto/crypto.dart';

void main() {
  var bytes = utf8.encode("foobar"); // data being hashed

  var digest = sha1.convert(bytes);

  print('Digest as bytes: ${digest.bytes}');
  print('Digest as hex string: $digest');
}
```

### Digest Stream input

If the input data is a `Stream<List<int>>`:


```dart
import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';

main() async {
  var byteStream =
      new Stream<String>.fromIterable(['foo', 'bar']).transform(UTF8.encoder);

  var digest = await byteStream
      .transform(sha1) // Convert to a Stream<Digest>
      .single; // There is only one

  print('Digest as bytes: ${digest.bytes}');
  print('Digest as hex string: $digest');
}
```

### HMAC

Create an instance of the [`Hmac`][Hmac] class with the hash function
and secret key being used.  The object can then be used like the other
hash calculating objects.

```dart
import 'dart:convert';

import 'package:crypto/crypto.dart';

void main() {
  var key = utf8.encode('p@ssw0rd');
  var bytes = utf8.encode("foobar");

  var hmacSha256 = new Hmac(sha256, key); // HMAC-SHA256
  var digest = hmacSha256.convert(bytes);

  print('HMAC digest as bytes: ${digest.bytes}');
  print('HMAC digest as hex string: $digest');
}
```

## Disclaimer

Support for this library is given as _best effort_.

This library has not been reviewed or vetted by security professionals.

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[convert]: https://www.dartdocs.org/documentation/crypto/latest/crypto/Hash/convert.html
[Digest]: https://www.dartdocs.org/documentation/crypto/latest/crypto/Digest-class.html
[Hmac]: https://www.dartdocs.org/documentation/crypto/latest/crypto/Hmac-class.html
[MD5]: https://www.dartdocs.org/documentation/crypto/latest/crypto/MD5-class.html
[Sha1]: https://www.dartdocs.org/documentation/crypto/latest/crypto/Sha1-class.html
[Sha256]: https://www.dartdocs.org/documentation/crypto/latest/crypto/Sha256-class.html
[md5-obj]: https://www.dartdocs.org/documentation/crypto/latest/crypto/md5.html
[sha1-obj]: https://www.dartdocs.org/documentation/crypto/latest/crypto/sha1.html
[sha256-obj]: https://www.dartdocs.org/documentation/crypto/latest/crypto/sha256.html
[tracker]: https://github.com/dart-lang/crypto/issues
