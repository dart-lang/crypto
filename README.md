# Cryptographic hashing functions for Dart

A set of cryptographic hashing functions implemented in pure Dart

The following hashing algorithms are supported:

* MD5
* SHA-1
* SHA-256
* HMAC (i.e. HMAC-MD5, HMAC-SHA1, HMAC-SHA256)

## Usage

### Digest on a single input

Use `sha256.convert()`, `sha1.convert()`, or `md5.convert()` to hash a
list of bytes.

These methods return a [`Digest`][Digest] object, where the hash value
can be obtained as a list of bytes or encoded in hexadecimal.

The variables [`sha256`][sha256], [`sha1`][sha1], and [`md5`][md5] are
instances of the [`Sha256`][Sha256], [`Sha1`][Sha1], and [`MD5`][MD5]
classes, respectively.

```dart
import 'package:crypto/crypto.dart';
import 'dart:convert'; // for the UTF8.encode method

void main() {
  var bytes = UTF8.encode("foobar"); // data being hashed

  var digest = sha1.convert(bytes);

  print("Digest as bytes: ${digest.bytes}");
  print("Digest as hex string: $digest");
}
```

### Digest on chunked input

If the input data is not a single `List<int>`, use the chunked
conversion approach.

Invoke the `startChunkedConversion` method to create a sink for the
input data. On the sink, invoke the `add` method for each chunk of
input data, and invoke the `close` method when all the chunks have
been added. The digest can then be retrieved from the `Sink<Digest>`
used to create the input data sink.

```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:crypto/src/digest_sink.dart';

void main() {
  var firstChunk = UTF8.encode("foo");
  var secondChunk = UTF8.encode("bar");

  var ds = new DigestSink();
  var s = sha1.startChunkedConversion(ds);
  s.add(firstChunk);
  s.add(secondChunk); // call `add` for every chunk of input data
  s.close();
  var digest = ds.value;

  print("Digest as bytes: ${digest.bytes}");
  print("Digest as hex string: $digest");
}
```

The above example uses the `DigestSink` class that comes with the
_crypto_ package. Its `value` property retrieves the last `Digest`
that was added to it, which is fine for this purpose since only one
`Digest` is added to it when the data sink's `close` method was
invoked.

### HMAC

Create an instance of the [`Hmac`][Hmac] class with the hash function
and secret key being used.  The object can then be used like the other
hash calculating objects.

```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:crypto/src/digest_sink.dart';

void main() {
  var keyBytes = UTF8.encode('p@ssw0rd');
  var bytes = UTF8.encode("foobar");

  var hmac = new Hmac(sha256, keyBytes); // HMAC-SHA256
  var digest = hmac.convert(bytes);
  
  print("HMAC digest as bytes: ${digest.bytes}");
  print("HMAC digest as hex string: $digest");
}
```

## Test status

See http://build.chromium.org/p/client.dart.packages/console

The individual builders are at:

http://build.chromium.org/p/client.dart.packages/builders/packages-windows-crypto
http://build.chromium.org/p/client.dart.packages/builders/packages-linux-crypto
http://build.chromium.org/p/client.dart.packages/builders/packages-mac-crypto

## Disclaimer

Support for this library is given as _best effort_.

This library has not been reviewed or vetted by security professionals.

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/dart-lang/crypto/issues

[Digest]: https://www.dartdocs.org/documentation/crypto/latest/crypto/Digest-class.html
[Hmac] https://www.dartdocs.org/documentation/crypto/latests/crypto/Hmac-class.html
[sha1]: https://www.dartdocs.org/documentation/crypto/latest/crypto/sha1.html
[sha256]: https://www.dartdocs.org/documentation/crypto/latest/crypto/sha256.html
[md5]: https://www.dartdocs.org/documentation/crypto/latest/crypto/md5.html

[MD5] https://www.dartdocs.org/documentation/crypto/latests/crypto/MD5-class.html
[Sha1] https://www.dartdocs.org/documentation/crypto/latests/crypto/Sha1-class.html
[Sha256] https://www.dartdocs.org/documentation/crypto/latests/crypto/Sha256-class.html
