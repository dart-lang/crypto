# Cryptographic digest functions for Dart

A set of cryptographic digest functions implemented in pure
Dart. Cryptographic digest is also known as cryptographic hashing.

The following digest/hashing algorithms are supported:

* MD5
* SHA-1
* SHA-256
* HMAC (i.e. HMAC-MD5, HMAC-SHA1, HMAC-SHA256)

## Usage

### Digest on a single input

Use the `sha256` property to obtain an instance of the `Sha256` class.
Or use the `sha1` or `md5` properties to use those other digest
algorithms.

Invoke the `convert` method, passing the input data as a sequence of
bytes (i.e. `List<int>`). It returns a `Digest` object, where the
digest value can be obtained as bytes in a `List<int>` or encoded in
hexadecimal as a `String`.

```dart
import 'package:crypto/crypto.dart';
import 'dart:convert'; // for the UTF8.encode method

  ...

  var dataString = "foobar"; // input data being hashed

  var bytes = UTF8.encode(dataString);

  var digest = sha1.convert(bytes);

  print("Digest as bytes: ${digest.bytes}");
  print("Digest as a hexadecimal string: $digest");
```

In the above example, the data being digested is a `String`, so the
`UTF8.encode` method was used to convert it into a sequence of bytes.

**Warning:** The input data represents a sequence of bytes, so the
`List<int>` **must not** contain integers outside the range 0-255.
Do not use the `codeUnits` property of a `String`, unless it is
_guaranteed_ the string will never contain characters outside the
range of 0-255. Even then, characters in the range of 128-255 might
produce the wrong result.

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

  ...

  var firstChunk = UTF8.encode("foo");
  var secondChunk = UTF8.encode("bar");

  var ds = new DigestSink();
  var s = sha1.startChunkedConversion(ds);
  s.add(firstChunk);
  s.add(secondChunk);
  // keep calling `add` for all input data
  s.close();
  var digest = ds.value;

  print("Digest as bytes: ${digest.bytes}");
  print("Digest as a hexadecimal string: $digest");
```

The above example uses the `DigestSink` class that comes with the
_crypto_ package. Its `value` property retrieves the last `Digest`
that was added to it, which is fine for this purpose since only one
`Digest` is added to it when the data sink's `close` method was
invoked.

### HMAC

Create a `Hmac` object with the hash function and secret key being
used.  The `Hmac` object is then used like the other hash calculating
objects.

```dart
  ...

  var keyBytes = UTF8.encode(keyString);
  var bytes = UTF8.encode(dataString);

  var hmac = new Hmac(sha256, keyBytes); // HMAC-SHA256
  var digest = hmac.convert(bytes);
  print("Digest as bytes: ${digest.bytes}");
  print("Digest as a hexadecimal string: $digest");
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
