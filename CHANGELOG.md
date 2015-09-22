## 0.9.2

* `Hash`, `MD5`, `SHA1`, and `SHA256` now implement `Converter`. They convert
  between `List<int>`s and the new `Digest` class, which represents a hash
  digest. The `Converter` APIs—`Hash.convert()` and
  `Hash.startChunkedConversion`—should be used in preference to the old APIs,
  which are now deprecated.

* Top-level `sha1`, `sha256`, and `md5` fields have been added to make it easier
  to use those hash algorithms without having to instantiate new instances.

* Hashing now works correctly for input sizes up to 2^64 bytes.

### Deprecations

* `Hash.add`, `Hash.close`, and `Hash.newInstance` are deprecated.
  `Hash.convert` should be used for hashing single values, and
  `Hash.startChunkedConversion` should be used for hashing streamed values.
  
* `new SHA1()`, `new SHA256()`, and `new MD5()` are deprecated. Use the
  top-level `sha1`, `sha256`, and `md5` fields instead.

## 0.9.1

* Base64 convert returns an Uint8List
* Base64 codec and encoder can now take an encodePaddingCharacter
* Implement a Base64 codec similar to codecs in 'dart:convert'

## 0.9.0

* ChangeLog starts here.
