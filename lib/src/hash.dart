// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.hash;

/// An interface for cryptographic hash functions.
///
/// The [add] method adds data to the hash. The [close] method extracts the
/// message digest.
///
/// If multiple instances of a given Hash is needed, the [newInstance] method
/// can provide a new instance.
// TODO(floitsch): make Hash implement Sink, EventSink or similar.
abstract class Hash {
  /// Add a list of bytes to the hash computation.
  ///
  /// If [this] has already been closed, throws a [StateError].
  void add(List<int> data);

  /// Finish the hash computation and extract the message digest as a list of
  /// bytes.
  List<int> close();

  /// Returns a new instance of this hash function.
  Hash newInstance();

  /// The internal block size of the hash in bytes.
  ///
  /// This is exposed for use by the [HMAC] class, which needs to know the block
  /// size for the [Hash] it uses.
  int get blockSize;
}
