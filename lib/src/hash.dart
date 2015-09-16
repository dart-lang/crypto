// Copyright (c) 2015, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.hash;

/**
 * Interface for cryptographic hash functions.
 *
 * The [add] method is used to add data to the hash. The [close] method
 * is used to extract the message digest.
 *
 * Once the [close] method has been called no more data can be added using the
 * [add] method. If [add] is called after the first call to [close] a
 * HashException is thrown.
 *
 * If multiple instances of a given Hash is needed the [newInstance]
 * method can provide a new instance.
 */
// TODO(floitsch): make Hash implement Sink, EventSink or similar.
abstract class Hash {
  /**
   * Add a list of bytes to the hash computation.
   */
  void add(List<int> data);

  /**
   * Finish the hash computation and extract the message digest as
   * a list of bytes.
   */
  List<int> close();

  /**
   * Returns a new instance of this hash function.
   */
  Hash newInstance();

  /**
   * Internal block size of the hash in bytes.
   *
   * This is exposed for use by the HMAC class which needs to know the
   * block size for the [Hash] it is using.
   */
  int get blockSize;
}
