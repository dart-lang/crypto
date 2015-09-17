// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.hash_base;

import 'dart:math' as math;
import 'dart:typed_data';

import 'hash.dart';
import 'utils.dart';

/// A base class for [Hash] implementations.
///
/// Subclasses should override [updateHash], and define it to update [h] with
/// the results of the hash function.
abstract class HashBase implements Hash {
  /// The size (in 32-bit words) of the chunks of input data that the hash
  /// function consumes at once.
  final int _chunkSizeInWords;

  /// The size (in 32-bit words) of the digest that the hash function emits.
  final int _digestSizeInWords;

  /// Whether the hash function operates on big-endian words.
  final bool _bigEndianWords;

  /// The words in the current chunk.
  final Uint32List _currentChunk;

  /// The words in the current digest.
  ///
  /// The size of this buffer is given by the `digestSizeInWords` constructor
  /// parameter.
  final Uint32List h;

  /// The length of the input data so far, in bytes.
  int _lengthInBytes = 0;

  /// Data that has yet to be processed by the hash function.
  List<int> _pendingData;

  /// Whether [close] has been called.
  bool _digestCalled = false;

  /// Creates a new hash.
  ///
  /// [chunkSizeInWords] represents the size of the input chunks processed by
  /// the algorithm. [digestSizeInWords] represents the size of the algorithm's
  /// output digest. Both are in terms of 32-bit words.
  HashBase(
      int chunkSizeInWords, int digestSizeInWords, bool this._bigEndianWords)
      : _pendingData = [],
        _currentChunk = new Uint32List(chunkSizeInWords),
        h = new Uint32List(digestSizeInWords),
        _chunkSizeInWords = chunkSizeInWords,
        _digestSizeInWords = digestSizeInWords;

  void add(List<int> data) {
    if (_digestCalled) {
      throw new StateError(
          'Hash update method called after digest was retrieved');
    }
    _lengthInBytes += data.length;
    _pendingData.addAll(data);
    _iterate();
  }

  List<int> close() {
    if (_digestCalled) {
      return _resultAsBytes();
    }
    _digestCalled = true;
    _finalizeData();
    _iterate();
    assert(_pendingData.length == 0);
    return _resultAsBytes();
  }

  int get blockSize {
    return _chunkSizeInWords * BYTES_PER_WORD;
  }

  /// Runs a single iteration of the hash computation, updating [h] with the
  /// result.
  ///
  /// [m] is the current chunk, whose size is given by the `chunkSizeInWords`
  /// parameter passed to the constructor.
  void updateHash(Uint32List m);

  /// Computes the final result of the hash as a list of bytes from the hash
  /// words.
  List<int> _resultAsBytes() {
    var result = [];
    for (var i = 0; i < h.length; i++) {
      result.addAll(_wordToBytes(h[i]));
    }
    return result;
  }

  /// Converts a list of bytes to a chunk of 32-bit words.
  ///
  /// Stores the result in [_currentChunk].
  void _bytesToChunk(List<int> data, int dataIndex) {
    assert((data.length - dataIndex) >= (_chunkSizeInWords * BYTES_PER_WORD));

    for (var wordIndex = 0; wordIndex < _chunkSizeInWords; wordIndex++) {
      var w3 = _bigEndianWords ? data[dataIndex] : data[dataIndex + 3];
      var w2 = _bigEndianWords ? data[dataIndex + 1] : data[dataIndex + 2];
      var w1 = _bigEndianWords ? data[dataIndex + 2] : data[dataIndex + 1];
      var w0 = _bigEndianWords ? data[dataIndex + 3] : data[dataIndex];
      dataIndex += 4;
      var word = (w3 & 0xff) << 24;
      word |= (w2 & MASK_8) << 16;
      word |= (w1 & MASK_8) << 8;
      word |= (w0 & MASK_8);
      _currentChunk[wordIndex] = word;
    }
  }

  /// Converts a 32-bit word to four bytes.
  List<int> _wordToBytes(int word) {
    List bytes = new List<int>(BYTES_PER_WORD);
    bytes[0] = (word >> (_bigEndianWords ? 24 : 0)) & MASK_8;
    bytes[1] = (word >> (_bigEndianWords ? 16 : 8)) & MASK_8;
    bytes[2] = (word >> (_bigEndianWords ? 8 : 16)) & MASK_8;
    bytes[3] = (word >> (_bigEndianWords ? 0 : 24)) & MASK_8;
    return bytes;
  }

  /// Iterates through [_pendingData], updating the hash computation for each
  /// chunk.
  void _iterate() {
    var len = _pendingData.length;
    var chunkSizeInBytes = _chunkSizeInWords * BYTES_PER_WORD;
    if (len >= chunkSizeInBytes) {
      var index = 0;
      for (; (len - index) >= chunkSizeInBytes; index += chunkSizeInBytes) {
        _bytesToChunk(_pendingData, index);
        updateHash(_currentChunk);
      }
      _pendingData = _pendingData.sublist(index, len);
    }
  }

  /// Finalizes [_pendingData].
  ///
  /// This adds a 1 bit to the end of the message, and expands it with 0 bits to
  /// pad it out.
  void _finalizeData() {
    _pendingData.add(0x80);
    var contentsLength = _lengthInBytes + 9;
    var chunkSizeInBytes = _chunkSizeInWords * BYTES_PER_WORD;
    var finalizedLength = _roundUp(contentsLength, chunkSizeInBytes);
    var zeroPadding = finalizedLength - contentsLength;
    for (var i = 0; i < zeroPadding; i++) {
      _pendingData.add(0);
    }
    var lengthInBits = _lengthInBytes * BITS_PER_BYTE;
    const MAX_UINT64 = 0xFFFFFFFFFFFFFFFF;
    if (lengthInBits > MAX_UINT64) {
      throw new UnsupportedError(
          "Hash undefined for message bit lengths larger than 64 bits");
    }
    if (_bigEndianWords) {
      _pendingData.addAll(_wordToBytes((lengthInBits >> 32) & MASK_32));
      _pendingData.addAll(_wordToBytes(lengthInBits & MASK_32));
    } else {
      _pendingData.addAll(_wordToBytes(lengthInBits & MASK_32));
      _pendingData.addAll(_wordToBytes((lengthInBits >> 32) & MASK_32));
    }
  }

  /// Rounds [val] to the nearest multiple of [n].
  int _roundUp(val, n) => (val + n - 1) & -n;
}
