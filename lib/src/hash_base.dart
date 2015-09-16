// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypto.hash_base;

import 'dart:math' as math;
import 'dart:typed_data';

import 'hash.dart';
import 'utils.dart';

// Base class encapsulating common behavior for cryptographic hash
// functions.
abstract class HashBase implements Hash {
  final int _chunkSizeInWords;
  final int _digestSizeInWords;
  final bool _bigEndianWords;
  final Uint32List _currentChunk;
  final Uint32List h;
  int _lengthInBytes = 0;
  List<int> _pendingData;
  bool _digestCalled = false;

  HashBase(
      int chunkSizeInWords, int digestSizeInWords, bool this._bigEndianWords)
      : _pendingData = [],
        _currentChunk = new Uint32List(chunkSizeInWords),
        h = new Uint32List(digestSizeInWords),
        _chunkSizeInWords = chunkSizeInWords,
        _digestSizeInWords = digestSizeInWords;

  // Update the hasher with more data.
  void add(List<int> data) {
    if (_digestCalled) {
      throw new StateError(
          'Hash update method called after digest was retrieved');
    }
    _lengthInBytes += data.length;
    _pendingData.addAll(data);
    _iterate();
  }

  // Finish the hash computation and return the digest string.
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

  // Returns the block size of the hash in bytes.
  int get blockSize {
    return _chunkSizeInWords * BYTES_PER_WORD;
  }

  // One round of the hash computation.
  void updateHash(Uint32List m);

  // Compute the final result as a list of bytes from the hash words.
  List<int> _resultAsBytes() {
    var result = [];
    for (var i = 0; i < h.length; i++) {
      result.addAll(_wordToBytes(h[i]));
    }
    return result;
  }

  // Converts a list of bytes to a chunk of 32-bit words.
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

  // Convert a 32-bit word to four bytes.
  List<int> _wordToBytes(int word) {
    List bytes = new List<int>(BYTES_PER_WORD);
    bytes[0] = (word >> (_bigEndianWords ? 24 : 0)) & MASK_8;
    bytes[1] = (word >> (_bigEndianWords ? 16 : 8)) & MASK_8;
    bytes[2] = (word >> (_bigEndianWords ? 8 : 16)) & MASK_8;
    bytes[3] = (word >> (_bigEndianWords ? 0 : 24)) & MASK_8;
    return bytes;
  }

  // Iterate through data updating the hash computation for each
  // chunk.
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

  // Finalize the data. Add a 1 bit to the end of the message. Expand with
  // 0 bits and add the length of the message.
  void _finalizeData() {
    _pendingData.add(0x80);
    var contentsLength = _lengthInBytes + 9;
    var chunkSizeInBytes = _chunkSizeInWords * BYTES_PER_WORD;
    var finalizedLength = roundUp(contentsLength, chunkSizeInBytes);
    var zeroPadding = finalizedLength - contentsLength;
    for (var i = 0; i < zeroPadding; i++) {
      _pendingData.add(0);
    }
    var lengthInBits = _lengthInBytes * BITS_PER_BYTE;
    assert(lengthInBits < math.pow(2, 32));
    if (_bigEndianWords) {
      _pendingData.addAll(_wordToBytes(0));
      _pendingData.addAll(_wordToBytes(lengthInBits & MASK_32));
    } else {
      _pendingData.addAll(_wordToBytes(lengthInBits & MASK_32));
      _pendingData.addAll(_wordToBytes(0));
    }
  }
}
