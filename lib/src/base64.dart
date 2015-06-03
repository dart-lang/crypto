part of crypto;

const Base64Codec BASE64 = const Base64Codec();

const List<int> _decodeTable =
      const [ -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -2, -2, -1, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, 62, -2, 63,
              52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2,  0, -2, -2,
              -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
              15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, 63,
              -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
              41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
              -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2 ];

const String _encodeTableUrlSafe =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const String _encodeTable =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const List<String> _URL_SAFE_CHARACTERS = const ['+', '/'];
const List<String> _URL_UNSAFE_CHARACTERS = const ['-', '_'];

const int _LINE_LENGTH = 76;
const int _PAD = 61; // '='
const int _CR = 13;  // '\r'
const int _LF = 10;  // '\n'

class Base64Codec extends Codec<List<int>, String> {

  final bool _urlSafe;
  final bool _addLineSeparator;

  /**
   * Instantiates a new [Base64Codec].
   *
   * The optional [urlSafe] argument specifies if [encoder] and [encode]
   * should generate a string, that is safe to use in an URL.
   *
   * If [urlSafe] is `true` (and not overriden at the method invocation)
   * the [encoder] and [encode] use '-' instead of '+' and '_' instead of '/'.
   *
   * The default value of [urlSafe] is `false`.
   *
   * The optional [addLineSeparator] argument specifies if the [encoder] and
   * [encode] should add line separators.
   *
   * If `addLineSeparator` is `true` [encode] adds an
   * optional line separator (CR + LF) for each 76 char output.
   *
   * The default value of [addLineSeparator] if `false`.
   */
  const Base64Codec({bool urlSafe: false, bool addLineSeparator: false})
      : _urlSafe = urlSafe,
        _addLineSeparator = addLineSeparator;

  String get name => "base64";

  String encode(List<int> bytes,
                {bool urlSafe,
                 bool addLineSeparator}) {
    if (urlSafe == null) urlSafe = _urlSafe;
    if (addLineSeparator == null) addLineSeparator = _addLineSeparator;
    return new Base64Encoder(urlSafe: urlSafe,
                   addLineSeparator: addLineSeparator).convert(bytes);


  }

  Base64Encoder get encoder => new Base64Encoder(
                                     urlSafe: _urlSafe,
                                     addLineSeparator: _addLineSeparator);

  Base64Decoder get decoder => new Base64Decoder();

}

/**
 * This class encodes byte strings (lists of unsigned
 * 8-bit integers) to strings according to Base64.
 */
class Base64Encoder extends Converter<List<int>, String> {
  final bool _urlSafe;
  final bool _addLineSeparator;

  /**
   * Instantiates a new [Base64Encoder].
   *
   * The optional [urlSafe] argument specifies if [convert]
   * should generate a string, that is safe to use in an URL.
   *
   * If it is `true` the [convert] use
   * '-' instead of '+' and '_' instead of '/'.
   *
   * The default value of [urlSafe] is `false`.
   *
   * The optional [addLineSeparator] argument specifies if [convert]
   * should add line separators.
   *
   * If it is `true` [convert] adds an optional line separator(CR + LF)
   * for each 76 char output.
   *
   * The default value of [addLineSeparator] if `false`.
   */
  const Base64Encoder({bool urlSafe: false, bool addLineSeparator: false})
      : _urlSafe = urlSafe,
        _addLineSeparator = addLineSeparator;

  /**
   * Converts [bytes] to its Base64 representation as a string.
   *
   * if [start] and [end] are provided, only the sublist
   * `bytes.sublist(start, end)` is converted.
   */

  String convert(List<int> bytes, [int start = 0, int end]) {
    int bytes_length = bytes.length;
    RangeError.checkValidRange(start, end, bytes_length);
    if (end == null) end = bytes_length;
    int length = end - start;
    if (length == 0) {
      return "";
    }
    final String lookup = _urlSafe ? _encodeTableUrlSafe : _encodeTable;
    // Size of 24 bit chunks.
    final int remainderLength = length.remainder(3);
    final int chunkLength = length - remainderLength;
    // Size of base output.
    int baseOutputLength = ((length ~/ 3) * 4);
    int remainderOutputLength = ((remainderLength > 0) ? 4 : 0);
    int outputLength = baseOutputLength + remainderOutputLength;
    // Add extra for line separators.
    if (_addLineSeparator) {
      outputLength += ((outputLength - 1) ~/ _LINE_LENGTH) << 1;
    }
    List<int> out = new List<int>(outputLength);

    // Encode 24 bit chunks.
    int j = 0, i = start, c = 0;
    while (i < chunkLength) {
      int x = ((bytes[i++] << 16) & 0x00FFFFFF) |
              ((bytes[i++] << 8) & 0x00FFFFFF) |
                bytes[i++];
      out[j++] = lookup.codeUnitAt(x >> 18);
      out[j++] = lookup.codeUnitAt((x >> 12) & 0x3F);
      out[j++] = lookup.codeUnitAt((x >> 6)  & 0x3F);
      out[j++] = lookup.codeUnitAt(x & 0x3F);
      // Add optional line separator for each 76 char output.
      if (_addLineSeparator && ++c == 19 && j < outputLength - 2) {
        out[j++] = _CR;
        out[j++] = _LF;
        c = 0;
      }
    }

    // If input length if not a multiple of 3, encode remaining bytes and
    // add padding.
    if (remainderLength == 1) {
      int x = bytes[i];
      out[j++] = lookup.codeUnitAt(x >> 2);
      out[j++] = lookup.codeUnitAt((x << 4) & 0x3F);
      out[j++] = _PAD;
      out[j++] = _PAD;
    } else if (remainderLength == 2) {
      int x = bytes[i];
      int y = bytes[i + 1];
      out[j++] = lookup.codeUnitAt(x >> 2);
      out[j++] = lookup.codeUnitAt(((x << 4) | (y >> 4)) & 0x3F);
      out[j++] = lookup.codeUnitAt((y << 2) & 0x3F);
      out[j++] = _PAD;
    }

    return new String.fromCharCodes(out);
  }

  _Base64EncoderSink startChunkedConversion(Sink<String> sink) {
    StringConversionSink stringSink;
    if (sink is StringConversionSink) {
      stringSink = sink;
    } else {
      stringSink = new StringConversionSink.from(sink);
    }
    return new _Base64EncoderSink(stringSink, _urlSafe, _addLineSeparator);
  }
}

class _Base64EncoderSink extends ChunkedConversionSink<List<int>> {

  final Base64Encoder _encoder;
  final ChunkedConversionSink<String> _outSink;
  final List<int> _buffer = new List<int>();
  int _bufferCount = 0;

  _Base64EncoderSink(this._outSink, urlSafe, addLineSeparator)
      : _encoder = new Base64Encoder(urlSafe: urlSafe,
                                     addLineSeparator: addLineSeparator);


  void add(List<int> chunk) {
    var nextBufferCount = (chunk.length + _bufferCount) % 3;

    int decodableLength = _bufferCount + chunk.length - nextBufferCount;

    if (_bufferCount + chunk.length > _buffer.length) {
      _buffer.replaceRange(_bufferCount,
                           _buffer.length,
                           chunk.sublist(0, _buffer.length - _bufferCount));
      _buffer.addAll(chunk.sublist(_buffer.length - _bufferCount));
    } else {
      _buffer.replaceRange(_bufferCount, _bufferCount + chunk.length, chunk);
    }

    _outSink.add(_encoder.convert(_buffer, 0, decodableLength));
    _buffer.removeRange(0, decodableLength);
    _bufferCount = nextBufferCount;
  }

  void close() {
    if (_bufferCount > 0) {
      _outSink.add(_encoder.convert(_buffer.sublist(0, _bufferCount)));
    }
    _outSink.close();
  }
}

/**
 * This class decodes strings to lists of bytes(lists of
 * unsigned 8-bit integers) according to Base64.
 */
class Base64Decoder extends Converter<String, List<int>> {

  /**
   * Instantiates a new [Base64Decoder]
   */
  const Base64Decoder();

  List<int> convert(String input, {bool alwaysPadding: false}) {
    int length = input.length;
    if (length == 0) {
      return new List<int>(0);
    }

    // Count '\r', '\n' and illegal characters, check if
    // '/', '+' / '-', '_' are used consistently, for illegal characters,
    // throw an exception.
    int extrasLength = 0;
    bool expectedSafe = false;
    bool expectedUnsafe = false;

    for (int i = 0; i < length; i++) {
      int c = _decodeTable[input.codeUnitAt(i)];
      if (c < 0) {
        extrasLength++;
        if (c == -2) {
          throw new FormatException('Invalid character', input, i);
        }
      } else if (input[i] == _URL_UNSAFE_CHARACTERS[0] ||
                 input[i] == _URL_UNSAFE_CHARACTERS[1]) {

        if (expectedSafe) {
          throw new FormatException('Unsafe character in URL-safe string',
                                    input, i);
        }
        expectedUnsafe = true;
      } else if (input[i] == _URL_SAFE_CHARACTERS[0] ||
                 input[i] == _URL_SAFE_CHARACTERS[1]) {
        if (expectedUnsafe) {
          throw new FormatException('Invalid character', input, i);
        }
        expectedSafe = true;
      }
    }

    if ((length - extrasLength) % 4 != 0) {
      throw new FormatException('''Size of Base 64 characters in Input
          must be a multiple of 4''', input, length - extrasLength);
    }

    // Count pad characters.
    int padLength = 0;
    for (int i = length - 1; i >= 0; i--) {
      int currentCodeUnit = input.codeUnitAt(i);
      if (_decodeTable[currentCodeUnit] > 0) break;
      if (currentCodeUnit == _PAD) padLength++;
    }
    int outputLength = (((length - extrasLength) * 6) >> 3) - padLength;
    List<int> out = new List<int>(outputLength);

    for (int i = 0, o = 0; o < outputLength; ) {
      // Accumulate 4 valid 6 bit Base 64 characters into an int.
      int x = 0;
      for (int j = 4; j > 0; ) {
        int c = _decodeTable[input.codeUnitAt(i++)];
        if (c >= 0) {
          x = ((x << 6) & 0x00FFFFFF) | c;
          j--;
        }
      }
      out[o++] = x >> 16;
      if (o < outputLength) {
        out[o++] = (x >> 8) & 0xFF;
        if (o < outputLength) out[o++] = x & 0xFF;
      }
    }

    return out;
  }

  _Base64DecoderSink startChunkedConversion(Sink<List<int>> sink) {
    if (sink is! ByteConversionSink) {
      sink = new ByteConversionSink.from(sink);
    }
    return new _Base64DecoderSink(sink);
  }
}


class _Base64DecoderSink extends ChunkedConversionSink<String> {

  final Base64Decoder _decoder = new Base64Decoder();
  final ChunkedConversionSink<List<int>> _outSink;
  String _buffer = "";
  bool _isSafe = false;
  bool _isUnsafe = false;

  _Base64DecoderSink(this._outSink);

  void add(String chunk) {
    int nextBufferLength = (chunk.length + _buffer.length) % 4;

    if (chunk.length + _buffer.length >= 4) {
      int remainder = chunk.length - nextBufferLength;
      String decodable = _buffer + chunk.substring(0, remainder);
      _buffer = chunk.substring(remainder);

      for (int i = 0;i < decodable.length; i++) {
        if (decodable[i] == _URL_UNSAFE_CHARACTERS[0] ||
            decodable[i] == _URL_UNSAFE_CHARACTERS[1]) {
          if (_isSafe) {
            throw new FormatException('Unsafe character in URL-safe string',
                                       decodable, i);
          }
          _isUnsafe = true;
        } else if (decodable[i] == _URL_SAFE_CHARACTERS[0] ||
                   decodable[i] == _URL_SAFE_CHARACTERS[1]) {
          if (_isUnsafe) {
            throw new FormatException('Invalid character', decodable, i);
          }
          _isSafe = true;
        }
      }

      _outSink.add(_decoder.convert(decodable));
    } else {
      _buffer += chunk;
    }
  }

  void close() {
    if (!_buffer.isEmpty) {
      throw new FormatException(
          "Size of Base 64 input must be a multiple of 4",
          _buffer,
          _buffer.length);
    }
    _outSink.close();
  }
}

