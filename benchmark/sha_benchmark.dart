import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:crypto/src/digest_sink.dart';

void main() {
  const loops = 1000;
  print("benchmarks:");

  final random = Random();
  final watch = Stopwatch()..start();
  final seed = Uint8List(1<<20);
  for (var i = 0; i < seed.length; i++) {
    seed[i] = random.nextInt(256);
  }

  for (final hash in [sha224, sha256, sha384, sha512]) {

    watch.reset();
    var innerSink = DigestSink();
    var outerSink = hash.startChunkedConversion(innerSink);
    for (int i = 0; i < loops; i++) {
      outerSink.add(seed);
    }
    outerSink.close();
    final value = innerSink.value;
    final elapsed = watch.elapsed;

    final bytes = loops * seed.length;
    print("${hash.runtimeType}: $elapsed "
        "= ${(bytes / elapsed.inMicroseconds).toStringAsFixed(2)} MB/s; "
        " ${base64Encode(value.bytes)}");
  }
}
