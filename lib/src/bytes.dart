import 'dart:typed_data';

import 'errors.dart';

/// Writes the binary encodings of this package (big-endian integers).
class ByteWriter {
  final _b = BytesBuilder(copy: false);

  void u8(int v) => _b.addByte(v);

  void u32(int v) => _b.add(Uint8List(4)..buffer.asByteData().setUint32(0, v));

  void bytes(List<int> v) => _b.add(v);

  /// A length (u32) and then [v].
  void blob(List<int> v) {
    u32(v.length);
    bytes(v);
  }

  /// A flag, and [v] when it is not null.
  void optional(List<int>? v) {
    u8(v == null ? 0 : 1);
    if (v != null) bytes(v);
  }

  Uint8List take() => _b.takeBytes();
}

/// Reads what [ByteWriter] writes. Throws [InvalidMessageException] when
/// the input is too short.
class ByteReader {
  final Uint8List _data;
  int _at = 0;

  ByteReader(List<int> data) : _data = data is Uint8List ? data : Uint8List.fromList(data);

  int get remaining => _data.length - _at;

  int get offset => _at;

  void _need(int n) {
    if (remaining < n) throw const InvalidMessageException('truncated');
  }

  int u8() {
    _need(1);
    return _data[_at++];
  }

  int u32() {
    _need(4);
    final v = _data.buffer.asByteData(_data.offsetInBytes + _at, 4).getUint32(0);
    _at += 4;
    return v;
  }

  Uint8List bytes(int n) {
    _need(n);
    final v = Uint8List.fromList(_data.sublist(_at, _at + n));
    _at += n;
    return v;
  }

  Uint8List blob() => bytes(u32());

  Uint8List? optional(int n) => switch (u8()) {
        0 => null,
        1 => bytes(n),
        _ => throw const InvalidMessageException('bad flag'),
      };

  Uint8List rest() => bytes(remaining);

  /// Throws unless every byte was read.
  void end() {
    if (remaining != 0) throw const InvalidMessageException('trailing bytes');
  }
}

bool bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Compares in time that depends only on the length, for MACs.
bool constantTimeEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}

String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
