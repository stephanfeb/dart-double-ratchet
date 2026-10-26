import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'errors.dart';

final _hmac = Hmac.sha256();
final _aesCbc = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);

/// The application-specific `info` strings of the KDFs (X3DH section 2.1,
/// Double Ratchet section 5.2). Both parties must use the same.
final class ProtocolInfo {
  final Uint8List x3dh, rootChain, messageKeys;

  /// The label before a signed pre-key in what the identity key signs, so
  /// that the signature cannot stand for one the key made for something
  /// else.
  final Uint8List signedPreKey;

  ProtocolInfo._(this.x3dh, this.rootChain, this.messageKeys, this.signedPreKey);

  /// The `info` strings for the application [name].
  factory ProtocolInfo(String name) => ProtocolInfo._(
        utf8.encode('$name X3DH'),
        utf8.encode('$name Ratchet'),
        utf8.encode('$name MessageKeys'),
        utf8.encode('$name signed pre-key'),
      );
}

Future<Uint8List> hkdf(List<int> ikm, {required List<int> salt, required List<int> info, required int length}) async {
  final out =
      await Hkdf(hmac: _hmac, outputLength: length).deriveKey(secretKey: SecretKey(ikm), nonce: salt, info: info);
  return Uint8List.fromList(await out.extractBytes());
}

Future<Uint8List> hmacSha256(List<int> key, List<int> data) async =>
    Uint8List.fromList((await _hmac.calculateMac(data, secretKey: SecretKey(key))).bytes);

/// The X3DH KDF (section 2.2): HKDF over F || [dhs], F being 32 0xFF bytes,
/// with a zero salt. Returns SK, 32 bytes.
Future<Uint8List> kdfX3dh(List<int> dhs, ProtocolInfo info) =>
    hkdf([...List.filled(32, 0xff), ...dhs], salt: Uint8List(32), info: info.x3dh, length: 32);

/// `KDF_RK(rk, dh_out)` (Double Ratchet section 5.2): HKDF with [rk] as the
/// salt. Returns the new root key and a chain key.
Future<(Uint8List, Uint8List)> kdfRk(List<int> rk, List<int> dhOut, ProtocolInfo info) async {
  final out = await hkdf(dhOut, salt: rk, info: info.rootChain, length: 64);
  return (out.sublist(0, 32), out.sublist(32));
}

/// `KDF_CK(ck)` (section 5.2): HMAC-SHA256 of [ck] over 0x02 for the next
/// chain key and over 0x01 for the message key.
Future<(Uint8List, Uint8List)> kdfCk(List<int> ck) async =>
    (await hmacSha256(ck, const [0x02]), await hmacSha256(ck, const [0x01]));

/// Bytes the MAC adds to a ciphertext.
const macLength = 32;

/// `ENCRYPT(mk, plaintext, associated_data)` as section 5.2 recommends:
/// HKDF of [mk] gives an AES-256 key, an HMAC key and an IV; AES-256-CBC
/// with PKCS#7 padding; HMAC-SHA256 over [ad] || ciphertext. Returns
/// ciphertext || MAC.
Future<Uint8List> encrypt(List<int> mk, List<int> plaintext, List<int> ad, ProtocolInfo info) async {
  final (encKey, authKey, iv) = await _messageKeys(mk, info);
  final box = await _aesCbc.encrypt(plaintext, secretKey: SecretKey(encKey), nonce: iv);
  final mac = await hmacSha256(authKey, [...ad, ...box.cipherText]);
  return Uint8List.fromList([...box.cipherText, ...mac]);
}

/// `DECRYPT`: checks the MAC, then decrypts. Throws
/// [InvalidMessageException] when the MAC does not match.
Future<Uint8List> decrypt(List<int> mk, List<int> data, List<int> ad, ProtocolInfo info) async {
  if (data.length < 16 + macLength || (data.length - macLength) % 16 != 0) {
    throw const InvalidMessageException('bad ciphertext length');
  }
  final (encKey, authKey, iv) = await _messageKeys(mk, info);
  final ct = data.sublist(0, data.length - macLength);
  final mac = await hmacSha256(authKey, [...ad, ...ct]);
  if (!constantTimeEqual(mac, data.sublist(data.length - macLength))) {
    throw const InvalidMessageException('bad MAC');
  }
  try {
    return Uint8List.fromList(
      await _aesCbc.decrypt(SecretBox(ct, nonce: iv, mac: Mac.empty), secretKey: SecretKey(encKey)),
    );
  } catch (_) {
    throw const InvalidMessageException('bad padding');
  }
}

Future<(Uint8List, Uint8List, Uint8List)> _messageKeys(List<int> mk, ProtocolInfo info) async {
  final out = await hkdf(mk, salt: Uint8List(32), info: info.messageKeys, length: 80);
  return (out.sublist(0, 32), out.sublist(32, 64), out.sublist(64));
}
