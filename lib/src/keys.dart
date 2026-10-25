import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'errors.dart';

final _x25519 = X25519();
final _ed25519 = Ed25519();

/// The type byte before an encoded X25519 public key, as in libsignal
/// (the `Encode(PK)` of the X3DH specification, section 2.5).
const djbType = 0x05;

/// Bytes in an encoded X25519 public key: [djbType] and the u-coordinate.
const encodedKeyLength = 33;

/// An X25519 public key.
final class DhPublicKey {
  /// The u-coordinate, 32 bytes, little-endian (RFC 7748).
  final Uint8List bytes;

  DhPublicKey(List<int> bytes) : bytes = Uint8List.fromList(bytes) {
    if (this.bytes.length != 32) throw const InvalidKeyException('an X25519 key is 32 bytes');
  }

  /// `Encode(PK)`: [djbType] and the 32 bytes.
  Uint8List encode() => Uint8List(encodedKeyLength)
    ..[0] = djbType
    ..setRange(1, encodedKeyLength, bytes);

  static DhPublicKey decode(List<int> encoded) {
    if (encoded.length != encodedKeyLength || encoded[0] != djbType) {
      throw const InvalidKeyException('not an encoded X25519 key');
    }
    return DhPublicKey(encoded.sublist(1));
  }

  @override
  bool operator ==(Object other) => other is DhPublicKey && bytesEqual(bytes, other.bytes);

  @override
  int get hashCode => Object.hashAll(bytes);

  @override
  String toString() => 'DhPublicKey(${hex(bytes)})';
}

/// An X25519 key pair.
final class DhKeyPair {
  final Uint8List _private;
  final DhPublicKey publicKey;

  DhKeyPair._(this._private, this.publicKey);

  /// A new random key pair.
  static Future<DhKeyPair> generate() async {
    final kp = await _x25519.newKeyPair();
    return _of(kp);
  }

  /// The key pair of the 32 private bytes [private] (clamped by X25519).
  static Future<DhKeyPair> fromPrivate(List<int> private) async {
    if (private.length != 32) throw const InvalidKeyException('an X25519 private key is 32 bytes');
    return _of(await _x25519.newKeyPairFromSeed(private));
  }

  /// A stored key pair: [private] and its [public] key, not checked
  /// against each other (that costs a scalar multiplication).
  static DhKeyPair fromStorage(List<int> private, List<int> public) {
    if (private.length != 32) throw const InvalidKeyException('an X25519 private key is 32 bytes');
    return DhKeyPair._(Uint8List.fromList(private), DhPublicKey(public));
  }

  static Future<DhKeyPair> _of(SimpleKeyPair kp) async {
    final private = Uint8List.fromList(await kp.extractPrivateKeyBytes());
    final public = await kp.extractPublicKey();
    return DhKeyPair._(private, DhPublicKey(public.bytes));
  }

  /// The private bytes, for storage.
  Uint8List get privateBytes => Uint8List.fromList(_private);

  /// `DH(this, other)`. Throws [InvalidKeyException] when [other] is a
  /// low-order point (the shared secret is all zeros).
  Future<Uint8List> agree(DhPublicKey other) async {
    final kp = SimpleKeyPairData(
      _private,
      publicKey: SimplePublicKey(publicKey.bytes, type: KeyPairType.x25519),
      type: KeyPairType.x25519,
    );
    final shared = await _x25519.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(other.bytes, type: KeyPairType.x25519),
    );
    final out = Uint8List.fromList(await shared.extractBytes());
    if (out.every((b) => b == 0)) throw const InvalidKeyException('low-order X25519 key');
    return out;
  }
}

/// A public identity key: an Ed25519 key, which signs, and the X25519 key
/// that the birational map gives for it, which takes part in X3DH.
///
/// The Signal specifications use XEdDSA, so that an X25519 identity key
/// can sign. This package goes the other way: the identity is an Ed25519
/// key (a libp2p peer key, an SSH key, ...), and its X25519 form comes from
/// RFC 7748's map, as libsodium's `crypto_sign_ed25519_pk_to_curve25519`
/// does. Both give one key for signatures and for DH.
final class IdentityKey {
  /// The Ed25519 public key, 32 bytes.
  final Uint8List ed25519;

  /// The X25519 form of [ed25519].
  final DhPublicKey x25519;

  IdentityKey._(this.ed25519, this.x25519);

  /// Throws [InvalidKeyException] when [ed25519] is not a valid point
  /// encoding.
  factory IdentityKey(List<int> ed25519) {
    final ed = Uint8List.fromList(ed25519);
    return IdentityKey._(ed, DhPublicKey(edPublicToX25519(ed)));
  }

  /// Checks an Ed25519 [signature] by this key.
  Future<bool> verify(List<int> message, List<int> signature) async {
    if (signature.length != 64) return false;
    try {
      return await _ed25519.verify(
        message,
        signature: Signature(signature, publicKey: SimplePublicKey(ed25519, type: KeyPairType.ed25519)),
      );
    } catch (_) {
      return false;
    }
  }

  @override
  bool operator ==(Object other) => other is IdentityKey && bytesEqual(ed25519, other.ed25519);

  @override
  int get hashCode => Object.hashAll(ed25519);

  @override
  String toString() => 'IdentityKey(${hex(ed25519)})';
}

/// An identity key pair: an Ed25519 key pair, and its X25519 form.
final class IdentityKeyPair {
  final Uint8List _seed;
  final SimpleKeyPair _ed;
  final IdentityKey publicKey;

  /// For DH in X3DH.
  final DhKeyPair dh;

  IdentityKeyPair._(this._seed, this._ed, this.publicKey, this.dh);

  /// The identity of the 32-byte Ed25519 [seed] (RFC 8032's private key;
  /// libp2p keeps it as the first half of its 64-byte private key).
  static Future<IdentityKeyPair> fromSeed(List<int> seed) async {
    if (seed.length != 32) throw const InvalidKeyException('an Ed25519 seed is 32 bytes');
    final s = Uint8List.fromList(seed);
    final ed = await _ed25519.newKeyPairFromSeed(s);
    final public = await ed.extractPublicKey();
    // RFC 8032 5.1.5: the scalar is the first half of SHA-512(seed); X25519
    // clamps it the same way.
    final h = await Sha512().hash(s);
    final dh = await DhKeyPair.fromPrivate(h.bytes.sublist(0, 32));
    final key = IdentityKey(public.bytes);
    if (key.x25519 != dh.publicKey) throw StateError('Ed25519 to X25519 map disagrees');
    return IdentityKeyPair._(s, ed, key, dh);
  }

  /// A new random identity.
  static Future<IdentityKeyPair> generate() async {
    final ed = await _ed25519.newKeyPair();
    return fromSeed(await ed.extractPrivateKeyBytes());
  }

  /// The seed, for storage.
  Uint8List get seed => Uint8List.fromList(_seed);

  Future<Uint8List> sign(List<int> message) async =>
      Uint8List.fromList((await _ed25519.sign(message, keyPair: _ed)).bytes);
}

final _p = (BigInt.one << 255) - BigInt.from(19);
final _d = (BigInt.from(-121665) * BigInt.from(121666).modInverse(_p)) % _p;

/// The X25519 public key of an Ed25519 public key: u = (1 + y) / (1 - y)
/// mod p (RFC 7748, section 4.1). Throws [InvalidKeyException] for bytes
/// that are not the encoding of a point on the curve.
Uint8List edPublicToX25519(Uint8List edPublic) {
  if (edPublic.length != 32) throw const InvalidKeyException('an Ed25519 key is 32 bytes');
  final le = Uint8List.fromList(edPublic)..[31] &= 0x7f; // Drop the sign of x.
  var y = BigInt.zero;
  for (var i = 31; i >= 0; i--) {
    y = (y << 8) | BigInt.from(le[i]);
  }
  if (y >= _p) throw const InvalidKeyException('not an Ed25519 key');
  // On the curve: x^2 = (y^2 - 1) / (d y^2 + 1) must have a root (Euler's
  // criterion), as RFC 8032 5.1.3 decoding requires.
  final y2 = (y * y) % _p;
  final x2 = ((y2 - BigInt.one) * ((_d * y2 + BigInt.one) % _p).modInverse(_p)) % _p;
  if (x2 != BigInt.zero && x2.modPow((_p - BigInt.one) >> 1, _p) != BigInt.one) {
    throw const InvalidKeyException('not a point on Ed25519');
  }
  final denominator = (BigInt.one - y) % _p;
  if (denominator == BigInt.zero) throw const InvalidKeyException('not an Ed25519 key');
  var u = ((BigInt.one + y) * denominator.modInverse(_p)) % _p;
  final out = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    out[i] = (u & BigInt.from(0xff)).toInt();
    u >>= 8;
  }
  return out;
}
