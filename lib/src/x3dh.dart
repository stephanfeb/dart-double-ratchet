import 'dart:typed_data';

import 'bytes.dart';
import 'errors.dart';
import 'kdf.dart';
import 'keys.dart';
import 'ratchet.dart';

/// The type byte of a pre-key message.
const preKeyMessageType = 2;

/// The version byte of a bundle. Version 2 signs the signed pre-key with a
/// label and its id ([signedPreKeyMessage]); version 1 signed the bare key
/// and is not read.
const bundleVersion = 2;

/// What the identity key signs for the signed pre-key [key] with [id]:
/// `utf8("<application> signed pre-key") || u32(id) || Encode(key)`.
Uint8List signedPreKeyMessage(ProtocolInfo info, int id, DhPublicKey key) => (ByteWriter()
      ..bytes(info.signedPreKey)
      ..u32(id)
      ..bytes(key.encode()))
    .take();

/// A signed pre-key (X3DH section 2.3): Bob's medium-term key, signed by
/// his identity key, and the private half.
final class SignedPreKey {
  final int id;
  final DhKeyPair keyPair;

  /// `Sig(IK_B, signedPreKeyMessage(...))`.
  final Uint8List signature;

  /// When it was made, so the owner can rotate it.
  final DateTime createdAt;

  SignedPreKey(this.id, this.keyPair, this.signature, this.createdAt);

  /// A new key with [id], signed by [identity] for [application] (the name
  /// given to [SessionCipher]).
  static Future<SignedPreKey> generate(IdentityKeyPair identity, int id,
      {required String application, DateTime? now}) async {
    final kp = await DhKeyPair.generate();
    final signature = await identity.sign(signedPreKeyMessage(ProtocolInfo(application), id, kp.publicKey));
    return SignedPreKey(id, kp, signature, now ?? DateTime.now());
  }

  /// Whether [signature] is [identity]'s for this key under [application]:
  /// false for a key signed for another application, or by version 0.1.
  Future<bool> verify(IdentityKey identity, String application) =>
      identity.verify(signedPreKeyMessage(ProtocolInfo(application), id, keyPair.publicKey), signature);

  Uint8List encode() => (ByteWriter()
        ..u32(id)
        ..bytes(keyPair.privateBytes)
        ..bytes(signature)
        ..u32(createdAt.millisecondsSinceEpoch ~/ 1000))
      .take();

  static Future<SignedPreKey> decode(List<int> bytes) async {
    final r = ByteReader(bytes);
    final key = SignedPreKey(
      r.u32(),
      await DhKeyPair.fromPrivate(r.bytes(32)),
      r.bytes(64),
      DateTime.fromMillisecondsSinceEpoch(r.u32() * 1000),
    );
    r.end();
    return key;
  }
}

/// A one-time pre-key (X3DH section 2.3): used in one session, then
/// deleted.
final class OneTimePreKey {
  final int id;
  final DhKeyPair keyPair;

  OneTimePreKey(this.id, this.keyPair);

  static Future<OneTimePreKey> generate(int id) async => OneTimePreKey(id, await DhKeyPair.generate());

  /// [count] keys with ids from [firstId] up.
  static Future<List<OneTimePreKey>> generateMany(int firstId, int count) =>
      Future.wait([for (var i = 0; i < count; i++) generate(firstId + i)]);

  Uint8List encode() => (ByteWriter()
        ..u32(id)
        ..bytes(keyPair.privateBytes))
      .take();

  static Future<OneTimePreKey> decode(List<int> bytes) async {
    final r = ByteReader(bytes);
    final key = OneTimePreKey(r.u32(), await DhKeyPair.fromPrivate(r.bytes(32)));
    r.end();
    return key;
  }
}

/// What Alice needs from Bob to start a session (X3DH section 3.2): his
/// identity key, his signed pre-key and its signature, and maybe a
/// one-time pre-key.
final class PreKeyBundle {
  final IdentityKey identityKey;
  final int signedPreKeyId;
  final DhPublicKey signedPreKey;
  final Uint8List signedPreKeySignature;
  final int? oneTimePreKeyId;
  final DhPublicKey? oneTimePreKey;

  PreKeyBundle({
    required this.identityKey,
    required this.signedPreKeyId,
    required this.signedPreKey,
    required List<int> signedPreKeySignature,
    this.oneTimePreKeyId,
    this.oneTimePreKey,
  }) : signedPreKeySignature = Uint8List.fromList(signedPreKeySignature) {
    if ((oneTimePreKeyId == null) != (oneTimePreKey == null)) {
      throw ArgumentError('a one-time pre-key needs its id, and the other way round');
    }
  }

  /// Bob's bundle from his keys.
  factory PreKeyBundle.of(IdentityKey identity, SignedPreKey signed, [OneTimePreKey? oneTime]) => PreKeyBundle(
        identityKey: identity,
        signedPreKeyId: signed.id,
        signedPreKey: signed.keyPair.publicKey,
        signedPreKeySignature: signed.signature,
        oneTimePreKeyId: oneTime?.id,
        oneTimePreKey: oneTime?.keyPair.publicKey,
      );

  /// Checks the signature on the signed pre-key, made for [application].
  Future<bool> verify(String application) => identityKey.verify(
      signedPreKeyMessage(ProtocolInfo(application), signedPreKeyId, signedPreKey), signedPreKeySignature);

  Uint8List encode() {
    final w = ByteWriter()
      ..u8(bundleVersion)
      ..bytes(identityKey.ed25519)
      ..u32(signedPreKeyId)
      ..bytes(signedPreKey.encode())
      ..bytes(signedPreKeySignature)
      ..u8(oneTimePreKey == null ? 0 : 1);
    if (oneTimePreKey case final opk?) {
      w
        ..u32(oneTimePreKeyId!)
        ..bytes(opk.encode());
    }
    return w.take();
  }

  /// Throws [InvalidMessageException] or [InvalidKeyException] for bytes
  /// that are not a bundle. Does not check the signature: see [verify].
  static PreKeyBundle decode(List<int> bytes) {
    final r = ByteReader(bytes);
    if (r.u8() != bundleVersion) throw const InvalidMessageException('unknown bundle version');
    final ik = IdentityKey(r.bytes(32));
    final spkId = r.u32();
    final spk = DhPublicKey.decode(r.bytes(encodedKeyLength));
    final sig = r.bytes(64);
    int? opkId;
    DhPublicKey? opk;
    switch (r.u8()) {
      case 0:
        break;
      case 1:
        opkId = r.u32();
        opk = DhPublicKey.decode(r.bytes(encodedKeyLength));
      default:
        throw const InvalidMessageException('bad flag');
    }
    r.end();
    return PreKeyBundle(
      identityKey: ik,
      signedPreKeyId: spkId,
      signedPreKey: spk,
      signedPreKeySignature: sig,
      oneTimePreKeyId: opkId,
      oneTimePreKey: opk,
    );
  }
}

/// Alice's initial message (X3DH section 3.3): her identity key, her
/// ephemeral key, which of Bob's pre-keys she used, and the first Double
/// Ratchet message. She sends every message in one until Bob answers, so
/// that Bob can start the session from whichever arrives first.
final class PreKeyMessage {
  final IdentityKey identityKey;
  final DhPublicKey baseKey;
  final int signedPreKeyId;
  final int? oneTimePreKeyId;
  final RatchetMessage message;

  const PreKeyMessage({
    required this.identityKey,
    required this.baseKey,
    required this.signedPreKeyId,
    required this.oneTimePreKeyId,
    required this.message,
  });

  Uint8List encode() {
    final w = ByteWriter()
      ..u8(protocolVersion)
      ..u8(preKeyMessageType)
      ..bytes(identityKey.ed25519)
      ..bytes(baseKey.encode())
      ..u32(signedPreKeyId)
      ..u8(oneTimePreKeyId == null ? 0 : 1);
    if (oneTimePreKeyId case final id?) w.u32(id);
    w.bytes(message.encode());
    return w.take();
  }

  static PreKeyMessage decode(List<int> bytes) {
    final r = ByteReader(bytes);
    if (r.u8() != protocolVersion) throw const InvalidMessageException('unknown version');
    if (r.u8() != preKeyMessageType) throw const InvalidMessageException('not a pre-key message');
    try {
      final ik = IdentityKey(r.bytes(32));
      final base = DhPublicKey.decode(r.bytes(encodedKeyLength));
      final spkId = r.u32();
      final opkId = switch (r.u8()) {
        0 => null,
        1 => r.u32(),
        _ => throw const InvalidMessageException('bad flag'),
      };
      return PreKeyMessage(
        identityKey: ik,
        baseKey: base,
        signedPreKeyId: spkId,
        oneTimePreKeyId: opkId,
        message: RatchetMessage.decode(r.rest()),
      );
    } on InvalidKeyException catch (e) {
      throw InvalidMessageException(e.message);
    }
  }
}

/// `AD = Encode(IK_A) || Encode(IK_B)` (X3DH section 3.3). The identity
/// keys go in as Ed25519 keys: two Ed25519 keys (x and -x) map to one
/// X25519 key, and the Ed25519 form is the one that identifies.
Uint8List associatedData(IdentityKey alice, IdentityKey bob) => Uint8List.fromList([...alice.ed25519, ...bob.ed25519]);

/// Alice's side of X3DH (section 3.3). Returns SK.
Future<Uint8List> x3dhAlice({
  required IdentityKeyPair identity,
  required DhKeyPair ephemeral,
  required PreKeyBundle bundle,
  required ProtocolInfo info,
}) async {
  final dh1 = await identity.dh.agree(bundle.signedPreKey);
  final dh2 = await ephemeral.agree(bundle.identityKey.x25519);
  final dh3 = await ephemeral.agree(bundle.signedPreKey);
  final dh4 = bundle.oneTimePreKey == null ? const <int>[] : await ephemeral.agree(bundle.oneTimePreKey!);
  return kdfX3dh([...dh1, ...dh2, ...dh3, ...dh4], info);
}

/// Bob's side of X3DH (section 3.4). Returns SK.
Future<Uint8List> x3dhBob({
  required IdentityKeyPair identity,
  required SignedPreKey signedPreKey,
  required OneTimePreKey? oneTimePreKey,
  required IdentityKey aliceIdentity,
  required DhPublicKey aliceBaseKey,
  required ProtocolInfo info,
}) async {
  final dh1 = await signedPreKey.keyPair.agree(aliceIdentity.x25519);
  final dh2 = await identity.dh.agree(aliceBaseKey);
  final dh3 = await signedPreKey.keyPair.agree(aliceBaseKey);
  final dh4 = oneTimePreKey == null ? const <int>[] : await oneTimePreKey.keyPair.agree(aliceBaseKey);
  return kdfX3dh([...dh1, ...dh2, ...dh3, ...dh4], info);
}
