import 'dart:typed_data';

import 'bytes.dart';
import 'errors.dart';
import 'kdf.dart';
import 'keys.dart';

/// The wire version of this package's messages.
const protocolVersion = 1;

/// The type byte of a Double Ratchet message.
const messageType = 1;

/// Bytes before the ciphertext of a message: version, type, header.
const messageHeaderLength = 2 + encodedKeyLength + 4 + 4;

/// How much skipping one session allows (Double Ratchet section 3.5).
final class RatchetLimits {
  /// `MAX_SKIP`: the most message keys one message can skip in one chain.
  /// Messages that need more are rejected before any key is stored.
  final int maxSkip;

  /// The most skipped message keys a session keeps; above this, the oldest
  /// are deleted (section 6.5 asks for skipped keys to be deleted in time).
  final int maxSkippedKeys;

  const RatchetLimits({this.maxSkip = 1000, this.maxSkippedKeys = 2000})
      : assert(maxSkip >= 0 && maxSkippedKeys >= maxSkip);
}

/// A Double Ratchet header (section 3.2): the sender's ratchet public key,
/// the length of its previous sending chain, and the message number.
final class Header {
  final DhPublicKey dh;
  final int pn, n;

  const Header(this.dh, this.pn, this.n);

  /// The bytes before the ciphertext of a message.
  Uint8List encode() => (ByteWriter()
        ..u8(protocolVersion)
        ..u8(messageType)
        ..bytes(dh.encode())
        ..u32(pn)
        ..u32(n))
      .take();
}

/// A Double Ratchet message: [header], then ciphertext || MAC.
final class RatchetMessage {
  final Header header;
  final Uint8List ciphertext;

  const RatchetMessage(this.header, this.ciphertext);

  Uint8List encode() => Uint8List.fromList([...header.encode(), ...ciphertext]);

  /// Throws [InvalidMessageException] for bytes that are not a message.
  static RatchetMessage decode(List<int> bytes) {
    final r = ByteReader(bytes);
    if (r.u8() != protocolVersion) throw const InvalidMessageException('unknown version');
    if (r.u8() != messageType) throw const InvalidMessageException('not a ratchet message');
    final DhPublicKey dh;
    try {
      dh = DhPublicKey.decode(r.bytes(encodedKeyLength));
    } on InvalidKeyException {
      throw const InvalidMessageException('bad ratchet key');
    }
    final header = Header(dh, r.u32(), r.u32());
    final ct = r.rest();
    if (ct.length < 16 + macLength) throw const InvalidMessageException('short ciphertext');
    return RatchetMessage(header, ct);
  }
}

/// The state of one Double Ratchet session (section 3.2).
///
/// The functions below change it in place. A caller that may fail half way
/// (decryption) works on a [copy] and keeps it only on success, as section
/// 3.5 requires.
final class RatchetState {
  DhKeyPair dhs;
  DhPublicKey? dhr;
  Uint8List rk;
  Uint8List? cks, ckr;
  int ns, nr, pn;

  /// `MKSKIPPED`: message keys by ratchet key and message number, oldest
  /// first (a Dart map keeps insertion order).
  final Map<String, Uint8List> skipped;

  /// The last few receiving ratchet keys before [dhr], newest last. Not in
  /// the specification: a message on one of these chains whose key is not
  /// in [skipped] was already read (or its key was dropped), and must not
  /// be taken for a new ratchet step. libsignal keeps old chains the same
  /// way.
  final List<DhPublicKey> previous;

  /// How many [previous] keys a state keeps.
  static const maxPrevious = 5;

  RatchetState({
    required this.dhs,
    required this.dhr,
    required this.rk,
    required this.cks,
    required this.ckr,
    required this.ns,
    required this.nr,
    required this.pn,
    Map<String, Uint8List>? skipped,
    List<DhPublicKey>? previous,
  })  : skipped = skipped ?? <String, Uint8List>{},
        previous = previous ?? [];

  RatchetState copy() => RatchetState(
        dhs: dhs,
        dhr: dhr,
        rk: rk,
        cks: cks,
        ckr: ckr,
        ns: ns,
        nr: nr,
        pn: pn,
        skipped: Map.of(skipped),
        previous: [...previous],
      );

  static String skippedKey(DhPublicKey dh, int n) => '${hex(dh.bytes)}:$n';

  void write(ByteWriter w) {
    w
      ..bytes(dhs.privateBytes)
      ..bytes(dhs.publicKey.bytes)
      ..optional(dhr?.bytes)
      ..bytes(rk)
      ..optional(cks)
      ..optional(ckr)
      ..u32(ns)
      ..u32(nr)
      ..u32(pn)
      ..u32(skipped.length);
    for (final MapEntry(:key, :value) in skipped.entries) {
      final [dh, n] = key.split(':');
      w
        ..bytes(_unhex(dh))
        ..u32(int.parse(n))
        ..bytes(value);
    }
    w.u8(previous.length);
    for (final k in previous) {
      w.bytes(k.bytes);
    }
  }

  static RatchetState read(ByteReader r) {
    final dhs = DhKeyPair.fromStorage(r.bytes(32), r.bytes(32));
    final dhr = r.optional(32);
    final rk = r.bytes(32);
    final cks = r.optional(32);
    final ckr = r.optional(32);
    final ns = r.u32(), nr = r.u32(), pn = r.u32();
    final skipped = <String, Uint8List>{};
    for (var i = r.u32(); i > 0; i--) {
      final dh = DhPublicKey(r.bytes(32));
      skipped[skippedKey(dh, r.u32())] = r.bytes(32);
    }
    final previous = [for (var i = r.u8(); i > 0; i--) DhPublicKey(r.bytes(32))];
    return RatchetState(
      dhs: dhs,
      dhr: dhr == null ? null : DhPublicKey(dhr),
      rk: rk,
      cks: cks,
      ckr: ckr,
      ns: ns,
      nr: nr,
      pn: pn,
      skipped: skipped,
      previous: previous,
    );
  }
}

Uint8List _unhex(String s) =>
    Uint8List.fromList([for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);

/// `RatchetInitAlice` (section 3.3): [sk] from X3DH, [bobRatchetKey] being
/// Bob's signed pre-key.
Future<RatchetState> ratchetInitAlice(List<int> sk, DhPublicKey bobRatchetKey, ProtocolInfo info) async {
  final dhs = await DhKeyPair.generate();
  final (rk, cks) = await kdfRk(sk, await dhs.agree(bobRatchetKey), info);
  return RatchetState(dhs: dhs, dhr: bobRatchetKey, rk: rk, cks: cks, ckr: null, ns: 0, nr: 0, pn: 0);
}

/// `RatchetInitBob` (section 3.3): [bobRatchetKey] being Bob's signed
/// pre-key pair.
RatchetState ratchetInitBob(List<int> sk, DhKeyPair bobRatchetKey) => RatchetState(
      dhs: bobRatchetKey,
      dhr: null,
      rk: Uint8List.fromList(sk),
      cks: null,
      ckr: null,
      ns: 0,
      nr: 0,
      pn: 0,
    );

/// `RatchetEncrypt` (section 3.4). [ad] is the X3DH associated data; the
/// MAC covers it and the header.
Future<RatchetMessage> ratchetEncrypt(RatchetState state, List<int> plaintext, List<int> ad, ProtocolInfo info) async {
  final cks = state.cks;
  if (cks == null) throw StateError('no sending chain: this side has not received a message yet');
  final (next, mk) = await kdfCk(cks);
  state.cks = next;
  final header = Header(state.dhs.publicKey, state.pn, state.ns);
  state.ns += 1;
  return RatchetMessage(header, await encrypt(mk, plaintext, [...ad, ...header.encode()], info));
}

/// `RatchetDecrypt` (section 3.5). Throws [InvalidMessageException] or
/// [DuplicateMessageException]; [state] is then half changed, so callers
/// pass a copy.
Future<Uint8List> ratchetDecrypt(
  RatchetState state,
  RatchetMessage message,
  List<int> ad,
  ProtocolInfo info,
  RatchetLimits limits,
) async {
  final header = message.header;
  final fullAd = [...ad, ...header.encode()];
  final skippedMk = state.skipped.remove(RatchetState.skippedKey(header.dh, header.n));
  if (skippedMk != null) return decrypt(skippedMk, message.ciphertext, fullAd, info);
  if (state.previous.contains(header.dh)) {
    throw const DuplicateMessageException('message key of an earlier chain already used or dropped');
  }
  if (header.dh != state.dhr) {
    await _skipMessageKeys(state, header.pn, limits);
    await _dhRatchet(state, header, info);
  } else if (header.n < state.nr) {
    throw const DuplicateMessageException('message key already used');
  }
  // Alice's first ratchet key is Bob's signed pre-key, with no receiving
  // chain: Bob never sends with it.
  if (state.ckr == null) throw const InvalidMessageException('no receiving chain for this ratchet key');
  await _skipMessageKeys(state, header.n, limits);
  final (next, mk) = await kdfCk(state.ckr!);
  state.ckr = next;
  state.nr += 1;
  return decrypt(mk, message.ciphertext, fullAd, info);
}

Future<void> _skipMessageKeys(RatchetState state, int until, RatchetLimits limits) async {
  if (state.nr + limits.maxSkip < until) throw const InvalidMessageException('too many skipped messages');
  var ckr = state.ckr;
  if (ckr == null) return;
  while (state.nr < until) {
    final (next, mk) = await kdfCk(ckr!);
    ckr = next;
    state.skipped[RatchetState.skippedKey(state.dhr!, state.nr)] = mk;
    state.nr += 1;
  }
  state.ckr = ckr;
  while (state.skipped.length > limits.maxSkippedKeys) {
    state.skipped.remove(state.skipped.keys.first);
  }
}

Future<void> _dhRatchet(RatchetState state, Header header, ProtocolInfo info) async {
  if (state.dhr case final old?) {
    state.previous.add(old);
    if (state.previous.length > RatchetState.maxPrevious) state.previous.removeAt(0);
  }
  state
    ..pn = state.ns
    ..ns = 0
    ..nr = 0
    ..dhr = header.dh;
  final (rk1, ckr) = await kdfRk(state.rk, await state.dhs.agree(header.dh), info);
  state
    ..rk = rk1
    ..ckr = ckr
    ..dhs = await DhKeyPair.generate();
  final (rk2, cks) = await kdfRk(state.rk, await state.dhs.agree(header.dh), info);
  state
    ..rk = rk2
    ..cks = cks;
}
