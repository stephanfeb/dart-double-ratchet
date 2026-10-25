import 'dart:typed_data';

import 'bytes.dart';
import 'errors.dart';
import 'keys.dart';
import 'ratchet.dart';

/// Which of Bob's pre-keys Alice used, kept until Bob answers.
final class PendingPreKey {
  final int signedPreKeyId;
  final int? oneTimePreKeyId;

  const PendingPreKey(this.signedPreKeyId, this.oneTimePreKeyId);
}

/// One Double Ratchet session with an address.
final class SessionState {
  final IdentityKey remoteIdentity;

  /// The X3DH associated data.
  final Uint8List ad;

  /// Alice's ephemeral key: identifies the session in pre-key messages.
  final DhPublicKey baseKey;

  /// Set on Alice's side until a message from Bob arrives: until then, each
  /// message goes in a pre-key message.
  PendingPreKey? pending;

  RatchetState ratchet;

  SessionState({
    required this.remoteIdentity,
    required this.ad,
    required this.baseKey,
    required this.pending,
    required this.ratchet,
  });

  void write(ByteWriter w) {
    w
      ..bytes(remoteIdentity.ed25519)
      ..blob(ad)
      ..bytes(baseKey.bytes)
      ..u8(pending == null ? 0 : 1);
    if (pending case final p?) {
      w
        ..u32(p.signedPreKeyId)
        ..u8(p.oneTimePreKeyId == null ? 0 : 1);
      if (p.oneTimePreKeyId case final id?) w.u32(id);
    }
    ratchet.write(w);
  }

  static SessionState read(ByteReader r) {
    final identity = IdentityKey(r.bytes(32));
    final ad = r.blob();
    final baseKey = DhPublicKey(r.bytes(32));
    PendingPreKey? pending;
    if (_flag(r)) {
      final spk = r.u32();
      pending = PendingPreKey(spk, _flag(r) ? r.u32() : null);
    }
    return SessionState(
      remoteIdentity: identity,
      ad: ad,
      baseKey: baseKey,
      pending: pending,
      ratchet: RatchetState.read(r),
    );
  }
}

bool _flag(ByteReader r) => switch (r.u8()) {
      0 => false,
      1 => true,
      _ => throw const InvalidMessageException('bad flag'),
    };

const _recordVersion = 1;

/// Every session with one address: the current one first, then earlier
/// ones (as libsignal keeps them), which messages still in flight may use.
/// Two parties that start sessions with each other at once end up with
/// both, and each reads what the other sends with either.
final class SessionRecord {
  final List<SessionState> states;

  SessionRecord([List<SessionState>? states]) : states = states ?? [];

  SessionState? get current => states.firstOrNull;

  /// Puts [state] first, keeping at most [maxStates] states.
  void promote(SessionState state, int maxStates) {
    states
      ..remove(state)
      ..insert(0, state);
    if (states.length > maxStates) states.removeRange(maxStates, states.length);
  }

  /// Puts [state] second, after the current one, keeping at most
  /// [maxStates] states.
  void keep(SessionState state, int maxStates) {
    states
      ..remove(state)
      ..insert(states.isEmpty ? 0 : 1, state);
    if (states.length > maxStates) states.removeRange(maxStates, states.length);
  }

  Uint8List encode() {
    final w = ByteWriter()
      ..u8(_recordVersion)
      ..u32(states.length);
    for (final s in states) {
      s.write(w);
    }
    return w.take();
  }

  /// Throws [InvalidMessageException] for bytes that are not a record.
  static SessionRecord decode(List<int> bytes) {
    final r = ByteReader(bytes);
    if (r.u8() != _recordVersion) throw const InvalidMessageException('unknown session record version');
    final states = [for (var i = r.u32(); i > 0; i--) SessionState.read(r)];
    r.end();
    return SessionRecord(states);
  }
}
