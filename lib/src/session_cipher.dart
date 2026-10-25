import 'dart:async';
import 'dart:typed_data';

import 'errors.dart';
import 'kdf.dart';
import 'keys.dart';
import 'ratchet.dart';
import 'session.dart';
import 'store.dart';
import 'x3dh.dart';

/// Starts sessions (X3DH) and encrypts and decrypts with them (Double
/// Ratchet), keeping the state in the stores.
///
/// Use one [SessionCipher] for a set of stores: it runs the calls for one
/// address one at a time, so that two of them do not read the same session
/// state and write back two different ones, and it starts one session from
/// a pre-key message at a time, so that a one-time pre-key is used once. A
/// call that fails changes no state.
///
/// Which session is current changes only when this side starts one
/// ([processBundle]), when the other side starts one (a new pre-key
/// message), or when a message arrives in another session while the current
/// one is still unanswered. A message in an earlier session is read, but
/// does not make that session current again.
///
/// Each forged message costs up to [maxStates] decryption attempts, each
/// with up to 2 x [RatchetLimits.maxSkip] HMACs, before it fails: limit
/// what one sender can deliver.
class SessionCipher {
  final IdentityStore identities;
  final PreKeyStore preKeys;
  final SessionStore sessions;
  final ProtocolInfo info;
  final RatchetLimits limits;

  /// How many sessions to keep for each address (the current one and
  /// earlier ones).
  final int maxStates;

  final _locks = <String, Future<void>>{};

  /// The key of the lock for starting sessions from pre-key messages; no
  /// address is empty with a NUL in it.
  static const _preKeyLock = '\u0000pre-keys';

  /// [application] names the protocol in the KDFs: both parties must use
  /// the same.
  SessionCipher({
    required this.identities,
    required this.preKeys,
    required this.sessions,
    required String application,
    this.limits = const RatchetLimits(),
    this.maxStates = 5,
  }) : info = ProtocolInfo(application) {
    if (maxStates < 1) throw ArgumentError.value(maxStates, 'maxStates', 'at least 1');
    if (limits.maxSkip < 0 || limits.maxSkippedKeys < limits.maxSkip) {
      throw ArgumentError('maxSkippedKeys must be at least maxSkip, and maxSkip at least 0');
    }
  }

  /// Starts a session with [address] from its [bundle], as Alice (X3DH
  /// section 3.3). Messages sent before [address] answers carry what it
  /// needs to start its side.
  ///
  /// Throws [InvalidKeyException] when the signature on the signed pre-key
  /// does not verify, [UntrustedIdentityException] when [identities] does
  /// not trust the bundle's identity key for [address].
  Future<void> processBundle(String address, PreKeyBundle bundle) => _locked(address, () async {
        if (!await bundle.verify()) throw const InvalidKeyException('bad signed pre-key signature');
        if (!await identities.isTrusted(address, bundle.identityKey)) {
          throw UntrustedIdentityException(address, 'identity key not trusted');
        }
        final ours = await identities.identityKeyPair();
        final ephemeral = await DhKeyPair.generate();
        final sk = await x3dhAlice(identity: ours, ephemeral: ephemeral, bundle: bundle, info: info);
        final state = SessionState(
          remoteIdentity: bundle.identityKey,
          ad: associatedData(ours.publicKey, bundle.identityKey),
          baseKey: ephemeral.publicKey,
          pending: PendingPreKey(bundle.signedPreKeyId, bundle.oneTimePreKeyId),
          ratchet: await ratchetInitAlice(sk, bundle.signedPreKey, info),
        );
        final record = await _load(address) ?? SessionRecord();
        record.promote(state, maxStates);
        await sessions.storeSession(address, record.encode());
        await identities.saveIdentity(address, bundle.identityKey);
      });

  /// Whether there is a session with [address] that can send.
  Future<bool> hasSession(String address) async {
    final current = (await _load(address))?.current;
    return current != null && current.ratchet.cks != null;
  }

  /// The identity key of the current session with [address].
  Future<IdentityKey?> remoteIdentity(String address) async => (await _load(address))?.current?.remoteIdentity;

  /// Forgets every session with [address].
  Future<void> deleteSession(String address) => _locked(address, () => sessions.deleteSession(address));

  /// Encrypts [plaintext] for [address]: a pre-key message until [address]
  /// has answered, a Double Ratchet message after. Throws
  /// [NoSessionException] when there is no session.
  Future<Uint8List> encrypt(String address, List<int> plaintext) => _locked(address, () async {
        final record = await _load(address);
        final state = record?.current;
        if (record == null || state == null || state.ratchet.cks == null) {
          throw NoSessionException('no session with $address');
        }
        final message = await ratchetEncrypt(state.ratchet, plaintext, state.ad, info);
        final Uint8List out;
        if (state.pending case final p?) {
          out = PreKeyMessage(
            identityKey: (await identities.identityKeyPair()).publicKey,
            baseKey: state.baseKey,
            signedPreKeyId: p.signedPreKeyId,
            oneTimePreKeyId: p.oneTimePreKeyId,
            message: message,
          ).encode();
        } else {
          out = message.encode();
        }
        await sessions.storeSession(address, record.encode());
        return out;
      });

  /// Decrypts [message] from [address]: a pre-key message (which may start
  /// a session, as Bob) or a Double Ratchet message.
  ///
  /// Throws [InvalidMessageException], [DuplicateMessageException],
  /// [NoSessionException], [UntrustedIdentityException] or
  /// [InvalidKeyIdException]; no state changes then.
  Future<Uint8List> decrypt(String address, List<int> message) => _locked(address, () async {
        if (message.length < 2 || message[0] != protocolVersion) {
          throw const InvalidMessageException('unknown version');
        }
        return switch (message[1]) {
          messageType => _decryptMessage(address, RatchetMessage.decode(message)),
          preKeyMessageType => _decryptPreKey(address, PreKeyMessage.decode(message)),
          _ => throw const InvalidMessageException('unknown message type'),
        };
      });

  Future<Uint8List> _decryptMessage(String address, RatchetMessage message) async {
    final record = await _load(address);
    if (record == null || record.states.isEmpty) throw NoSessionException('no session with $address');
    return _decryptWith(address, record, record.states, message);
  }

  Future<Uint8List> _decryptPreKey(String address, PreKeyMessage message) async {
    if (!await identities.isTrusted(address, message.identityKey)) {
      throw UntrustedIdentityException(address, 'identity key not trusted');
    }
    final record = await _load(address) ?? SessionRecord();
    // Alice sends each message in a pre-key message until Bob answers: the
    // second one and later belong to the session the first one started.
    final existing =
        record.states.where((s) => s.baseKey == message.baseKey && s.remoteIdentity == message.identityKey).toList();
    if (existing.isNotEmpty) return _decryptWith(address, record, existing, message.message, promote: false);
    // A new session: one at a time across all addresses, so that a pre-key
    // message replayed to another address (or at the same moment) finds
    // its base key used and its one-time pre-key gone.
    return _locked(_preKeyLock, () => _startSession(address, record, message));
  }

  Future<Uint8List> _startSession(String address, SessionRecord record, PreKeyMessage message) async {
    if (await preKeys.isBaseKeyUsed(message.signedPreKeyId, message.baseKey)) {
      throw const DuplicateMessageException('pre-key message replayed');
    }
    final signed = await preKeys.loadSignedPreKey(message.signedPreKeyId);
    if (signed == null) throw InvalidKeyIdException('no signed pre-key ${message.signedPreKeyId}');
    OneTimePreKey? oneTime;
    if (message.oneTimePreKeyId case final id?) {
      oneTime = await preKeys.loadOneTimePreKey(id);
      if (oneTime == null) throw InvalidKeyIdException('no one-time pre-key $id');
    }
    final ours = await identities.identityKeyPair();
    final Uint8List sk;
    try {
      sk = await x3dhBob(
        identity: ours,
        signedPreKey: signed,
        oneTimePreKey: oneTime,
        aliceIdentity: message.identityKey,
        aliceBaseKey: message.baseKey,
        info: info,
      );
    } on InvalidKeyException catch (e) {
      throw InvalidMessageException(e.message);
    }
    final state = SessionState(
      remoteIdentity: message.identityKey,
      ad: associatedData(message.identityKey, ours.publicKey),
      baseKey: message.baseKey,
      pending: null,
      ratchet: ratchetInitBob(sk, signed.keyPair),
    );
    final plaintext = await _ratchetDecrypt(state.ratchet, message.message, state.ad);
    // Both sides started a session at once, and ours is unanswered: both
    // keep the session with the lower base key current, so they agree.
    final current = record.current;
    if (current != null && current.pending != null && _lower(current.baseKey, state.baseKey)) {
      record.keep(state, maxStates);
    } else {
      record.promote(state, maxStates);
    }
    await preKeys.markBaseKeyUsed(message.signedPreKeyId, message.baseKey);
    if (oneTime != null) await preKeys.removeOneTimePreKey(oneTime.id);
    await sessions.storeSession(address, record.encode());
    await identities.saveIdentity(address, message.identityKey);
    return plaintext;
  }

  static bool _lower(DhPublicKey a, DhPublicKey b) {
    for (var i = 0; i < a.bytes.length; i++) {
      if (a.bytes[i] != b.bytes[i]) return a.bytes[i] < b.bytes[i];
    }
    return false;
  }

  /// Tries [candidates] (states of [record]): those that know the header's
  /// ratchet key first, then the others in order. With [promote], the one
  /// that decrypts becomes current when the current one is unanswered (the
  /// other side has settled on that one).
  Future<Uint8List> _decryptWith(
    String address,
    SessionRecord record,
    List<SessionState> candidates,
    RatchetMessage message, {
    bool promote = true,
  }) async {
    final dh = message.header.dh;
    bool knows(SessionState s) =>
        s.ratchet.dhr == dh || s.ratchet.skipped.containsKey(RatchetState.skippedKey(dh, message.header.n));
    final ordered = [...candidates.where(knows), ...candidates.where((s) => !knows(s))];
    DoubleRatchetException? failure;
    for (final state in ordered) {
      final attempt = state.ratchet.copy();
      try {
        final plaintext = await _ratchetDecrypt(attempt, message, state.ad);
        final current = record.current;
        state
          ..ratchet = attempt
          ..pending = null;
        if (promote && current != state && current?.pending != null) record.promote(state, maxStates);
        await sessions.storeSession(address, record.encode());
        return plaintext;
      } on DuplicateMessageException catch (e) {
        failure = e;
      } on InvalidMessageException catch (e) {
        failure ??= e;
      }
    }
    throw failure ?? const InvalidMessageException('no session decrypts the message');
  }

  Future<Uint8List> _ratchetDecrypt(RatchetState state, RatchetMessage message, List<int> ad) async {
    try {
      return await ratchetDecrypt(state, message, ad, info, limits);
    } on InvalidKeyException catch (e) {
      throw InvalidMessageException(e.message);
    }
  }

  Future<SessionRecord?> _load(String address) async {
    final bytes = await sessions.loadSession(address);
    if (bytes == null) return null;
    try {
      return SessionRecord.decode(bytes);
    } on DoubleRatchetException catch (e) {
      throw InvalidSessionRecordException('session record for $address: ${e.message}');
    }
  }

  Future<T> _locked<T>(String address, Future<T> Function() body) {
    final previous = _locks[address] ?? Future<void>.value();
    final result = previous.then((_) => body());
    final done = result.then<void>((_) {}, onError: (_) {});
    _locks[address] = done;
    unawaited(done.then((_) {
      if (identical(_locks[address], done)) _locks.remove(address);
    }));
    return result;
  }
}
