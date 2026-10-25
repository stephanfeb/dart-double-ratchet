import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:double_ratchet/double_ratchet.dart';
import 'package:test/test.dart';

const _app = 'test';

class _Party {
  final String name;
  final IdentityKeyPair identity;
  final MemoryIdentityStore identities;
  final preKeys = MemoryPreKeyStore();
  final sessions = MemorySessionStore();
  late final SessionCipher cipher;
  late SignedPreKey signed;

  _Party(this.name, this.identity, {int maxStates = 5}) : identities = MemoryIdentityStore(identity) {
    cipher = SessionCipher(
      identities: identities,
      preKeys: preKeys,
      sessions: sessions,
      application: _app,
      maxStates: maxStates,
    );
  }

  static Future<_Party> create(String name, {int oneTime = 5, int maxStates = 5}) async {
    final p = _Party(name, await IdentityKeyPair.generate(), maxStates: maxStates);
    p.signed = await SignedPreKey.generate(p.identity, 1);
    p.preKeys
      ..addSigned(p.signed)
      ..addOneTime(await OneTimePreKey.generateMany(100, oneTime));
    return p;
  }

  /// A bundle with the lowest one-time pre-key left, if any.
  PreKeyBundle bundle({bool oneTime = true}) {
    final ids = preKeys.oneTime.keys.toList()..sort();
    return PreKeyBundle.of(
      identity.publicKey,
      signed,
      oneTime && ids.isNotEmpty ? preKeys.oneTime[ids.first] : null,
    );
  }

  Future<Uint8List> send(_Party to, String text) => cipher.encrypt(to.name, utf8.encode(text));

  Future<String> receive(_Party from, Uint8List message) async => utf8.decode(await cipher.decrypt(from.name, message));
}

bool _isPreKey(Uint8List m) => m[1] == 2;

void main() {
  late _Party alice, bob;

  setUp(() async {
    alice = await _Party.create('alice');
    bob = await _Party.create('bob');
  });

  test('a session from a bundle: pre-key messages until Bob answers, then plain ones', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    final a0 = await alice.send(bob, 'hello');
    final a1 = await alice.send(bob, 'again');
    expect(_isPreKey(a0) && _isPreKey(a1), isTrue);
    expect(await bob.receive(alice, a0), 'hello');
    expect(await bob.receive(alice, a1), 'again');
    // The one-time pre-key is gone once used.
    expect(bob.preKeys.oneTime.containsKey(100), isFalse);

    expect(await alice.cipher.isAwaitingReply('bob'), isTrue);
    expect(await bob.cipher.isAwaitingReply('alice'), isFalse);
    final b0 = await bob.send(alice, 'hi');
    expect(_isPreKey(b0), isFalse);
    expect(await alice.cipher.isAwaitingReply('bob'), isTrue);
    expect(await alice.receive(bob, b0), 'hi');
    expect(await alice.cipher.isAwaitingReply('bob'), isFalse);
    final a2 = await alice.send(bob, 'now plain');
    expect(_isPreKey(a2), isFalse);
    expect(await bob.receive(alice, a2), 'now plain');
  });

  test('the first message lost: the next pre-key message starts the session', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    await alice.send(bob, 'lost');
    final a1 = await alice.send(bob, 'arrives');
    expect(await bob.receive(alice, a1), 'arrives');
    expect(await alice.receive(bob, await bob.send(alice, 'ok')), 'ok');
  });

  test('a bundle without a one-time pre-key works (X3DH without DH4)', () async {
    await alice.cipher.processBundle('bob', bob.bundle(oneTime: false));
    expect(await bob.receive(alice, await alice.send(bob, 'x')), 'x');
    expect(bob.preKeys.oneTime, hasLength(5));
  });

  test('a replayed pre-key message is a duplicate, not a new session', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    final a0 = await alice.send(bob, 'once');
    await bob.receive(alice, a0);
    final record = Uint8List.fromList(bob.sessions.records['alice']!);
    await expectLater(bob.receive(alice, a0), throwsA(isA<DuplicateMessageException>()));
    expect(bob.sessions.records['alice'], record);
  });

  test('a replay after its session aged out is still refused (seen base keys)', () async {
    bob = await _Party.create('bob', maxStates: 1, oneTime: 0);
    await alice.cipher.processBundle('bob', bob.bundle());
    final old = await alice.send(bob, 'old');
    await bob.receive(alice, old);
    // A second session pushes the first out of Bob's record.
    await alice.cipher.processBundle('bob', bob.bundle());
    await bob.receive(alice, await alice.send(bob, 'new'));
    await expectLater(bob.receive(alice, old), throwsA(isA<DuplicateMessageException>()));
  });

  test('a pre-key message replayed under another address does not start a session', () async {
    await alice.cipher.processBundle('bob', bob.bundle(oneTime: false));
    final m = await alice.send(bob, 'pay 10');
    expect(await bob.receive(alice, m), 'pay 10');
    await expectLater(bob.cipher.decrypt('mallory', m), throwsA(isA<DuplicateMessageException>()));
    expect(bob.sessions.records.containsKey('mallory'), isFalse);
    expect(bob.identities.identities.containsKey('mallory'), isFalse);
  });

  test('one pre-key message decrypted under two addresses at once: only one session', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    final m = await alice.send(bob, 'hi');
    final results = await Future.wait([
      for (final from in ['alice', 'mallory'])
        bob.cipher.decrypt(from, m).then<Object>((p) => utf8.decode(p), onError: (Object e) => e),
    ]);
    expect(results.whereType<String>(), ['hi']);
    expect(results.whereType<DoubleRatchetException>(), hasLength(1));
  });

  test('a held-back message from an earlier session is read but does not make it current', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    await bob.receive(alice, await alice.send(bob, 's1'));
    await alice.receive(bob, await bob.send(alice, 'r1'));
    final heldBack = await alice.send(bob, 'old');
    // Alice starts a new session; Bob reads in it and answers.
    await alice.cipher.processBundle('bob', bob.bundle());
    await bob.receive(alice, await alice.send(bob, 's2'));
    await alice.receive(bob, await bob.send(alice, 'r2'));
    final s2 = SessionRecord.decode(bob.sessions.records['alice']!).current!.baseKey;
    expect(await bob.receive(alice, heldBack), 'old');
    expect(SessionRecord.decode(bob.sessions.records['alice']!).current!.baseKey, s2);
    expect(await alice.receive(bob, await bob.send(alice, 'r3')), 'r3');
    expect(SessionRecord.decode(alice.sessions.records['bob']!).current!.baseKey, s2);
  });

  test('a corrupt stored record is an InvalidSessionRecordException', () async {
    bob.sessions.records['alice'] = Uint8List.fromList([1, 0, 0, 0, 9]);
    await expectLater(bob.cipher.encrypt('alice', [1]), throwsA(isA<InvalidSessionRecordException>()));
  });

  test('limits are checked', () {
    SessionCipher make({int maxStates = 5, RatchetLimits limits = const RatchetLimits()}) => SessionCipher(
          identities: alice.identities,
          preKeys: alice.preKeys,
          sessions: alice.sessions,
          application: _app,
          maxStates: maxStates,
          limits: limits,
        );
    expect(() => make(maxStates: 0), throwsArgumentError);
    expect(() => make(limits: const RatchetLimits(maxSkip: 10, maxSkippedKeys: 5)), throwsArgumentError);
  });

  test('a used one-time pre-key cannot start a second session', () async {
    final bundle = bob.bundle();
    await alice.cipher.processBundle('bob', bundle);
    await bob.receive(alice, await alice.send(bob, 'x'));
    final carol = await _Party.create('carol');
    await carol.cipher.processBundle('bob', bundle);
    await expectLater(bob.receive(carol, await carol.send(bob, 'y')), throwsA(isA<InvalidKeyIdException>()));
  });

  test('a bundle with a bad signature is refused', () async {
    final b = bob.bundle();
    final bad = PreKeyBundle(
      identityKey: b.identityKey,
      signedPreKeyId: b.signedPreKeyId,
      signedPreKey: (await DhKeyPair.generate()).publicKey,
      signedPreKeySignature: b.signedPreKeySignature,
    );
    await expectLater(alice.cipher.processBundle('bob', bad), throwsA(isA<InvalidKeyException>()));
    expect(await alice.cipher.hasSession('bob'), isFalse);
  });

  test('an identity the store does not trust is refused, both ways', () async {
    final mallory = await _Party.create('mallory');
    alice.identities.identities['bob'] = bob.identity.publicKey;
    await expectLater(alice.cipher.processBundle('bob', mallory.bundle()), throwsA(isA<UntrustedIdentityException>()));

    // Mallory sends as "alice" to Bob, who knows Alice's key.
    bob.identities.identities['alice'] = alice.identity.publicKey;
    await mallory.cipher.processBundle('bob', bob.bundle());
    await expectLater(
      bob.cipher.decrypt('alice', await mallory.cipher.encrypt('bob', [1])),
      throwsA(isA<UntrustedIdentityException>()),
    );
    expect(bob.preKeys.oneTime, hasLength(5));
  });

  test('the identity key in a pre-key message is authenticated by the MAC', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    final m = PreKeyMessage.decode(await alice.send(bob, 'x'));
    final mallory = await IdentityKeyPair.generate();
    final swapped = PreKeyMessage(
      identityKey: mallory.publicKey,
      baseKey: m.baseKey,
      signedPreKeyId: m.signedPreKeyId,
      oneTimePreKeyId: m.oneTimePreKeyId,
      message: m.message,
    );
    await expectLater(bob.cipher.decrypt('alice', swapped.encode()), throwsA(isA<InvalidMessageException>()));
    expect(bob.sessions.records, isEmpty);
    expect(bob.preKeys.oneTime, hasLength(5));
  });

  test('a message that fails changes nothing in the store', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    await bob.receive(alice, await alice.send(bob, 'x'));
    await alice.receive(bob, await bob.send(alice, 'y'));
    final good = await alice.send(bob, 'z');
    final before = Uint8List.fromList(bob.sessions.records['alice']!);
    final bad = Uint8List.fromList(good)..[good.length - 1] ^= 1;
    await expectLater(bob.cipher.decrypt('alice', bad), throwsA(isA<InvalidMessageException>()));
    expect(bob.sessions.records['alice'], before);
    expect(await bob.receive(alice, good), 'z');
  });

  test('both start sessions at once: every message is read, and they settle on one', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    await bob.cipher.processBundle('alice', alice.bundle());
    final a0 = await alice.send(bob, 'a0');
    final b0 = await bob.send(alice, 'b0');
    expect(await bob.receive(alice, a0), 'a0');
    expect(await alice.receive(bob, b0), 'b0');
    for (var i = 1; i < 6; i++) {
      final a = await alice.send(bob, 'a$i');
      final b = await bob.send(alice, 'b$i');
      expect(await alice.receive(bob, b), 'b$i');
      expect(await bob.receive(alice, a), 'a$i');
    }
    // Sequential traffic after that ends on one shared session.
    for (var i = 0; i < 3; i++) {
      expect(await bob.receive(alice, await alice.send(bob, 'x$i')), 'x$i');
      expect(await alice.receive(bob, await bob.send(alice, 'y$i')), 'y$i');
    }
    final aCurrent = SessionRecord.decode(alice.sessions.records['bob']!).current!;
    final bCurrent = SessionRecord.decode(bob.sessions.records['alice']!).current!;
    expect(aCurrent.baseKey, bCurrent.baseKey);
  });

  test('concurrent calls for one address do not lose state', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    await bob.receive(alice, await alice.send(bob, 'start'));
    await alice.receive(bob, await bob.send(alice, 'ok'));
    final sent = await Future.wait([for (var i = 0; i < 20; i++) alice.send(bob, 'm$i')]);
    final got = await Future.wait([for (final m in sent.reversed) bob.receive(alice, m)]);
    expect(got.toSet(), {for (var i = 0; i < 20; i++) 'm$i'});
  });

  test('sessions survive a reload of the stores (a new SessionCipher)', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    final a0 = await alice.send(bob, 'a0');
    final a1 = await alice.send(bob, 'a1');
    await bob.receive(alice, a1);
    final bob2 = SessionCipher(
      identities: bob.identities,
      preKeys: bob.preKeys,
      sessions: bob.sessions,
      application: _app,
    );
    expect(utf8.decode(await bob2.decrypt('alice', a0)), 'a0');
    expect(await alice.receive(bob, await bob2.encrypt('alice', utf8.encode('b0'))), 'b0');
  });

  test('another application name cannot read the messages', () async {
    await alice.cipher.processBundle('bob', bob.bundle());
    final other = SessionCipher(
      identities: bob.identities,
      preKeys: bob.preKeys,
      sessions: bob.sessions,
      application: 'other',
    );
    await expectLater(other.decrypt('alice', await alice.send(bob, 'x')), throwsA(isA<InvalidMessageException>()));
  });

  test('no session: encrypt and decrypt say so', () async {
    await expectLater(alice.send(bob, 'x'), throwsA(isA<NoSessionException>()));
    await expectLater(
      alice.cipher.decrypt('bob', Uint8List.fromList([1, 1, ...List.filled(100, 0)])),
      throwsA(isA<DoubleRatchetException>()),
    );
    await expectLater(alice.cipher.decrypt('bob', [9, 9]), throwsA(isA<InvalidMessageException>()));
  });

  test('bundles and pre-keys survive encoding', () async {
    final b = bob.bundle();
    final d = PreKeyBundle.decode(b.encode());
    expect(d.identityKey, b.identityKey);
    expect(d.oneTimePreKeyId, b.oneTimePreKeyId);
    expect(await d.verify(), isTrue);
    final s = await SignedPreKey.decode(bob.signed.encode());
    expect(s.keyPair.publicKey, bob.signed.keyPair.publicKey);
    final o = bob.preKeys.oneTime[100]!;
    expect((await OneTimePreKey.decode(o.encode())).keyPair.publicKey, o.keyPair.publicKey);
  });

  for (final both in const [false, true]) {
    for (final seed in const [1, 7, 15, 42, 2026]) {
      test('random reordering, loss and duplicates over a long conversation (seed $seed${both ? ', both start' : ''})',
          () async {
        final rng = Random(seed);
        await alice.cipher.processBundle('bob', bob.bundle());
        if (both) await bob.cipher.processBundle('alice', alice.bundle());
        final toBob = <(Uint8List, String)>[];
        final toAlice = <(Uint8List, String)>[];
        final readByBob = <String>{}, readByAlice = <String>{};
        var bobHasSession = both;

        Future<void> deliver(List<(Uint8List, String)> queue, _Party to, _Party from, Set<String> read) async {
          if (queue.isEmpty) return;
          final (m, text) = queue.removeAt(rng.nextInt(queue.length));
          if (rng.nextInt(10) == 0) return; // lost
          if (rng.nextInt(10) == 0) queue.add((m, text)); // delivered twice
          try {
            final got = await to.receive(from, m);
            expect(got, text);
            expect(read.add(got), isTrue, reason: 'read twice: $got');
            if (to == bob) bobHasSession = true;
          } on DuplicateMessageException {
            expect(read, contains(text));
          } on InvalidMessageException {
            // A copy of a message read many ratchet steps ago no longer
            // matches a known chain; a message never read must decrypt.
            expect(read, contains(text));
          }
        }

        for (var step = 0; step < 400; step++) {
          switch (rng.nextInt(4)) {
            case 0:
              toBob.add((await alice.send(bob, 'a$step'), 'a$step'));
            case 1:
              if (bobHasSession) toAlice.add((await bob.send(alice, 'b$step'), 'b$step'));
            case 2:
              await deliver(toBob, bob, alice, readByBob);
            default:
              await deliver(toAlice, alice, bob, readByAlice);
          }
        }
        // Every delivery that was not lost or a duplicate decrypted (above).
        expect(readByBob.length, greaterThan(50));
        expect(readByAlice.length, greaterThan(30));
      });
    }
  }
}
