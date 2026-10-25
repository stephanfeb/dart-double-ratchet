import 'dart:convert';
import 'dart:typed_data';

import 'package:double_ratchet/double_ratchet.dart';
import 'package:double_ratchet/src/bytes.dart';
import 'package:test/test.dart';

/// Two ratchets started as in Double Ratchet section 3.3, with a fixed SK.
class _Pair {
  final RatchetState alice, bob;
  final ad = utf8.encode('ad');
  final info = ProtocolInfo('test');
  final RatchetLimits limits;

  _Pair(this.alice, this.bob, this.limits);

  static Future<_Pair> start({RatchetLimits limits = const RatchetLimits()}) async {
    final sk = Uint8List(32)..[0] = 42;
    final bobKey = await DhKeyPair.generate();
    final info = ProtocolInfo('test');
    return _Pair(await ratchetInitAlice(sk, bobKey.publicKey, info), ratchetInitBob(sk, bobKey), limits);
  }

  Future<RatchetMessage> send(RatchetState from, String text) => ratchetEncrypt(from, utf8.encode(text), ad, info);

  /// Decrypts on a copy, and keeps it only on success, as section 3.5 asks.
  Future<String> receive(RatchetState to, RatchetMessage m) async {
    final copy = to.copy();
    final pt = await ratchetDecrypt(copy, m, ad, info, limits);
    _assign(to, copy);
    return utf8.decode(pt);
  }

  static void _assign(RatchetState to, RatchetState from) {
    to
      ..dhs = from.dhs
      ..dhr = from.dhr
      ..rk = from.rk
      ..cks = from.cks
      ..ckr = from.ckr
      ..ns = from.ns
      ..nr = from.nr
      ..pn = from.pn
      ..skipped.clear()
      ..skipped.addAll(from.skipped)
      ..previous.clear()
      ..previous.addAll(from.previous);
  }
}

void main() {
  test('messages each way, in order', () async {
    final p = await _Pair.start();
    for (var round = 0; round < 3; round++) {
      for (var i = 0; i < 3; i++) {
        expect(await p.receive(p.bob, await p.send(p.alice, 'a$round$i')), 'a$round$i');
      }
      for (var i = 0; i < 2; i++) {
        expect(await p.receive(p.alice, await p.send(p.bob, 'b$round$i')), 'b$round$i');
      }
    }
  });

  test('each reply turns the DH ratchet: a new ratchet key per turn', () async {
    final p = await _Pair.start();
    final keys = <DhPublicKey>{};
    for (var i = 0; i < 5; i++) {
      final a = await p.send(p.alice, 'a$i');
      keys.add(a.header.dh);
      await p.receive(p.bob, a);
      final b = await p.send(p.bob, 'b$i');
      keys.add(b.header.dh);
      await p.receive(p.alice, b);
    }
    expect(keys, hasLength(10));
  });

  test('out of order and lost messages, across a DH ratchet step (PN)', () async {
    final p = await _Pair.start();
    final first = [for (var i = 0; i < 4; i++) await p.send(p.alice, 'a$i')];
    expect(await p.receive(p.bob, first[0]), 'a0');
    // Bob answers; Alice turns her ratchet and sends on a new chain.
    expect(await p.receive(p.alice, await p.send(p.bob, 'b0')), 'b0');
    final second = [for (var i = 0; i < 2; i++) await p.send(p.alice, 'c$i')];
    // Bob gets the new chain first: a1..a3 are skipped (PN = 4).
    expect(await p.receive(p.bob, second[1]), 'c1');
    expect(await p.receive(p.bob, first[3]), 'a3');
    expect(await p.receive(p.bob, second[0]), 'c0');
    expect(await p.receive(p.bob, first[1]), 'a1');
    // first[2] is lost; the session goes on.
    expect(await p.receive(p.alice, await p.send(p.bob, 'b1')), 'b1');
    expect(p.bob.skipped, hasLength(1));
  });

  test('a message that needs more than MAX_SKIP keys is refused and stores nothing', () async {
    final p = await _Pair.start(limits: const RatchetLimits(maxSkip: 10, maxSkippedKeys: 20));
    final ms = [for (var i = 0; i < 12; i++) await p.send(p.alice, 'a$i')];
    final before = p.bob.copy();
    await expectLater(p.receive(p.bob, ms[11]), throwsA(isA<InvalidMessageException>()));
    expect(p.bob.skipped, isEmpty);
    expect(p.bob.dhr, before.dhr);
    expect(await p.receive(p.bob, ms[10]), 'a10');
    expect(p.bob.skipped, hasLength(10));
  });

  test('a forged header with a huge counter costs nothing (refused before any key work)', () async {
    final p = await _Pair.start();
    final real = await p.send(p.alice, 'a0');
    final forged = RatchetMessage(Header(real.header.dh, 0, 0x7fffffff), real.ciphertext);
    final sw = Stopwatch()..start();
    await expectLater(p.receive(p.bob, forged), throwsA(isA<InvalidMessageException>()));
    expect(sw.elapsedMilliseconds, lessThan(200));
    expect(p.bob.skipped, isEmpty);
    expect(await p.receive(p.bob, real), 'a0');
  });

  test('skipped keys are capped: the oldest go first', () async {
    final p = await _Pair.start(limits: const RatchetLimits(maxSkip: 10, maxSkippedKeys: 10));
    final ms = [for (var i = 0; i < 16; i++) await p.send(p.alice, 'a$i')];
    await p.receive(p.bob, ms[8]); // skips 0..7
    await p.receive(p.bob, ms[15]); // skips 9..14: 14 keys, 10 kept
    expect(p.bob.skipped, hasLength(10));
    await expectLater(p.receive(p.bob, ms[0]), throwsA(isA<DoubleRatchetException>()));
    expect(await p.receive(p.bob, ms[4]), 'a4');
  });

  test('a message decrypts once', () async {
    final p = await _Pair.start();
    final m0 = await p.send(p.alice, 'a0');
    final m1 = await p.send(p.alice, 'a1');
    await p.receive(p.bob, m1);
    await p.receive(p.bob, m0); // from the skipped keys
    await expectLater(p.receive(p.bob, m0), throwsA(isA<DoubleRatchetException>()));
    await expectLater(p.receive(p.bob, m1), throwsA(isA<DuplicateMessageException>()));
  });

  test('a message from an earlier chain, delivered again, is a duplicate', () async {
    final p = await _Pair.start();
    final a0 = await p.send(p.alice, 'a0');
    await p.receive(p.bob, a0);
    await p.receive(p.alice, await p.send(p.bob, 'b0'));
    await p.receive(p.bob, await p.send(p.alice, 'a1')); // Bob moves to Alice's next chain
    final before = p.bob.copy();
    await expectLater(p.receive(p.bob, a0), throwsA(isA<DuplicateMessageException>()));
    expect(p.bob.rk, before.rk);
  });

  test('a tampered message changes no state', () async {
    final p = await _Pair.start();
    final m = await p.send(p.alice, 'a0');
    final bad = RatchetMessage(m.header, Uint8List.fromList(m.ciphertext)..[0] ^= 1);
    await expectLater(p.receive(p.bob, bad), throwsA(isA<InvalidMessageException>()));
    expect(p.bob.dhr, isNull);
    expect(await p.receive(p.bob, m), 'a0');
  });

  test('post-compromise security: a stolen state stops working once Bob ratchets with a fresh key', () async {
    final p = await _Pair.start();
    await p.receive(p.bob, await p.send(p.alice, 'a0'));
    // An attacker copies Bob's state and reads everything Alice sends.
    final stolen = p.bob.copy();

    // The state holds Bob's next ratchet key, so the attacker follows the
    // conversation until Bob makes a key it has not seen.
    final a1 = await p.send(p.alice, 'a1');
    expect(await p.receive(stolen, a1), 'a1');
    await p.receive(p.bob, a1);
    await p.receive(p.alice, await p.send(p.bob, 'b0'));
    final a2 = await p.send(p.alice, 'a2');
    expect(await p.receive(stolen, a2), 'a2');
    await p.receive(p.bob, a2);

    // Bob's reply uses a fresh ratchet key: from Alice's next turn on, the
    // stolen state is useless.
    await p.receive(p.alice, await p.send(p.bob, 'b1'));
    final a3 = await p.send(p.alice, 'a3');
    await expectLater(p.receive(stolen, a3), throwsA(isA<DoubleRatchetException>()));
    expect(await p.receive(p.bob, a3), 'a3');
  });

  test('both sides sending at once does not break the session', () async {
    final p = await _Pair.start();
    await p.receive(p.bob, await p.send(p.alice, 'a0'));
    // Both send before either receives, for several turns.
    for (var i = 0; i < 4; i++) {
      final a = await p.send(p.alice, 'a$i');
      final b = await p.send(p.bob, 'b$i');
      expect(await p.receive(p.alice, b), 'b$i');
      expect(await p.receive(p.bob, a), 'a$i');
    }
  });

  test('state survives a write and a read', () async {
    final p = await _Pair.start();
    final ms = [for (var i = 0; i < 3; i++) await p.send(p.alice, 'a$i')];
    await p.receive(p.bob, ms[2]);
    final w = ByteWriter();
    p.bob.write(w);
    final r = ByteReader(w.take());
    final restored = RatchetState.read(r);
    r.end();
    expect(await p.receive(restored, ms[0]), 'a0');
    expect(await p.receive(p.alice, await p.send(restored, 'b0')), 'b0');
  });
}
