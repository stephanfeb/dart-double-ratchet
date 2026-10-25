import 'dart:convert';
import 'dart:typed_data';

import 'package:double_ratchet/double_ratchet.dart';
import 'package:double_ratchet/src/kdf.dart';
import 'package:test/test.dart';

Uint8List _unhex(String s) =>
    Uint8List.fromList([for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);

void main() {
  final info = ProtocolInfo('test');

  group('KDFs', () {
    test('HKDF matches RFC 5869 test case 1', () async {
      final okm = await hkdf(
        List.filled(22, 0x0b),
        salt: _unhex('000102030405060708090a0b0c'),
        info: _unhex('f0f1f2f3f4f5f6f7f8f9'),
        length: 42,
      );
      expect(
        okm,
        _unhex('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'),
      );
    });

    test('KDF_CK gives different message and chain keys, the same each time', () async {
      final ck = Uint8List(32)..[0] = 1;
      final (next, mk) = await kdfCk(ck);
      expect(next, isNot(mk));
      final (next2, mk2) = await kdfCk(ck);
      expect([next2, mk2], [next, mk]);
    });

    test('the application name changes every key', () async {
      final a = await kdfX3dh(Uint8List(96), ProtocolInfo('a'));
      final b = await kdfX3dh(Uint8List(96), ProtocolInfo('b'));
      expect(a, isNot(b));
    });
  });

  group('ENCRYPT / DECRYPT', () {
    final mk = Uint8List(32)..[5] = 9;
    final ad = utf8.encode('associated');

    test('round trip, any length', () async {
      for (final n in [0, 1, 15, 16, 17, 1000]) {
        final pt = Uint8List(n)..fillRange(0, n, 7);
        final ct = await encrypt(mk, pt, ad, info);
        expect(ct.length % 16, 0);
        expect(await decrypt(mk, ct, ad, info), pt);
      }
    });

    test('other associated data, a changed bit, or another key: InvalidMessageException', () async {
      final ct = await encrypt(mk, utf8.encode('hello'), ad, info);
      await expectLater(decrypt(mk, ct, utf8.encode('other'), info), throwsA(isA<InvalidMessageException>()));
      final flipped = Uint8List.fromList(ct)..[3] ^= 1;
      await expectLater(decrypt(mk, flipped, ad, info), throwsA(isA<InvalidMessageException>()));
      await expectLater(decrypt(Uint8List(32), ct, ad, info), throwsA(isA<InvalidMessageException>()));
      await expectLater(decrypt(mk, ct.sublist(1), ad, info), throwsA(isA<InvalidMessageException>()));
    });
  });

  group('keys', () {
    test('RFC 8032 test 1: the Ed25519 public key of the seed', () async {
      final id = await IdentityKeyPair.fromSeed(
        _unhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
      );
      expect(id.publicKey.ed25519, _unhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));
    });

    test('the X25519 form of the identity agrees with its private half', () async {
      final a = await IdentityKeyPair.generate();
      final b = await IdentityKeyPair.generate();
      final ab = await a.dh.agree(IdentityKey(b.publicKey.ed25519).x25519);
      final ba = await b.dh.agree(IdentityKey(a.publicKey.ed25519).x25519);
      expect(ab, ba);
    });

    test('signatures verify only with the right key and message', () async {
      final a = await IdentityKeyPair.generate();
      final sig = await a.sign([1, 2, 3]);
      expect(await a.publicKey.verify([1, 2, 3], sig), isTrue);
      expect(await a.publicKey.verify([1, 2, 4], sig), isFalse);
      expect(await (await IdentityKeyPair.generate()).publicKey.verify([1, 2, 3], sig), isFalse);
      expect(await a.publicKey.verify([1, 2, 3], sig.sublist(1)), isFalse);
    });

    test('bytes that are not a point on Ed25519 are not an identity key', () {
      // About half of all y values have no x on the curve.
      var refused = 0;
      for (var i = 0; i < 64; i++) {
        final b = Uint8List(32)
          ..[0] = i + 2
          ..[1] = 7;
        try {
          IdentityKey(b);
        } on InvalidKeyException {
          refused++;
        }
      }
      expect(refused, inInclusiveRange(10, 54));
    });

    test('DH with a low-order point is refused', () async {
      final kp = await DhKeyPair.generate();
      await expectLater(kp.agree(DhPublicKey(Uint8List(32))), throwsA(isA<InvalidKeyException>()));
      await expectLater(kp.agree(DhPublicKey(Uint8List(32)..[0] = 1)), throwsA(isA<InvalidKeyException>()));
    });

    test('encoded keys carry the type byte', () async {
      final kp = await DhKeyPair.generate();
      final e = kp.publicKey.encode();
      expect(e.length, 33);
      expect(e[0], 0x05);
      expect(DhPublicKey.decode(e), kp.publicKey);
      expect(() => DhPublicKey.decode([0x06, ...kp.publicKey.bytes]), throwsA(isA<InvalidKeyException>()));
    });
  });
}
