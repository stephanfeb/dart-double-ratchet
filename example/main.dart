import 'dart:convert';

import 'package:double_ratchet/double_ratchet.dart';

Future<void> main() async {
  // Bob makes his keys and publishes a bundle (here: as bytes).
  final bobIdentity = await IdentityKeyPair.generate();
  final bobPreKeys = MemoryPreKeyStore()
    ..addSigned(await SignedPreKey.generate(bobIdentity, 1, application: 'my-app'))
    ..addOneTime(await OneTimePreKey.generateMany(100, 20));
  final published = PreKeyBundle.of(bobIdentity.publicKey, bobPreKeys.signed[1]!, bobPreKeys.oneTime[100]).encode();

  final alice = SessionCipher(
    identities: MemoryIdentityStore(await IdentityKeyPair.generate()),
    preKeys: MemoryPreKeyStore(),
    sessions: MemorySessionStore(),
    application: 'example',
  );
  final bob = SessionCipher(
    identities: MemoryIdentityStore(bobIdentity),
    preKeys: bobPreKeys,
    sessions: MemorySessionStore(),
    application: 'example',
  );

  // Alice starts a session while Bob is offline, and sends two messages.
  await alice.processBundle('bob', PreKeyBundle.decode(published));
  final m1 = await alice.encrypt('bob', utf8.encode('Hi Bob'));
  final m2 = await alice.encrypt('bob', utf8.encode('Are you there?'));

  // Bob reads them, in any order, and answers.
  print('bob reads: ${utf8.decode(await bob.decrypt('alice', m2))}');
  print('bob reads: ${utf8.decode(await bob.decrypt('alice', m1))}');
  final reply = await bob.encrypt('alice', utf8.encode('Hi Alice'));
  print('alice reads: ${utf8.decode(await alice.decrypt('bob', reply))}');
}
