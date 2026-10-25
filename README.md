# double_ratchet

The Signal protocol's two building blocks in pure Dart, written from the
published specifications:

- [X3DH](https://signal.org/docs/specifications/x3dh/): asynchronous key
  agreement from a pre-key bundle, so Alice can start a session while Bob is
  offline.
- [The Double Ratchet](https://signal.org/docs/specifications/doubleratchet/):
  a new key for every message (forward secrecy) and a new DH exchange on
  every turn of the conversation (post-compromise security).

It has one dependency, [`package:cryptography`](https://pub.dev/packages/cryptography),
and no Flutter or platform code. MIT licensed.

## Use

```dart
import 'dart:convert';

import 'package:double_ratchet/double_ratchet.dart';

// Bob publishes a bundle.
final bobIdentity = await IdentityKeyPair.generate();
final bobPreKeys = MemoryPreKeyStore()
  ..addSigned(await SignedPreKey.generate(bobIdentity, 1))
  ..addOneTime(await OneTimePreKey.generateMany(100, 20));
final bundle = PreKeyBundle.of(bobIdentity.publicKey, bobPreKeys.signed[1]!, bobPreKeys.oneTime[100]);

// Alice starts a session from it, and sends.
final alice = SessionCipher(
  identities: MemoryIdentityStore(await IdentityKeyPair.generate()),
  preKeys: MemoryPreKeyStore(),
  sessions: MemorySessionStore(),
  application: 'my-app',
);
await alice.processBundle('bob', PreKeyBundle.decode(bundle.encode()));
final message = await alice.encrypt('bob', utf8.encode('hello'));

// Bob reads it: that starts his side of the session.
final bob = SessionCipher(
  identities: MemoryIdentityStore(bobIdentity),
  preKeys: bobPreKeys,
  sessions: MemorySessionStore(),
  application: 'my-app',
);
print(utf8.decode(await bob.decrypt('alice', message)));
```

See [example/main.dart](example/main.dart).

An application supplies three stores:

- `IdentityStore`: our identity key pair, and which identity key we accept
  for each address. This is where trust is decided: trust on first use, a
  key checked out of band (a QR code, a safety number), or a key that the
  address itself is (a libp2p peer ID is an Ed25519 key).
- `PreKeyStore`: our signed pre-key(s) and one-time pre-keys, and the base
  keys of the pre-key messages that started sessions (against replays).
  Rotate the signed pre-key now and then, and keep the old one for a while
  for messages still in flight; its base keys can go with it.
- `SessionStore`: the session records as opaque bytes. They hold private
  keys: encrypt them at rest.

Addresses are strings that the application picks: a user, a device, a peer
ID. The protocol authenticates keys, not addresses: `IdentityStore.isTrusted`
is what ties an address to its key, so check that a key belongs to the
address before trusting it on first use.

## How closely it follows the specifications

| | Specification | This package |
|---|---|---|
| X3DH DHs | DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) | The same |
| X3DH KDF | HKDF-SHA256, F = 32 × 0xFF before the DHs, zero salt | The same |
| X3DH AD | Encode(IK_A) ‖ Encode(IK_B) | Both Ed25519 identity keys |
| Encode(PK) | Application choice | 0x05 ‖ u-coordinate, as libsignal |
| Signed pre-key | Sig(IK_B, Encode(SPK_B)) | Ed25519 signature |
| One-time pre-keys | Deleted after use | Deleted after use (`removeOneTimePreKey`) |
| KDF_RK | HKDF, root key as salt | The same |
| KDF_CK | HMAC-SHA256, 0x01 → message key, 0x02 → chain key | The same |
| ENCRYPT | Recommended: HKDF → AES-256-CBC key, HMAC key, IV; HMAC over AD ‖ ciphertext | The same, with the full 32-byte MAC |
| DH ratchet | On every message with a new ratchet key | The same: each reply turns it |
| MAX_SKIP | Refuse messages that skip too many keys | 1000 per chain, checked before any key is derived |
| Skipped keys | Kept for late messages, deleted in time | Kept across chains (PN); at most 2000 per session, oldest dropped |
| State on failure | Changes discarded | Decrypts on a copy; stores only on success |
| Initial messages | Alice sends X3DH data with her messages | Every message is a pre-key message until Bob answers |

Some things go beyond the specifications:

- A session record keeps earlier sessions (5 by default), as libsignal does,
  for messages still in flight. When two parties start sessions with each
  other at the same time, both keep the one with the lower base key current,
  so they settle on one.
- A message in an earlier session is read, but does not make that session
  current again (libsignal does), so a held-back message cannot roll a
  conversation back to an old session.
- The base key of every pre-key message that started a session is kept, so
  a replayed pre-key message cannot start a session again, under its own
  address or another. Sessions start from pre-key messages one at a time,
  so a one-time pre-key is used once.
- A state remembers its last 5 receiving chains, so a duplicate of an older
  message is reported as one, rather than taken for a new ratchet step.

### What is different on purpose

- **Ed25519 identity keys, not XEdDSA.** Signal's identity keys are X25519
  keys that sign with XEdDSA. Here the identity is an Ed25519 key, and its
  X25519 form comes from the birational map of RFC 7748 (as libsodium's
  `crypto_sign_ed25519_pk_to_curve25519`). Both ways give one key pair for
  signatures and DH; this way, an existing Ed25519 identity (a libp2p peer
  key) is the Signal identity.
- **Its own wire format.** Messages and bundles are a small binary format
  (version byte, type byte, fixed fields), not libsignal's protobufs. This
  package does not talk to Signal clients.

### Not in this version

- Header encryption (Double Ratchet section 4).
- Sesame (multi-device session management): an address is one device.
- PQXDH (the post-quantum X3DH).

## Security

Skipped message keys and earlier sessions are bounded in number, not
deleted after a time: a message that never arrives keeps its key until
2000 others are skipped or the session leaves the record.

A forged message costs a receiver up to one decryption attempt per kept
session, each up to 2 × MAX_SKIP HMACs, before it fails. Limit what one
sender can deliver.

This code has not had an independent audit. Its tests cover the
specifications' properties (forward secrecy, post-compromise recovery,
out-of-order and lost messages, MAX_SKIP, replays, tampering, simultaneous
starts, concurrent calls) and a randomized delivery test with loss,
reordering and duplicates.
