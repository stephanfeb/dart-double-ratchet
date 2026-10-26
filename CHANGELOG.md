# Changelog

## 0.2.0

- The identity key signs a signed pre-key as
  `utf8("<application> signed pre-key") ‖ u32(id) ‖ Encode(SPK)`, not the
  bare key, so that the signature cannot stand for one the key made for
  something else, and the key's id is bound to it.
- `SignedPreKey.generate` takes the `application`, as `SessionCipher` does;
  `PreKeyBundle.verify` takes it too. New: `SignedPreKey.verify`,
  `signedPreKeyMessage`, `bundleVersion`, `SessionCipher.application`.
- Bundles are version 2. Version 1 bundles are not read, and signed
  pre-keys made by 0.1 do not verify: make new ones.

## 0.1.0

- X3DH (Signal specification, revision 1) with Ed25519 identity keys.
- The Double Ratchet (Signal specification, revision 1), with the
  recommended KDFs and AES-256-CBC + HMAC-SHA256.
- `SessionCipher`: sessions over application stores, pre-key messages until
  the first reply, earlier sessions kept for simultaneous starts (which
  settle on the lower base key), no rollback to earlier sessions, replay
  protection across addresses, one call at a time for each address and one
  session start at a time.
- `SessionCipher.isAwaitingReply`: whether our current session is still
  unanswered.
