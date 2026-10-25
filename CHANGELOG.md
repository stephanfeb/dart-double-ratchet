# Changelog

## 0.1.0

- X3DH (Signal specification, revision 1) with Ed25519 identity keys.
- The Double Ratchet (Signal specification, revision 1), with the
  recommended KDFs and AES-256-CBC + HMAC-SHA256.
- `SessionCipher`: sessions over application stores, pre-key messages until
  the first reply, earlier sessions kept for simultaneous starts (which
  settle on the lower base key), no rollback to earlier sessions, replay
  protection across addresses, one call at a time for each address and one
  session start at a time.
