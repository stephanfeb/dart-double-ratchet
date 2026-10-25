/// The Signal protocol's X3DH key agreement and Double Ratchet.
///
/// Most applications use [SessionCipher] with their own [IdentityStore],
/// [PreKeyStore] and [SessionStore]. The lower layers (X3DH, the ratchet
/// functions, the KDFs) are exported for applications that keep state
/// their own way.
library;

export 'src/errors.dart';
export 'src/kdf.dart' show ProtocolInfo;
export 'src/keys.dart' show DhKeyPair, DhPublicKey, IdentityKey, IdentityKeyPair, edPublicToX25519;
export 'src/ratchet.dart'
    show
        Header,
        RatchetLimits,
        RatchetMessage,
        RatchetState,
        ratchetDecrypt,
        ratchetEncrypt,
        ratchetInitAlice,
        ratchetInitBob;
export 'src/session.dart' show SessionRecord, SessionState;
export 'src/session_cipher.dart';
export 'src/store.dart';
export 'src/x3dh.dart'
    show OneTimePreKey, PreKeyBundle, PreKeyMessage, SignedPreKey, associatedData, x3dhAlice, x3dhBob;
