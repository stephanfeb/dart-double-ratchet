import 'dart:typed_data';

import 'keys.dart';
import 'x3dh.dart';

/// Our identity, and the identity keys we accept for each address.
///
/// An address is whatever the application sends to: a user, a device, a
/// libp2p peer ID. The application decides which identity key belongs to
/// an address ([isTrusted]): trust on first use, a key checked out of band
/// (a QR code, a safety number), or a key that the address itself is (a
/// libp2p peer ID is its Ed25519 key).
abstract interface class IdentityStore {
  Future<IdentityKeyPair> identityKeyPair();

  /// Whether [key] may be the identity of [address]. Sessions start only
  /// with trusted keys.
  Future<bool> isTrusted(String address, IdentityKey key);

  /// Called when a session with [address] starts with [key].
  Future<void> saveIdentity(String address, IdentityKey key);
}

/// Our pre-keys.
abstract interface class PreKeyStore {
  Future<SignedPreKey?> loadSignedPreKey(int id);

  Future<OneTimePreKey?> loadOneTimePreKey(int id);

  /// Called once a session used the key: X3DH section 3.4 requires that it
  /// is deleted.
  Future<void> removeOneTimePreKey(int id);
}

/// The session records, as opaque bytes. They hold private keys: encrypt
/// them at rest.
abstract interface class SessionStore {
  Future<Uint8List?> loadSession(String address);

  Future<void> storeSession(String address, Uint8List record);

  Future<void> deleteSession(String address);
}

/// [IdentityStore] in memory, trusting each address's first key (TOFU) and
/// no other after it.
class MemoryIdentityStore implements IdentityStore {
  final IdentityKeyPair identity;
  final identities = <String, IdentityKey>{};

  MemoryIdentityStore(this.identity);

  @override
  Future<IdentityKeyPair> identityKeyPair() async => identity;

  @override
  Future<bool> isTrusted(String address, IdentityKey key) async =>
      identities[address] == null || identities[address] == key;

  @override
  Future<void> saveIdentity(String address, IdentityKey key) async => identities[address] = key;
}

/// [PreKeyStore] in memory.
class MemoryPreKeyStore implements PreKeyStore {
  final signed = <int, SignedPreKey>{};
  final oneTime = <int, OneTimePreKey>{};

  void addSigned(SignedPreKey key) => signed[key.id] = key;

  void addOneTime(Iterable<OneTimePreKey> keys) {
    for (final k in keys) {
      oneTime[k.id] = k;
    }
  }

  @override
  Future<SignedPreKey?> loadSignedPreKey(int id) async => signed[id];

  @override
  Future<OneTimePreKey?> loadOneTimePreKey(int id) async => oneTime[id];

  @override
  Future<void> removeOneTimePreKey(int id) async => oneTime.remove(id);
}

/// [SessionStore] in memory.
class MemorySessionStore implements SessionStore {
  final records = <String, Uint8List>{};

  @override
  Future<Uint8List?> loadSession(String address) async => records[address];

  @override
  Future<void> storeSession(String address, Uint8List record) async => records[address] = record;

  @override
  Future<void> deleteSession(String address) async => records.remove(address);
}
