/// The base of the errors of this package.
sealed class DoubleRatchetException implements Exception {
  final String message;

  const DoubleRatchetException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// The message does not decode, does not authenticate, or needs more
/// skipped keys than allowed. No session state changed.
class InvalidMessageException extends DoubleRatchetException {
  const InvalidMessageException(super.message);
}

/// The message was decrypted before (its key is used up). No session state
/// changed.
class DuplicateMessageException extends DoubleRatchetException {
  const DuplicateMessageException(super.message);
}

/// There is no session with the address: process a pre-key bundle first.
class NoSessionException extends DoubleRatchetException {
  const NoSessionException(super.message);
}

/// The identity key of the other party is not the one the
/// [IdentityStore] trusts for the address.
class UntrustedIdentityException extends DoubleRatchetException {
  final String address;

  const UntrustedIdentityException(this.address, super.message);
}

/// A pre-key message names a signed or one-time pre-key that the
/// [PreKeyStore] does not have (used up, rotated out, or never made).
class InvalidKeyIdException extends DoubleRatchetException {
  const InvalidKeyIdException(super.message);
}

/// A key or a signature is not valid.
class InvalidKeyException extends DoubleRatchetException {
  const InvalidKeyException(super.message);
}
