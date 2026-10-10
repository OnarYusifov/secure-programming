"""Encryption module: key derivation and authenticated encryption.

Implements the scheme in DESIGN.md §4:

- the key-encryption key (KEK) is derived from the master password with Argon2id;
- a second KEK is derived from the paper recovery key with HKDF-SHA256;
- a random data key (DEK) encrypts the vault with AES-256-GCM;
- the DEK is stored wrapped (encrypted) under each KEK.

Every failure raises CryptoError without detail, so a caller cannot tell a wrong
password from a tampered file (T4, T7, T8).

Keys are returned as bytearrays that the caller overwrites with wipe() when it
is done (T13). The KDF and the DEK unwrap write straight into those buffers, so
these keys never exist as immutable bytes in Python. This is best effort only:
the library may hold internal copies that Python cannot reach.
"""

import secrets
import unicodedata
from dataclasses import dataclass
from typing import NamedTuple, Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # 96-bit GCM nonce
TAG_BYTES = 16
SALT_BYTES = 16

# Argon2id floor: the second recommended option of RFC 9106. These are constants
# on purpose: a vault header or a config file may ask for more, never for less (T7).
MIN_MEMORY_KIB = 65_536  # 64 MiB
MIN_ITERATIONS = 3
MIN_LANES = 4

# Argon2id ceiling: a crafted header must not make the program allocate unbounded
# memory or hash for hours before the authentication check gets a chance to fail.
MAX_MEMORY_KIB = 1_048_576  # 1 GiB
MAX_ITERATIONS = 64
MAX_LANES = 16

RECOVERY_KEY_BYTES = 20  # 160 bits, written down as 32 Base32 characters

# HKDF "info" label. It ties the derived key to this one purpose and version, so
# it can never equal a key derived from the same input for anything else.
RECOVERY_KEK_INFO = b"yunarpass/recovery-kek/v1"

type Key = bytes | bytearray


class CryptoError(Exception):
    """A cryptographic operation failed. Deliberately carries no detail."""

    def __init__(self) -> None:
        super().__init__("cryptographic operation failed")


def _int_in(value: object, low: int, high: int) -> bool:
    # bool is a subclass of int: a JSON `true` must not pass as 1.
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


@dataclass(frozen=True, slots=True)
class KdfParams:
    """Argon2id parameters, as stored in the vault header."""

    memory_kib: int
    iterations: int
    lanes: int
    salt: bytes

    def __post_init__(self) -> None:
        self.check()

    def check(self) -> None:
        """Raise CryptoError unless every parameter is within the floor and ceiling."""
        if not (
            _int_in(self.memory_kib, MIN_MEMORY_KIB, MAX_MEMORY_KIB)
            and _int_in(self.iterations, MIN_ITERATIONS, MAX_ITERATIONS)
            and _int_in(self.lanes, MIN_LANES, MAX_LANES)
            and isinstance(self.salt, bytes)
            and len(self.salt) == SALT_BYTES
        ):
            raise CryptoError

    @classmethod
    def new(cls) -> Self:
        """The floor parameters with a fresh random salt."""
        return cls(MIN_MEMORY_KIB, MIN_ITERATIONS, MIN_LANES, secrets.token_bytes(SALT_BYTES))


class Sealed(NamedTuple):
    """Output of encrypt(): the nonce, and the ciphertext with the tag appended."""

    nonce: bytes
    ct: bytes


def _check_key(key: Key) -> None:
    if not isinstance(key, bytes | bytearray) or len(key) != KEY_BYTES:
        raise CryptoError


def _check_aad(aad: bytes) -> None:
    # Every encryption in the scheme is bound to a header. Empty associated data
    # would mean a caller forgot it, so it is refused rather than allowed.
    if not isinstance(aad, bytes) or not aad:
        raise CryptoError


def _check_sealed(nonce: bytes, ct: bytes) -> None:
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise CryptoError
    if not isinstance(ct, bytes) or len(ct) < TAG_BYTES:
        raise CryptoError


def wipe(buf: bytearray) -> None:
    """Overwrite a key buffer with zeros, in place (best effort, T13)."""
    buf[:] = bytes(len(buf))


def new_key() -> bytearray:
    """Return a fresh random 256-bit key (a DEK) from the OS CSPRNG."""
    return bytearray(secrets.token_bytes(KEY_BYTES))


def derive_kek(password: str, params: KdfParams) -> bytearray:
    """Derive the 32-byte KEK from a master password with Argon2id.

    The password is NFC-normalized and then UTF-8 encoded, so the same password
    typed with composed or decomposed accents gives the same key.
    """
    params.check()  # again, in case the object was built around __post_init__
    try:
        secret = unicodedata.normalize("NFC", password).encode("utf-8")
    except (TypeError, UnicodeError):
        raise CryptoError from None
    kdf = Argon2id(
        salt=params.salt,
        length=KEY_BYTES,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_kib,
    )
    kek = bytearray(KEY_BYTES)
    kdf.derive_into(secret, kek)
    return kek


def derive_recovery_kek(recovery_key: Key, salt: bytes) -> bytearray:
    """Derive the 32-byte recovery KEK from the recovery key with HKDF-SHA256.

    A slow KDF is not needed here: the recovery key is 160 random bits, so there
    is no small set of likely values for an attacker to try first (T5).
    """
    if not isinstance(recovery_key, bytes | bytearray) or len(recovery_key) != RECOVERY_KEY_BYTES:
        raise CryptoError
    if not isinstance(salt, bytes) or len(salt) != SALT_BYTES:
        raise CryptoError
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=RECOVERY_KEK_INFO)
    kek = bytearray(KEY_BYTES)
    hkdf.derive_into(recovery_key, kek)
    return kek


def encrypt(key: Key, plaintext: bytes | bytearray, aad: bytes) -> Sealed:
    """Encrypt and authenticate with AES-256-GCM under a fresh random nonce."""
    _check_key(key)
    _check_aad(aad)
    nonce = secrets.token_bytes(NONCE_BYTES)
    return Sealed(nonce, AESGCM(key).encrypt(nonce, plaintext, aad))


def decrypt(key: Key, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    """Verify and decrypt. Any wrong key, nonce, ciphertext or AAD raises CryptoError."""
    _check_key(key)
    _check_aad(aad)
    _check_sealed(nonce, ct)
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise CryptoError from None


def wrap_dek(kek: Key, dek: Key, aad: bytes) -> Sealed:
    """Encrypt the DEK under a KEK."""
    _check_key(dek)
    return encrypt(kek, dek, aad)  # no bytes() copy of the DEK


def unwrap_dek(kek: Key, nonce: bytes, ct: bytes, aad: bytes) -> bytearray:
    """Decrypt a wrapped DEK straight into a new buffer the caller must wipe()."""
    _check_key(kek)
    _check_aad(aad)
    _check_sealed(nonce, ct)
    if len(ct) != KEY_BYTES + TAG_BYTES:
        raise CryptoError
    dek = bytearray(KEY_BYTES)
    try:
        AESGCM(kek).decrypt_into(nonce, ct, aad, dek)
    except InvalidTag:
        wipe(dek)  # never leave unverified plaintext behind
        raise CryptoError from None
    return dek
