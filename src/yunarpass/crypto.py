"""Encryption module: key derivation and authenticated encryption.

Implements the scheme in DESIGN.md §4:

- the key-encryption key (KEK) is derived from the master password with Argon2id;
- a random data key (DEK) encrypts the vault with AES-256-GCM;
- the DEK is stored wrapped (encrypted) under the KEK.

Every failure raises CryptoError without detail, so a caller cannot tell a wrong
password from a tampered file (T4, T7, T8).
"""

import secrets
import unicodedata
from dataclasses import dataclass
from typing import Self

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

KEY_BYTES = 32  # AES-256
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
