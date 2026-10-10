"""Tests for the encryption module (DESIGN.md §4; threats T1, T6, T7, T8, T13)."""

import dataclasses

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from yunarpass import crypto
from yunarpass.crypto import CryptoError, KdfParams

PASSWORD = "correct horse battery staple"
FIXED_SALT = bytes(range(16))
AAD = b'{"format":1,"username":"alice"}'

# Our own known answer: derive_kek(PASSWORD) with FIXED_SALT and the floor
# parameters. If normalization, encoding or the parameter mapping ever changed,
# existing vaults would stop opening; this catches it.
KNOWN_ANSWER = "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e"

# RFC 9106 §5.3, the Argon2id test vector.
RFC9106_TAG = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


@pytest.fixture(scope="module")
def params() -> KdfParams:
    return KdfParams(crypto.MIN_MEMORY_KIB, crypto.MIN_ITERATIONS, crypto.MIN_LANES, FIXED_SALT)


@pytest.fixture(scope="module")
def kek(params: KdfParams) -> bytearray:
    return crypto.derive_kek(PASSWORD, params)


def flip_bit(data: bytes, index: int) -> bytes:
    changed = bytearray(data)
    changed[index] ^= 0x01
    return bytes(changed)


# --- Key derivation (T1) ---------------------------------------------------


def test_derive_kek_known_answer(kek: bytearray) -> None:
    assert isinstance(kek, bytearray)
    assert kek.hex() == KNOWN_ANSWER


def test_derive_kek_depends_on_password_and_salt(params: KdfParams, kek: bytearray) -> None:
    other_salt = dataclasses.replace(params, salt=bytes(16))
    assert crypto.derive_kek(PASSWORD + "!", params) != kek
    assert crypto.derive_kek(PASSWORD, other_salt) != kek


def test_derive_kek_normalizes_unicode(params: KdfParams) -> None:
    composed = "café au lait 12"
    decomposed = "café au lait 12"
    assert composed != decomposed
    assert crypto.derive_kek(composed, params) == crypto.derive_kek(decomposed, params)


def test_derive_kek_refuses_unencodable_password(params: KdfParams) -> None:
    with pytest.raises(CryptoError):
        crypto.derive_kek("lone surrogate \ud800", params)


def test_argon2id_matches_rfc9106_vector() -> None:
    # The library primitive, called directly: the RFC vector uses 32 KiB, below
    # our floor. It confirms that memory_cost is in KiB, as KdfParams assumes.
    kdf = Argon2id(
        salt=b"\x02" * 16,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=32,
        ad=b"\x04" * 12,
        secret=b"\x03" * 8,
    )
    assert kdf.derive(b"\x01" * 32).hex() == RFC9106_TAG


# --- Parameter floor and ceiling (T7) ---------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        {"memory_kib": crypto.MIN_MEMORY_KIB - 1},
        {"iterations": crypto.MIN_ITERATIONS - 1},
        {"lanes": crypto.MIN_LANES - 1},
        {"memory_kib": crypto.MAX_MEMORY_KIB + 1},
        {"iterations": crypto.MAX_ITERATIONS + 1},
        {"lanes": crypto.MAX_LANES + 1},
        {"iterations": True},
        {"memory_kib": 65536.0},
        {"salt": bytes(15)},
        {"salt": bytes(17)},
        {"salt": bytearray(16)},
    ],
)
def test_kdf_params_outside_limits_are_refused(
    params: KdfParams, change: dict[str, object]
) -> None:
    with pytest.raises(CryptoError):
        dataclasses.replace(params, **change)  # type: ignore[arg-type]


def test_derive_kek_rechecks_params(params: KdfParams) -> None:
    weak = KdfParams.new()
    object.__setattr__(weak, "memory_kib", 1024)  # bypasses __post_init__
    with pytest.raises(CryptoError):
        crypto.derive_kek(PASSWORD, weak)


def test_kdf_params_new_uses_the_floor_and_a_fresh_salt() -> None:
    first, second = KdfParams.new(), KdfParams.new()
    assert (first.memory_kib, first.iterations, first.lanes) == (65536, 3, 4)
    assert len(first.salt) == crypto.SALT_BYTES
    assert first.salt != second.salt
