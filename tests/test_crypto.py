"""Tests for the encryption module (DESIGN.md §4; threats T1, T5, T6, T7, T8, T13)."""

import dataclasses

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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


# --- Authenticated encryption (T6, T7, T8) -----------------------------------


def test_encrypt_decrypt_round_trip() -> None:
    key = crypto.new_key()
    sealed = crypto.encrypt(key, b"secret vault body", AAD)
    assert b"secret vault body" not in sealed.ct
    assert len(sealed.nonce) == crypto.NONCE_BYTES
    assert crypto.decrypt(key, sealed.nonce, sealed.ct, AAD) == b"secret vault body"


def test_decrypt_with_wrong_key_fails() -> None:
    sealed = crypto.encrypt(crypto.new_key(), b"body", AAD)
    with pytest.raises(CryptoError):
        crypto.decrypt(crypto.new_key(), sealed.nonce, sealed.ct, AAD)


@pytest.mark.parametrize("index", [0, 5, -17, -1])  # ciphertext bytes and tag bytes
def test_flipped_ciphertext_bit_fails(index: int) -> None:
    key = crypto.new_key()
    sealed = crypto.encrypt(key, b"sixteen byte msg", AAD)
    with pytest.raises(CryptoError):
        crypto.decrypt(key, sealed.nonce, flip_bit(sealed.ct, index), AAD)


def test_flipped_nonce_bit_fails() -> None:
    key = crypto.new_key()
    sealed = crypto.encrypt(key, b"body", AAD)
    with pytest.raises(CryptoError):
        crypto.decrypt(key, flip_bit(sealed.nonce, 0), sealed.ct, AAD)


def test_changed_associated_data_fails() -> None:
    # The header is the AAD: weakened KDF parameters (T7) or another username
    # (T8) in the header make decryption fail.
    key = crypto.new_key()
    sealed = crypto.encrypt(key, b"body", AAD)
    for changed in (flip_bit(AAD, 3), AAD.replace(b"alice", b"mallo"), AAD + b" "):
        with pytest.raises(CryptoError):
            crypto.decrypt(key, sealed.nonce, sealed.ct, changed)


@pytest.mark.parametrize(
    ("nonce", "ct"),
    [(bytes(11), bytes(32)), (bytes(13), bytes(32)), (bytes(12), bytes(15)), ("x" * 12, bytes(32))],
)
def test_malformed_input_is_refused_before_decrypting(nonce: bytes, ct: bytes) -> None:
    with pytest.raises(CryptoError):
        crypto.decrypt(crypto.new_key(), nonce, ct, AAD)


@pytest.mark.parametrize("key", [bytes(16), bytes(24), bytes(33), "k" * 32])
def test_only_256_bit_keys_are_accepted(key: bytes) -> None:
    with pytest.raises(CryptoError):
        crypto.encrypt(key, b"body", AAD)


def test_empty_associated_data_is_refused() -> None:
    with pytest.raises(CryptoError):
        crypto.encrypt(crypto.new_key(), b"body", b"")


def test_nonces_are_unique() -> None:
    key = crypto.new_key()
    nonces = {crypto.encrypt(key, b"x", AAD).nonce for _ in range(10_000)}
    assert len(nonces) == 10_000


# --- DEK wrapping (UC2, UC7) ------------------------------------------------------


def test_wrap_unwrap_round_trip(kek: bytearray) -> None:
    dek = crypto.new_key()
    sealed = crypto.wrap_dek(kek, dek, AAD)
    unwrapped = crypto.unwrap_dek(kek, sealed.nonce, sealed.ct, AAD)
    assert isinstance(unwrapped, bytearray)
    assert unwrapped == dek


def test_wrong_password_and_tampered_header_look_the_same(
    params: KdfParams, kek: bytearray
) -> None:
    sealed = crypto.wrap_dek(kek, crypto.new_key(), AAD)
    wrong_kek = crypto.derive_kek("not the password", params)
    errors = []
    for key, aad in ((wrong_kek, AAD), (kek, flip_bit(AAD, 0))):
        with pytest.raises(CryptoError) as caught:
            crypto.unwrap_dek(key, sealed.nonce, sealed.ct, aad)
        errors.append(caught.value)
    assert str(errors[0]) == str(errors[1]) == "cryptographic operation failed"
    for error in errors:
        # No chained library exception that a traceback could reveal (T17).
        assert error.__cause__ is None
        assert error.__suppress_context__


def test_unwrap_refuses_wrong_length(kek: bytearray) -> None:
    sealed = crypto.encrypt(kek, bytes(31), AAD)
    with pytest.raises(CryptoError):
        crypto.unwrap_dek(kek, sealed.nonce, sealed.ct, AAD)


def test_wrap_refuses_a_short_dek(kek: bytearray) -> None:
    with pytest.raises(CryptoError):
        crypto.wrap_dek(kek, bytes(16), AAD)


# --- Key hygiene (T13) ---------------------------------------------------------------


def test_wipe_zeroes_the_buffer_in_place() -> None:
    key = crypto.new_key()
    same_object = key
    crypto.wipe(key)
    assert key is same_object
    assert key == bytearray(crypto.KEY_BYTES)


def test_new_keys_are_random() -> None:
    assert crypto.new_key() != crypto.new_key()


# --- Recovery KEK (T5) -------------------------------------------------------------

RECOVERY_KEY = bytes(range(20))
RECOVERY_SALT = bytes(range(100, 116))
# Our own known answer, cross-checked with an HKDF written from hmac/hashlib.
# Changing the info label or the length would break every existing recovery key.
RECOVERY_KNOWN_ANSWER = "bd48d885476a11b2e9f2d8af7f3c65faae12979daee221e0b49055b3a9de57bf"
# RFC 5869, test case 1.
RFC5869_OKM = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"


def test_hkdf_matches_rfc5869_vector() -> None:
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=42, salt=bytes(range(13)), info=bytes(range(0xF0, 0xFA))
    )
    assert hkdf.derive(b"\x0b" * 22).hex() == RFC5869_OKM


def test_recovery_kek_known_answer() -> None:
    kek = crypto.derive_recovery_kek(RECOVERY_KEY, RECOVERY_SALT)
    assert isinstance(kek, bytearray)
    assert kek.hex() == RECOVERY_KNOWN_ANSWER


def test_recovery_kek_depends_on_key_and_salt() -> None:
    kek = crypto.derive_recovery_kek(RECOVERY_KEY, RECOVERY_SALT)
    assert crypto.derive_recovery_kek(bytes(20), RECOVERY_SALT) != kek
    assert crypto.derive_recovery_kek(RECOVERY_KEY, bytes(16)) != kek
    assert crypto.derive_recovery_kek(bytearray(RECOVERY_KEY), RECOVERY_SALT) == kek


@pytest.mark.parametrize(
    ("key", "salt"),
    [
        (bytes(19), RECOVERY_SALT),
        (bytes(21), RECOVERY_SALT),
        ("k" * 20, RECOVERY_SALT),
        (RECOVERY_KEY, bytes(15)),
        (RECOVERY_KEY, bytearray(16)),
    ],
)
def test_recovery_kek_refuses_wrong_sizes(key: bytes, salt: bytes) -> None:
    with pytest.raises(CryptoError):
        crypto.derive_recovery_kek(key, salt)


def test_recovery_kek_unwraps_the_same_dek_as_the_password() -> None:
    # The scheme: one DEK, wrapped once under each KEK (DESIGN.md §4).
    dek = crypto.new_key()
    rk_kek = crypto.derive_recovery_kek(RECOVERY_KEY, RECOVERY_SALT)
    sealed = crypto.wrap_dek(rk_kek, dek, AAD)
    assert crypto.unwrap_dek(rk_kek, sealed.nonce, sealed.ct, AAD) == dek
