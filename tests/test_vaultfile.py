"""Tests for the vault file format (DESIGN.md §4; threats T7, T8, T9, T13, T19)."""

import dataclasses
import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from yunarpass import crypto, vaultfile
from yunarpass.crypto import CryptoError, KdfParams
from yunarpass.vaultfile import Body, Header, VaultFile, VaultFormatError

PASSWORD = "correct horse battery staple"
RECOVERY_KEY = bytes(range(20))
ENTRIES: tuple[dict[str, object], ...] = (
    {"id": "1", "type": "login", "name": "github", "password": "hunter2-but-longer"},
    {"id": "2", "type": "login", "name": "café", "notes": "ünïcödé ✓"},
)

type Doc = dict[str, Any]

FIXED_HEADER = Header(
    vault_id="0" * 32,
    username="alice",
    kdf=KdfParams(65536, 3, 4, bytes(16)),
    recovery_salt=bytes(range(16)),
)


@pytest.fixture(scope="module")
def created() -> tuple[VaultFile, bytearray]:
    return vaultfile.create("alice", PASSWORD, RECOVERY_KEY, Body(7, ENTRIES))


@pytest.fixture
def vault(created: tuple[VaultFile, bytearray]) -> VaultFile:
    return created[0]


@pytest.fixture
def dek(created: tuple[VaultFile, bytearray]) -> bytearray:
    return created[1]


def as_doc(vault: VaultFile) -> Doc:
    doc: Doc = json.loads(vaultfile.serialize(vault))
    return doc


def from_doc(doc: Doc) -> VaultFile:
    return vaultfile.parse(json.dumps(doc).encode())


# --- Round trip and layout -----------------------------------------------------------


def test_serialize_then_parse_gives_the_same_vault(vault: VaultFile) -> None:
    assert vaultfile.parse(vaultfile.serialize(vault)) == vault


def test_the_file_has_the_layout_of_the_design(vault: VaultFile) -> None:
    doc = as_doc(vault)
    assert doc["format"] == 1
    assert doc["username"] == "alice"
    assert len(doc["vault_id"]) == 32
    assert doc["kdf"] | {"salt": None} == {
        "alg": "argon2id",
        "m_kib": 65536,
        "t": 3,
        "p": 4,
        "salt": None,
    }
    assert set(doc["wrapped_dek"]) == {"password", "recovery"}
    assert set(doc["wrapped_dek"]["recovery"]) == {"salt", "nonce", "ct"}
    assert set(doc["body"]) == {"nonce", "ct"}
    assert vaultfile.serialize(vault).isascii()


def test_new_vaults_get_fresh_ids_salts_and_nonces(vault: VaultFile) -> None:
    other, _ = vaultfile.create("alice", PASSWORD, RECOVERY_KEY, Body())
    assert other.header.vault_id != vault.header.vault_id
    assert other.header.kdf.salt != vault.header.kdf.salt
    assert other.header.recovery_salt != vault.header.recovery_salt
    assert other.password_dek.nonce != vault.password_dek.nonce


def test_password_and_recovery_key_both_give_the_dek(vault: VaultFile, dek: bytearray) -> None:
    assert vaultfile.unlock_with_password(vault, PASSWORD) == dek
    assert vaultfile.unlock_with_recovery_key(vault, RECOVERY_KEY) == dek


def test_the_body_decrypts_to_the_entries(vault: VaultFile, dek: bytearray) -> None:
    assert vaultfile.open_body(vault, dek) == Body(7, ENTRIES)


def test_no_entry_text_appears_in_the_file(vault: VaultFile) -> None:
    data = vaultfile.serialize(vault)
    # Whole words only: a short string of hex letters such as "caf" can turn
    # up in the random vault ID or the Base64 by chance.
    for text in (b"github", b"hunter2-but-longer", "café".encode(), rb"caf\u00e9", b"login"):
        assert text not in data


def test_every_seal_uses_a_fresh_nonce(vault: VaultFile, dek: bytearray) -> None:
    first = vaultfile.seal_body(vault.header, dek, Body(8, ENTRIES))
    second = vaultfile.seal_body(vault.header, dek, Body(8, ENTRIES))
    assert first.nonce != second.nonce
    assert first.ct != second.ct


def test_wrong_secrets_fail_with_the_generic_error(vault: VaultFile) -> None:
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_password(vault, PASSWORD + "!")
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_recovery_key(vault, bytes(20))


# --- Malformed files are refused before any cryptography (T19) --------------------------


def set_path(path: str, value: object) -> Callable[[Doc], None]:
    *parents, last = path.split(".")

    def change(doc: Doc) -> None:
        node = doc
        for key in parents:
            node = node[key]
        node[last] = value

    return change


def drop_path(path: str) -> Callable[[Doc], None]:
    *parents, last = path.split(".")

    def change(doc: Doc) -> None:
        node = doc
        for key in parents:
            node = node[key]
        del node[last]

    return change


B64_15 = "AAAAAAAAAAAAAAAAAAAA"  # 15 bytes
B64_16 = "AAAAAAAAAAAAAAAAAAAAAA=="  # 16 bytes
MALFORMED = {
    "unknown top-level field": set_path("extra", 1),
    "missing top-level field": drop_path("body"),
    "unknown kdf field": set_path("kdf.extra", 1),
    "missing recovery salt": drop_path("wrapped_dek.recovery.salt"),
    "unknown body field": set_path("body.tag", "AAAA"),
    "format as a string": set_path("format", "1"),
    "format as a bool": set_path("format", True),
    "format as a float": set_path("format", 1.0),
    "unsupported format": set_path("format", 2),
    "vault_id as a number": set_path("vault_id", 123),
    "vault_id uppercase": set_path("vault_id", "0123456789ABCDEF0123456789ABCDEF"),
    "vault_id too short": set_path("vault_id", "0" * 31),
    "vault_id with a path": set_path("vault_id", "../" + "0" * 29),
    "username uppercase": set_path("username", "Alice"),
    "username too short": set_path("username", "al"),
    "username too long": set_path("username", "a" * 33),
    "username with a path": set_path("username", "../alice"),
    "username with a newline": set_path("username", "alice\n"),
    "username non-ASCII": set_path("username", "ålice"),
    "username starting with a dash": set_path("username", "-alice"),
    "username as null": set_path("username", None),
    "kdf as a list": set_path("kdf", []),
    "other kdf algorithm": set_path("kdf.alg", "argon2i"),
    "m_kib as a string": set_path("kdf.m_kib", "65536"),
    "t as a bool": set_path("kdf.t", True),
    "p as a float": set_path("kdf.p", 4.0),
    "salt not Base64": set_path("kdf.salt", "!!!!"),
    "salt with whitespace": set_path("kdf.salt", "AAAA AAAAAAAAAAAAAAAAAA=="),
    "salt without padding": set_path("kdf.salt", "AAAAAAAAAAAAAAAAAAAAAA"),
    "salt not canonical": set_path("kdf.salt", "AAAAAAAAAAAAAAAAAAAAAB=="),
    "salt non-ASCII": set_path("kdf.salt", "ÄAAAAAAAAAAAAAAAAAAAAA=="),
    "salt as bytes list": set_path("kdf.salt", [0] * 16),
    "salt 15 bytes": set_path("kdf.salt", B64_15),
    "recovery salt 15 bytes": set_path("wrapped_dek.recovery.salt", B64_15),
    "nonce 11 bytes": set_path("wrapped_dek.password.nonce", "AAAAAAAAAAAAAAA="),
    "wrapped DEK 47 bytes": set_path("wrapped_dek.password.ct", "A" * 60 + "AAA="),
    "wrapped DEK 49 bytes": set_path("wrapped_dek.recovery.ct", "A" * 64 + "AA=="),
    "body shorter than a tag": set_path("body.ct", B64_15),
    "body nonce missing": drop_path("body.nonce"),
}


@pytest.mark.parametrize("change", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_vaults_are_refused(vault: VaultFile, change: Callable[[Doc], None]) -> None:
    doc = as_doc(vault)
    change(doc)
    with pytest.raises(VaultFormatError):
        from_doc(doc)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"[]",
        b"null",
        b"1",
        b"\xff\xfe{}",
        b"[" * 100_000,  # nesting deep enough to exhaust the parser's recursion
    ],
    ids=["empty", "array", "null", "number", "not UTF-8", "deep nesting"],
)
def test_input_that_is_not_a_json_object_is_refused(data: bytes) -> None:
    with pytest.raises(VaultFormatError):
        vaultfile.parse(data)


def test_text_instead_of_bytes_is_refused(vault: VaultFile) -> None:
    with pytest.raises(VaultFormatError, match="bytes"):
        vaultfile.parse(vaultfile.serialize(vault).decode())  # type: ignore[arg-type]


def test_a_byte_order_mark_is_refused(vault: VaultFile) -> None:
    with pytest.raises(VaultFormatError, match="JSON"):
        vaultfile.parse(b"\xef\xbb\xbf" + vaultfile.serialize(vault))


def test_duplicate_keys_are_refused(vault: VaultFile) -> None:
    text = vaultfile.serialize(vault).decode()
    # json.loads alone would keep the last value and see "mallory".
    top = text.replace("{", '{\n  "username": "mallory",', 1)
    nested = text.replace('"kdf": {', '"kdf": {"t": 64, ', 1)
    for changed in (top, nested):
        with pytest.raises(VaultFormatError, match="duplicate"):
            vaultfile.parse(changed.encode())


def test_nan_and_infinity_are_refused(vault: VaultFile) -> None:
    text = vaultfile.serialize(vault).decode()
    for constant in ("NaN", "Infinity", "-Infinity"):
        changed = text.replace('"t": 3', f'"t": {constant}', 1)
        with pytest.raises(VaultFormatError):
            vaultfile.parse(changed.encode())


def test_a_huge_number_is_refused(vault: VaultFile) -> None:
    text = vaultfile.serialize(vault).decode()
    changed = text.replace('"m_kib": 65536', '"m_kib": ' + "9" * 5000, 1)
    with pytest.raises(VaultFormatError):
        vaultfile.parse(changed.encode())


def test_an_oversized_file_is_refused_before_parsing() -> None:
    with pytest.raises(VaultFormatError, match="too large"):
        vaultfile.parse(b" " * (vaultfile.MAX_VAULT_BYTES + 1))


def test_serialize_refuses_a_vault_too_large_to_read_back(
    vault: VaultFile, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vaultfile, "MAX_VAULT_BYTES", 100)
    with pytest.raises(VaultFormatError, match="too large"):
        vaultfile.serialize(vault)


def test_error_messages_do_not_repeat_the_file_content(vault: VaultFile) -> None:
    doc = as_doc(vault)
    doc["username"] = "<script>alert(1)</script>"
    with pytest.raises(VaultFormatError) as caught:
        from_doc(doc)
    assert "script" not in str(caught.value)


# --- T7: weakened KDF parameters ---------------------------------------------------------


@pytest.fixture
def kdf_spy(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[KdfParams]]:
    calls: list[KdfParams] = []
    real = crypto.derive_kek

    def spy(password: str, params: KdfParams) -> bytearray:
        calls.append(params)
        return real(password, params)

    monkeypatch.setattr(crypto, "derive_kek", spy)
    yield calls


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("m_kib", crypto.MIN_MEMORY_KIB - 1),
        ("m_kib", 1024),
        ("t", crypto.MIN_ITERATIONS - 1),
        ("t", 1),
        ("p", crypto.MIN_LANES - 1),
        ("m_kib", crypto.MAX_MEMORY_KIB + 1),
        ("t", crypto.MAX_ITERATIONS + 1),
        ("p", crypto.MAX_LANES + 1),
    ],
)
def test_weakened_kdf_parameters_are_refused_before_the_kdf_runs(
    vault: VaultFile, kdf_spy: list[KdfParams], field: str, value: int
) -> None:
    doc = as_doc(vault)
    doc["kdf"][field] = value
    with pytest.raises(VaultFormatError, match=f"kdf.{field}"):
        from_doc(doc)
    assert kdf_spy == []  # no vault object exists, so no KDF could run on these values


def test_stronger_kdf_parameters_still_break_the_password_copy(
    vault: VaultFile, kdf_spy: list[KdfParams]
) -> None:
    # Within the limits, so the file parses, but the parameters are bound to
    # the password copy of the DEK as associated data.
    doc = as_doc(vault)
    doc["kdf"]["t"] = 4
    edited = from_doc(doc)
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_password(edited, PASSWORD)
    assert len(kdf_spy) == 1


def test_a_changed_salt_breaks_only_its_own_copy(vault: VaultFile, dek: bytearray) -> None:
    other_salt = dataclasses.replace(vault.header.kdf, salt=bytes(16))
    edited = dataclasses.replace(vault, header=dataclasses.replace(vault.header, kdf=other_salt))
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_password(edited, PASSWORD)
    assert vaultfile.unlock_with_recovery_key(edited, RECOVERY_KEY) == dek
    assert vaultfile.open_body(edited, dek) == Body(7, ENTRIES)

    edited = dataclasses.replace(
        vault, header=dataclasses.replace(vault.header, recovery_salt=bytes(16))
    )
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_recovery_key(edited, RECOVERY_KEY)
    assert vaultfile.unlock_with_password(edited, PASSWORD) == dek


# --- T8: vaults moved between users ----------------------------------------------------


@pytest.mark.parametrize(("field", "value"), [("username", "bob"), ("vault_id", "f" * 32)])
def test_a_changed_identity_breaks_every_encryption(
    vault: VaultFile, dek: bytearray, field: str, value: str
) -> None:
    doc = as_doc(vault)
    doc[field] = value
    moved = from_doc(doc)  # well-formed, so only the cryptography can catch it
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_password(moved, PASSWORD)
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_recovery_key(moved, RECOVERY_KEY)
    with pytest.raises(CryptoError):
        vaultfile.open_body(moved, dek)  # even with the right DEK


def test_parts_of_another_vault_do_not_fit(vault: VaultFile, dek: bytearray) -> None:
    # Bob made his vault with the same password and recovery key as Alice.
    bob, bob_dek = vaultfile.create("bob", PASSWORD, RECOVERY_KEY, Body(1, ()))
    with_bobs_body = dataclasses.replace(vault, body=bob.body)
    with pytest.raises(CryptoError):
        vaultfile.open_body(with_bobs_body, dek)
    with pytest.raises(CryptoError):
        vaultfile.open_body(with_bobs_body, bob_dek)
    with_bobs_key = dataclasses.replace(vault, password_dek=bob.password_dek)
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_password(with_bobs_key, PASSWORD)


# --- The associated data -----------------------------------------------------------------


def test_associated_data_known_answer() -> None:
    # Pinned: if the encoding ever changed, every existing vault would stop opening.
    zeros = "0" * 32
    assert (
        FIXED_HEADER.body_aad()
        == ('{"aad":"body","format":1,"username":"alice","vault_id":"' + zeros + '"}').encode()
    )
    assert (
        FIXED_HEADER.password_aad()
        == (
            '{"aad":"password-wrap","format":1,'
            '"kdf":{"alg":"argon2id","m_kib":65536,"p":4,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","t":3},'
            '"username":"alice","vault_id":"' + zeros + '"}'
        ).encode()
    )
    assert (
        FIXED_HEADER.recovery_aad()
        == (
            '{"aad":"recovery-wrap","format":1,"salt":"AAECAwQFBgcICQoLDA0ODw==",'
            '"username":"alice","vault_id":"' + zeros + '"}'
        ).encode()
    )


def test_each_encryption_has_its_own_associated_data() -> None:
    aads = {FIXED_HEADER.body_aad(), FIXED_HEADER.password_aad(), FIXED_HEADER.recovery_aad()}
    assert len(aads) == 3


def test_rewrapping_the_password_copy_leaves_the_rest_valid(
    vault: VaultFile, dek: bytearray
) -> None:
    # A password change (UC7, D10): new salt, new KEK, new password copy. The
    # recovery copy and the body are not touched and must still work.
    changed = vaultfile.rewrap_password(vault, dek, "a brand new password")
    changed = vaultfile.parse(vaultfile.serialize(changed))
    assert vaultfile.unlock_with_password(changed, "a brand new password") == dek
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_password(changed, PASSWORD)
    assert vaultfile.unlock_with_recovery_key(changed, RECOVERY_KEY) == dek
    assert vaultfile.open_body(changed, dek) == Body(7, ENTRIES)


def test_rewrapping_changes_only_the_salt_and_the_password_copy(
    vault: VaultFile, dek: bytearray
) -> None:
    before, after = as_doc(vault), as_doc(vaultfile.rewrap_password(vault, dek, PASSWORD))
    assert after["kdf"]["salt"] != before["kdf"]["salt"]
    assert after["wrapped_dek"]["password"] != before["wrapped_dek"]["password"]
    for doc in (before, after):
        del doc["kdf"]["salt"], doc["wrapped_dek"]["password"]
    assert after == before  # the KDF parameters, the recovery copy and the body


def test_rewrapping_keeps_stronger_kdf_parameters() -> None:
    vault, dek = vaultfile.create("alice", PASSWORD, RECOVERY_KEY, Body())
    stronger = KdfParams(131072, 4, 4, vault.header.kdf.salt)
    header = dataclasses.replace(vault.header, kdf=stronger)
    kek = crypto.derive_kek(PASSWORD, stronger)
    vault = VaultFile(
        header, crypto.wrap_dek(kek, dek, header.password_aad()), vault.recovery_dek, vault.body
    )
    changed = vaultfile.rewrap_password(vault, dek, "a brand new password")
    kdf = changed.header.kdf
    assert (kdf.memory_kib, kdf.iterations, kdf.lanes) == (131072, 4, 4)
    assert vaultfile.unlock_with_password(changed, "a brand new password") == dek


# --- The body (T9) -------------------------------------------------------------------------


def test_body_round_trip() -> None:
    body = Body(42, ENTRIES)
    assert vaultfile.parse_body(vaultfile.serialize_body(body)) == body
    assert vaultfile.serialize_body(body).isascii()


@pytest.mark.parametrize(
    "plaintext",
    [
        b'{"counter":0}',
        b'{"entries":[]}',
        b'{"counter":0,"entries":[],"extra":1}',
        b'{"counter":-1,"entries":[]}',
        b'{"counter":true,"entries":[]}',
        b'{"counter":1.5,"entries":[]}',
        b'{"counter":9223372036854775808,"entries":[]}',
        b'{"counter":0,"entries":{}}',
        b'{"counter":0,"entries":["github"]}',
        b'{"counter":0,"entries":[{"name":"a","name":"b"}]}',
        b'{"counter":0,"counter":1,"entries":[]}',
        b"[]",
        b"not json",
    ],
)
def test_malformed_bodies_are_refused(plaintext: bytes) -> None:
    with pytest.raises(VaultFormatError):
        vaultfile.parse_body(plaintext)


def test_body_constructor_checks_its_fields() -> None:
    with pytest.raises(VaultFormatError):
        Body(-1)
    with pytest.raises(VaultFormatError):
        Body(0, [{}])  # type: ignore[arg-type]
    with pytest.raises(VaultFormatError):
        Body(0, ("github",))  # type: ignore[arg-type]


# --- Constructors check their fields too ---------------------------------------------------


def test_header_constructor_checks_its_fields() -> None:
    for change in (
        {"username": "Bob"},
        {"vault_id": "x" * 32},
        {"recovery_salt": bytes(15)},
        {"kdf": None},
    ):
        with pytest.raises(VaultFormatError):
            dataclasses.replace(FIXED_HEADER, **change)


def test_vaultfile_constructor_checks_its_fields(vault: VaultFile) -> None:
    for change in (
        {"password_dek": crypto.Sealed(bytes(12), bytes(47))},
        {"recovery_dek": crypto.Sealed(bytes(11), bytes(48))},
        {"body": crypto.Sealed(bytes(12), bytes(15))},
        {"body": (bytes(12), bytes(16))},
        {"header": None},
    ):
        with pytest.raises(VaultFormatError):
            dataclasses.replace(vault, **change)


# --- Key hygiene (T13) ---------------------------------------------------------------------


def test_unlock_wipes_the_kek(vault: VaultFile, monkeypatch: pytest.MonkeyPatch) -> None:
    keks: list[bytearray] = []
    real = crypto.derive_kek

    def keep(password: str, params: KdfParams) -> bytearray:
        keks.append(real(password, params))
        return keks[-1]

    monkeypatch.setattr(crypto, "derive_kek", keep)
    vaultfile.unlock_with_password(vault, PASSWORD)
    with pytest.raises(CryptoError):
        vaultfile.unlock_with_password(vault, "wrong password")
    assert keks == [bytearray(32), bytearray(32)]  # zeroed after success and after failure


def test_create_wipes_the_dek_if_it_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    deks: list[bytearray] = []
    real = crypto.new_key

    def keep() -> bytearray:
        deks.append(real())
        return deks[-1]

    monkeypatch.setattr(crypto, "new_key", keep)
    with pytest.raises(CryptoError):
        vaultfile.create("alice", PASSWORD, bytes(19), Body())  # a recovery key too short
    assert deks == [bytearray(32)]
