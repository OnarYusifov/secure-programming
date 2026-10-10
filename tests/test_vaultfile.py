"""Tests for the vault file format (DESIGN.md §4; threats T7, T9, T19)."""

import dataclasses
import json
import secrets
from collections.abc import Callable
from typing import Any

import pytest

from yunarpass import crypto, vaultfile
from yunarpass.crypto import KdfParams, Sealed
from yunarpass.vaultfile import Body, Header, VaultFile, VaultFormatError

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


@pytest.fixture
def vault() -> VaultFile:
    """A well-formed vault with random ciphertexts: it parses, but nothing in it decrypts."""
    return VaultFile(
        header=Header(
            vault_id=secrets.token_hex(16),
            username="alice",
            kdf=KdfParams.new(),
            recovery_salt=secrets.token_bytes(16),
        ),
        password_dek=Sealed(secrets.token_bytes(12), secrets.token_bytes(48)),
        recovery_dek=Sealed(secrets.token_bytes(12), secrets.token_bytes(48)),
        body=Sealed(secrets.token_bytes(12), secrets.token_bytes(100)),
    )


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
def test_weakened_kdf_parameters_are_refused(vault: VaultFile, field: str, value: int) -> None:
    doc = as_doc(vault)
    doc["kdf"][field] = value
    with pytest.raises(VaultFormatError, match=f"kdf.{field}"):
        from_doc(doc)


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
