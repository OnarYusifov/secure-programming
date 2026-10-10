"""Vault file format, version 1 (DESIGN.md §4).

parse() checks a whole vault file before any cryptography runs: exact field
sets, no duplicate keys, exact JSON types (a bool is not an int), canonical
Base64 with exact decoded lengths, a size cap, and the Argon2id floor and
ceiling (T7, T19). serialize() writes the same format back.
"""

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, NoReturn

from yunarpass import crypto
from yunarpass.crypto import KdfParams, Sealed

FORMAT_VERSION = 1
KDF_ALGORITHM = "argon2id"
VAULT_ID_BYTES = 16
WRAPPED_DEK_BYTES = crypto.KEY_BYTES + crypto.TAG_BYTES

# The storage layer's cap on any data file; the parser enforces it again.
MAX_VAULT_BYTES = 8 * 1024 * 1024
MAX_COUNTER = 2**63 - 1

# Explicit ASCII ranges, never \w or \d: those also match non-ASCII letters and
# digits. Patterns are only ever used with fullmatch, which, unlike match with
# "$", does not accept a trailing newline.
USERNAME = re.compile(r"[a-z0-9][a-z0-9_-]{2,31}")
VAULT_ID = re.compile(r"[0-9a-f]{32}")

_TOP_FIELDS = frozenset({"format", "vault_id", "username", "kdf", "wrapped_dek", "body"})
_KDF_FIELDS = frozenset({"alg", "m_kib", "t", "p", "salt"})
_WRAPPED_FIELDS = frozenset({"password", "recovery"})
_SEALED_FIELDS = frozenset({"nonce", "ct"})
_RECOVERY_FIELDS = frozenset({"salt", "nonce", "ct"})
_BODY_FIELDS = frozenset({"counter", "entries"})


class VaultFormatError(Exception):
    """The vault file or body is malformed.

    The message names the rule that failed, never the value that was found, so
    no file content ends up in an error message or a log.
    """


# --- Strict JSON ---------------------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        # json.loads would quietly keep the last value, so two readers of the
        # same file could disagree about what it says.
        if key in result:
            raise VaultFormatError("duplicate field")
        result[key] = value
    return result


def _no_constants(name: str) -> NoReturn:
    raise VaultFormatError("NaN and Infinity are not allowed")


def _load_json(data: bytes) -> object:
    if not isinstance(data, bytes):
        raise VaultFormatError("not bytes")
    if len(data) > MAX_VAULT_BYTES:
        raise VaultFormatError("too large")
    try:
        text = data.decode("utf-8")  # strict: invalid UTF-8 and a BOM are refused
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (ValueError, RecursionError):  # includes JSONDecodeError and UnicodeDecodeError
        raise VaultFormatError("not valid JSON") from None


def _fields(value: object, names: frozenset[str], where: str) -> dict[str, object]:
    if not isinstance(value, dict) or value.keys() != names:
        raise VaultFormatError(f"{where}: unknown or missing fields")
    return value


def _int(value: object, low: int, high: int, where: str) -> int:
    # bool is a subclass of int: a JSON true must not pass as 1.
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise VaultFormatError(f"{where}: not a whole number in the allowed range")
    return value


def _text(value: object, pattern: re.Pattern[str], where: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise VaultFormatError(f"{where}: not allowed")
    return value


def _b64(value: object, where: str, *, size: int | None = None, min_size: int = 0) -> bytes:
    if not isinstance(value, str):
        raise VaultFormatError(f"{where}: not a string")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:  # binascii.Error, or non-ASCII characters
        raise VaultFormatError(f"{where}: not Base64") from None
    # Only the canonical spelling. The decoder ignores the unused low bits of
    # the last character, so several strings would otherwise decode the same.
    if _b64_text(raw) != value:
        raise VaultFormatError(f"{where}: not canonical Base64")
    if (size is not None and len(raw) != size) or len(raw) < min_size:
        raise VaultFormatError(f"{where}: wrong length")
    return raw


def _b64_text(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _sealed(fields: dict[str, object], where: str, **length: int) -> Sealed:
    return Sealed(
        _b64(fields["nonce"], f"{where}.nonce", size=crypto.NONCE_BYTES),
        _b64(fields["ct"], f"{where}.ct", **length),
    )


def _check_sealed(sealed: object, where: str, *, size: int | None = None) -> None:
    if not (
        isinstance(sealed, Sealed)
        and isinstance(sealed.nonce, bytes)
        and isinstance(sealed.ct, bytes)
        and len(sealed.nonce) == crypto.NONCE_BYTES
        and len(sealed.ct) >= crypto.TAG_BYTES
        and (size is None or len(sealed.ct) == size)
    ):
        raise VaultFormatError(f"{where}: wrong nonce or ciphertext length")


def _kdf_fields(kdf: KdfParams) -> dict[str, object]:
    return {
        "alg": KDF_ALGORITHM,
        "m_kib": kdf.memory_kib,
        "t": kdf.iterations,
        "p": kdf.lanes,
        "salt": _b64_text(kdf.salt),
    }


# --- The vault file ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Header:
    """Who the vault belongs to, and the inputs that turn a secret into a KEK."""

    vault_id: str
    username: str
    kdf: KdfParams
    recovery_salt: bytes

    def __post_init__(self) -> None:
        _text(self.vault_id, VAULT_ID, "vault_id")
        _text(self.username, USERNAME, "username")
        if not isinstance(self.kdf, KdfParams):
            raise VaultFormatError("kdf: not KDF parameters")
        if (
            not isinstance(self.recovery_salt, bytes)
            or len(self.recovery_salt) != crypto.SALT_BYTES
        ):
            raise VaultFormatError("recovery salt: wrong length")


@dataclass(frozen=True, slots=True)
class VaultFile:
    """A parsed vault file: the header and three ciphertexts."""

    header: Header
    password_dek: Sealed  # the DEK, wrapped under the KEK from the master password
    recovery_dek: Sealed  # the DEK, wrapped under the KEK from the recovery key
    body: Sealed  # the entries, encrypted under the DEK

    def __post_init__(self) -> None:
        if not isinstance(self.header, Header):
            raise VaultFormatError("header: not a header")
        _check_sealed(self.password_dek, "wrapped_dek.password", size=WRAPPED_DEK_BYTES)
        _check_sealed(self.recovery_dek, "wrapped_dek.recovery", size=WRAPPED_DEK_BYTES)
        _check_sealed(self.body, "body")


def parse(data: bytes) -> VaultFile:
    """Parse a vault file strictly. Raises VaultFormatError on anything unexpected."""
    doc = _load_json(data)
    if not isinstance(doc, dict):
        raise VaultFormatError("vault: not a JSON object")
    # The version first: a later format may differ in any other field.
    _int(doc.get("format"), FORMAT_VERSION, FORMAT_VERSION, "format")
    _fields(doc, _TOP_FIELDS, "vault")

    kdf = _fields(doc["kdf"], _KDF_FIELDS, "kdf")
    if kdf["alg"] != KDF_ALGORITHM:
        raise VaultFormatError("kdf.alg: not supported")
    # The floor and ceiling are checked here, before the KDF can ever run on
    # these values (T7).
    params = KdfParams(
        memory_kib=_int(kdf["m_kib"], crypto.MIN_MEMORY_KIB, crypto.MAX_MEMORY_KIB, "kdf.m_kib"),
        iterations=_int(kdf["t"], crypto.MIN_ITERATIONS, crypto.MAX_ITERATIONS, "kdf.t"),
        lanes=_int(kdf["p"], crypto.MIN_LANES, crypto.MAX_LANES, "kdf.p"),
        salt=_b64(kdf["salt"], "kdf.salt", size=crypto.SALT_BYTES),
    )

    wrapped = _fields(doc["wrapped_dek"], _WRAPPED_FIELDS, "wrapped_dek")
    password = _fields(wrapped["password"], _SEALED_FIELDS, "wrapped_dek.password")
    recovery = _fields(wrapped["recovery"], _RECOVERY_FIELDS, "wrapped_dek.recovery")
    body = _fields(doc["body"], _SEALED_FIELDS, "body")

    header = Header(
        vault_id=_text(doc["vault_id"], VAULT_ID, "vault_id"),
        username=_text(doc["username"], USERNAME, "username"),
        kdf=params,
        recovery_salt=_b64(recovery["salt"], "wrapped_dek.recovery.salt", size=crypto.SALT_BYTES),
    )
    return VaultFile(
        header=header,
        password_dek=_sealed(password, "wrapped_dek.password", size=WRAPPED_DEK_BYTES),
        recovery_dek=_sealed(recovery, "wrapped_dek.recovery", size=WRAPPED_DEK_BYTES),
        body=_sealed(body, "body", min_size=crypto.TAG_BYTES),
    )


def serialize(vault: VaultFile) -> bytes:
    """The vault file as UTF-8 JSON (in fact pure ASCII)."""
    header = vault.header
    doc = {
        "format": FORMAT_VERSION,
        "vault_id": header.vault_id,
        "username": header.username,
        "kdf": _kdf_fields(header.kdf),
        "wrapped_dek": {
            "password": {
                "nonce": _b64_text(vault.password_dek.nonce),
                "ct": _b64_text(vault.password_dek.ct),
            },
            "recovery": {
                "salt": _b64_text(header.recovery_salt),
                "nonce": _b64_text(vault.recovery_dek.nonce),
                "ct": _b64_text(vault.recovery_dek.ct),
            },
        },
        "body": {"nonce": _b64_text(vault.body.nonce), "ct": _b64_text(vault.body.ct)},
    }
    data = (json.dumps(doc, indent=2) + "\n").encode("ascii")
    if len(data) > MAX_VAULT_BYTES:  # never write what could not be read back
        raise VaultFormatError("vault: too large")
    return data


# --- The decrypted body --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Body:
    """The decrypted vault: a counter that grows on every save, and the entries.

    Each entry is a JSON object. Its fields are checked where entries are
    built and edited, not here.
    """

    counter: int = 0
    entries: tuple[dict[str, object], ...] = ()

    def __post_init__(self) -> None:
        _int(self.counter, 0, MAX_COUNTER, "counter")
        if not isinstance(self.entries, tuple) or not all(
            isinstance(entry, dict) for entry in self.entries
        ):
            raise VaultFormatError("entries: not a list of objects")


def parse_body(plaintext: bytes) -> Body:
    """Parse a decrypted body as strictly as the file around it."""
    doc = _fields(_load_json(plaintext), _BODY_FIELDS, "body")
    entries = doc["entries"]
    if not isinstance(entries, list):
        raise VaultFormatError("entries: not a list of objects")
    return Body(_int(doc["counter"], 0, MAX_COUNTER, "counter"), tuple(entries))


def serialize_body(body: Body) -> bytes:
    """The body as compact ASCII JSON, ready to encrypt."""
    doc = {"counter": body.counter, "entries": list(body.entries)}
    return json.dumps(doc, separators=(",", ":")).encode("ascii")
