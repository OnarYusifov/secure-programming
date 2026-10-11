"""Vault file format, version 1 (DESIGN.md §4).

parse() checks a whole vault file before any cryptography runs: exact field
sets, no duplicate keys, exact JSON types (a bool is not an int), canonical
Base64 with exact decoded lengths, a size cap, and the Argon2id floor and
ceiling (T7, T19). serialize() writes the same format back.

Associated data (AAD). Every encryption in the file is bound to the vault's
identity, its format version, vault_id and username, so a vault renamed to
another user, or swapped into another user's place, does not decrypt (T8). Each
copy of the DEK is also bound to its own key-derivation inputs: the password
copy to the Argon2id parameters and salt, the recovery copy to its HKDF salt
(T7). Changing the password therefore re-wraps only the password copy, and the
recovery copy and the body stay valid (DESIGN.md §6, D10).
"""

import base64
import dataclasses
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any, NoReturn

from yunarpass import crypto
from yunarpass.crypto import KdfParams, Key, Sealed

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


def load_json(data: bytes) -> object:
    """Parse UTF-8 JSON strictly: no duplicate keys, no NaN or Infinity, at most 8 MiB.

    Also used for users.json, so both data files follow the same rules.
    """
    if not isinstance(data, bytes):
        raise VaultFormatError("not bytes")
    if len(data) > MAX_VAULT_BYTES:
        raise VaultFormatError("too large")
    try:
        text = data.decode("utf-8")  # strict: invalid UTF-8 and a BOM are refused
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (ValueError, RecursionError):  # includes JSONDecodeError and UnicodeDecodeError
        raise VaultFormatError("not valid JSON") from None


def fields(value: object, names: frozenset[str], where: str) -> dict[str, object]:
    """Return value if it is a JSON object with exactly these field names."""
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

    def _aad(self, purpose: str, **extra: object) -> bytes:
        # Canonical JSON: sorted keys, no spaces, ASCII only. Every value is
        # validated, so the same header always gives the same bytes. "aad"
        # names the purpose, so no two encryptions share associated data.
        fields = {
            "aad": purpose,
            "format": FORMAT_VERSION,
            "vault_id": self.vault_id,
            "username": self.username,
            **extra,
        }
        return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")

    def body_aad(self) -> bytes:
        """Associated data of the body: the vault's identity."""
        return self._aad("body")

    def password_aad(self) -> bytes:
        """Associated data of the password copy of the DEK: identity and Argon2id inputs."""
        return self._aad("password-wrap", kdf=_kdf_fields(self.kdf))

    def recovery_aad(self) -> bytes:
        """Associated data of the recovery copy of the DEK: identity and HKDF salt."""
        return self._aad("recovery-wrap", salt=_b64_text(self.recovery_salt))


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
    doc = load_json(data)
    if not isinstance(doc, dict):
        raise VaultFormatError("vault: not a JSON object")
    # The version first: a later format may differ in any other field.
    _int(doc.get("format"), FORMAT_VERSION, FORMAT_VERSION, "format")
    fields(doc, _TOP_FIELDS, "vault")

    kdf = fields(doc["kdf"], _KDF_FIELDS, "kdf")
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

    wrapped = fields(doc["wrapped_dek"], _WRAPPED_FIELDS, "wrapped_dek")
    password = fields(wrapped["password"], _SEALED_FIELDS, "wrapped_dek.password")
    recovery = fields(wrapped["recovery"], _RECOVERY_FIELDS, "wrapped_dek.recovery")
    body = fields(doc["body"], _SEALED_FIELDS, "body")

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
    doc = fields(load_json(plaintext), _BODY_FIELDS, "body")
    entries = doc["entries"]
    if not isinstance(entries, list):
        raise VaultFormatError("entries: not a list of objects")
    return Body(_int(doc["counter"], 0, MAX_COUNTER, "counter"), tuple(entries))


def serialize_body(body: Body) -> bytes:
    """The body as compact ASCII JSON, ready to encrypt."""
    doc = {"counter": body.counter, "entries": list(body.entries)}
    return json.dumps(doc, separators=(",", ":")).encode("ascii")


# --- Putting the crypto and the format together ------------------------------------------


def _wrap(kek: bytearray, dek: Key, aad: bytes) -> Sealed:
    try:
        return crypto.wrap_dek(kek, dek, aad)
    finally:
        crypto.wipe(kek)


def _unwrap(kek: bytearray, sealed: Sealed, aad: bytes) -> bytearray:
    try:
        return crypto.unwrap_dek(kek, sealed.nonce, sealed.ct, aad)
    finally:
        crypto.wipe(kek)


def create(
    username: str, password: str, recovery_key: bytes, body: Body
) -> tuple[VaultFile, bytearray]:
    """Build a new vault: fresh vault ID, DEK, salts and nonces.

    Returns the vault and its DEK. The caller keeps the DEK while the vault is
    unlocked and wipes it on lock.
    """
    header = Header(
        vault_id=secrets.token_hex(VAULT_ID_BYTES),
        username=username,
        kdf=KdfParams.new(),
        recovery_salt=secrets.token_bytes(crypto.SALT_BYTES),
    )
    dek = crypto.new_key()
    try:
        password_kek = crypto.derive_kek(password, header.kdf)
        password_dek = _wrap(password_kek, dek, header.password_aad())
        recovery_kek = crypto.derive_recovery_kek(recovery_key, header.recovery_salt)
        recovery_dek = _wrap(recovery_kek, dek, header.recovery_aad())
        vault = VaultFile(header, password_dek, recovery_dek, seal_body(header, dek, body))
    except BaseException:
        crypto.wipe(dek)
        raise
    return vault, dek


def unlock_with_password(vault: VaultFile, password: str) -> bytearray:
    """Return the DEK if the password is right; otherwise raise CryptoError.

    A wrong password and a changed header fail in the same way (T4, T7, T8).
    """
    kek = crypto.derive_kek(password, vault.header.kdf)
    return _unwrap(kek, vault.password_dek, vault.header.password_aad())


def rewrap_password(vault: VaultFile, dek: Key, password: str) -> VaultFile:
    """The vault with the DEK wrapped under a new master password (UC7).

    The password copy gets a fresh salt, so a new KEK, and keeps the Argon2id
    parameters, which may be stronger than the floor. The body and the
    recovery copy stay exactly as they are: neither binds the password's KDF
    inputs (D10), so both remain valid.
    """
    kdf = dataclasses.replace(vault.header.kdf, salt=secrets.token_bytes(crypto.SALT_BYTES))
    header = dataclasses.replace(vault.header, kdf=kdf)
    password_dek = _wrap(crypto.derive_kek(password, kdf), dek, header.password_aad())
    return VaultFile(header, password_dek, vault.recovery_dek, vault.body)


def unlock_with_recovery_key(vault: VaultFile, recovery_key: bytes) -> bytearray:
    """Return the DEK if the recovery key is right; otherwise raise CryptoError."""
    kek = crypto.derive_recovery_kek(recovery_key, vault.header.recovery_salt)
    return _unwrap(kek, vault.recovery_dek, vault.header.recovery_aad())


def rewrap_recovery(vault: VaultFile, dek: Key, recovery_key: bytes) -> VaultFile:
    """The vault with the DEK wrapped under a new recovery key (UC8).

    The recovery copy gets a fresh HKDF salt. The body and the password copy
    stay exactly as they are: neither binds the recovery salt (D10), so both
    remain valid.
    """
    header = dataclasses.replace(vault.header, recovery_salt=secrets.token_bytes(crypto.SALT_BYTES))
    kek = crypto.derive_recovery_kek(recovery_key, header.recovery_salt)
    recovery_dek = _wrap(kek, dek, header.recovery_aad())
    return VaultFile(header, vault.password_dek, recovery_dek, vault.body)


def seal_body(header: Header, dek: Key, body: Body) -> Sealed:
    """Encrypt a body under the DEK with a fresh nonce."""
    return crypto.encrypt(dek, serialize_body(body), header.body_aad())


def open_body(vault: VaultFile, dek: Key) -> Body:
    """Decrypt and parse the body. A wrong DEK or a changed identity raises CryptoError."""
    plaintext = crypto.decrypt(dek, vault.body.nonce, vault.body.ct, vault.header.body_aad())
    return parse_body(plaintext)
