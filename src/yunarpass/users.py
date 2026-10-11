"""User management: the accounts in a data directory (UC1, UC2).

users.json is the index of accounts, username to vault ID, and holds no
secrets. It is parsed as strictly as a vault file (DESIGN.md §4):

    {"format": 1, "users": {"alice": "3f9c0d2e8a7b4c61a2e5f0b9d8c7a6e1"}}

A vault file is named after its random vault ID, never after the username, so
no file name is built from what a user types (T11). The username is also bound
into every encryption of the vault (T8).

Logging in has no separate password check and no stored hash: the password
is right if the KEK derived from it unwraps the DEK, which AES-GCM
authenticates (DESIGN.md §4, Login check).

Errors meant for the user are AccountError, PolicyError and StorageError, whose
messages are fixed and safe to show.
"""

import json
import time
from collections.abc import Callable
from typing import NoReturn

from yunarpass import crypto, policy, secrets_gen, vaultfile
from yunarpass.crypto import CryptoError, KdfParams
from yunarpass.session import Session
from yunarpass.storage import USERS_FILE, DataDir, StorageError, vault_file_name
from yunarpass.vaultfile import USERNAME, VAULT_ID, Body, VaultFile, VaultFormatError

INDEX_FORMAT = 1
USERNAME_RULE = (
    "a username has 3 to 32 characters: lowercase letters a-z, digits, '_' and '-', "
    "starting with a letter or a digit"
)

# Online guessing (T2): after a failed login the next attempt waits 1 s, then
# 2, 4, ... up to 32 s. Constants on purpose, like the KDF floor.
FIRST_DELAY_SECONDS = 1.0
MAX_DELAY_SECONDS = 32.0

_INDEX_FIELDS = frozenset({"format", "users"})


class AccountError(Exception):
    """An account operation was refused. The message is safe to show."""


class LoginError(AccountError):
    """The login failed. Deliberately the same for every cause (T4)."""

    def __init__(self) -> None:
        super().__init__("login failed")


class Backoff:
    """The growing delay between failed logins, kept by the running program (T2).

    After a failure the delay is slept at once, so the error appears late, and
    the next attempt also waits until the delay has passed. Interrupting the
    sleep with Ctrl-C therefore does not let the next password be tried sooner.
    """

    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._clock = clock
        self._sleep = sleep
        self._delay = 0.0
        self._not_before: float | None = None

    def wait(self) -> None:
        """Return once the next attempt is allowed."""
        if self._not_before is not None:
            remaining = self._not_before - self._clock()
            if remaining > 0:
                self._sleep(remaining)

    def failed(self) -> None:
        """Count a failure: the next attempt waits twice as long as the last (capped)."""
        self._delay = min(max(self._delay * 2, FIRST_DELAY_SECONDS), MAX_DELAY_SECONDS)
        self._not_before = self._clock() + self._delay

    def succeeded(self) -> None:
        self._delay = 0.0
        self._not_before = None


def parse_index(data: bytes) -> dict[str, str]:
    """Parse users.json strictly. Raises VaultFormatError on anything unexpected."""
    doc = vaultfile.fields(vaultfile.load_json(data), _INDEX_FIELDS, "users")
    # type() rather than isinstance(): a JSON true or 1.0 is not the version 1.
    if type(doc["format"]) is not int or doc["format"] != INDEX_FORMAT:
        raise VaultFormatError("users.format: not supported")
    users = doc["users"]
    if not isinstance(users, dict):
        raise VaultFormatError("users.users: not a JSON object")
    for username, vault_id in users.items():
        if not USERNAME.fullmatch(username):
            raise VaultFormatError("users.users: a username is not allowed")
        if not isinstance(vault_id, str) or not VAULT_ID.fullmatch(vault_id):
            raise VaultFormatError("users.users: a vault ID is not allowed")
    if len(set(users.values())) != len(users):
        raise VaultFormatError("users.users: two accounts share a vault")
    return dict(users)


def serialize_index(index: dict[str, str]) -> bytes:
    """users.json as ASCII JSON, accounts sorted by username."""
    doc = {"format": INDEX_FORMAT, "users": dict(sorted(index.items()))}
    return (json.dumps(doc, indent=2) + "\n").encode("ascii")


class Accounts:
    """The accounts of one data directory."""

    def __init__(self, data_dir: DataDir, backoff: Backoff | None = None) -> None:
        self.data_dir = data_dir
        self.backoff = Backoff() if backoff is None else backoff

    def _index(self) -> dict[str, str]:
        data = self.data_dir.read(USERS_FILE)
        if data is None:
            return {}
        try:
            return parse_index(data)
        except VaultFormatError:
            raise StorageError("the account list (users.json) is damaged") from None

    def check_new_username(self, username: str) -> None:
        """Raise AccountError unless the username is allowed and not taken yet."""
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise AccountError(USERNAME_RULE)
        if username in self._index():
            raise AccountError("that username is taken")

    def register(self, username: str, password: str) -> str:
        """Create an account with an empty vault.

        Returns the new recovery key, formatted for writing down. It is not
        stored anywhere: only a key derived from it, which wraps the DEK.
        """
        self.check_new_username(username)
        policy.check_master_password(password)
        recovery_key = secrets_gen.new_recovery_key()
        vault, dek = vaultfile.create(username, password, recovery_key, Body())
        crypto.wipe(dek)  # the vault is used after logging in, not now
        vault_id = vault.header.vault_id
        # The vault first, then the index: a crash in between leaves an unused
        # vault file, never an account without a vault.
        self.data_dir.write(vault_file_name(vault_id), vaultfile.serialize(vault))
        index = self._index()  # again: the KDF took a while
        if username in index:
            raise AccountError("that username is taken")
        index[username] = vault_id
        self.data_dir.write(USERS_FILE, serialize_index(index))
        return secrets_gen.format_recovery_key(recovery_key)

    def login(self, username: str, password: str) -> Session:
        """Unlock the user's vault (UC2). Raises LoginError on any failure.

        An unknown username, a wrong password and a damaged or swapped vault all
        fail the same way, after the same work: one Argon2id derivation (T4).
        Nothing in the vault is decrypted unless the password unwraps the DEK.
        """
        self.backoff.wait()
        vault = self._find_vault(username)
        if vault is None:
            # The same work as a real attempt, so the time taken does not show
            # whether the username exists.
            crypto.wipe(crypto.derive_kek(password, KdfParams.new()))
            self._fail()
        try:
            dek = vaultfile.unlock_with_password(vault, password)
        except CryptoError:
            self._fail()
        try:
            body = vaultfile.open_body(vault, dek)
        except (CryptoError, VaultFormatError):
            crypto.wipe(dek)
            self._fail()
        self.backoff.succeeded()
        return Session(vault, dek, body)

    def _find_vault(self, username: str) -> VaultFile | None:
        """The user's vault, or None if there is no usable one."""
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            return None
        vault_id = self._index().get(username)
        if vault_id is None:
            return None
        data = self.data_dir.read(vault_file_name(vault_id))
        if data is None:
            return None
        try:
            vault = vaultfile.parse(data)
        except VaultFormatError:
            return None
        # users.json is not trusted either: the vault must name this user and
        # carry this ID, or it is another user's vault put in its place (T8).
        if vault.header.username != username or vault.header.vault_id != vault_id:
            return None
        return vault

    def _fail(self) -> NoReturn:
        self.backoff.failed()
        self.backoff.wait()
        raise LoginError
