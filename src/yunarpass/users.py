"""User management: the accounts in a data directory (UC1).

users.json is the index of accounts, username to vault ID, and holds no
secrets. It is parsed as strictly as a vault file (DESIGN.md §4):

    {"format": 1, "users": {"alice": "3f9c0d2e8a7b4c61a2e5f0b9d8c7a6e1"}}

A vault file is named after its random vault ID, never after the username, so
no file name is built from what a user types (T11). The username is also bound
into every encryption of the vault (T8).

Errors meant for the user are AccountError, PolicyError and StorageError, whose
messages are fixed and safe to show.
"""

import json

from yunarpass import crypto, policy, secrets_gen, vaultfile
from yunarpass.storage import USERS_FILE, DataDir, StorageError, vault_file_name
from yunarpass.vaultfile import USERNAME, VAULT_ID, Body, VaultFormatError

INDEX_FORMAT = 1
USERNAME_RULE = (
    "a username has 3 to 32 characters: lowercase letters a-z, digits, '_' and '-', "
    "starting with a letter or a digit"
)

_INDEX_FIELDS = frozenset({"format", "users"})


class AccountError(Exception):
    """An account operation was refused. The message is safe to show."""


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

    def __init__(self, data_dir: DataDir) -> None:
        self.data_dir = data_dir

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
