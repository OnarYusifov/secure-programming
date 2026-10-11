"""Tests for accounts: users.json and registration (threats T1, T5, T11, T12)."""

import base64
import json
import os
from pathlib import Path

import pytest

from yunarpass import fsperm, secrets_gen, storage, users, vaultfile
from yunarpass.policy import PolicyError
from yunarpass.storage import USERS_FILE, DataDir, StorageError
from yunarpass.users import AccountError, Accounts
from yunarpass.vaultfile import Body, VaultFile, VaultFormatError

PASSWORD = "correct horse battery staple"


@pytest.fixture
def accounts(tmp_path: Path) -> Accounts:
    return Accounts(DataDir.open(tmp_path / "data"))


def file_names(accounts: Accounts) -> list[str]:
    return sorted(path.name for path in accounts.data_dir.path.iterdir())


def contents(accounts: Accounts) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in accounts.data_dir.path.iterdir()}


def index(accounts: Accounts) -> dict[str, str]:
    data = accounts.data_dir.read(USERS_FILE)
    assert data is not None
    return users.parse_index(data)


def vault_of(accounts: Accounts, username: str) -> VaultFile:
    data = accounts.data_dir.read(storage.vault_file_name(index(accounts)[username]))
    assert data is not None
    return vaultfile.parse(data)


# --- Registration (UC1) --------------------------------------------------------------


def test_register_writes_a_vault_and_the_index(accounts: Accounts) -> None:
    shown = accounts.register("alice", PASSWORD)
    vault_id = index(accounts)["alice"]
    assert file_names(accounts) == sorted([USERS_FILE, storage.vault_file_name(vault_id)])

    vault = vault_of(accounts, "alice")
    assert vault.header.username == "alice"
    assert vault.header.vault_id == vault_id
    dek = vaultfile.unlock_with_password(vault, PASSWORD)
    assert vaultfile.open_body(vault, dek) == Body(counter=0, entries=())
    recovery_key = secrets_gen.parse_recovery_key(shown)
    assert vaultfile.unlock_with_recovery_key(vault, recovery_key) == dek


def test_register_returns_the_recovery_key_formatted_for_paper(accounts: Accounts) -> None:
    shown = accounts.register("alice", PASSWORD)
    assert secrets_gen.format_recovery_key(secrets_gen.parse_recovery_key(shown)) == shown


def test_every_account_gets_its_own_vault_and_recovery_key(accounts: Accounts) -> None:
    alice_key = accounts.register("alice", PASSWORD)
    bob_key = accounts.register("bob", PASSWORD)
    assert alice_key != bob_key
    ids = index(accounts)
    assert ids.keys() == {"alice", "bob"}
    assert ids["alice"] != ids["bob"]


def test_vault_files_are_named_after_a_random_id_never_the_username(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)
    for name in file_names(accounts):
        assert "alice" not in name


@pytest.mark.parametrize("username", ["abc", "a" * 32, "0day", "alice_b-2", "con", "nul"])
def test_allowed_usernames(accounts: Accounts, username: str) -> None:
    # "con" and "nul" are reserved file names on Windows. They are fine as
    # usernames, because a username never becomes a file name (T11).
    accounts.register(username, PASSWORD)
    assert username in index(accounts)


@pytest.mark.parametrize(
    "username",
    [
        "../x",
        "..",
        "a/b/c",
        "a\\b\\c",
        "C:alice",
        "Alice",
        "ALICE",
        chr(0xE5) + "lice",  # a-ring
        chr(0x430) + "lice",  # Cyrillic a
        "",
        "ab",
        "a" * 33,
        "-alice",
        "_alice",
        "al ice",
        " alice",
        "alice\n",
        "alice\x00",
        "alice.json",
    ],
)
def test_a_bad_username_is_refused_and_nothing_is_written(
    accounts: Accounts, username: str
) -> None:
    with pytest.raises(AccountError, match="3 to 32 characters"):
        accounts.register(username, PASSWORD)
    assert file_names(accounts) == []


def test_a_taken_username_is_refused_and_the_first_account_is_unchanged(
    accounts: Accounts,
) -> None:
    accounts.register("alice", PASSWORD)
    before = contents(accounts)
    with pytest.raises(AccountError, match="taken"):
        accounts.register("alice", "another long password")
    assert contents(accounts) == before


@pytest.mark.parametrize(
    ("password", "rule"),
    [
        ("short", "at least 12"),
        ("unbelievable", "most common"),
        ("x" * 1025, "at most 1024"),
    ],
)
def test_a_password_against_the_policy_is_refused_and_nothing_is_written(
    accounts: Accounts, password: str, rule: str
) -> None:
    with pytest.raises(PolicyError, match=rule):
        accounts.register("alice", password)
    assert file_names(accounts) == []


def test_registered_files_are_owner_only(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)
    accounts.register("bob", PASSWORD)  # replaces users.json, keeping a .bak
    assert USERS_FILE + storage.BACKUP_SUFFIX in file_names(accounts)
    for path in accounts.data_dir.path.iterdir():
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            fsperm.check_private_fd(fd)
        finally:
            os.close(fd)


def test_the_recovery_key_is_not_stored_anywhere(accounts: Accounts) -> None:
    shown = accounts.register("alice", PASSWORD)
    accounts.register("bob", PASSWORD)
    raw = secrets_gen.parse_recovery_key(shown)
    forms = [
        raw,
        raw.hex().encode(),
        base64.b64encode(raw),
        base64.b32encode(raw),
        base64.b32encode(raw).lower(),
        shown.encode(),
    ]
    for name, content in contents(accounts).items():
        for form in forms:
            assert form not in content, name


def test_a_crash_before_the_index_is_written_leaves_no_account(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch
) -> None:
    write = DataDir.write

    def users_file_fails(self: DataDir, name: str, data: bytes) -> None:
        if name == USERS_FILE:
            raise StorageError("a data file could not be written")
        write(self, name, data)

    monkeypatch.setattr(DataDir, "write", users_file_fails)
    with pytest.raises(StorageError):
        accounts.register("alice", PASSWORD)
    monkeypatch.undo()
    # An unused vault file is left behind; the name is still free.
    assert USERS_FILE not in file_names(accounts)
    accounts.register("alice", PASSWORD)
    assert list(index(accounts)) == ["alice"]


def test_a_username_taken_while_the_kdf_ran_is_refused(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch
) -> None:
    create = vaultfile.create
    other = {"alice": "f" * 32}

    def create_while_another_process_registers(
        username: str, password: str, recovery_key: bytes, body: Body
    ) -> tuple[VaultFile, bytearray]:
        result = create(username, password, recovery_key, body)
        accounts.data_dir.write(USERS_FILE, users.serialize_index(other))
        return result

    monkeypatch.setattr(vaultfile, "create", create_while_another_process_registers)
    with pytest.raises(AccountError, match="taken"):
        accounts.register("alice", PASSWORD)
    assert index(accounts) == other


def test_a_damaged_index_stops_registration(accounts: Accounts) -> None:
    accounts.data_dir.write(USERS_FILE, b'{"format": 1, "users": {"Alice": 1}}')
    with pytest.raises(StorageError, match=r"the account list \(users.json\) is damaged"):
        accounts.register("bob", PASSWORD)


# --- users.json ----------------------------------------------------------------------


def test_index_round_trip_sorted_by_username() -> None:
    ids = {"bob": "1" * 32, "alice": "0" * 32}
    data = users.serialize_index(ids)
    assert users.parse_index(data) == ids
    assert json.loads(data) == {"format": 1, "users": {"alice": "0" * 32, "bob": "1" * 32}}
    assert data.index(b"alice") < data.index(b"bob")
    assert users.parse_index(users.serialize_index({})) == {}


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"users": {}},
        {"format": 1},
        {"format": 1, "users": {}, "extra": None},
        {"format": 2, "users": {}},
        {"format": True, "users": {}},
        {"format": 1.0, "users": {}},
        {"format": "1", "users": {}},
        {"format": 1, "users": []},
        {"format": 1, "users": {"Alice": "0" * 32}},
        {"format": 1, "users": {"../x": "0" * 32}},
        {"format": 1, "users": {"alice": "0" * 31}},
        {"format": 1, "users": {"alice": "A" * 32}},
        {"format": 1, "users": {"alice": "0" * 32 + "\n"}},
        {"format": 1, "users": {"alice": 0}},
        {"format": 1, "users": {"alice": None}},
        {"format": 1, "users": {"alice": "0" * 32, "bob": "0" * 32}},
    ],
)
def test_malformed_indexes_are_refused(doc: object) -> None:
    with pytest.raises(VaultFormatError):
        users.parse_index(json.dumps(doc).encode())


def test_an_index_with_a_username_twice_is_refused() -> None:
    data = b'{"format": 1, "users": {"alice": "%s", "alice": "%s"}}' % (b"0" * 32, b"1" * 32)
    with pytest.raises(VaultFormatError, match="duplicate"):
        users.parse_index(data)
