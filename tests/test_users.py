"""Tests for accounts: users.json and registration (threats T1, T5, T11, T12)."""

import base64
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from yunarpass import crypto, entries, fsperm, secrets_gen, storage, users, vaultfile
from yunarpass.crypto import KdfParams
from yunarpass.policy import PolicyError
from yunarpass.storage import USERS_FILE, DataDir, StorageError
from yunarpass.users import AccountError, Accounts, Backoff, LoginError
from yunarpass.vaultfile import Body, VaultFile, VaultFormatError

PASSWORD = "correct horse battery staple"
BOB_PASSWORD = "a different long password"


class FakeClock:
    """A monotonic clock that moves only when sleep() is called.

    Every sleep is logged. With interrupt_next set, the next sleep raises
    KeyboardInterrupt instead, as Ctrl-C would.
    """

    def __init__(self) -> None:
        self.now = 1000.0
        self.log: list[object] = []
        self.interrupt_next = False

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        if self.interrupt_next:
            self.interrupt_next = False
            raise KeyboardInterrupt
        self.log.append(seconds)
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def accounts(tmp_path: Path, clock: FakeClock) -> Accounts:
    return Accounts(DataDir.open(tmp_path / "data"), Backoff(clock.time, clock.sleep))


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


# --- Login (UC2) ---------------------------------------------------------------------


def log_kdf_calls(monkeypatch: pytest.MonkeyPatch, log: list[object]) -> None:
    derive_kek = crypto.derive_kek

    def logged(password: str, params: KdfParams) -> bytearray:
        log.append("kdf")
        return derive_kek(password, params)

    monkeypatch.setattr(crypto, "derive_kek", logged)


def vault_doc(accounts: Accounts, username: str) -> dict[str, Any]:
    data = accounts.data_dir.read(storage.vault_file_name(index(accounts)[username]))
    assert data is not None
    doc: dict[str, Any] = json.loads(data)
    return doc


def rewrite_vault(
    accounts: Accounts, username: str, change: Callable[[dict[str, Any]], None]
) -> None:
    doc = vault_doc(accounts, username)
    change(doc)
    name = storage.vault_file_name(index(accounts)[username])
    accounts.data_dir.write(name, json.dumps(doc).encode())


def test_the_right_password_unlocks_the_vault(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)
    session = accounts.login("alice", PASSWORD)
    assert session.username == "alice"
    assert session.counter == 0
    assert session.summaries() == []
    assert not session.closed


def save_body(accounts: Accounts, username: str, body: Body) -> None:
    """Write a body into a user's vault, as a session would."""
    vault = vault_of(accounts, username)
    dek = vaultfile.unlock_with_password(vault, PASSWORD)
    sealed = vaultfile.seal_body(vault.header, dek, body)
    saved = VaultFile(vault.header, vault.password_dek, vault.recovery_dek, sealed)
    name = storage.vault_file_name(vault.header.vault_id)
    accounts.data_dir.write(name, vaultfile.serialize(saved))


GITHUB = entries.new_login(
    "github", username="alice", password="s3cret-Password!", url="", notes=""
).to_json()


def test_login_reads_the_saved_counter_and_entries(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)
    save_body(accounts, "alice", Body(41, (GITHUB,)))
    session = accounts.login("alice", PASSWORD)
    assert session.counter == 41
    assert session.summaries() == [("github", "login")]


@pytest.mark.parametrize(
    "body",
    [
        Body(1, ({"name": "github"},)),  # fields missing
        Body(1, ({**GITHUB, "type": "totp"},)),  # a type this version does not know
        Body(2, (GITHUB, {**GITHUB, "name": "GitHub"})),  # the same name twice
    ],
)
def test_a_body_with_a_malformed_entry_fails_and_its_dek_is_wiped(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch, body: Body
) -> None:
    accounts.register("alice", PASSWORD)
    save_body(accounts, "alice", body)
    deks: list[bytearray] = []
    unlock = vaultfile.unlock_with_password

    def keep_dek(vault: VaultFile, password: str) -> bytearray:
        deks.append(unlock(vault, password))
        return deks[-1]

    monkeypatch.setattr(vaultfile, "unlock_with_password", keep_dek)
    with pytest.raises(LoginError):
        accounts.login("alice", PASSWORD)
    assert deks == [bytearray(crypto.KEY_BYTES)]


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("alice", PASSWORD + "!"),  # wrong password
        ("alice", ""),
        ("bob", PASSWORD),  # unknown user
        ("Alice", PASSWORD),  # not on the allow-list
        ("../alice", PASSWORD),
        ("", PASSWORD),
    ],
)
def test_every_failed_login_looks_the_same_and_costs_one_kdf_run(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch, username: str, password: str
) -> None:
    accounts.register("alice", PASSWORD)
    calls: list[object] = []
    log_kdf_calls(monkeypatch, calls)
    opened: list[object] = []
    monkeypatch.setattr(vaultfile, "open_body", lambda *args: opened.append(args))
    with pytest.raises(LoginError) as caught:
        accounts.login(username, password)
    assert type(caught.value) is LoginError
    assert str(caught.value) == "login failed"
    assert calls == ["kdf"]  # the KDF ran once, for unknown users too (T4)
    assert opened == []  # nothing from the vault was decrypted


def test_failed_logins_wait_longer_each_time_up_to_the_cap(
    accounts: Accounts, clock: FakeClock
) -> None:
    accounts.register("alice", PASSWORD)
    for _ in range(8):
        with pytest.raises(LoginError):
            accounts.login("alice", "a wrong password")
    assert clock.log == [1, 2, 4, 8, 16, 32, 32, 32]


def test_a_successful_login_resets_the_delay(accounts: Accounts, clock: FakeClock) -> None:
    accounts.register("alice", PASSWORD)
    for _ in range(2):
        with pytest.raises(LoginError):
            accounts.login("alice", "a wrong password")
    accounts.login("alice", PASSWORD)
    with pytest.raises(LoginError):
        accounts.login("alice", "a wrong password")
    assert clock.log == [1, 2, 1]


def test_interrupting_the_delay_does_not_let_the_next_attempt_skip_it(
    accounts: Accounts, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    accounts.register("alice", PASSWORD)
    clock.interrupt_next = True  # Ctrl-C during the delay after the failure
    with pytest.raises(KeyboardInterrupt):
        accounts.login("alice", "a wrong password")
    log_kdf_calls(monkeypatch, clock.log)
    accounts.login("alice", PASSWORD)
    assert clock.log == [1, "kdf"]  # the full second first, then the password


def test_the_real_backoff_uses_the_monotonic_clock_and_sleep() -> None:
    backoff = Backoff()
    backoff.wait()  # nothing failed yet: no delay
    backoff.failed()
    backoff.succeeded()
    backoff.wait()


def flip_a_body_byte(doc: dict[str, Any]) -> None:
    ct = bytearray(base64.b64decode(doc["body"]["ct"]))
    ct[0] ^= 1
    doc["body"]["ct"] = base64.b64encode(ct).decode()


def change_the_salt(doc: dict[str, Any]) -> None:
    doc["kdf"]["salt"] = base64.b64encode(bytes(16)).decode()


def rename_to_bob(doc: dict[str, Any]) -> None:
    doc["username"] = "bob"


def drop_a_field(doc: dict[str, Any]) -> None:
    del doc["body"]


@pytest.mark.parametrize("change", [flip_a_body_byte, change_the_salt, rename_to_bob, drop_a_field])
def test_a_tampered_vault_fails_like_a_wrong_password(
    accounts: Accounts,
    monkeypatch: pytest.MonkeyPatch,
    change: Callable[[dict[str, Any]], None],
) -> None:
    accounts.register("alice", PASSWORD)
    rewrite_vault(accounts, "alice", change)
    calls: list[object] = []
    log_kdf_calls(monkeypatch, calls)
    with pytest.raises(LoginError, match="login failed"):
        accounts.login("alice", PASSWORD)
    assert calls == ["kdf"]


def test_a_missing_or_unreadable_vault_fails_like_a_wrong_password(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)
    name = storage.vault_file_name(index(accounts)["alice"])
    accounts.data_dir.write(name, b"not a vault")
    with pytest.raises(LoginError):
        accounts.login("alice", PASSWORD)
    (accounts.data_dir.path / name).unlink()
    with pytest.raises(LoginError):
        accounts.login("alice", PASSWORD)


def test_a_body_that_does_not_decrypt_fails_and_its_dek_is_wiped(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch
) -> None:
    accounts.register("alice", PASSWORD)
    accounts.register("bob", PASSWORD)
    bob_body = vault_doc(accounts, "bob")["body"]
    rewrite_vault(accounts, "alice", lambda doc: doc.update(body=bob_body))
    deks: list[bytearray] = []
    unlock = vaultfile.unlock_with_password

    def keep_dek(vault: VaultFile, password: str) -> bytearray:
        deks.append(unlock(vault, password))
        return deks[-1]

    monkeypatch.setattr(vaultfile, "unlock_with_password", keep_dek)
    with pytest.raises(LoginError):
        accounts.login("alice", PASSWORD)
    # The password was right, so a DEK was unwrapped; it is zeroed again.
    assert deks == [bytearray(crypto.KEY_BYTES)]


def test_a_vault_copied_over_another_users_vault_does_not_open(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)
    accounts.register("bob", BOB_PASSWORD)
    alice_vault = accounts.data_dir.read(storage.vault_file_name(index(accounts)["alice"]))
    assert alice_vault is not None
    accounts.data_dir.write(storage.vault_file_name(index(accounts)["bob"]), alice_vault)
    for password in (BOB_PASSWORD, PASSWORD):
        with pytest.raises(LoginError):
            accounts.login("bob", password)
    assert accounts.login("alice", PASSWORD).username == "alice"


def test_users_json_pointing_at_another_users_vault_does_not_open_it(
    accounts: Accounts,
) -> None:
    accounts.register("alice", PASSWORD)
    alice_id = index(accounts)["alice"]
    accounts.data_dir.write(USERS_FILE, users.serialize_index({"bob": alice_id}))
    # Alice's password does unwrap that vault's DEK, but the vault is Alice's.
    with pytest.raises(LoginError):
        accounts.login("bob", PASSWORD)


def test_a_damaged_index_stops_login_with_its_own_message(accounts: Accounts) -> None:
    accounts.data_dir.write(USERS_FILE, b"[]")
    with pytest.raises(StorageError, match="damaged"):
        accounts.login("alice", PASSWORD)
