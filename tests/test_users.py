"""Tests for accounts: users.json, registration, login, password change and recovery.

Threats T1, T2, T4, T5, T7, T8, T11, T12.
"""

import base64
import json
import os
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from yunarpass import crypto, entries, fsperm, secrets_gen, storage, users, vaultfile
from yunarpass.crypto import CryptoError, KdfParams
from yunarpass.policy import PolicyError
from yunarpass.session import Session, VaultChangedError, VaultLockedError
from yunarpass.storage import USERS_FILE, DataDir, StorageError
from yunarpass.users import AccountError, Accounts, Backoff, LoginError, WrongPasswordError
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


def test_two_entries_with_one_name_load(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)
    other = entries.new_login("github", username="bob", password="x", url="", notes="")
    save_body(accounts, "alice", Body(2, (GITHUB, other.to_json())))
    session = accounts.login("alice", PASSWORD)
    assert sorted(s.username for s in session.find("github")) == ["alice", "bob"]


def test_login_reads_the_saved_counter_and_entries(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)
    save_body(accounts, "alice", Body(41, (GITHUB,)))
    session = accounts.login("alice", PASSWORD)
    assert session.counter == 41
    assert [(s.name, s.type) for s in session.summaries()] == [("github", "login")]


@pytest.mark.parametrize(
    "body",
    [
        Body(1, ({"name": "github"},)),  # fields missing
        Body(1, ({**GITHUB, "type": "totp"},)),  # a type this version does not know
        Body(2, (GITHUB, {**GITHUB, "name": "mail"})),  # the same ID twice
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


# --- Changing the master password (UC7) ----------------------------------------------

NEW_PASSWORD = "a brand new passphrase"


@pytest.fixture
def alice(accounts: Accounts) -> Session:
    """Alice's unlocked session."""
    accounts.register("alice", PASSWORD)
    return accounts.login("alice", PASSWORD)


def test_after_a_change_the_old_password_fails_and_the_new_one_works(
    accounts: Accounts, alice: Session
) -> None:
    alice.add("github", username="", password="s3cret-Password!", url="", notes="")
    accounts.change_password(alice, PASSWORD, NEW_PASSWORD)
    alice.close()
    with pytest.raises(LoginError):
        accounts.login("alice", PASSWORD)
    again = accounts.login("alice", NEW_PASSWORD)
    assert again.counter == 1  # the body was not saved again
    assert [summary.name for summary in again.summaries()] == ["github"]


def test_the_recovery_key_still_works_after_a_change(accounts: Accounts) -> None:
    recovery_key = accounts.register("alice", PASSWORD)
    accounts.change_password(accounts.login("alice", PASSWORD), PASSWORD, NEW_PASSWORD)
    vault = vault_of(accounts, "alice")
    key = secrets_gen.parse_recovery_key(recovery_key)
    dek = vaultfile.unlock_with_recovery_key(vault, key)
    assert vaultfile.open_body(vault, dek) == Body()


def test_a_change_rewraps_only_the_password_copy(
    accounts: Accounts, alice: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = vault_doc(accounts, "alice")
    calls: list[object] = []
    log_kdf_calls(monkeypatch, calls)
    accounts.change_password(alice, PASSWORD, NEW_PASSWORD)
    assert calls == ["kdf", "kdf"]  # the current password checked, the new one derived
    after = vault_doc(accounts, "alice")
    assert after["kdf"]["salt"] != before["kdf"]["salt"]
    for doc in (before, after):
        del doc["kdf"]["salt"], doc["wrapped_dek"]["password"]
    assert after == before  # identity, KDF parameters, recovery copy and body


def test_a_wrong_current_password_is_refused_with_the_login_delay(
    accounts: Accounts, alice: Session, clock: FakeClock
) -> None:
    before = contents(accounts)
    for _ in range(3):
        with pytest.raises(WrongPasswordError) as caught:
            accounts.change_password(alice, "a wrong password", NEW_PASSWORD)
        assert str(caught.value) == "the current master password is wrong, so it was not changed"
    assert clock.log == [1, 2, 4]
    assert contents(accounts) == before
    accounts.change_password(alice, PASSWORD, NEW_PASSWORD)
    with pytest.raises(LoginError):
        accounts.login("alice", PASSWORD)
    assert clock.log == [1, 2, 4, 1]  # the success reset the delay


def test_the_delay_is_shared_with_login(
    accounts: Accounts, alice: Session, clock: FakeClock
) -> None:
    with pytest.raises(WrongPasswordError):
        accounts.change_password(alice, "a wrong password", NEW_PASSWORD)
    with pytest.raises(LoginError):
        accounts.login("alice", "another wrong password")
    assert clock.log == [1, 2]


@pytest.mark.parametrize("new", ["too short", "unbelievable", "x" * 1025])
def test_a_new_password_against_the_policy_is_refused_before_any_work(
    accounts: Accounts,
    alice: Session,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
    new: str,
) -> None:
    before = contents(accounts)
    calls: list[object] = []
    log_kdf_calls(monkeypatch, calls)
    with pytest.raises(PolicyError):
        accounts.change_password(alice, "a wrong password", new)
    assert calls == []
    assert clock.log == []  # a policy error costs no delay
    assert contents(accounts) == before


def test_a_changed_password_is_normalized_like_a_new_one(
    accounts: Accounts, alice: Session
) -> None:
    composed = "pässwörd mit ümlaut"
    accounts.change_password(alice, PASSWORD, composed)
    accounts.login("alice", unicodedata.normalize("NFD", composed))


def test_a_change_on_a_locked_session_is_refused(accounts: Accounts, alice: Session) -> None:
    alice.close()
    with pytest.raises(VaultLockedError):
        accounts.change_password(alice, PASSWORD, NEW_PASSWORD)
    accounts.login("alice", PASSWORD)


def test_a_change_is_refused_if_another_session_saved_first(
    accounts: Accounts, alice: Session
) -> None:
    other = accounts.login("alice", PASSWORD)
    other.add("github", username="", password="s3cret-Password!", url="", notes="")
    with pytest.raises(VaultChangedError):
        accounts.change_password(alice, PASSWORD, NEW_PASSWORD)
    assert accounts.login("alice", PASSWORD).counter == 1  # still the old password


def test_the_session_alone_also_needs_the_current_password(alice: Session) -> None:
    with pytest.raises(CryptoError):
        alice.change_password("a wrong password", NEW_PASSWORD)
    with pytest.raises(PolicyError):
        alice.change_password(PASSWORD, "too short")


# --- Recovering with the recovery key (UC8) ------------------------------------------

WRONG_KEY = "A" * 32  # well formed: twenty zero bytes


def test_recovery_replaces_the_password_and_the_recovery_key(accounts: Accounts) -> None:
    old_key = accounts.register("alice", PASSWORD)
    accounts.login("alice", PASSWORD).add(
        "github", username="", password="s3cret-Password!", url="", notes=""
    )
    session, new_key = accounts.recover("alice", old_key, NEW_PASSWORD)
    assert session.username == "alice"
    assert not session.closed
    assert [summary.name for summary in session.summaries()] == ["github"]
    assert session.counter == 1  # the body was not saved again
    assert new_key != old_key
    assert secrets_gen.format_recovery_key(secrets_gen.parse_recovery_key(new_key)) == new_key
    # Neither the old password nor the old key opens the vault any more (T5).
    with pytest.raises(LoginError):
        accounts.login("alice", PASSWORD)
    with pytest.raises(LoginError):
        accounts.recover("alice", old_key, "yet another passphrase")
    assert accounts.login("alice", NEW_PASSWORD).counter == 1
    accounts.recover("alice", new_key, "yet another passphrase")


def test_the_recovery_key_is_read_as_typed(accounts: Accounts) -> None:
    key = accounts.register("alice", PASSWORD)
    typed = " " + key.lower().replace("-", " ") + " "
    session, _ = accounts.recover("alice", typed, NEW_PASSWORD)
    assert not session.closed


def test_a_recovery_rewraps_both_copies_and_leaves_the_rest(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = accounts.register("alice", PASSWORD)
    before = vault_doc(accounts, "alice")
    calls: list[object] = []
    log_kdf_calls(monkeypatch, calls)
    accounts.recover("alice", key, NEW_PASSWORD)
    assert calls == ["kdf"]  # Argon2id for the new password only: the key needs just HKDF
    after = vault_doc(accounts, "alice")
    assert after["kdf"]["salt"] != before["kdf"]["salt"]
    for copy in ("password", "recovery"):
        assert after["wrapped_dek"][copy] != before["wrapped_dek"][copy]
    assert after["wrapped_dek"]["recovery"]["salt"] != before["wrapped_dek"]["recovery"]["salt"]
    for doc in (before, after):
        del doc["kdf"]["salt"], doc["wrapped_dek"]
    assert after == before  # identity, KDF parameters and body


def test_the_new_recovery_key_is_not_stored_anywhere(accounts: Accounts) -> None:
    old_key = accounts.register("alice", PASSWORD)
    _, shown = accounts.recover("alice", old_key, NEW_PASSWORD)
    raw = secrets_gen.parse_recovery_key(shown)
    forms = [raw, raw.hex().encode(), base64.b64encode(raw), base64.b32encode(raw), shown.encode()]
    for name, content in contents(accounts).items():
        for form in forms:
            assert form not in content, name


def test_every_failed_recovery_looks_the_same_and_waits_longer_each_time(
    accounts: Accounts, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = accounts.register("alice", PASSWORD)
    bob_key = accounts.register("bob", BOB_PASSWORD)
    before = contents(accounts)
    opened: list[object] = []
    monkeypatch.setattr(vaultfile, "open_body", lambda *args: opened.append(args))
    attempts = [
        ("alice", bob_key),  # another user's key
        ("alice", WRONG_KEY),
        ("alice", "not a recovery key"),  # malformed
        ("alice", key + "A"),
        ("alice", "x" * 1000),
        ("bob", key),
        ("carol", key),  # unknown user
        ("../alice", key),
    ]
    for username, typed in attempts:
        with pytest.raises(LoginError) as caught:
            accounts.recover(username, typed, NEW_PASSWORD)
        assert type(caught.value) is LoginError
        assert str(caught.value) == "login failed"
    assert clock.log == [1, 2, 4, 8, 16, 32, 32, 32]
    assert opened == []  # nothing from a vault was decrypted
    assert contents(accounts) == before


def test_recovery_and_login_share_the_delay(accounts: Accounts, clock: FakeClock) -> None:
    key = accounts.register("alice", PASSWORD)
    with pytest.raises(LoginError):
        accounts.recover("alice", WRONG_KEY, NEW_PASSWORD)
    with pytest.raises(LoginError):
        accounts.login("alice", "a wrong password")
    accounts.recover("alice", key, NEW_PASSWORD)  # a success resets it
    with pytest.raises(LoginError):
        accounts.login("alice", PASSWORD)
    assert clock.log == [1, 2, 1]


@pytest.mark.parametrize("new", ["too short", "unbelievable", "x" * 1025])
def test_a_recovery_checks_the_new_password_before_the_key(
    accounts: Accounts, clock: FakeClock, monkeypatch: pytest.MonkeyPatch, new: str
) -> None:
    key = accounts.register("alice", PASSWORD)
    before = contents(accounts)
    tried: list[object] = []
    monkeypatch.setattr(vaultfile, "unlock_with_recovery_key", lambda *args: tried.append(args))
    with pytest.raises(PolicyError):
        accounts.recover("alice", key, new)
    assert tried == []
    assert clock.log == []  # a policy error costs no delay
    assert contents(accounts) == before


def change_the_recovery_salt(doc: dict[str, Any]) -> None:
    doc["wrapped_dek"]["recovery"]["salt"] = base64.b64encode(bytes(16)).decode()


@pytest.mark.parametrize(
    "change", [flip_a_body_byte, change_the_recovery_salt, rename_to_bob, drop_a_field]
)
def test_a_tampered_vault_fails_recovery_like_a_wrong_key(
    accounts: Accounts, change: Callable[[dict[str, Any]], None]
) -> None:
    key = accounts.register("alice", PASSWORD)
    rewrite_vault(accounts, "alice", change)
    before = contents(accounts)
    with pytest.raises(LoginError, match="login failed"):
        accounts.recover("alice", key, NEW_PASSWORD)
    assert contents(accounts) == before


def test_a_body_that_does_not_open_fails_recovery_and_its_dek_is_wiped(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = accounts.register("alice", PASSWORD)
    rewrite_vault(accounts, "alice", flip_a_body_byte)
    deks: list[bytearray] = []
    unlock = vaultfile.unlock_with_recovery_key

    def keep_dek(vault: VaultFile, recovery_key: bytes) -> bytearray:
        deks.append(unlock(vault, recovery_key))
        return deks[-1]

    monkeypatch.setattr(vaultfile, "unlock_with_recovery_key", keep_dek)
    with pytest.raises(LoginError):
        accounts.recover("alice", key, NEW_PASSWORD)
    assert deks == [bytearray(crypto.KEY_BYTES)]


def test_a_recovery_is_refused_if_another_session_saved_meanwhile(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = accounts.register("alice", PASSWORD)
    other = accounts.login("alice", PASSWORD)
    rewrap = vaultfile.rewrap_recovery

    def save_first(vault: VaultFile, dek: crypto.Key, recovery_key: bytes) -> VaultFile:
        if not other.summaries():  # only once
            other.add("github", username="", password="s3cret-Password!", url="", notes="")
        return rewrap(vault, dek, recovery_key)

    monkeypatch.setattr(vaultfile, "rewrap_recovery", save_first)
    closed: list[Session] = []
    close = Session.close

    def logged_close(self: Session) -> None:
        closed.append(self)
        close(self)

    monkeypatch.setattr(Session, "close", logged_close)
    with pytest.raises(VaultChangedError):
        accounts.recover("alice", key, NEW_PASSWORD)
    assert len(closed) == 1  # the session is not handed out
    # Nothing changed: the other session's save stands, and the old secrets still work.
    assert accounts.login("alice", PASSWORD).counter == 1
    accounts.recover("alice", key, NEW_PASSWORD)


def test_the_session_alone_also_needs_the_recovery_key(accounts: Accounts) -> None:
    key = secrets_gen.parse_recovery_key(accounts.register("alice", PASSWORD))
    session = accounts.login("alice", PASSWORD)
    before = contents(accounts)
    with pytest.raises(CryptoError):
        session.recover(bytes(crypto.RECOVERY_KEY_BYTES), NEW_PASSWORD)
    with pytest.raises(PolicyError):
        session.recover(key, "too short")
    assert contents(accounts) == before
    session.close()
    with pytest.raises(VaultLockedError):
        session.recover(key, NEW_PASSWORD)
