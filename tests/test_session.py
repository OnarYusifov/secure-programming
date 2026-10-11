"""Tests for the unlocked session and its entries (threats T6, T9, T13, T19, T25, T28)."""

import dataclasses
from collections.abc import Callable
from pathlib import Path

import pytest

from yunarpass import crypto, storage, vaultfile
from yunarpass.entries import EntryError
from yunarpass.session import Session, VaultChangedError, VaultLockedError
from yunarpass.storage import DataDir, StorageError
from yunarpass.users import Accounts, Backoff
from yunarpass.vaultfile import VaultFile

PASSWORD = "correct horse battery staple"
SECRET = "s3cret-Password!"
FIELDS = {"username": "alice@example.com", "url": "https://github.com", "notes": "personal"}


def no_sleep(seconds: float) -> None:
    pass


@pytest.fixture
def accounts(tmp_path: Path) -> Accounts:
    accounts = Accounts(DataDir.open(tmp_path / "data"), Backoff(sleep=no_sleep))
    accounts.register("alice", PASSWORD)
    return accounts


@pytest.fixture
def session(accounts: Accounts) -> Session:
    return accounts.login("alice", PASSWORD)


def vault_path(session: Session) -> Path:
    return session._data_dir.path / storage.vault_file_name(session.vault.header.vault_id)


def on_disk(session: Session) -> VaultFile:
    return vaultfile.parse(vault_path(session).read_bytes())


def add_github(session: Session, name: str = "github", **changes: str) -> None:
    session.add(name, **{**FIELDS, "password": SECRET, **changes})


# --- The session itself --------------------------------------------------------------


def test_a_session_knows_its_user_and_counter(session: Session) -> None:
    assert session.username == "alice"
    assert session.counter == 0
    assert session.summaries() == []
    assert not session.closed


def test_close_wipes_the_dek_and_drops_the_entries(session: Session) -> None:
    add_github(session)
    dek = session._dek
    session.close()
    assert dek == bytearray(crypto.KEY_BYTES)  # zeroed in place
    assert session._entries == {}
    assert session.closed
    session.close()  # a second close is harmless
    assert session.closed


@pytest.mark.parametrize(
    "use",
    [
        lambda s: s.summaries(),
        lambda s: s.view("github"),
        lambda s: s.check_new_name("mail"),
        lambda s: add_github(s, "mail"),
        lambda s: s.update("github", username="bob"),
        lambda s: s.remove("github"),
    ],
)
def test_a_closed_session_refuses_everything(
    session: Session, use: Callable[[Session], object]
) -> None:
    add_github(session)
    before = vault_path(session).read_bytes()
    session.close()
    with pytest.raises(VaultLockedError, match="the vault is locked"):
        use(session)
    # Nothing was written, least of all a body sealed under the zeroed DEK.
    assert vault_path(session).read_bytes() == before


# --- Add, view, update, remove (UC3) -------------------------------------------------


def test_add_then_view_without_the_password(session: Session) -> None:
    add_github(session)
    view = session.view("github")
    assert (view.name, view.type, view.username, view.url, view.notes) == (
        "github", "login", "alice@example.com", "https://github.com", "personal",
    )  # fmt: skip
    assert view.created == view.modified
    assert SECRET not in repr(view)


def test_summaries_are_sorted_without_regard_to_case(session: Session) -> None:
    for name in ("mail", "Bank", "github", "a.example"):
        add_github(session, name)
    assert [s.name for s in session.summaries()] == ["a.example", "Bank", "github", "mail"]
    assert {s.type for s in session.summaries()} == {"login"}


def test_names_are_found_and_kept_unique_without_regard_to_case(session: Session) -> None:
    add_github(session, "GitHub")
    assert session.view("github").name == "GitHub"
    with pytest.raises(EntryError, match="already exists"):
        add_github(session, "GITHUB")
    with pytest.raises(EntryError, match="already exists"):
        session.check_new_name("github")


def test_an_unknown_name_is_refused(session: Session) -> None:
    for use in (session.view, session.remove, lambda name: session.update(name, url="")):
        with pytest.raises(EntryError, match="there is no entry with that name"):
            use("github")


def test_a_name_off_the_allow_list_is_refused_before_any_lookup(session: Session) -> None:
    with pytest.raises(EntryError, match="an entry name has"):
        session.view("../github")
    with pytest.raises(EntryError, match="an entry name has"):
        add_github(session, "two words")
    assert session.counter == 0  # nothing was saved


def test_update_changes_only_the_given_fields(session: Session) -> None:
    add_github(session)
    created = session.view("github").created
    session.update("github", username="bob", notes="")
    view = session.view("github")
    assert (view.username, view.url, view.notes) == ("bob", "https://github.com", "")
    assert view.created == created
    assert session._entries["github"].password == SECRET  # None kept the password


def test_update_can_change_the_password(session: Session) -> None:
    add_github(session)
    session.update("github", password="a new password")
    assert session._entries["github"].password == "a new password"


def test_update_can_rename_but_not_onto_another_entry(session: Session) -> None:
    add_github(session)
    add_github(session, "mail")
    session.update("github", new_name="GitHub")  # only the case changes
    session.update("GitHub", new_name="code")
    assert [s.name for s in session.summaries()] == ["code", "mail"]
    with pytest.raises(EntryError, match="already exists"):
        session.update("code", new_name="MAIL")
    with pytest.raises(EntryError, match="an entry name has"):
        session.update("code", new_name="two words")


def test_update_checks_every_field(session: Session) -> None:
    add_github(session)
    with pytest.raises(EntryError, match="control character"):
        session.update("github", url="\x1b]8;;evil\x07")
    with pytest.raises(EntryError, match="needs a password"):
        session.update("github", password="")
    assert session.view("github").url == "https://github.com"


def test_remove(session: Session) -> None:
    add_github(session)
    add_github(session, "mail")
    session.remove("GITHUB")
    assert [s.name for s in session.summaries()] == ["mail"]


# --- Saving (T6, T9, T10) ------------------------------------------------------------


def test_changes_persist_across_lock_and_login(accounts: Accounts, session: Session) -> None:
    add_github(session)
    add_github(session, "mail")
    add_github(session, "bank")
    session.update("github", new_name="code", password="a new password")
    session.remove("mail")
    session.close()
    again = accounts.login("alice", PASSWORD)
    assert again.counter == 5
    assert [s.name for s in again.summaries()] == ["bank", "code"]
    assert again._entries["code"].password == "a new password"
    assert again.view("code").username == "alice@example.com"


def test_every_save_counts_up_and_uses_a_fresh_nonce(session: Session) -> None:
    add_github(session)
    seen = [on_disk(session).body]
    for _ in range(2):  # the same content each time, apart from the counter
        session.update("github", notes="personal")
        seen.append(on_disk(session).body)
    assert session.counter == 3
    assert len({body.nonce for body in seen}) == 3
    assert len({body.ct for body in seen}) == 3


def test_only_the_body_changes_on_a_save(session: Session) -> None:
    before = on_disk(session)
    add_github(session)
    after = on_disk(session)
    assert dataclasses.replace(after, body=before.body) == before


def test_no_entry_text_appears_in_the_file(session: Session) -> None:
    add_github(session, "my-bank", username="jürgen-1987", notes="pin is 4321")
    data = vault_path(session).read_bytes()
    backup = vault_path(session).with_name(vault_path(session).name + ".bak").read_bytes()
    for plaintext in ("my-bank", "jürgen", "j\\u00fcrgen", "4321", SECRET, "github.com"):
        assert plaintext.encode() not in data
        assert plaintext.encode() not in backup


def test_a_failed_save_changes_nothing_in_memory(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_github(session)

    def broken(name: str, data: bytes) -> None:
        raise StorageError("a data file could not be written")

    monkeypatch.setattr(session._data_dir, "write", broken)
    with pytest.raises(StorageError):
        session.remove("github")
    with pytest.raises(StorageError):
        add_github(session, "mail")
    assert [s.name for s in session.summaries()] == ["github"]
    assert session.counter == 1


def test_a_vault_too_large_to_save_is_refused(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vaultfile, "MAX_VAULT_BYTES", 2000)
    with pytest.raises(EntryError, match="larger than 8 MiB"):
        add_github(session, notes="x" * 2000)
    assert session.summaries() == []


# --- Two sessions of one vault (T28) -------------------------------------------------


def test_a_save_by_another_session_is_not_overwritten(accounts: Accounts) -> None:
    first = accounts.login("alice", PASSWORD)
    second = accounts.login("alice", PASSWORD)
    add_github(first)
    with pytest.raises(VaultChangedError, match="changed by another session"):
        add_github(second, "mail")
    assert isinstance(VaultChangedError(), StorageError)  # shown to the user as is
    third = accounts.login("alice", PASSWORD)
    assert [s.name for s in third.summaries()] == ["github"]  # the first change survived
    add_github(first, "mail")  # the first session can go on saving


@pytest.mark.parametrize("change", ["delete", "damage", "older"])
def test_a_vault_file_changed_behind_the_session_is_not_overwritten(
    session: Session, change: str
) -> None:
    add_github(session)
    path = vault_path(session)
    if change == "delete":
        path.unlink()
    elif change == "damage":
        session._data_dir.write(path.name, b"{}")
    else:  # an older copy put back, e.g. from the backup
        session._data_dir.write(path.name, path.with_name(path.name + ".bak").read_bytes())
    with pytest.raises(VaultChangedError):
        add_github(session, "mail")
