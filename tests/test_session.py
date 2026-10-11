"""Tests for the unlocked session and its entries.

Threats T6, T9, T13, T15, T18, T19, T25, T28, T29.
"""

import dataclasses
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from yunarpass import crypto, storage, vaultfile
from yunarpass.clipboard import ClipboardGuard
from yunarpass.crypto import Sealed
from yunarpass.entries import EntryError
from yunarpass.session import Session, VaultChangedError, VaultLockedError
from yunarpass.storage import DataDir, StorageError
from yunarpass.users import Accounts, Backoff
from yunarpass.vaultfile import Body, VaultFile

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


def add_github(session: Session, name: str = "github", **changes: str) -> str:
    """Add an entry; return its full ID."""
    return session.add(name, **{**FIELDS, "password": SECRET, **changes}).id


def password_of(session: Session, entry_id: str) -> str:
    return session._entries[entry_id].password


def names(session: Session) -> list[str]:
    return [summary.name for summary in session.summaries()]


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
        lambda s, entry_id: s.summaries(),
        lambda s, entry_id: s.find("github"),
        lambda s, entry_id: s.view(entry_id),
        lambda s, entry_id: add_github(s, "mail"),
        lambda s, entry_id: s.update(entry_id, username="bob"),
        lambda s, entry_id: s.remove(entry_id),
    ],
)
def test_a_closed_session_refuses_everything(
    session: Session, use: Callable[[Session, str], object]
) -> None:
    entry_id = add_github(session)
    before = vault_path(session).read_bytes()
    session.close()
    with pytest.raises(VaultLockedError, match="the vault is locked"):
        use(session, entry_id)
    # Nothing was written, least of all a body sealed under the zeroed DEK.
    assert vault_path(session).read_bytes() == before


# --- Closing from another thread (T13, T15) ------------------------------------------


def close_on_another_thread(session: Session) -> threading.Thread:
    """Call close() from another thread, as the auto-lock timer does, and check that it waits."""
    closer = threading.Thread(target=session.close)
    closer.start()
    closer.join(timeout=0.2)
    assert closer.is_alive(), "close() did not wait for the method using the DEK"
    return closer


def test_close_waits_for_a_save_in_progress(
    accounts: Accounts, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seal_body = vaultfile.seal_body
    closers: list[threading.Thread] = []

    def seal_while_closing(header: vaultfile.Header, dek: crypto.Key, body: Body) -> Sealed:
        closers.append(close_on_another_thread(session))
        return seal_body(header, dek, body)

    monkeypatch.setattr(vaultfile, "seal_body", seal_while_closing)
    add_github(session)
    (closer,) = closers
    closer.join()
    assert session.closed
    # The body was sealed under the real DEK, not a zeroed one.
    assert names(accounts.login("alice", PASSWORD)) == ["github"]


def test_close_waits_for_a_password_change_in_progress(
    accounts: Accounts, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    rewrap_password = vaultfile.rewrap_password
    closers: list[threading.Thread] = []

    def rewrap_while_closing(vault: VaultFile, dek: crypto.Key, password: str) -> VaultFile:
        closers.append(close_on_another_thread(session))
        return rewrap_password(vault, dek, password)

    monkeypatch.setattr(vaultfile, "rewrap_password", rewrap_while_closing)
    add_github(session)
    session.change_password(PASSWORD, "a brand new passphrase")
    (closer,) = closers
    closer.join()
    assert session.closed
    assert session._dek == bytearray(crypto.KEY_BYTES)
    # The new password copy wraps the real DEK: the vault still opens.
    assert names(accounts.login("alice", "a brand new passphrase")) == ["github"]


# --- Add, find, view, update, remove (UC3, T29) --------------------------------------


def test_add_returns_the_summary_and_view_has_no_password(session: Session) -> None:
    summary = session.add("github", **FIELDS, password=SECRET)
    assert (summary.short_id, summary.name, summary.type, summary.username) == (
        summary.id[:6], "github", "login", "alice@example.com",
    )  # fmt: skip
    view = session.view(summary.id)
    assert (view.id, view.short_id, view.name, view.type) == (
        summary.id, summary.short_id, "github", "login",
    )  # fmt: skip
    assert (view.username, view.url, view.notes) == (
        "alice@example.com", "https://github.com", "personal",
    )  # fmt: skip
    assert view.created == view.modified
    assert SECRET not in repr(view) + repr(summary)


def test_summaries_are_sorted_by_name_then_from_the_oldest(session: Session) -> None:
    first = add_github(session, "github")
    for name in ("mail", "Bank", "a.example"):
        add_github(session, name)
    second = add_github(session, "GitHub")
    assert names(session) == ["a.example", "Bank", "github", "GitHub", "mail"]
    assert [s.id for s in session.summaries()][2:4] == [first, second]
    assert {s.type for s in session.summaries()} == {"login"}


def test_two_entries_may_have_the_same_name(accounts: Accounts, session: Session) -> None:
    personal = add_github(session, username="alice@personal.com")
    work = add_github(session, "GitHub", username="alice@work.com")
    assert personal != work
    session.close()
    again = accounts.login("alice", PASSWORD)  # both survive a lock and a login
    assert [(s.id, s.username) for s in again.find("github")] == [
        (personal, "alice@personal.com"),
        (work, "alice@work.com"),
    ]


def test_find_by_name_without_regard_to_case(session: Session) -> None:
    entry_id = add_github(session, "GitHub")
    add_github(session, "mail")
    for ref in ("github", "GITHUB", "GitHub"):
        assert [s.id for s in session.find(ref)] == [entry_id]
    assert session.find("gitlab") == []


def test_find_by_the_start_of_an_id(session: Session) -> None:
    entry_id = add_github(session)
    add_github(session, "mail")
    for ref in (entry_id[:6], entry_id[:7], entry_id, entry_id[:6].upper()):
        assert [s.id for s in session.find(ref)] == [entry_id]
    assert session.find(entry_id[:5]) == []  # five characters are a name, not an ID


def test_an_ambiguous_start_of_an_id_finds_every_match(session: Session) -> None:
    for name in ("a", "b", "c"):
        add_github(session, name)
    # Give two entries IDs that start alike, as random IDs now and then will.
    renamed = {}
    for entry, start in zip(
        list(session._entries.values())[:2], ("3f9c0d1", "3f9c0d2"), strict=True
    ):
        moved = dataclasses.replace(entry, id=start + entry.id[7:])
        renamed[entry.id] = moved
    session._entries = {
        renamed.get(k, e).id: renamed.get(k, e) for k, e in session._entries.items()
    }
    assert [s.name for s in session.find("3f9c0d")] == ["a", "b"]
    assert [s.short_id for s in session.find("3f9c0d")] == ["3f9c0d1", "3f9c0d2"]
    assert [s.name for s in session.find("3f9c0d2")] == ["b"]


def test_an_id_wins_over_a_name_that_looks_like_one(session: Session) -> None:
    entry_id = add_github(session)
    add_github(session, entry_id[:6])  # an entry named like the first one's ID
    assert [s.name for s in session.find(entry_id[:6])] == ["github"]


def test_find_refuses_what_is_neither_a_name_nor_an_id(session: Session) -> None:
    with pytest.raises(EntryError, match="an entry name has"):
        session.find("../github")


def test_methods_that_change_an_entry_need_its_full_id(session: Session) -> None:
    entry_id = add_github(session)
    uses: list[Callable[[str], object]] = [
        session.view,
        session.remove,
        lambda ref: session.update(ref, url=""),
    ]
    for use in uses:
        for ref in ("github", entry_id[:6], "0" * 32):
            with pytest.raises(EntryError, match="there is no entry with that ID"):
                use(ref)
    assert session.counter == 1


def test_a_name_off_the_allow_list_is_refused(session: Session) -> None:
    with pytest.raises(EntryError, match="an entry name has"):
        add_github(session, "two words")
    assert session.counter == 0  # nothing was saved


def test_update_changes_only_the_given_fields(session: Session) -> None:
    entry_id = add_github(session)
    created = session.view(entry_id).created
    session.update(entry_id, username="bob", notes="")
    view = session.view(entry_id)
    assert (view.username, view.url, view.notes) == ("bob", "https://github.com", "")
    assert view.created == created
    assert password_of(session, entry_id) == SECRET  # None kept the password


def test_update_can_change_the_password(session: Session) -> None:
    entry_id = add_github(session)
    session.update(entry_id, password="a new password")
    assert password_of(session, entry_id) == "a new password"


def test_update_can_rename_also_onto_a_name_in_use(session: Session) -> None:
    entry_id = add_github(session)
    add_github(session, "mail")
    session.update(entry_id, name="MAIL")
    assert names(session) == ["MAIL", "mail"]  # the renamed one is older
    assert session.view(entry_id).name == "MAIL"
    with pytest.raises(EntryError, match="an entry name has"):
        session.update(entry_id, name="two words")


def test_update_checks_every_field(session: Session) -> None:
    entry_id = add_github(session)
    with pytest.raises(EntryError, match="control character"):
        session.update(entry_id, url="\x1b]8;;evil\x07")
    with pytest.raises(EntryError, match="needs a password"):
        session.update(entry_id, password="")
    assert session.view(entry_id).url == "https://github.com"


def test_remove_deletes_only_that_entry(session: Session) -> None:
    personal = add_github(session)
    work = add_github(session)
    session.remove(work)
    assert [s.id for s in session.summaries()] == [personal]


# --- Saving (T6, T9, T10) ------------------------------------------------------------


def test_changes_persist_across_lock_and_login(accounts: Accounts, session: Session) -> None:
    github = add_github(session)
    mail = add_github(session, "mail")
    add_github(session, "bank")
    session.update(github, name="code", password="a new password")
    session.remove(mail)
    session.close()
    again = accounts.login("alice", PASSWORD)
    assert again.counter == 5
    assert names(again) == ["bank", "code"]
    assert password_of(again, github) == "a new password"
    assert again.view(github).username == "alice@example.com"


def test_every_save_counts_up_and_uses_a_fresh_nonce(session: Session) -> None:
    entry_id = add_github(session)
    seen = [on_disk(session).body]
    for _ in range(2):  # the same content each time, apart from the counter
        session.update(entry_id, notes="personal")
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
    entry_id = add_github(session, "my-bank", username="jürgen-1987", notes="pin is 4321")
    data = vault_path(session).read_bytes()
    backup = vault_path(session).with_name(vault_path(session).name + ".bak").read_bytes()
    for plaintext in (
        "my-bank",
        "jürgen",
        "j\\u00fcrgen",
        "pin is 4321",
        SECRET,
        "github.com",
        entry_id,
    ):
        assert plaintext.encode() not in data
        assert plaintext.encode() not in backup


def test_a_failed_save_changes_nothing_in_memory(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry_id = add_github(session)

    def broken(name: str, data: bytes) -> None:
        raise StorageError("a data file could not be written")

    monkeypatch.setattr(session._data_dir, "write", broken)
    with pytest.raises(StorageError):
        session.remove(entry_id)
    with pytest.raises(StorageError):
        add_github(session, "mail")
    assert names(session) == ["github"]
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
    assert names(third) == ["github"]  # the first change survived
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


# --- Copying a password (T18, T25) ---------------------------------------------------


class MemoryClipboard:
    """A clipboard backend in memory."""

    def __init__(self) -> None:
        self.text: str | None = None

    def read(self) -> str | None:
        return self.text

    def write(self, text: str) -> None:
        self.text = text

    def clear(self) -> None:
        self.text = None


def guard(backend: MemoryClipboard) -> ClipboardGuard:
    return ClipboardGuard(backend, lambda seconds, callback: lambda: None)


def test_copy_password_copies_the_password_of_that_entry_only(session: Session) -> None:
    add_github(session, password="the personal one")
    work = add_github(session)
    backend = MemoryClipboard()
    session.copy_password(work, guard(backend))
    assert backend.text == SECRET


def test_copy_password_refuses_an_unknown_entry_or_a_closed_session(session: Session) -> None:
    backend = MemoryClipboard()
    with pytest.raises(EntryError, match="no entry"):
        session.copy_password("0" * 32, guard(backend))
    entry_id = add_github(session)
    session.close()
    with pytest.raises(VaultLockedError):
        session.copy_password(entry_id, guard(backend))
    assert backend.text is None
