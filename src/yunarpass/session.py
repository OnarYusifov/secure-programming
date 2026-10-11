"""An unlocked vault (UC2, UC3, UC7, UC8): the DEK and the entries, held until close().

The DEK lives in a bytearray that close() overwrites with zeros (T13, best
effort: the decrypted entries are ordinary Python objects and cannot be wiped,
only dropped).

Every change is saved at once. The body gets counter + 1 and is encrypted
under a fresh nonce, and the vault file is replaced atomically (T6, T9, T10).
The entries in memory change only after the save succeeded, so a failed save
leaves the session as it was.

Entries are addressed by their ID, which is unique in the vault; names may
repeat. find() turns what a user typed, a name or the start of an ID, into the
entries it matches, and the user interface decides what to do with several.

Before writing, the vault file is read again and must still be the version
this session loaded or last saved. If another session of the same account
saved in between (a second prompt, or the CLI and the GUI open together), the
save is refused rather than overwriting that change (T28).

close() may be called from another thread, such as the CLI's auto-lock timer
(T15). Every method that uses the DEK or the entries holds the session's
lock, and so does close(), which therefore waits for a save or a password
change in progress. Zeroing the DEK in the middle of one would seal the body
or wrap the DEK under a key of zeros, and lose the vault for good.
"""

import contextlib
import dataclasses
import threading
from collections.abc import Iterable, Iterator

from yunarpass import crypto, entries, policy, secrets_gen, vaultfile
from yunarpass.clipboard import ClipboardGuard
from yunarpass.entries import EntryError, EntrySummary, EntryView, LoginEntry
from yunarpass.storage import DataDir, StorageError, vault_file_name
from yunarpass.vaultfile import Body, VaultFile, VaultFormatError


class VaultLockedError(Exception):
    """The session was closed. The message is safe to show."""

    def __init__(self) -> None:
        super().__init__("the vault is locked")


class VaultChangedError(StorageError):
    """The vault file is no longer the version this session loaded."""

    def __init__(self) -> None:
        super().__init__(
            "the vault file was changed by another session since you logged in, "
            "so this change was not saved; log in again to continue"
        )


class Session:
    """The state of a logged-in user. Created by Accounts.login()."""

    def __init__(self, vault: VaultFile, dek: bytearray, body: Body, data_dir: DataDir) -> None:
        """Raises VaultFormatError if an entry in the body is malformed."""
        self.vault = vault
        self._dek = dek
        self._data_dir = data_dir
        self._entries = _load(body)
        self._counter = body.counter
        self._lock = threading.Lock()
        self.closed = False

    @property
    def username(self) -> str:
        return self.vault.header.username

    @property
    def counter(self) -> int:
        """How many times the vault has been saved; shown after login (T9)."""
        return self._counter

    def close(self) -> None:
        """Wipe the DEK and drop the entries. Calling it again does nothing.

        Safe to call from any thread: it waits until a method that is using
        the DEK has finished.
        """
        with self._lock:
            crypto.wipe(self._dek)
            self._entries = {}
            self.closed = True

    # --- Reading ---------------------------------------------------------------------

    def summaries(self) -> list[EntrySummary]:
        """Every entry's ID, name, type and username (never the password).

        Sorted by name without regard to case, then from the oldest entry.
        """
        with self._open():
            return self._summarise(self._entries.values())

    def find(self, ref: str) -> list[EntrySummary]:
        """The entries a user means by a name or an ID, sorted like summaries().

        6 to 32 hex characters that start at least one entry's ID mean those
        entries, in any case. Anything else is a name, compared without
        regard to case. An empty list means nothing matches; more than one
        entry means the user has to choose. Raises EntryError if ref is
        neither a name nor an ID.
        """
        with self._open():
            entries.check_name(ref)  # hex digits are letters and digits: an ID passes too
            if entries.ID_PREFIX.fullmatch(ref):
                start = ref.lower()
                by_id = [entry for entry in self._entries.values() if entry.id.startswith(start)]
                if by_id:
                    return self._summarise(by_id)
            name = entries.key(ref)
            return self._summarise(e for e in self._entries.values() if entries.key(e.name) == name)

    def view(self, entry_id: str) -> EntryView:
        """Every field of an entry except the password (T25)."""
        with self._open():
            entry = self._get(entry_id)
            return entry.view(self._short_ids()[entry.id])

    def copy_password(self, entry_id: str, clipboard: ClipboardGuard) -> None:
        """Put an entry's password on the clipboard, which clears it again (T18).

        The password goes from the entry to the clipboard and never to a user
        interface (T25).
        """
        with self._open():
            clipboard.copy(self._get(entry_id).password)

    # --- Changing (each one saves) ---------------------------------------------------

    def add(self, name: str, *, username: str, password: str, url: str, notes: str) -> EntrySummary:
        """Add a login entry with a new random ID, and save. Returns its summary."""
        with self._open():
            entry = entries.new_login(
                name, username=username, password=password, url=url, notes=notes
            )
            self._save({**self._entries, entry.id: entry})
            return entry.summary(self._short_ids()[entry.id])

    def update(
        self,
        entry_id: str,
        *,
        name: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
    ) -> None:
        """Change the fields that are not None, and save.

        The interface never holds the stored password, so this takes changes
        rather than a whole entry: a password of None keeps the stored one.
        """
        with self._open():
            old = self._get(entry_id)
            new = dataclasses.replace(
                old,
                name=old.name if name is None else name,
                username=old.username if username is None else username,
                password=old.password if password is None else password,
                url=old.url if url is None else url,
                notes=old.notes if notes is None else notes,
                modified=entries.timestamp(),
            )  # every field is checked again
            self._save({k: (new if k == old.id else entry) for k, entry in self._entries.items()})

    def remove(self, entry_id: str) -> None:
        """Delete an entry and save."""
        with self._open():
            old = self._get(entry_id)
            self._save({k: entry for k, entry in self._entries.items() if k != old.id})

    def change_password(self, current: str, new: str) -> None:
        """Wrap the DEK under a new master password, and save (UC7).

        The current password must unwrap the DEK first, or CryptoError is
        raised and nothing changes. Only the password copy of the DEK is
        replaced; the entries are not encrypted again, and the recovery key
        keeps working. Accounts.change_password adds the delay after a wrong
        current password; user interfaces call that one.
        """
        with self._open():
            policy.check_master_password(new)
            crypto.wipe(vaultfile.unlock_with_password(self.vault, current))
            self._write(vaultfile.rewrap_password(self.vault, self._dek, new))

    def recover(self, recovery_key: bytes, new_password: str) -> str:
        """Replace the master password and the recovery key, and save (UC8).

        The recovery key must unwrap the DEK first, or CryptoError is raised
        and nothing changes. Then both copies of the DEK are wrapped again:
        one under the new password, one under a new random recovery key, so
        the old password and the old key no longer open the vault (T5). The
        entries are not encrypted again. Returns the new recovery key,
        formatted for writing down. Accounts.recover adds the delay after a
        wrong key; user interfaces call that one.
        """
        with self._open():
            policy.check_master_password(new_password)
            crypto.wipe(vaultfile.unlock_with_recovery_key(self.vault, recovery_key))
            new_key = secrets_gen.new_recovery_key()
            vault = vaultfile.rewrap_recovery(self.vault, self._dek, new_key)
            self._write(vaultfile.rewrap_password(vault, self._dek, new_password))
            return secrets_gen.format_recovery_key(new_key)

    # --- Inside ----------------------------------------------------------------------

    @contextlib.contextmanager
    def _open(self) -> Iterator[None]:
        """Hold the session's lock while the session is open; raise VaultLockedError if not.

        The methods below expect the caller to hold it.
        """
        with self._lock:
            if self.closed:
                raise VaultLockedError
            yield

    def _get(self, entry_id: str) -> LoginEntry:
        """The entry with exactly this (full) ID."""
        entry = self._entries.get(entry_id) if isinstance(entry_id, str) else None
        if entry is None:
            raise EntryError("there is no entry with that ID")
        return entry

    def _short_ids(self) -> dict[str, str]:
        return entries.short_ids(self._entries)

    def _summarise(self, chosen: Iterable[LoginEntry]) -> list[EntrySummary]:
        short = self._short_ids()
        # sorted() is stable: entries with the same name and creation second
        # stay in their saved order, which is the order they were added in.
        ordered = sorted(chosen, key=lambda e: (entries.key(e.name), e.created))
        return [entry.summary(short[entry.id]) for entry in ordered]

    def _save(self, new_entries: dict[str, LoginEntry]) -> None:
        """Encrypt the entries as the next version of the body and write the vault."""
        body = Body(self._counter + 1, tuple(entry.to_json() for entry in new_entries.values()))
        sealed = vaultfile.seal_body(self.vault.header, self._dek, body)
        self._write(dataclasses.replace(self.vault, body=sealed))
        self._entries = new_entries
        self._counter = body.counter

    def _write(self, vault: VaultFile) -> None:
        """Replace the vault file, unless it changed since this session last saw it (T28)."""
        name = vault_file_name(self.vault.header.vault_id)
        if self._on_disk(name) != self.vault:
            raise VaultChangedError
        try:
            data = vaultfile.serialize(vault)
        except VaultFormatError:
            raise EntryError(
                "the vault would be larger than 8 MiB, so the change was not saved"
            ) from None
        self._data_dir.write(name, data)
        self.vault = vault

    def _on_disk(self, name: str) -> VaultFile | None:
        data = self._data_dir.read(name)
        if data is None:
            return None
        try:
            return vaultfile.parse(data)
        except VaultFormatError:
            return None


def _load(body: Body) -> dict[str, LoginEntry]:
    """The body's entries by ID, in their saved order. Raises VaultFormatError.

    Two entries may have the same name, never the same ID.
    """
    loaded: dict[str, LoginEntry] = {}
    for doc in body.entries:
        entry = entries.from_json(doc)
        if entry.id in loaded:
            raise VaultFormatError("entries: two entries have the same ID")
        loaded[entry.id] = entry
    return loaded
