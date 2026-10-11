"""An unlocked vault (UC2, UC3): the DEK and the entries, held until close().

The DEK lives in a bytearray that close() overwrites with zeros (T13, best
effort: the decrypted entries are ordinary Python objects and cannot be wiped,
only dropped).

Every change is saved at once. The body gets counter + 1 and is encrypted
under a fresh nonce, and the vault file is replaced atomically (T6, T9, T10).
The entries in memory change only after the save succeeded, so a failed save
leaves the session as it was.

Before writing, the vault file is read again and must still be the version
this session loaded or last saved. If another session of the same account
saved in between (a second prompt, or the CLI and the GUI open together), the
save is refused rather than overwriting that change (T28).
"""

import dataclasses

from yunarpass import crypto, entries, policy, vaultfile
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
        self.closed = False

    @property
    def username(self) -> str:
        return self.vault.header.username

    @property
    def counter(self) -> int:
        """How many times the vault has been saved; shown after login (T9)."""
        return self._counter

    def close(self) -> None:
        """Wipe the DEK and drop the entries. Calling it again does nothing."""
        crypto.wipe(self._dek)
        self._entries = {}
        self.closed = True

    # --- Reading ---------------------------------------------------------------------

    def summaries(self) -> list[EntrySummary]:
        """Every entry's name and type, sorted by name without regard to case."""
        self._check_open()
        short = self._short_ids()
        return [self._entries[k].summary(short[self._entries[k].id]) for k in sorted(self._entries)]

    def view(self, name: str) -> EntryView:
        """Every field of an entry except the password (T25)."""
        entry = self._find(name)
        return entry.view(self._short_ids()[entry.id])

    def copy_password(self, name: str, clipboard: ClipboardGuard) -> None:
        """Put an entry's password on the clipboard, which clears it again (T18).

        The password goes from the entry to the clipboard and never to a user
        interface (T25).
        """
        clipboard.copy(self._find(name).password)

    def check_new_name(self, name: str) -> None:
        """Raise EntryError unless the name is allowed and no entry has it yet."""
        self._check_open()
        if entries.key(entries.check_name(name)) in self._entries:
            raise EntryError("an entry with that name already exists")

    # --- Changing (each one saves) ---------------------------------------------------

    def add(self, name: str, *, username: str, password: str, url: str, notes: str) -> None:
        """Add a login entry and save."""
        self.check_new_name(name)
        entry = entries.new_login(name, username=username, password=password, url=url, notes=notes)
        self._save({**self._entries, entries.key(name): entry})

    def update(
        self,
        name: str,
        *,
        new_name: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
    ) -> None:
        """Change the fields that are not None, and save.

        The interface never holds the stored password, so this takes changes
        rather than a whole entry: a password of None keeps the stored one.
        """
        old = self._find(name)
        if new_name is not None and entries.key(new_name) != entries.key(old.name):
            self.check_new_name(new_name)
        new = dataclasses.replace(
            old,
            name=old.name if new_name is None else new_name,
            username=old.username if username is None else username,
            password=old.password if password is None else password,
            url=old.url if url is None else url,
            notes=old.notes if notes is None else notes,
            modified=entries.timestamp(),
        )  # every field is checked again
        old_key = entries.key(old.name)
        self._save(
            {
                (entries.key(new.name) if k == old_key else k): (new if k == old_key else entry)
                for k, entry in self._entries.items()
            }
        )

    def remove(self, name: str) -> None:
        """Delete an entry and save."""
        old_key = entries.key(self._find(name).name)
        self._save({k: entry for k, entry in self._entries.items() if k != old_key})

    def change_password(self, current: str, new: str) -> None:
        """Wrap the DEK under a new master password, and save (UC7).

        The current password must unwrap the DEK first, or CryptoError is
        raised and nothing changes. Only the password copy of the DEK is
        replaced; the entries are not encrypted again, and the recovery key
        keeps working. Accounts.change_password adds the delay after a wrong
        current password; user interfaces call that one.
        """
        self._check_open()
        policy.check_master_password(new)
        crypto.wipe(vaultfile.unlock_with_password(self.vault, current))
        self._write(vaultfile.rewrap_password(self.vault, self._dek, new))

    # --- Inside ----------------------------------------------------------------------

    def _check_open(self) -> None:
        if self.closed:
            raise VaultLockedError

    def _short_ids(self) -> dict[str, str]:
        return entries.short_ids(entry.id for entry in self._entries.values())

    def _find(self, name: str) -> LoginEntry:
        self._check_open()
        entry = self._entries.get(entries.key(entries.check_name(name)))
        if entry is None:
            raise EntryError("there is no entry with that name")
        return entry

    def _save(self, new_entries: dict[str, LoginEntry]) -> None:
        """Encrypt the entries as the next version of the body and write the vault."""
        self._check_open()
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
    """The body's entries by name, in their saved order. Raises VaultFormatError."""
    loaded: dict[str, LoginEntry] = {}
    for doc in body.entries:
        entry = entries.from_json(doc)
        if entries.key(entry.name) in loaded:
            raise VaultFormatError("entries: two entries have the same name")
        loaded[entries.key(entry.name)] = entry
    return loaded
