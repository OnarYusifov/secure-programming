"""An unlocked vault (UC2): the DEK and the decrypted body, held until close().

The DEK lives in a bytearray that close() overwrites with zeros (T13, best
effort: the decrypted entries are ordinary Python objects and cannot be wiped,
only dropped).
"""

from yunarpass import crypto
from yunarpass.vaultfile import Body, VaultFile


class Session:
    """The state of a logged-in user. Created by Accounts.login()."""

    def __init__(self, vault: VaultFile, dek: bytearray, body: Body) -> None:
        self.vault = vault
        self._dek = dek
        self.body = body
        self.closed = False

    @property
    def username(self) -> str:
        return self.vault.header.username

    @property
    def counter(self) -> int:
        """How many times the vault has been saved; shown after login (T9)."""
        return self.body.counter

    def close(self) -> None:
        """Wipe the DEK and drop the entries. Calling it again does nothing."""
        crypto.wipe(self._dek)
        self.body = Body()
        self.closed = True
