"""Storage layer: the only code that reads or writes the data directory.

- The directory is $YUNARPASS_HOME (an absolute path) or ~/.yunarpass. It never
  comes from a command-line argument.
- File names come from a fixed allow-list, so no path is ever built from user
  input (T11).
- A read refuses links, hard links, files that are not private to this user and
  oversized files, and checks that the file it opened is the file it checked:
  lstat, then open, then fstat, then compare (T11, the TOCTOU pattern).

Errors are StorageError or its subclass UnsafeFileError. Their messages are
fixed and contain no path (T17).
"""

import errno
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

from yunarpass import fsperm
from yunarpass.fsperm import StorageError as StorageError
from yunarpass.fsperm import UnsafeFileError as UnsafeFileError

HOME_ENV = "YUNARPASS_HOME"
DEFAULT_DIR_NAME = ".yunarpass"
USERS_FILE = "users.json"

# Far above any real vault, which is a few hundred KiB even with thousands of
# entries. It stops a planted multi-gigabyte file from exhausting memory.
MAX_FILE_BYTES = 8 * 1024 * 1024

_VAULT_ID = re.compile(r"[0-9a-f]{32}")
# The allow-list: users.json, vault-<32 hex>.json, and a backup of either.
_FILE_NAME = re.compile(r"(?:users|vault-[0-9a-f]{32})\.json(\.bak)?")
_CHUNK_BYTES = 64 * 1024

if sys.platform == "win32":
    # Binary: in text mode the C runtime would translate line ends and stop
    # reading at the first Ctrl-Z byte.
    _READ_FLAGS = os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT
else:
    _READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def vault_file_name(vault_id: str) -> str:
    """The file name of a vault: vault-<32 lowercase hex>.json."""
    if not isinstance(vault_id, str) or not _VAULT_ID.fullmatch(vault_id):
        raise ValueError("not a vault ID")
    return f"vault-{vault_id}.json"


def data_dir_path(environ: Mapping[str, str] | None = None) -> Path:
    """Where the data lives: $YUNARPASS_HOME if it is set and not empty, else ~/.yunarpass."""
    value = (os.environ if environ is None else environ).get(HOME_ENV, "")
    if not value:  # unset or empty both mean the default, as with the XDG variables
        try:
            return Path.home() / DEFAULT_DIR_NAME
        except RuntimeError:
            raise StorageError("the home directory could not be determined") from None
    path = Path(value)
    # Allow-list, not repair: a relative path would depend on the current
    # directory, and ".." is never needed to name a directory.
    if "\0" in value or not path.is_absolute() or ".." in path.parts:
        raise StorageError(f"{HOME_ENV} must be an absolute path without '..'")
    return path


def _is_reparse_point(st: os.stat_result) -> bool:
    if sys.platform == "win32":
        # Symlinks, junctions and other redirections on Windows.
        return bool(st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return False


def _read_at_most(fd: int, limit: int) -> bytes:
    chunks = []
    size = 0
    while chunk := os.read(fd, _CHUNK_BYTES):
        size += len(chunk)
        if size > limit:  # the file grew after it was checked
            raise StorageError("a data file is too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _read_private(path: Path) -> bytes | None:
    """Read a regular, private, single-link file, or return None if it does not exist."""
    try:
        before = os.lstat(path)  # lstat: a link is seen as a link, not followed
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or _is_reparse_point(before):
        raise UnsafeFileError("a data file is a link or not a regular file")
    try:
        fd = os.open(path, _READ_FLAGS)
    except OSError as error:
        if error.errno == errno.ELOOP:  # O_NOFOLLOW: it became a symlink after the lstat
            raise UnsafeFileError("a data file is a link or not a regular file") from None
        raise
    try:
        after = os.fstat(fd)
        # The file that was opened must be the file that was checked. If it was
        # swapped in between (a TOCTOU race), the device or inode differs.
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise UnsafeFileError("a data file was replaced while it was being opened")
        if after.st_nlink != 1:
            raise UnsafeFileError("a data file has a second name (a hard link)")
        fsperm.check_private_fd(fd)
        if after.st_size > MAX_FILE_BYTES:
            raise StorageError("a data file is too large")
        return _read_at_most(fd, MAX_FILE_BYTES)
    finally:
        os.close(fd)


class DataDir:
    """The data directory, after it has been created or checked. Use DataDir.open()."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @classmethod
    def open(cls, path: Path | None = None) -> "DataDir":
        """Create the data directory owner-only, or check the existing one.

        Raises UnsafeFileError if the directory is a link, belongs to another
        user or gives anyone else access.
        """
        path = data_dir_path() if path is None else path
        try:
            fsperm.ensure_data_dir(path)
        except OSError:
            raise StorageError("the data directory could not be created or opened") from None
        return cls(path)

    def _file(self, name: str, *, backup_allowed: bool) -> Path:
        match = _FILE_NAME.fullmatch(name) if isinstance(name, str) else None
        if match is None or (match.group(1) and not backup_allowed):
            raise ValueError("not an allowed data file name")
        return self.path / name

    def read(self, name: str) -> bytes | None:
        """Return the content of a data file or its .bak, or None if it does not exist."""
        path = self._file(name, backup_allowed=True)
        try:
            return _read_private(path)
        except OSError:
            raise StorageError("a data file could not be read") from None
