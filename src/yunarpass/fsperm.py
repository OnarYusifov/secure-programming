"""Owner-only files and directories (T11, T12).

The data directory and every file in it are private to the current OS user from
the moment they exist, and are checked again whenever they are opened:

- POSIX: the directory has mode 0700 and files 0600, owned by the effective user.
- Windows: the owner is the current user's SID, and the DACL is protected (it
  inherits nothing from the parent folder) and holds a single full-control entry,
  for that SID. The security descriptor is passed to CreateDirectory and
  CreateFile, so the ACL exists from the first moment. There is no window in
  which another user could open the file and keep the handle: Windows checks
  access when a file is opened, not on every later read.

Every refusal raises UnsafeFileError. Messages never contain a path (T17).
"""

import contextlib
import errno
import os
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING

DIR_MODE = 0o700
FILE_MODE = 0o600


class StorageError(Exception):
    """The data directory or a data file could not be used safely.

    Base class of the storage layer's errors. Messages are fixed strings that
    are safe to show to the user.
    """


class UnsafeFileError(StorageError):
    """A file or directory is a link, belongs to another user or is shared with one."""


if sys.platform == "win32":
    import functools
    import msvcrt

    import ntsecuritycon
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32security

    if TYPE_CHECKING:
        from _win32typing import PySECURITY_ATTRIBUTES, PySECURITY_DESCRIPTOR, PySID

    _OWNER_AND_DACL = (
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    )

    def _os_error(error: pywintypes.error) -> OSError:
        # OSError picks the subclass (FileExistsError, PermissionError, ...)
        # from the Windows error code. No file name, so no path in the message.
        return OSError(0, error.strerror, None, error.winerror)

    @functools.cache
    def _user_sid() -> "PySID":
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            sid, _attributes = win32security.GetTokenInformation(token, win32security.TokenUser)
        finally:
            win32api.CloseHandle(token)
        return sid  # type: ignore[no-any-return]

    def _private_attributes(*, directory: bool) -> "PySECURITY_ATTRIBUTES":
        """Security attributes granting full control to the current user and nobody else."""
        sid = _user_sid()
        # On the directory the entry is inherited by new children, so even a
        # file created in it by some other means starts out private.
        inherit = (
            ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE
            if directory
            else 0
        )
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION, inherit, ntsecuritycon.FILE_ALL_ACCESS, sid
        )
        descriptor = win32security.SECURITY_DESCRIPTOR()
        # Set explicitly: an elevated process would otherwise make the
        # Administrators group the owner.
        descriptor.SetSecurityDescriptorOwner(sid, False)
        descriptor.SetSecurityDescriptorDacl(True, dacl, False)
        # Protected: nothing is inherited from the parent folder's ACL.
        descriptor.SetSecurityDescriptorControl(
            win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED
        )
        attributes = win32security.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = descriptor
        attributes.bInheritHandle = False
        return attributes

    def _check_descriptor(descriptor: "PySECURITY_DESCRIPTOR", what: str) -> None:
        sid = _user_sid()
        if descriptor.GetSecurityDescriptorOwner() != sid:
            raise UnsafeFileError(f"the {what} is owned by another user")
        dacl = descriptor.GetSecurityDescriptorDacl()
        if dacl is None:  # a NULL DACL grants everyone full access
            raise UnsafeFileError(f"the {what} has permissions for other users")
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            ace_type = ace[0][0]
            # Only allow-entries for this user. Anything else, even a deny
            # entry, means someone changed the ACL we created.
            if ace_type != ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE or ace[2] != sid:
                raise UnsafeFileError(f"the {what} has permissions for other users")

else:

    def _check_posix_stat(st: os.stat_result, what: str) -> None:
        if st.st_uid != os.geteuid():
            raise UnsafeFileError(f"the {what} is owned by another user")
        if stat.S_IMODE(st.st_mode) & 0o077:  # any bit for group or others
            raise UnsafeFileError(f"the {what} has permissions for other users")


def make_private_dir(path: Path) -> None:
    """Create a directory that only the current user can access.

    Raises FileExistsError if the name already exists, whatever it is.
    """
    if sys.platform == "win32":
        try:
            win32file.CreateDirectory(str(path), _private_attributes(directory=True))
        except pywintypes.error as error:
            raise _os_error(error) from None
    else:
        path.mkdir(mode=DIR_MODE)  # the umask can only remove bits, never add any


def create_private_file(path: Path) -> int:
    """Create a new, empty file that only the current user can access.

    Returns a file descriptor open for writing in binary mode; the caller closes
    it. Raises FileExistsError if the name already exists, even as a link, so an
    existing file or link is never followed or reused.
    """
    if sys.platform == "win32":
        try:
            handle = win32file.CreateFile(
                str(path),
                win32con.GENERIC_WRITE,
                0,  # not shared: nobody else can open the file while it is written
                _private_attributes(directory=False),
                win32con.CREATE_NEW,
                win32con.FILE_ATTRIBUTE_NORMAL,
                None,
            )
        except pywintypes.error as error:
            raise _os_error(error) from None
        raw = int(handle.Detach())  # from here on, closing it is up to us
        try:
            return msvcrt.open_osfhandle(raw, 0)  # flags 0: binary, not read-only
        except BaseException:
            win32api.CloseHandle(raw)
            raise
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        return os.open(path, flags, FILE_MODE)


def check_private_fd(fd: int) -> None:
    """Raise UnsafeFileError unless the open file belongs to, and is private to, this user.

    It checks the file that is open, not a name, so the file cannot be swapped
    between the check and its use.
    """
    if sys.platform == "win32":
        try:
            descriptor = win32security.GetSecurityInfo(
                msvcrt.get_osfhandle(fd), win32security.SE_FILE_OBJECT, _OWNER_AND_DACL
            )
        except pywintypes.error as error:
            raise _os_error(error) from None
        _check_descriptor(descriptor, "data file")
    else:
        _check_posix_stat(os.fstat(fd), "data file")


def check_private_dir(path: Path) -> None:
    """Raise UnsafeFileError unless path is a real directory private to this user.

    A symlink or a junction in place of the directory is refused, not followed.
    """
    link_or_file = "the data directory is a link or not a directory"
    if sys.platform == "win32":
        try:
            handle = win32file.CreateFile(
                str(path),
                win32con.READ_CONTROL | ntsecuritycon.FILE_READ_ATTRIBUTES,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                # Open a directory, and open a link or junction itself, not its target.
                win32file.FILE_FLAG_BACKUP_SEMANTICS | win32file.FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        except pywintypes.error as error:
            raise _os_error(error) from None
        try:
            attributes = win32file.GetFileInformationByHandle(handle.handle)[0]
            if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT or not (
                attributes & stat.FILE_ATTRIBUTE_DIRECTORY
            ):
                raise UnsafeFileError(link_or_file)
            descriptor = win32security.GetSecurityInfo(
                handle.handle, win32security.SE_FILE_OBJECT, _OWNER_AND_DACL
            )
        except pywintypes.error as error:
            raise _os_error(error) from None
        finally:
            handle.Close()
        _check_descriptor(descriptor, "data directory")
    else:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                raise UnsafeFileError(link_or_file) from None
            raise
        try:
            st = os.fstat(fd)
        finally:
            os.close(fd)
        _check_posix_stat(st, "data directory")


def ensure_data_dir(path: Path) -> None:
    """Create the data directory owner-only, or check the one that exists.

    A directory that fails the check is refused, not repaired: whoever loosened
    it may already have read or replaced the files inside. The parent directory
    must exist.
    """
    with contextlib.suppress(FileExistsError):
        make_private_dir(path)
    check_private_dir(path)
