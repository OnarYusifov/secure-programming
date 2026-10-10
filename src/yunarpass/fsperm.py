"""Owner-only files and directories (T11, T12).

The data directory and every file in it are private to the current OS user from
the moment they exist:

- POSIX: the directory has mode 0700 and files 0600, owned by the effective user.
- Windows: the owner is the current user's SID, and the DACL is protected (it
  inherits nothing from the parent folder) and holds a single full-control entry,
  for that SID. The security descriptor is passed to CreateDirectory and
  CreateFile, so the ACL exists from the first moment. There is no window in
  which another user could open the file and keep the handle: Windows checks
  access when a file is opened, not on every later read.

Errors name no path (T17).
"""

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

DIR_MODE = 0o700
FILE_MODE = 0o600


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
        from _win32typing import PySECURITY_ATTRIBUTES, PySID

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
