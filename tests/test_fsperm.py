"""Tests for owner-only files and directories (threats T11, T12).

The POSIX and Windows tests are defined only on their own OS; CI runs both.
"""

import os
import stat
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from yunarpass import fsperm


@pytest.fixture
def private_dir(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    fsperm.make_private_dir(path)
    return path


# --- Both operating systems ---------------------------------------------------


def test_new_file_is_written_in_binary_mode(private_dir: Path) -> None:
    path = private_dir / "file"
    fd = fsperm.create_private_file(path)
    try:
        os.write(fd, b"line\r\nbinary\x1a")
    finally:
        os.close(fd)
    assert path.read_bytes() == b"line\r\nbinary\x1a"  # binary mode: nothing translated


def test_create_private_file_refuses_an_existing_name(private_dir: Path) -> None:
    path = private_dir / "file"
    path.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        fsperm.create_private_file(path)
    assert path.read_bytes() == b"original"


def test_make_private_dir_refuses_an_existing_name(private_dir: Path) -> None:
    with pytest.raises(FileExistsError):
        fsperm.make_private_dir(private_dir)


def test_make_private_dir_needs_the_parent(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError) as caught:
        fsperm.make_private_dir(tmp_path / "missing" / "data")
    if sys.platform == "win32":
        assert caught.value.filename is None  # translated from pywin32 without the path


# --- POSIX ------------------------------------------------------------------

if sys.platform != "win32":

    @pytest.fixture
    def umask_022() -> Iterator[None]:
        """The usual umask, so tests see the modes the code asks for."""
        old = os.umask(0o022)
        try:
            yield
        finally:
            os.umask(old)

    def test_posix_new_directory_is_0700(tmp_path: Path, umask_022: None) -> None:
        path = tmp_path / "data"
        fsperm.make_private_dir(path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o700

    def test_posix_new_file_is_0600(private_dir: Path, umask_022: None) -> None:
        path = private_dir / "file"
        os.close(fsperm.create_private_file(path))
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_posix_create_does_not_follow_a_symlink(private_dir: Path, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere"
        link = private_dir / "file"
        link.symlink_to(target)  # dangling: following it would create the target
        with pytest.raises(FileExistsError):
            fsperm.create_private_file(link)
        assert not target.exists()

# --- Windows ----------------------------------------------------------------

if sys.platform == "win32":
    import ntsecuritycon
    import win32security

    EVERYONE = win32security.ConvertStringSidToSid("S-1-1-0")
    OWNER_AND_DACL = (
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    )

    def read_acl(path: Path) -> tuple[str, int, list[tuple[int, int, int, str]]]:
        """Owner SID, control flags, and (type, flags, mask, SID) for every ACE."""
        descriptor = win32security.GetNamedSecurityInfo(
            str(path), win32security.SE_FILE_OBJECT, OWNER_AND_DACL
        )
        owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        control = descriptor.GetSecurityDescriptorControl()[0]
        dacl = descriptor.GetSecurityDescriptorDacl()
        aces = []
        for index in range(dacl.GetAceCount()):
            (ace_type, ace_flags), mask, sid = dacl.GetAce(index)
            aces.append((ace_type, ace_flags, mask, win32security.ConvertSidToStringSid(sid)))
        return owner, control, aces

    def current_user_sid() -> str:
        return win32security.ConvertSidToStringSid(fsperm._user_sid())

    @pytest.mark.parametrize("directory", [True, False])
    def test_windows_acl_is_protected_with_one_entry_for_the_user(
        private_dir: Path, directory: bool
    ) -> None:
        path = private_dir
        if not directory:
            path = private_dir / "file"
            os.close(fsperm.create_private_file(path))
        owner, control, aces = read_acl(path)
        user = current_user_sid()
        inherit = (
            ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE
            if directory
            else 0
        )
        assert owner == user
        assert control & win32security.SE_DACL_PROTECTED  # nothing inherited from the parent
        assert aces == [
            (ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE, inherit, ntsecuritycon.FILE_ALL_ACCESS, user)
        ]
