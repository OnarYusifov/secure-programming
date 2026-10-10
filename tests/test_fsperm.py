"""Tests for owner-only files and directories (threats T11, T12).

The POSIX and Windows tests are defined only on their own OS; CI runs both.
"""

import os
import stat
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from yunarpass import fsperm
from yunarpass.fsperm import UnsafeFileError


@pytest.fixture
def private_dir(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    fsperm.make_private_dir(path)
    return path


# --- Both operating systems ---------------------------------------------------


def test_new_directory_passes_the_check(private_dir: Path) -> None:
    fsperm.check_private_dir(private_dir)


def test_new_file_passes_the_check(private_dir: Path) -> None:
    fd = fsperm.create_private_file(private_dir / "file")
    try:
        fsperm.check_private_fd(fd)
    finally:
        os.close(fd)


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


def test_ensure_data_dir_creates_and_then_accepts(tmp_path: Path) -> None:
    path = tmp_path / "data"
    fsperm.ensure_data_dir(path)
    assert path.is_dir()
    fsperm.ensure_data_dir(path)  # existing and private: accepted


def test_check_private_dir_reports_a_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        fsperm.check_private_dir(tmp_path / "missing")


def test_a_file_in_place_of_the_directory_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "data"
    path.write_bytes(b"")
    with pytest.raises(UnsafeFileError) as caught:
        fsperm.ensure_data_dir(path)
    assert str(tmp_path) not in str(caught.value)  # no path in the message (T17)


def test_unsafe_file_error_is_a_storage_error() -> None:
    assert issubclass(UnsafeFileError, fsperm.StorageError)


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

    @pytest.mark.parametrize("mode", [0o755, 0o750, 0o701, 0o707])
    def test_posix_loosened_directory_is_refused(private_dir: Path, mode: int) -> None:
        private_dir.chmod(mode)
        with pytest.raises(UnsafeFileError, match="permissions for other users"):
            fsperm.ensure_data_dir(private_dir)

    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620])
    def test_posix_loosened_file_is_refused(private_dir: Path, mode: int) -> None:
        path = private_dir / "file"
        os.close(fsperm.create_private_file(path))
        path.chmod(mode)
        fd = os.open(path, os.O_RDONLY)
        try:
            with pytest.raises(UnsafeFileError, match="permissions for other users"):
                fsperm.check_private_fd(fd)
        finally:
            os.close(fd)

    def test_posix_symlink_in_place_of_the_directory_is_refused(
        private_dir: Path, tmp_path: Path
    ) -> None:
        link = tmp_path / "link"
        link.symlink_to(private_dir, target_is_directory=True)
        with pytest.raises(UnsafeFileError, match="link"):
            fsperm.ensure_data_dir(link)

    def test_posix_create_does_not_follow_a_symlink(private_dir: Path, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere"
        link = private_dir / "file"
        link.symlink_to(target)  # dangling: following it would create the target
        with pytest.raises(FileExistsError):
            fsperm.create_private_file(link)
        assert not target.exists()

    def test_posix_directory_owned_by_another_user_is_refused(
        private_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        other_uid = os.geteuid() + 1
        monkeypatch.setattr(os, "geteuid", lambda: other_uid)
        with pytest.raises(UnsafeFileError, match="owned by another user"):
            fsperm.check_private_dir(private_dir)


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

    def test_windows_directory_with_an_entry_for_everyone_is_refused(
        private_dir: Path, grant_others_read: Callable[[Path], None]
    ) -> None:
        grant_others_read(private_dir)
        with pytest.raises(UnsafeFileError, match="permissions for other users"):
            fsperm.ensure_data_dir(private_dir)

    def test_windows_file_with_an_entry_for_everyone_is_refused(
        private_dir: Path, grant_others_read: Callable[[Path], None]
    ) -> None:
        path = private_dir / "file"
        os.close(fsperm.create_private_file(path))
        grant_others_read(path)
        fd = os.open(path, os.O_RDONLY)
        try:
            with pytest.raises(UnsafeFileError, match="permissions for other users"):
                fsperm.check_private_fd(fd)
        finally:
            os.close(fd)

    def test_windows_directory_with_inherited_entries_is_refused(tmp_path: Path) -> None:
        # A directory made the ordinary way inherits SYSTEM, Administrators and
        # others from the parent folder.
        path = tmp_path / "data"
        path.mkdir()
        with pytest.raises(UnsafeFileError, match="permissions for other users"):
            fsperm.ensure_data_dir(path)

    def test_windows_null_dacl_is_refused(private_dir: Path) -> None:
        # A NULL DACL (as opposed to an empty one) grants everyone full access.
        win32security.SetNamedSecurityInfo(
            str(private_dir),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
        )
        with pytest.raises(UnsafeFileError, match="permissions for other users"):
            fsperm.check_private_dir(private_dir)

    def test_windows_directory_owned_by_another_user_is_refused(
        private_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(fsperm, "_user_sid", lambda: EVERYONE)
        with pytest.raises(UnsafeFileError, match="owned by another user"):
            fsperm.check_private_dir(private_dir)

    def test_windows_junction_in_place_of_the_directory_is_refused(
        private_dir: Path, tmp_path: Path
    ) -> None:
        import _winapi

        junction = tmp_path / "junction"
        _winapi.CreateJunction(str(private_dir), str(junction))
        with pytest.raises(UnsafeFileError, match="link"):
            fsperm.ensure_data_dir(junction)

    def test_windows_symlink_in_place_of_the_directory_is_refused(
        private_dir: Path, tmp_path: Path
    ) -> None:
        link = tmp_path / "link"
        try:
            link.symlink_to(private_dir, target_is_directory=True)
        except OSError:
            pytest.skip("creating symlinks needs Developer Mode or administrator rights")
        with pytest.raises(UnsafeFileError, match="link"):
            fsperm.ensure_data_dir(link)
