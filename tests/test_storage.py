"""Tests for the storage layer (threats T10, T11, T12, T17)."""

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from yunarpass import fsperm, storage
from yunarpass.storage import DataDir, StorageError, UnsafeFileError

USERS = storage.USERS_FILE
VAULT = storage.vault_file_name("0123456789abcdef0123456789abcdef")


@pytest.fixture
def data_dir(tmp_path: Path) -> DataDir:
    return DataDir.open(tmp_path / "data")


def place_private_file(data_dir: DataDir, name: str, content: bytes) -> Path:
    """Put a file in the data directory the way the program would, bypassing write()."""
    path = data_dir.path / name
    with os.fdopen(fsperm.create_private_file(path), "wb") as file:
        file.write(content)
    return path


def symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("creating symlinks needs Developer Mode or administrator rights")


# --- Where the data directory is ------------------------------------------------


def test_default_location_is_dot_yunarpass_in_the_home_directory() -> None:
    expected = Path.home() / ".yunarpass"
    assert storage.data_dir_path({}) == expected
    assert storage.data_dir_path({storage.HOME_ENV: ""}) == expected  # empty means unset


def test_yunarpass_home_overrides_the_default(tmp_path: Path) -> None:
    assert storage.data_dir_path({storage.HOME_ENV: str(tmp_path)}) == tmp_path


def test_yunarpass_home_must_be_absolute_without_dotdot(tmp_path: Path) -> None:
    for value in (
        "relative",
        str(Path("relative", "data")),
        str(tmp_path / ".." / "data"),
        str(tmp_path) + "\0suffix",
    ):
        with pytest.raises(StorageError, match="absolute path"):
            storage.data_dir_path({storage.HOME_ENV: value})


def test_open_uses_yunarpass_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(storage.HOME_ENV, str(tmp_path / "data"))
    data_dir = DataDir.open()
    assert data_dir.path == tmp_path / "data"
    assert data_dir.path.is_dir()


def test_open_refuses_a_directory_open_to_other_users(
    data_dir: DataDir, grant_others_read: Callable[[Path], None]
) -> None:
    grant_others_read(data_dir.path)
    with pytest.raises(UnsafeFileError):
        DataDir.open(data_dir.path)


def test_open_reports_a_missing_parent_without_the_path(tmp_path: Path) -> None:
    with pytest.raises(StorageError) as caught:
        DataDir.open(tmp_path / "missing" / "data")
    assert not isinstance(caught.value, UnsafeFileError)
    assert str(tmp_path) not in str(caught.value)  # T17


# --- File-name allow-list (T11) ---------------------------------------------------


def test_vault_file_name() -> None:
    assert VAULT == "vault-0123456789abcdef0123456789abcdef.json"
    for bad in ("0123456789ABCDEF0123456789ABCDEF", "0" * 31, "0" * 33, "../" + "0" * 29, ""):
        with pytest.raises(ValueError, match="vault ID"):
            storage.vault_file_name(bad)


@pytest.mark.parametrize(
    "name",
    [
        "../users.json",
        "sub/users.json",
        "USERS.json",
        "users.JSON",
        "users.json.tmp",
        ".users.json",
        "users.json\n",
        "users.json.bak.bak",
        "vault-0123.json",
        "vault-" + "G" * 32 + ".json",
        "",
    ],
)
def test_names_off_the_allow_list_are_refused(data_dir: DataDir, name: str) -> None:
    with pytest.raises(ValueError, match="not an allowed"):
        data_dir.read(name)


def test_an_absolute_path_is_not_a_name(data_dir: DataDir) -> None:
    with pytest.raises(ValueError, match="not an allowed"):
        data_dir.read(str(data_dir.path / USERS))


# --- Reading (T11, T12) -------------------------------------------------------------


def test_a_missing_file_reads_as_none(data_dir: DataDir) -> None:
    assert data_dir.read(USERS) is None
    assert data_dir.read(VAULT) is None


def test_read_returns_the_exact_bytes(data_dir: DataDir) -> None:
    content = bytes(range(256)) * 4  # every byte value, including CR, LF and Ctrl-Z
    place_private_file(data_dir, VAULT, content)
    assert data_dir.read(VAULT) == content


def test_a_backup_can_be_read(data_dir: DataDir) -> None:
    assert data_dir.read(USERS + ".bak") is None
    place_private_file(data_dir, USERS + ".bak", b"{}")
    assert data_dir.read(USERS + ".bak") == b"{}"


def test_a_symlink_is_refused(data_dir: DataDir, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_bytes(b"planted")
    symlink_or_skip(data_dir.path / USERS, target)
    with pytest.raises(UnsafeFileError, match="link"):
        data_dir.read(USERS)


def test_a_hard_link_is_refused(data_dir: DataDir) -> None:
    path = place_private_file(data_dir, USERS, b"{}")
    os.link(path, data_dir.path / "second-name")
    with pytest.raises(UnsafeFileError, match="hard link"):
        data_dir.read(USERS)


def test_a_directory_in_place_of_a_file_is_refused(data_dir: DataDir) -> None:
    (data_dir.path / USERS).mkdir()
    with pytest.raises(UnsafeFileError, match="not a regular file"):
        data_dir.read(USERS)


def test_a_file_swapped_between_the_check_and_the_open_is_refused(
    data_dir: DataDir, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = place_private_file(data_dir, USERS, b"checked")
    decoy = place_private_file(data_dir, VAULT, b"planted")
    real_lstat = os.lstat

    def lstat_then_swap(target: Path) -> os.stat_result:
        result = real_lstat(target)
        decoy.replace(path)  # an attacker wins the race right after the check
        return result

    monkeypatch.setattr(os, "lstat", lstat_then_swap)
    with pytest.raises(UnsafeFileError, match="replaced"):
        data_dir.read(USERS)


def test_a_file_open_to_other_users_is_refused(
    data_dir: DataDir, grant_others_read: Callable[[Path], None]
) -> None:
    path = place_private_file(data_dir, USERS, b"{}")
    grant_others_read(path)
    with pytest.raises(UnsafeFileError, match="permissions for other users"):
        data_dir.read(USERS)


def test_an_oversized_file_is_refused(data_dir: DataDir, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(storage, "MAX_FILE_BYTES", 16)
    place_private_file(data_dir, USERS, bytes(16))
    assert data_dir.read(USERS) == bytes(16)
    place_private_file(data_dir, VAULT, bytes(17))
    with pytest.raises(StorageError, match="too large"):
        data_dir.read(VAULT)


def test_a_file_that_grows_after_the_check_is_cut_off(data_dir: DataDir) -> None:
    path = place_private_file(data_dir, USERS, bytes(17))
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(StorageError, match="too large"):
            storage._read_at_most(fd, 16)
    finally:
        os.close(fd)
