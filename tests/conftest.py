"""Fixtures shared by the test modules."""

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

if sys.platform == "win32":
    import ntsecuritycon
    import win32security


def _grant_others_read(path: Path) -> None:
    """Let other users read a file or directory, as a careless chmod or icacls would."""
    if sys.platform == "win32":
        everyone = win32security.ConvertStringSidToSid("S-1-1-0")
        descriptor = win32security.GetNamedSecurityInfo(
            str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
        )
        dacl = descriptor.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, everyone
        )
        win32security.SetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
    else:
        path.chmod(0o755 if path.is_dir() else 0o644)


@pytest.fixture
def grant_others_read() -> Callable[[Path], None]:
    return _grant_others_read


@pytest.fixture(autouse=True)
def _no_real_data_dir(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point YUNARPASS_HOME at a fresh directory, so no test touches ~/.yunarpass."""
    monkeypatch.setenv("YUNARPASS_HOME", str(tmp_path_factory.mktemp("home") / "data"))
