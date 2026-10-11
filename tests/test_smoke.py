import os
import subprocess
import sys
from pathlib import Path

from yunarpass import __version__


def test_version_is_set() -> None:
    assert __version__


def test_python_dash_m_yunarpass_starts_and_exits_at_the_end_of_input(tmp_path: Path) -> None:
    # The README's run command, as a fresh process with stdin closed.
    result = subprocess.run(
        [sys.executable, "-m", "yunarpass"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=os.environ | {"YUNARPASS_HOME": str(tmp_path / "data")},
        timeout=60,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.startswith(f"yunarpass {__version__}. Type help")
    assert result.stderr == ""
