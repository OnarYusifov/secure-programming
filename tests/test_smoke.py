from yunarpass import __version__
from yunarpass.__main__ import main


def test_version_is_set() -> None:
    assert __version__


def test_main_exits_cleanly() -> None:
    assert main() == 0
