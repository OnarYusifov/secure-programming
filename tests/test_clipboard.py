"""Tests for the clipboard: the timed clear and the backends (threats T16, T18).

No test touches the real clipboard, which belongs to whoever runs the tests.
The Windows backend is tested against a fake win32clipboard module.
"""

import os
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from yunarpass import clipboard
from yunarpass.clipboard import ClipboardError, ClipboardGuard, CommandClipboard, NoClipboard

SECRET = "s3cret-Password!"


class FakeBackend:
    """A clipboard in memory. With broken set, every call fails."""

    def __init__(self) -> None:
        self.text: str | None = None
        self.calls: list[str] = []
        self.broken = False

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.broken:
            raise ClipboardError("the clipboard could not be used")

    def read(self) -> str | None:
        self._call("read")
        return self.text

    def write(self, text: str) -> None:
        self._call("write")
        self.text = text

    def clear(self) -> None:
        self._call("clear")
        self.text = None


class FakeTimers:
    """call_later that runs nothing until fire() is called."""

    def __init__(self) -> None:
        self.pending: list[tuple[float, Callable[[], None], list[bool]]] = []

    def __call__(self, seconds: float, callback: Callable[[], None]) -> Callable[[], None]:
        cancelled = [False]
        self.pending.append((seconds, callback, cancelled))
        return lambda: cancelled.__setitem__(0, True)

    @property
    def active(self) -> list[float]:
        return [seconds for seconds, _, cancelled in self.pending if not cancelled[0]]

    def fire(self) -> None:
        """Run every timer, cancelled or not, the way a late timer thread would."""
        pending, self.pending = self.pending, []
        for _, callback, _ in pending:
            callback()


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def timers() -> FakeTimers:
    return FakeTimers()


@pytest.fixture
def guard(backend: FakeBackend, timers: FakeTimers) -> ClipboardGuard:
    return ClipboardGuard(backend, timers)


# --- The guard (T18) -----------------------------------------------------------------


def test_copy_puts_the_text_on_the_clipboard_and_sets_a_20_second_timer(
    guard: ClipboardGuard, backend: FakeBackend, timers: FakeTimers
) -> None:
    guard.copy(SECRET)
    assert backend.text == SECRET
    assert timers.active == [20]
    assert guard.seconds == clipboard.CLEAR_SECONDS == 20


def test_the_timer_clears_the_clipboard(
    guard: ClipboardGuard, backend: FakeBackend, timers: FakeTimers
) -> None:
    guard.copy(SECRET)
    timers.fire()
    assert backend.text is None


def test_a_newer_copy_by_the_user_is_left_alone(
    guard: ClipboardGuard, backend: FakeBackend, timers: FakeTimers
) -> None:
    guard.copy(SECRET)
    backend.text = "something the user copied"
    timers.fire()
    assert backend.text == "something the user copied"
    assert "clear" not in backend.calls
    guard.clear()  # at lock or quit: still not ours
    assert backend.text == "something the user copied"


def test_clear_on_lock_or_quit_clears_at_once_and_stops_the_timer(
    guard: ClipboardGuard, backend: FakeBackend, timers: FakeTimers
) -> None:
    guard.copy(SECRET)
    guard.clear()
    assert backend.text is None
    assert timers.active == []


def test_clear_without_a_copy_does_not_touch_the_clipboard(
    guard: ClipboardGuard, backend: FakeBackend
) -> None:
    backend.text = "the user's"
    guard.clear()
    guard.clear()
    assert backend.calls == []
    assert backend.text == "the user's"


def test_a_late_timer_of_an_earlier_copy_does_not_clear_a_newer_one(
    guard: ClipboardGuard, backend: FakeBackend, timers: FakeTimers
) -> None:
    guard.copy(SECRET)
    guard.copy("a newer password")
    assert timers.active == [20]  # the first timer was cancelled
    first = timers.pending[0][1]
    first()  # it had already started when it was cancelled
    assert backend.text == "a newer password"
    timers.pending[1][1]()
    assert backend.text is None


def test_the_same_text_copied_twice_is_cleared_once(
    guard: ClipboardGuard, backend: FakeBackend, timers: FakeTimers
) -> None:
    guard.copy(SECRET)
    guard.clear()
    backend.text = SECRET  # the user copied the same text themselves
    timers.fire()
    assert backend.text == SECRET


def test_a_failed_clear_is_tried_again_later(
    guard: ClipboardGuard, backend: FakeBackend, timers: FakeTimers
) -> None:
    guard.copy(SECRET)
    backend.broken = True
    timers.fire()  # the timer has nobody to tell, so it says nothing
    assert backend.text == SECRET
    with pytest.raises(ClipboardError):
        guard.clear()  # at lock: the error is reported
    backend.broken = False
    guard.clear()  # at quit: tried again
    assert backend.text is None


def test_the_guard_keeps_no_copy_of_the_text(guard: ClipboardGuard) -> None:
    guard.copy(SECRET)
    state = {name: getattr(guard, name) for name in vars(guard)}
    assert SECRET not in repr(state)
    assert SECRET.encode() not in b"".join(v for v in state.values() if isinstance(v, bytes))


def test_a_failed_copy_sets_no_timer(
    guard: ClipboardGuard, backend: FakeBackend, timers: FakeTimers
) -> None:
    backend.broken = True
    with pytest.raises(ClipboardError):
        guard.copy(SECRET)
    assert timers.pending == []


def test_thread_timer_runs_the_callback_and_can_be_cancelled() -> None:
    done = threading.Event()
    clipboard.thread_timer(0.01, done.set)
    assert done.wait(5)
    never = threading.Event()
    cancel = clipboard.thread_timer(30, never.set)  # long enough never to fire first
    cancel()
    assert not never.wait(0.2)


# --- Command-line tools (macOS, Linux; T16) ------------------------------------------


class FakeRun:
    """subprocess.run, recorded. Returns the given code and output."""

    def __init__(
        self, returncode: int = 0, stdout: bytes = b"", error: Exception | None = None
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.error = error
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((argv, kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, None)


def tool(run: FakeRun, clear: list[str] | None = None) -> CommandClipboard:
    return CommandClipboard(["/usr/bin/copy"], ["/usr/bin/paste"], clear, run=run)


def test_a_tool_gets_the_text_on_stdin_never_as_an_argument() -> None:
    run = FakeRun()
    tool(run).write(SECRET)
    ((argv, kwargs),) = run.calls
    assert argv == ["/usr/bin/copy"]
    assert kwargs["input"] == SECRET.encode()
    assert "shell" not in kwargs  # an argument list, never a shell
    assert kwargs["timeout"] == 5
    assert kwargs["stdout"] == subprocess.DEVNULL


def test_reading_returns_the_tools_output_as_text() -> None:
    run = FakeRun(stdout="pässword".encode())
    assert tool(run).read() == "pässword"
    assert run.calls[0][0] == ["/usr/bin/paste"]
    assert run.calls[0][1]["stdout"] == subprocess.PIPE


@pytest.mark.parametrize(("returncode", "stdout"), [(1, b""), (0, b"\xff\xfe not utf-8")])
def test_reading_an_empty_or_non_text_clipboard_gives_none(returncode: int, stdout: bytes) -> None:
    assert tool(FakeRun(returncode, stdout)).read() is None


def test_clearing_runs_the_clear_command_or_copies_nothing() -> None:
    run = FakeRun()
    tool(run, clear=["/usr/bin/copy", "--clear"]).clear()
    assert run.calls[0][0] == ["/usr/bin/copy", "--clear"]
    run = FakeRun()
    tool(run).clear()
    assert run.calls[0][0] == ["/usr/bin/copy"]
    assert run.calls[0][1]["input"] == b""


@pytest.mark.parametrize(
    "run",
    [
        FakeRun(returncode=1),
        FakeRun(error=FileNotFoundError(2, "No such file", "/usr/bin/copy")),
        FakeRun(error=subprocess.TimeoutExpired(["/usr/bin/copy"], 5)),
    ],
)
def test_a_failing_tool_raises_a_clipboard_error(run: FakeRun) -> None:
    uses: list[Callable[[], None]] = [
        lambda: tool(run).write(SECRET),
        lambda: tool(run, ["/usr/bin/x"]).clear(),
    ]
    for use in uses:
        with pytest.raises(ClipboardError, match="the clipboard tool did not work") as caught:
            use()
        assert SECRET not in str(caught.value)
        assert "/usr/bin" not in str(caught.value)


def test_tools_are_found_in_the_system_directories_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = tmp_path / "xclip"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
    found = clipboard.find_tool("xclip")
    assert found is None or Path(found).parent in {Path(d) for d in clipboard.SYSTEM_DIRS}


def finder(*available: str) -> Callable[[str], str | None]:
    return lambda name: f"/usr/bin/{name}" if name in available else None


def test_macos_uses_pbcopy() -> None:
    backend = clipboard.posix_clipboard("darwin", {})
    assert isinstance(backend, CommandClipboard)
    assert backend._copy == ["/usr/bin/pbcopy"]
    assert backend._paste == ["/usr/bin/pbpaste"]


def test_wayland_uses_wl_copy() -> None:
    backend = clipboard.posix_clipboard(
        "linux", {"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, finder("wl-copy", "wl-paste")
    )
    assert isinstance(backend, CommandClipboard)
    assert backend._copy == ["/usr/bin/wl-copy"]
    assert backend._paste == ["/usr/bin/wl-paste", "--no-newline"]
    assert backend._clear == ["/usr/bin/wl-copy", "--clear"]


def test_x11_uses_xclip_also_under_wayland_without_wl_copy() -> None:
    for environ in ({"DISPLAY": ":0"}, {"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}):
        backend = clipboard.posix_clipboard("linux", environ, finder("xclip"))
        assert isinstance(backend, CommandClipboard)
        assert backend._copy == ["/usr/bin/xclip", "-selection", "clipboard", "-in"]
        assert backend._paste == ["/usr/bin/xclip", "-selection", "clipboard", "-out"]


@pytest.mark.parametrize(
    ("environ", "tools"),
    [
        ({}, ("xclip", "wl-copy", "wl-paste")),
        ({"DISPLAY": ":0"}, ()),
        ({"WAYLAND_DISPLAY": "w"}, ("wl-copy",)),
    ],
)
def test_without_a_tool_every_use_says_what_to_install(
    environ: dict[str, str], tools: tuple[str, ...]
) -> None:
    backend = clipboard.posix_clipboard("linux", environ, finder(*tools))
    assert isinstance(backend, NoClipboard)
    for use in (backend.read, backend.clear, lambda: backend.write(SECRET)):
        with pytest.raises(ClipboardError, match="install wl-clipboard .* or xclip"):
            use()


@pytest.mark.skipif(sys.platform == "win32", reason="the POSIX choice")
def test_the_system_clipboard_outside_windows_is_a_tool_or_none() -> None:
    assert isinstance(clipboard.system_clipboard(), CommandClipboard | NoClipboard)


# --- Windows (T18) -------------------------------------------------------------------

if sys.platform == "win32":
    import pywintypes
    import win32con

    class FakeWin32Clipboard:
        """The parts of win32clipboard that the backend uses, in memory."""

        def __init__(self) -> None:
            self.data: dict[int, object] = {}
            self.formats = {name: 0xC000 + i for i, name in enumerate(clipboard.PRIVACY_FORMATS)}
            self.log: list[str] = []
            self.busy = 0  # how many OpenClipboard calls fail first
            self.fail: str | None = None  # the name of a call that fails
            self.open = False

        def _call(self, name: str) -> None:
            self.log.append(name)
            if name == self.fail:
                raise pywintypes.error(5, name, "Access is denied.")

        def OpenClipboard(self, hwnd: object) -> None:  # noqa: N802 (the pywin32 names)
            assert hwnd is None
            if self.busy:
                self.busy -= 1
                self._call("busy")
                raise pywintypes.error(5, "OpenClipboard", "Access is denied.")
            self._call("open")
            self.open = True

        def CloseClipboard(self) -> None:  # noqa: N802
            assert self.open
            self.open = False
            self._call("close")

        def EmptyClipboard(self) -> None:  # noqa: N802
            assert self.open
            self._call("empty")
            self.data = {}

        def RegisterClipboardFormat(self, name: str) -> int:  # noqa: N802
            return self.formats[name]

        def SetClipboardData(self, fmt: int, data: object) -> None:  # noqa: N802
            assert self.open
            self._call("set")
            self.data[fmt] = data

        def IsClipboardFormatAvailable(self, fmt: int) -> bool:  # noqa: N802
            assert self.open
            return fmt in self.data

        def GetClipboardData(self, fmt: int) -> object:  # noqa: N802
            assert self.open
            self._call("get")
            return self.data[fmt]

    @pytest.fixture
    def win32(monkeypatch: pytest.MonkeyPatch) -> FakeWin32Clipboard:
        fake = FakeWin32Clipboard()
        monkeypatch.setattr(clipboard, "win32clipboard", fake)
        return fake

    def windows(sleeps: list[float] | None = None) -> clipboard.WindowsClipboard:
        return clipboard.WindowsClipboard(sleep=(sleeps if sleeps is not None else []).append)

    def test_windows_copy_is_kept_out_of_the_history_and_the_cloud(
        win32: FakeWin32Clipboard,
    ) -> None:
        windows().write(SECRET)
        assert win32.data[win32con.CF_UNICODETEXT] == SECRET
        exclude, history, cloud = (win32.formats[name] for name in clipboard.PRIVACY_FORMATS)
        assert exclude in win32.data
        assert win32.data[history] == b"\x00\x00\x00\x00"  # DWORD 0: not in Win+V
        assert win32.data[cloud] == b"\x00\x00\x00\x00"  # DWORD 0: not synced
        assert win32.log == ["open", "empty", "set", "set", "set", "set", "close"]

    def test_windows_read_and_clear(win32: FakeWin32Clipboard) -> None:
        backend = windows()
        assert backend.read() is None  # no text on the clipboard
        backend.write(SECRET)
        assert backend.read() == SECRET
        backend.clear()
        assert win32.data == {}
        assert not win32.open

    def test_windows_waits_while_another_program_has_the_clipboard_open(
        win32: FakeWin32Clipboard,
    ) -> None:
        win32.busy = 3
        sleeps: list[float] = []
        windows(sleeps).write(SECRET)
        assert sleeps == [0.05, 0.05, 0.05]
        assert win32.data[win32con.CF_UNICODETEXT] == SECRET

    def test_windows_gives_up_on_a_clipboard_that_stays_busy(win32: FakeWin32Clipboard) -> None:
        win32.busy = 100
        sleeps: list[float] = []
        with pytest.raises(ClipboardError, match="in use by another program"):
            windows(sleeps).write(SECRET)
        assert len(sleeps) == 9  # ten attempts in all

    @pytest.mark.parametrize("call", ["empty", "set", "get"])
    def test_windows_errors_become_clipboard_errors_and_close_the_clipboard(
        win32: FakeWin32Clipboard, call: str
    ) -> None:
        win32.data[win32con.CF_UNICODETEXT] = "text"
        win32.fail = call
        with pytest.raises(ClipboardError, match="could not be used"):
            windows().read() if call == "get" else windows().write(SECRET)
        assert not win32.open

    def test_windows_ignores_a_failed_close(win32: FakeWin32Clipboard) -> None:
        win32.fail = "close"
        windows().write(SECRET)
        assert win32.data[win32con.CF_UNICODETEXT] == SECRET

    def test_the_system_clipboard_on_windows_is_pywin32() -> None:
        assert isinstance(clipboard.system_clipboard(), clipboard.WindowsClipboard)
