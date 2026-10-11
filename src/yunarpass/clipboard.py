"""The clipboard (UC4, UC5): how a password leaves yunarpass without being printed (T18, T25).

ClipboardGuard puts a password on the clipboard and takes it off again after
CLEAR_SECONDS, but only if the clipboard still holds it: anything the user
copied in the meantime is left alone. The user interface also calls clear()
when the vault is locked and when the program exits. To recognise its own copy
the guard keeps only an HMAC of it, under a key made for that one copy, never
the password itself.

The guard does not know how time passes: it is given call_later(seconds,
callback), which schedules the clear and returns a function that cancels it.
The CLI passes thread_timer; the GUI will pass a Qt timer.

Backends:

- Windows: pywin32's win32clipboard. The copy carries three more formats that
  keep it out of the clipboard history (Win+V) and the cloud clipboard, and
  tell clipboard monitors to ignore it.
- macOS and Linux: pbcopy and pbpaste, wl-copy and wl-paste (Wayland), or
  xclip (X11). The tools are looked up in the system directories only, never
  through PATH, run with an argument list and no shell, and get the text
  through stdin, never as an argument (T16).

Every failure is a ClipboardError, whose message is safe to show.
"""

import contextlib
import hashlib
import hmac
import os
import secrets
import shutil

# Runs only fixed tools, by absolute path, with no shell.
import subprocess  # nosec B404
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from typing import Protocol

CLEAR_SECONDS = 20

type Cancel = Callable[[], None]
type CallLater = Callable[[float, Callable[[], None]], Cancel]


class ClipboardError(Exception):
    """The clipboard could not be used. The message is safe to show."""


class Backend(Protocol):
    """The system clipboard, holding text."""

    def read(self) -> str | None:
        """The text on the clipboard, or None if it holds no text."""

    def write(self, text: str) -> None: ...

    def clear(self) -> None: ...


def thread_timer(seconds: float, callback: Callable[[], None]) -> Cancel:
    """call_later for a program without an event loop: a daemon thread timer."""
    timer = threading.Timer(seconds, callback)
    timer.daemon = True  # never keeps the program alive after quit
    timer.start()
    return timer.cancel


class ClipboardGuard:
    """Copies text to the clipboard and makes sure it does not stay there."""

    def __init__(
        self,
        backend: Backend,
        call_later: CallLater = thread_timer,
        seconds: float = CLEAR_SECONDS,
    ) -> None:
        self._backend = backend
        self._call_later = call_later
        self._seconds = seconds
        # The timer runs in another thread (CLI) or callback (GUI).
        self._lock = threading.Lock()
        self._key = b""
        self._digest: bytes | None = None  # of the text we copied last, while it may be there
        self._copies = 0
        self._cancel: Cancel | None = None

    @property
    def seconds(self) -> float:
        return self._seconds

    def copy(self, text: str) -> None:
        """Put text on the clipboard, to be cleared after the timeout."""
        with self._lock:
            self._cancel_timer()
            self._backend.write(text)
            self._key = secrets.token_bytes(32)
            self._digest = self._mac(text)
            self._copies += 1
            copy = self._copies
            self._cancel = self._call_later(self._seconds, lambda: self._expire(copy))

    def clear(self) -> None:
        """Clear the clipboard now if it still holds our copy; otherwise leave it.

        If reading or clearing the clipboard fails, the ClipboardError is
        raised and the copy is still remembered, so a later clear() tries again.
        """
        with self._lock:
            self._clear()

    def _expire(self, copy: int) -> None:
        # Runs on the timer. A newer copy has its own timer, so this one only
        # acts on the copy it was set for. There is nobody to report a failure
        # to here; the next clear(), on lock or exit, tries again.
        with self._lock, contextlib.suppress(ClipboardError):
            if copy == self._copies:
                self._clear()

    def _clear(self) -> None:
        self._cancel_timer()
        if self._digest is None:
            return
        current = self._backend.read()
        if current is not None and hmac.compare_digest(self._mac(current), self._digest):
            self._backend.clear()
        self._digest = None
        self._key = b""

    def _cancel_timer(self) -> None:
        if self._cancel is not None:
            self._cancel()
            self._cancel = None

    def _mac(self, text: str) -> bytes:
        data = text.encode("utf-8", "surrogatepass")
        return hmac.new(self._key, data, hashlib.sha256).digest()


# --- macOS and Linux: system tools ---------------------------------------------------

# Only directories that an ordinary user cannot write to; PATH is never used,
# so a planted "xclip" earlier in PATH is not run.
SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/local/bin")
_TIMEOUT_SECONDS = 5

type Run = Callable[..., subprocess.CompletedProcess[bytes]]


def find_tool(name: str) -> str | None:
    """The absolute path of a tool in SYSTEM_DIRS, or None."""
    return shutil.which(name, path=os.pathsep.join(SYSTEM_DIRS))


class CommandClipboard:
    """A clipboard reached through command-line tools."""

    def __init__(
        self,
        copy: list[str],
        paste: list[str],
        clear: list[str] | None = None,
        run: Run = subprocess.run,
    ) -> None:
        self._copy = copy
        self._paste = paste
        self._clear = clear
        self._run = run

    def _call(self, argv: list[str], data: bytes, *, output: bool) -> bytes | None:
        """Run a tool; return its output, or None if it failed."""
        try:
            result = self._run(
                argv,
                input=data,
                stdout=subprocess.PIPE if output else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise ClipboardError("the clipboard tool did not work") from None
        if result.returncode != 0:
            return None
        return result.stdout if output else b""

    def read(self) -> str | None:
        data = self._call(self._paste, b"", output=True)
        if data is None:
            return None  # the tools fail when the clipboard is empty
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None  # not text we could have put there

    def write(self, text: str) -> None:
        if self._call(self._copy, text.encode("utf-8"), output=False) is None:
            raise ClipboardError("the clipboard tool did not work")

    def clear(self) -> None:
        if self._clear is None:
            self.write("")
        elif self._call(self._clear, b"", output=False) is None:
            raise ClipboardError("the clipboard tool did not work")


class NoClipboard:
    """Stands in when no clipboard tool was found; every use says so."""

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def read(self) -> str | None:
        raise ClipboardError(self._reason)

    def write(self, text: str) -> None:
        raise ClipboardError(self._reason)

    def clear(self) -> None:
        raise ClipboardError(self._reason)


def posix_clipboard(
    platform: str,
    environ: Mapping[str, str],
    find: Callable[[str], str | None] = find_tool,
) -> Backend:
    """The clipboard of a macOS or Linux session: pbcopy, wl-copy or xclip."""
    if platform == "darwin":
        return CommandClipboard(["/usr/bin/pbcopy"], ["/usr/bin/pbpaste"])
    if environ.get("WAYLAND_DISPLAY"):
        wl_copy, wl_paste = find("wl-copy"), find("wl-paste")
        if wl_copy and wl_paste:
            return CommandClipboard(
                [wl_copy], [wl_paste, "--no-newline"], clear=[wl_copy, "--clear"]
            )
    if environ.get("DISPLAY"):
        xclip = find("xclip")
        if xclip:
            selection = ["-selection", "clipboard"]
            return CommandClipboard([xclip, *selection, "-in"], [xclip, *selection, "-out"])
    return NoClipboard("no clipboard tool was found; install wl-clipboard (Wayland) or xclip (X11)")


# --- Windows -------------------------------------------------------------------------

if sys.platform == "win32":
    import pywintypes
    import win32clipboard
    import win32con

    # Placed next to the text. ExcludeClipboardContentFromMonitorProcessing
    # works by being there at all; the other two hold a DWORD, and 0 means
    # "no": not in the history, not uploaded to the cloud clipboard.
    PRIVACY_FORMATS = (
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    )
    _DWORD_ZERO = bytes(4)
    _OPEN_ATTEMPTS = 10
    _OPEN_RETRY_SECONDS = 0.05

    class WindowsClipboard:
        """The Windows clipboard, through pywin32."""

        def __init__(self, sleep: Callable[[float], None] = time.sleep) -> None:
            self._sleep = sleep

        @contextlib.contextmanager
        def _opened(self) -> Iterator[None]:
            # Another program may hold the clipboard open for a moment.
            for attempt in range(_OPEN_ATTEMPTS):
                try:
                    win32clipboard.OpenClipboard(None)
                    break
                except pywintypes.error:
                    if attempt == _OPEN_ATTEMPTS - 1:
                        raise ClipboardError(
                            "the clipboard is in use by another program; try again"
                        ) from None
                    self._sleep(_OPEN_RETRY_SECONDS)
            try:
                yield
            except pywintypes.error:
                raise ClipboardError("the clipboard could not be used") from None
            finally:
                with contextlib.suppress(pywintypes.error):
                    win32clipboard.CloseClipboard()  # type: ignore[no-untyped-call]

        def read(self) -> str | None:
            with self._opened():
                if not win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                    return None
                text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
            return text if isinstance(text, str) else None

        def write(self, text: str) -> None:
            with self._opened():
                win32clipboard.EmptyClipboard()  # type: ignore[no-untyped-call]
                # Windows tells other programs about the new content only
                # when the clipboard is closed, with every format in place.
                for name in PRIVACY_FORMATS:
                    fmt = win32clipboard.RegisterClipboardFormat(name)
                    win32clipboard.SetClipboardData(fmt, _DWORD_ZERO)  # type: ignore[no-untyped-call]
                win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, text)  # type: ignore[no-untyped-call]

        def clear(self) -> None:
            with self._opened():
                win32clipboard.EmptyClipboard()  # type: ignore[no-untyped-call]


def system_clipboard() -> Backend:
    """The clipboard of the session this program runs in."""
    if sys.platform == "win32":
        return WindowsClipboard()
    return posix_clipboard(sys.platform, os.environ)
