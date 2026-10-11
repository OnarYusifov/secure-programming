"""Tests for the REPL (threats T3, T16, T17, T19)."""

import getpass
import io
import sys
from collections.abc import Iterable

import pytest

from yunarpass import __version__, cli
from yunarpass.cli import Console, Repl
from yunarpass.storage import StorageError

type Typed = str | BaseException


class FakeConsole:
    """Types lines and secrets into the REPL and records everything it writes.

    An exception in the input is raised instead of returned, the way Ctrl-C
    would be. Once the input runs out, reading raises EOFError, like a closed
    stdin.
    """

    def __init__(self, lines: Iterable[Typed] = (), secrets: Iterable[Typed] = ()) -> None:
        self.lines = list(lines)
        self.secrets = list(secrets)
        self.output: list[str] = []
        self.secret_prompts: list[str] = []

    @staticmethod
    def _next(queue: list[Typed]) -> str:
        if not queue:
            raise EOFError
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def read_line(self, prompt: str) -> str:
        self.output.append(prompt)
        return self._next(self.lines)

    def read_secret(self, prompt: str) -> str:
        self.output.append(prompt)
        self.secret_prompts.append(prompt)
        return self._next(self.secrets)

    def console(self) -> Console:
        return Console(self.read_line, self.read_secret, self.output.append)

    @property
    def text(self) -> str:
        return "".join(self.output)


def run(*lines: Typed) -> FakeConsole:
    fake = FakeConsole(lines)
    assert Repl(fake.console()).run() == 0
    return fake


# --- The loop ----------------------------------------------------------------------


def test_starts_with_a_banner_then_the_prompt() -> None:
    fake = run()
    assert fake.output[0] == f"yunarpass {__version__}. Type help to see the commands.\n"
    assert fake.output[1] == cli.PROMPT


def test_help_lists_the_commands() -> None:
    fake = run("help")
    assert "Commands:\n  help  Show this list\n  quit  Exit\n" in fake.text


def test_quit_stops_reading() -> None:
    fake = run("quit", "help")
    assert "Commands:" not in fake.text
    assert fake.text.count(cli.PROMPT) == 1


def test_end_of_input_exits_cleanly() -> None:
    fake = run("help")
    assert fake.text.endswith(cli.PROMPT + "\n")


def test_ctrl_c_at_the_prompt_exits_cleanly() -> None:
    fake = run(KeyboardInterrupt(), "help")
    assert "Commands:" not in fake.text
    assert fake.text.endswith(cli.PROMPT + "\n")


def test_ctrl_c_inside_a_command_cancels_only_that_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupted(self: Repl, args: str) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(Repl, "help", interrupted)
    fake = run("help", "quit")
    assert "\nCancelled.\n" in fake.text
    assert fake.text.count(cli.PROMPT) == 2  # it went on to read "quit"


def test_an_empty_line_does_not_repeat_the_last_command() -> None:
    fake = run("help", "", "   ")
    assert fake.text.count("Commands:") == 1


# --- Allow-list and line length (T19) ------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "correct-horse-battery-staple",  # a password typed at the wrong prompt
        "HELP",
        "help-me",
        "!ls",
        "rm -rf /",
        "help;quit",
        "\x1b[2Jhelp",
    ],
)
def test_an_unknown_command_is_refused_and_not_echoed(line: str) -> None:
    fake = run(line)
    assert cli.UNKNOWN_COMMAND in fake.text
    assert line not in fake.text


def test_an_overlong_line_is_refused_before_it_is_parsed() -> None:
    fake = run("help" + " " * cli.MAX_LINE)
    assert f"Error: a line can be at most {cli.MAX_LINE} characters." in fake.text
    assert "Commands:" not in fake.text


def test_a_line_of_exactly_the_maximum_length_is_accepted() -> None:
    fake = run("help".ljust(cli.MAX_LINE))
    assert "Commands:" in fake.text


def test_arguments_to_a_command_that_takes_none_are_refused_and_not_echoed() -> None:
    fake = run("quit correct-horse-battery-staple", "help")
    assert "Error: quit takes no arguments." in fake.text
    assert "correct-horse" not in fake.text
    assert "Commands:" in fake.text  # still running


# --- Errors (T17) --------------------------------------------------------------------


def test_an_unexpected_error_gives_the_generic_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(self: Repl, args: str) -> None:
        raise RuntimeError("detail: C:\\Users\\alice\\.yunarpass, key 00ff")

    monkeypatch.setattr(Repl, "help", broken)
    fake = run("help", "quit")
    assert cli.GENERIC_ERROR in fake.text
    for leak in ("detail", "alice", "00ff", "RuntimeError", "Traceback"):
        assert leak not in fake.text
    assert fake.text.count(cli.PROMPT) == 2  # still running


def test_an_error_written_for_the_user_shows_its_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(self: Repl, args: str) -> None:
        raise StorageError("a data file is too large")

    monkeypatch.setattr(Repl, "help", refused)
    fake = run("help")
    assert "Error: a data file is too large.\n" in fake.text


# --- Output sanitizer (T19) ----------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("plain text", "plain text"),
        ("\x1b[31mred\x1b[0m", "red"),
        ("\x1b[2J\x1b[1;1Hcleared", "cleared"),
        ("\x1b]0;new window title\x07name", "name"),
        ("\x1b]8;;https://example.com\x1b\\link\x1b]8;;\x1b\\", "link"),
        ("\x1bPdevice control\x1b\\after", "after"),
        ("\x1bcreset", "reset"),
        ("bell\x07 bs\x08 cr\r lf\n tab\t del\x7f nul\x00", "bell bs cr lf tab del nul"),
        ("eight-bit \x9b31mcsi", "eight-bit 31mcsi"),
        ("trailing escape\x1b", "trailing escape"),
        ("\u202eexe.txt", "exe.txt"),
        ("isolate\u2066d\u2069", "isolated"),
        ("line\u2028separator\u2029", "lineseparator"),
        ("café ✓ 日本語", "café ✓ 日本語"),
    ],
)
def test_sanitize_removes_escape_sequences_and_control_characters(raw: str, shown: str) -> None:
    assert cli.sanitize(raw) == shown


def test_every_printed_line_is_sanitized() -> None:
    fake = FakeConsole()
    Repl(fake.console()).say("\x1b[2Jfirst", "second\x1b]0;title\x07\r\n")
    assert fake.text == "first\nsecond\n"


# --- Masked input and no arguments (T3, T16) -----------------------------------------


def test_the_default_console_reads_secrets_with_getpass() -> None:
    assert Console().read_secret is getpass.getpass


def test_main_refuses_any_argument_and_does_not_echo_it(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--password", "correct-horse-battery-staple"]) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("usage: yunarpass")
    assert "correct-horse" not in err


def test_main_prints_the_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out == f"yunarpass {__version__}\n"


def test_main_prints_the_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == 0
    assert capsys.readouterr().out.startswith("usage: yunarpass")


def test_main_runs_the_prompt_until_the_input_ends(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("help\n"))
    assert cli.main([]) == 0
    assert "Commands:" in capsys.readouterr().out


def test_main_turns_an_unexpected_error_into_the_generic_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(self: Repl) -> int:
        raise RuntimeError("detail")

    monkeypatch.setattr(Repl, "run", broken)
    assert cli.main([]) == 1
    out, err = capsys.readouterr()
    assert err == cli.GENERIC_ERROR + "\n"
    assert "detail" not in out + err


def test_main_exits_cleanly_on_ctrl_c_outside_a_command(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(self: Repl) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(Repl, "run", interrupted)
    assert cli.main([]) == 0
