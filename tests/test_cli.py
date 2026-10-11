"""Tests for the REPL (threats T3, T16, T17, T19)."""

import getpass
import io
import re
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol

import pytest

from yunarpass import __version__, cli, storage
from yunarpass.cli import Console, Repl
from yunarpass.storage import DataDir, StorageError
from yunarpass.users import AccountError, Accounts

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


class Run(Protocol):
    def __call__(self, *lines: Typed, secrets: Iterable[Typed] = ()) -> FakeConsole: ...


@pytest.fixture
def accounts(tmp_path: Path) -> Accounts:
    return Accounts(DataDir.open(tmp_path / "data"))


@pytest.fixture
def run(accounts: Accounts) -> Run:
    """Run the REPL on typed lines and secrets until the input runs out."""

    def run_repl(*lines: Typed, secrets: Iterable[Typed] = ()) -> FakeConsole:
        fake = FakeConsole(lines, secrets)
        assert Repl(accounts, fake.console()).run() == 0
        return fake

    return run_repl


# --- The loop ----------------------------------------------------------------------


def test_starts_with_a_banner_then_the_prompt(run: Run) -> None:
    fake = run()
    assert fake.output[0] == f"yunarpass {__version__}. Type help to see the commands.\n"
    assert fake.output[1] == cli.PROMPT


def test_help_lists_the_commands(run: Run) -> None:
    fake = run("help")
    assert fake.text.endswith(
        "Commands:\n"
        "  register  Create an account and its vault\n"
        "  help      Show this list\n"
        "  quit      Exit\n" + cli.PROMPT + "\n"
    )


def test_quit_stops_reading(run: Run) -> None:
    fake = run("quit", "help")
    assert "Commands:" not in fake.text
    assert fake.text.count(cli.PROMPT) == 1


def test_end_of_input_exits_cleanly(run: Run) -> None:
    fake = run("help")
    assert fake.text.endswith(cli.PROMPT + "\n")


def test_ctrl_c_at_the_prompt_exits_cleanly(run: Run) -> None:
    fake = run(KeyboardInterrupt(), "help")
    assert "Commands:" not in fake.text
    assert fake.text.endswith(cli.PROMPT + "\n")


def test_ctrl_c_inside_a_command_cancels_only_that_command(
    run: Run,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupted(self: Repl, args: str) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(Repl, "help", interrupted)
    fake = run("help", "quit")
    assert "\nCancelled.\n" in fake.text
    assert fake.text.count(cli.PROMPT) == 2  # it went on to read "quit"


def test_an_empty_line_does_not_repeat_the_last_command(run: Run) -> None:
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
def test_an_unknown_command_is_refused_and_not_echoed(run: Run, line: str) -> None:
    fake = run(line)
    assert cli.UNKNOWN_COMMAND in fake.text
    assert line not in fake.text


def test_an_overlong_line_is_refused_before_it_is_parsed(run: Run) -> None:
    fake = run("help" + " " * cli.MAX_LINE)
    assert f"Error: a line can be at most {cli.MAX_LINE} characters." in fake.text
    assert "Commands:" not in fake.text


def test_a_line_of_exactly_the_maximum_length_is_accepted(run: Run) -> None:
    fake = run("help".ljust(cli.MAX_LINE))
    assert "Commands:" in fake.text


def test_arguments_to_a_command_that_takes_none_are_refused_and_not_echoed(run: Run) -> None:
    fake = run("quit correct-horse-battery-staple", "help")
    assert "Error: quit takes no arguments." in fake.text
    assert "correct-horse" not in fake.text
    assert "Commands:" in fake.text  # still running


# --- Errors (T17) --------------------------------------------------------------------


def test_an_unexpected_error_gives_the_generic_message(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Repl, args: str) -> None:
        raise RuntimeError("detail: C:\\Users\\alice\\.yunarpass, key 00ff")

    monkeypatch.setattr(Repl, "help", broken)
    fake = run("help", "quit")
    assert cli.GENERIC_ERROR in fake.text
    for leak in ("detail", "alice", "00ff", "RuntimeError", "Traceback"):
        assert leak not in fake.text
    assert fake.text.count(cli.PROMPT) == 2  # still running


def test_an_error_written_for_the_user_shows_its_message(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_every_printed_line_is_sanitized(accounts: Accounts) -> None:
    fake = FakeConsole()
    Repl(accounts, fake.console()).say("\x1b[2Jfirst", "second\x1b]0;title\x07\r\n")
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


def test_main_refuses_a_data_directory_open_to_other_users(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    grant_others_read: Callable[[Path], None],
) -> None:
    data = tmp_path / "data"
    DataDir.open(data)
    grant_others_read(data)
    monkeypatch.setenv(storage.HOME_ENV, str(data))
    monkeypatch.setattr(sys, "stdin", io.StringIO("help\n"))
    assert cli.main([]) == 1
    out, err = capsys.readouterr()
    assert out == ""  # the prompt never started
    assert err == "Error: the data directory has permissions for other users.\n"


# --- register (UC1) ------------------------------------------------------------------

PASSWORD = "correct horse battery staple"
SHOWN_RECOVERY_KEY = re.compile(r"\n    ([A-Z2-7]{4}(?:-[A-Z2-7]{4}){7})\n")


def is_taken(accounts: Accounts, username: str) -> bool:
    try:
        accounts.check_new_username(username)
    except AccountError:
        return True
    return False


def test_register_creates_the_account_and_shows_the_recovery_key_once(
    run: Run, accounts: Accounts
) -> None:
    fake = run("register", "alice", "", secrets=[PASSWORD, PASSWORD])
    assert "Account created. This is your recovery key:" in fake.text
    assert len(SHOWN_RECOVERY_KEY.findall(fake.text)) == 1
    assert "It is shown only now and is not stored anywhere." in fake.text
    assert is_taken(accounts, "alice")


def test_register_reads_passwords_only_at_masked_prompts(run: Run) -> None:
    fake = run("register", "alice", "", secrets=[PASSWORD, PASSWORD])
    assert fake.secret_prompts == [
        "Master password (at least 12 characters): ",
        "Repeat the master password: ",
    ]
    assert "correct horse" not in fake.text


def test_register_refuses_two_different_passwords(run: Run, accounts: Accounts) -> None:
    fake = run("register", "alice", secrets=[PASSWORD, PASSWORD + "!"])
    assert "Error: the two passwords are different, so nothing was created." in fake.text
    assert list(accounts.data_dir.path.iterdir()) == []


def test_register_refuses_a_weak_password_before_asking_for_it_again(
    run: Run, accounts: Accounts
) -> None:
    fake = run("register", "alice", "register", "alice", secrets=["unbelievable", "too short"])
    assert "Error: the master password is one of the 10 000 most common passwords." in fake.text
    assert "Error: the master password must have at least 12 characters." in fake.text
    assert len(fake.secret_prompts) == 2  # once per attempt, never the repeat prompt
    assert list(accounts.data_dir.path.iterdir()) == []


def test_register_checks_the_username_before_asking_for_a_password(
    run: Run, accounts: Accounts
) -> None:
    accounts.register("alice", PASSWORD)
    fake = run("register", "alice", "register", "../alice", "register", "Alice")
    assert "Error: that username is taken." in fake.text
    assert fake.text.count("Error: a username has 3 to 32 characters") == 2
    assert fake.secret_prompts == []
    assert "../alice" not in fake.text


def test_register_takes_no_arguments(run: Run) -> None:
    fake = run("register alice")
    assert "Error: register takes no arguments." in fake.text
    assert fake.secret_prompts == []


def test_ctrl_c_after_the_recovery_key_is_shown_does_not_cancel_the_account(
    run: Run, accounts: Accounts
) -> None:
    fake = run("register", "alice", KeyboardInterrupt(), secrets=[PASSWORD, PASSWORD])
    assert "Cancelled." not in fake.text
    assert is_taken(accounts, "alice")


def test_ctrl_c_at_a_password_prompt_cancels_the_registration(run: Run, accounts: Accounts) -> None:
    fake = run("register", "alice", secrets=[KeyboardInterrupt()])
    assert "\nCancelled.\n" in fake.text
    assert not is_taken(accounts, "alice")
