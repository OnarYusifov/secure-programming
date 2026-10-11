"""Tests for the REPL (threats T3, T16, T17, T19, T25, T28)."""

import getpass
import io
import re
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol

import pytest

from yunarpass import __version__, cli, entries, storage, vaultfile
from yunarpass.cli import Console, Repl
from yunarpass.session import Session
from yunarpass.storage import DataDir, StorageError
from yunarpass.users import AccountError, Accounts, Backoff
from yunarpass.vaultfile import Body

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


def no_sleep(seconds: float) -> None:
    pass  # the login delay itself is tested in test_users.py


@pytest.fixture
def accounts(tmp_path: Path) -> Accounts:
    return Accounts(DataDir.open(tmp_path / "data"), Backoff(sleep=no_sleep))


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
        "  login     Unlock your vault\n"
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


# --- Output sanitizer (T19; the rules themselves are in test_text.py) ---------------


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


def test_register_then_login_end_to_end(run: Run) -> None:
    fake = run("register", "alice", "", "login", "alice", secrets=[PASSWORD] * 3)
    assert "\nLog in with: login\n" in fake.text
    assert "Vault unlocked. Saved 0 times.\n" in fake.text
    assert "correct horse" not in fake.text


# --- login (UC2) ---------------------------------------------------------------------


@pytest.fixture
def alice(accounts: Accounts) -> None:
    accounts.register("alice", PASSWORD)


@pytest.mark.usefixtures("alice")
def test_login_unlocks_the_vault_and_shows_the_counter(run: Run) -> None:
    fake = run("login", "alice", secrets=[PASSWORD])
    assert fake.secret_prompts == ["Master password: "]
    assert "Vault unlocked. Saved 0 times.\n" in fake.text
    # The prompt names the user; at the end of the input the vault is locked.
    assert fake.text.endswith("Saved 0 times.\nyunarpass:alice> \nVault locked.\n")


def test_one_save_is_singular(
    run: Run, accounts: Accounts, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, dek = vaultfile.create("alice", PASSWORD, bytes(20), Body(1, ()))
    monkeypatch.setattr(
        accounts, "login", lambda *args: Session(vault, dek, Body(1, ()), accounts.data_dir)
    )
    fake = run("login", "alice", secrets=[PASSWORD])
    assert "Vault unlocked. Saved 1 time.\n" in fake.text


@pytest.mark.usefixtures("alice")
def test_a_failed_login_looks_the_same_for_a_wrong_password_and_an_unknown_user(
    run: Run,
) -> None:
    wrong_password = run("login", "alice", secrets=["a wrong password"])
    unknown_user = run("login", "bob", secrets=[PASSWORD])
    assert wrong_password.text == unknown_user.text
    assert f"Master password: {cli.LOGIN_FAILED}\n{cli.PROMPT}" in wrong_password.text
    assert "unlocked" not in wrong_password.text


@pytest.mark.usefixtures("alice")
def test_login_takes_no_arguments(run: Run) -> None:
    fake = run("login alice correct-horse-battery-staple")
    assert "Error: login takes no arguments." in fake.text
    assert "correct-horse" not in fake.text
    assert fake.secret_prompts == []


@pytest.mark.usefixtures("alice")
def test_unlocked_the_prompt_offers_only_the_unlocked_commands(run: Run) -> None:
    fake = run("login", "alice", "help", "register", "login", secrets=[PASSWORD])
    assert (
        "Commands:\n"
        "  add <name>   Add a login entry\n"
        "  list         List the entries\n"
        "  show <name>  Show an entry; the password stays masked\n"
        "  edit <name>  Change an entry\n"
        "  rm <name>    Delete an entry\n"
        "  help         Show this list\n"
        "  quit         Lock the vault and exit\n"
    ) in fake.text
    assert fake.text.count(cli.UNKNOWN_COMMAND) == 2


@pytest.mark.usefixtures("alice")
@pytest.mark.parametrize("leave", ["quit", KeyboardInterrupt(), None])
def test_leaving_the_prompt_locks_the_vault(
    accounts: Accounts, monkeypatch: pytest.MonkeyPatch, leave: Typed | None
) -> None:
    closed: list[Session] = []
    close = Session.close

    def logged_close(self: Session) -> None:
        closed.append(self)
        close(self)

    monkeypatch.setattr(Session, "close", logged_close)
    lines: list[Typed] = ["login", "alice"]
    if leave is not None:  # None: the input simply ends
        lines.append(leave)
    fake = FakeConsole(lines, [PASSWORD])
    repl = Repl(accounts, fake.console())
    assert repl.run() == 0
    assert repl.session is None
    assert len(closed) == 1
    assert fake.text.endswith("Vault locked.\n")


# --- Entries (UC3; T19, T25, T28) ----------------------------------------------------

SECRET = "s3cret-Password!"
ADD_GITHUB = ("add github", "alice@example.com", "https://github.com", "personal")


def unlocked(run: Run, *lines: Typed, secrets: Iterable[Typed] = ()) -> FakeConsole:
    """Log in as alice, then type the lines."""
    return run("login", "alice", *lines, secrets=[PASSWORD, *secrets])


@pytest.mark.usefixtures("alice")
def test_add_then_list_and_show(run: Run) -> None:
    fake = unlocked(run, *ADD_GITHUB, "list", "show github", secrets=[SECRET, SECRET])
    assert fake.secret_prompts == ["Master password: ", "Password: ", "Repeat the password: "]
    assert "Added github.\n" in fake.text
    assert "1 entry:\n  github  login\n" in fake.text
    assert re.search(
        r"  Name:     github\n"
        r"  Type:     login\n"
        r"  Username: alice@example\.com\n"
        r"  Password: \*{8}\n"
        r"  URL:      https://github\.com\n"
        r"  Created:  [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC\n"
        r"  Modified: [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC\n"
        r"  Notes:    personal\n",
        fake.text,
    )


@pytest.mark.usefixtures("alice")
def test_no_password_is_ever_printed(run: Run) -> None:
    new = "an0ther-Secret!"
    fake = unlocked(
        run,
        *ADD_GITHUB,
        "show github",
        "list",
        "edit github",
        "",
        "",
        "",
        "",
        "show github",
        secrets=[SECRET, SECRET, new, new],
    )
    assert "Saved the changes to github.\n" in fake.text
    assert fake.text.count("  Password: ********\n") == 2
    for secret in (SECRET, new, PASSWORD):
        assert secret not in fake.text


@pytest.mark.usefixtures("alice")
def test_entries_persist_after_quit(run: Run) -> None:
    unlocked(run, *ADD_GITHUB, "quit", secrets=[SECRET, SECRET])
    fake = unlocked(run, "list")
    assert "Vault unlocked. Saved 1 time.\n" in fake.text
    assert "  github  login\n" in fake.text


@pytest.mark.usefixtures("alice")
def test_list_of_an_empty_vault(run: Run) -> None:
    fake = unlocked(run, "list")
    assert "The vault is empty. Add an entry with: add <name>\n" in fake.text


@pytest.mark.usefixtures("alice")
def test_list_takes_no_arguments(run: Run) -> None:
    fake = unlocked(run, "list secret-word")
    assert "Error: list takes no arguments.\n" in fake.text
    assert "secret-word" not in fake.text


@pytest.mark.usefixtures("alice")
@pytest.mark.parametrize("command", ["add", "show", "edit", "rm"])
def test_an_entry_command_needs_a_name(run: Run, command: str) -> None:
    fake = unlocked(run, command)
    assert f"Error: {command} needs the name of an entry: {command} <name>.\n" in fake.text


@pytest.mark.usefixtures("alice")
@pytest.mark.parametrize("command", ["add", "show", "edit", "rm"])
@pytest.mark.parametrize("name", ["../secret-name", "secret name", "\x1b[2Jsecret-name"])
def test_a_name_off_the_allow_list_is_refused_and_not_echoed(
    run: Run, command: str, name: str
) -> None:
    fake = unlocked(run, f"{command} {name}")
    assert f"Error: {entries.NAME_RULE}.\n" in fake.text
    assert "secret" not in fake.text
    assert fake.secret_prompts == ["Master password: "]


@pytest.mark.usefixtures("alice")
@pytest.mark.parametrize("command", ["show github", "edit github", "rm github"])
def test_an_unknown_entry_is_refused(run: Run, command: str) -> None:
    fake = unlocked(run, command)
    assert "Error: there is no entry with that name.\n" in fake.text


@pytest.mark.usefixtures("alice")
def test_add_refuses_a_taken_name_before_asking_anything(run: Run) -> None:
    fake = unlocked(run, *ADD_GITHUB, "add GitHub", secrets=[SECRET, SECRET])
    assert "Error: an entry with that name already exists.\n" in fake.text
    assert fake.text.count("Username: ") == 2  # at login and in the first add only


@pytest.mark.usefixtures("alice")
def test_add_refuses_two_different_passwords_and_saves_nothing(run: Run) -> None:
    fake = unlocked(run, "add github", "alice", "list", secrets=[SECRET, SECRET + "!"])
    assert "Error: the two passwords are different, so nothing was saved.\n" in fake.text
    assert "URL: " not in fake.text
    assert "The vault is empty." in fake.text


@pytest.mark.usefixtures("alice")
def test_add_refuses_an_empty_password_before_asking_again(run: Run) -> None:
    fake = unlocked(run, "add github", "alice", secrets=[""])
    assert "Error: an entry needs a password.\n" in fake.text
    assert "Repeat the password: " not in fake.text


@pytest.mark.usefixtures("alice")
@pytest.mark.parametrize(
    ("username", "error"),
    [
        ("x" * 257, "the username can have at most 256 characters"),
        ("alice\x1b[2J", "the username contains a control character"),
    ],
)
def test_add_checks_each_answer_as_it_is_typed(run: Run, username: str, error: str) -> None:
    fake = unlocked(run, "add github", username)
    assert f"Error: {error}.\n" in fake.text
    assert fake.secret_prompts == ["Master password: "]  # no entry password asked for


@pytest.mark.usefixtures("alice")
def test_edit_keeps_on_enter_clears_on_a_dash_and_renames(run: Run) -> None:
    fake = unlocked(
        run,
        *ADD_GITHUB,
        "edit github",
        "code",  # name
        "-",  # username: cleared
        "https://example.com",  # URL
        "",  # notes: kept
        "show code",
        "list",
        secrets=[SECRET, SECRET, ""],  # Enter keeps the password
    )
    for prompt in (
        "Name [github]: ",
        "Username [alice@example.com]: ",
        "URL [https://github.com]: ",
        "Notes [personal]: ",
    ):
        assert prompt in fake.text
    assert fake.secret_prompts[-1] == "Password (Enter keeps the current one): "
    assert "Saved the changes to code.\n" in fake.text
    assert "  Username:\n" in fake.text
    assert "  URL:      https://example.com\n" in fake.text
    assert "  Notes:    personal\n" in fake.text
    assert "1 entry:\n  code  login\n" in fake.text


@pytest.mark.usefixtures("alice")
def test_edit_without_changes_saves_nothing(run: Run) -> None:
    lines = ("edit github", "github", "", "https://github.com", "")  # the same values
    fake = unlocked(run, *ADD_GITHUB, *lines, secrets=[SECRET, SECRET, ""])
    assert "Nothing changed.\n" in fake.text
    assert "Vault unlocked. Saved 1 time.\n" in unlocked(run).text


@pytest.mark.usefixtures("alice")
def test_edit_can_change_the_password(run: Run, accounts: Accounts) -> None:
    new = "an0ther-Secret!"
    unlocked(run, *ADD_GITHUB, "edit github", "", "", "", "", secrets=[SECRET, SECRET, new, new])
    session = accounts.login("alice", PASSWORD)
    assert session._entries["github"].password == new


@pytest.mark.usefixtures("alice")
def test_edit_refuses_a_rename_onto_another_entry(run: Run) -> None:
    fake = unlocked(
        run,
        *ADD_GITHUB,
        "add mail",
        "",
        "",
        "",
        "edit github",
        "MAIL",
        secrets=[SECRET] * 4,
    )
    assert "Error: an entry with that name already exists.\n" in fake.text
    assert "Username [alice@example.com]: " not in fake.text  # it stopped at the name


@pytest.mark.usefixtures("alice")
def test_edit_cannot_clear_the_name(run: Run) -> None:
    fake = unlocked(run, *ADD_GITHUB, "edit github", "-", secrets=[SECRET, SECRET])
    assert f"Error: {entries.NAME_RULE}.\n" in fake.text


@pytest.mark.usefixtures("alice")
def test_rm_needs_the_name_typed_again(run: Run) -> None:
    fake = unlocked(
        run,
        *ADD_GITHUB,
        "rm github",
        "gihtub",
        "list",
        "rm GITHUB",
        "github",
        "list",
        secrets=[SECRET, SECRET],
    )
    assert fake.text.count("Type github again to delete it: ") == 2
    assert "The names are different, so nothing was deleted.\n" in fake.text
    assert "1 entry:\n  github  login\n" in fake.text
    assert "Deleted github.\n" in fake.text
    assert fake.text.rstrip().endswith(
        "The vault is empty. Add an entry with: add <name>\nyunarpass:alice> \nVault locked."
    )


@pytest.mark.usefixtures("alice")
def test_notes_with_line_breaks_are_shown_line_by_line(run: Run, accounts: Accounts) -> None:
    session = accounts.login("alice", PASSWORD)
    session.add("github", username="", password=SECRET, url="", notes="first\nsecond")
    session.close()
    fake = unlocked(run, "show github")
    assert "  Notes:    first\n            second\n" in fake.text


def test_a_prompt_shows_only_the_start_of_a_long_value() -> None:
    assert cli._brief("short") == "short"
    assert cli._brief("x" * 40) == "x" * 40
    assert cli._brief("x" * 41) == "x" * 40 + "..."
    assert cli._brief("first\nsecond") == "first..."


@pytest.mark.usefixtures("alice")
def test_two_prompts_do_not_overwrite_each_others_entries(accounts: Accounts) -> None:
    typed = (["alice", "", "", ""], [PASSWORD, SECRET, SECRET])
    one, two = FakeConsole(*typed), FakeConsole(*typed)
    first, second = Repl(accounts, one.console()), Repl(accounts, two.console())
    first.execute("login")
    second.execute("login")
    first.execute("add github")
    second.execute("add mail")
    assert "Added github.\n" in one.text
    assert (
        "Error: the vault file was changed by another session since you logged in, "
        "so this change was not saved; log in again to continue.\n"
    ) in two.text
    assert [s.name for s in accounts.login("alice", PASSWORD).summaries()] == ["github"]
