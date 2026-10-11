"""The interactive prompt (REPL): the UI layer over the core (DESIGN.md §2).

- Commands come from an allow-list for the current state. A line longer than
  MAX_LINE characters is refused before it is parsed (T19).
- Secrets are read only at masked prompts. No command takes a secret as an
  argument, and the program takes no arguments at all, so a secret cannot end
  up in the shell history or the process list (T3, T16).
- Every line printed goes through sanitize() (text.py), which removes control
  characters and terminal escape sequences. Text from a user or a file cannot
  move the cursor, clear the screen or retitle the window (T19).
- An unexpected error becomes one generic message, never a traceback (T17).
  Ctrl-C cancels the command in progress; at the prompt, Ctrl-C and end of
  input exit cleanly.

It is a small loop rather than the standard library's cmd.Cmd, whose defaults
do not fit a password manager: an empty line repeats the last command, an
unknown command is printed back, and command names cannot contain a dash.
"""

import contextlib
import getpass
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from yunarpass import __version__, policy
from yunarpass.policy import PolicyError
from yunarpass.session import Session
from yunarpass.storage import DataDir, StorageError
from yunarpass.text import sanitize
from yunarpass.users import AccountError, Accounts, LoginError

MAX_LINE = 256  # characters in one command line

PROMPT = "yunarpass> "
LOGIN_FAILED = "Login failed."
GENERIC_ERROR = "Something went wrong and the command did not complete."
UNKNOWN_COMMAND = "Unknown command. Type help to see the commands."


def _write_stdout(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


@dataclass(frozen=True, slots=True)
class Console:
    """Where the REPL reads and writes. Tests pass their own functions."""

    read_line: Callable[[str], str] = input
    # getpass turns echo off, so a secret never appears on the screen (T3).
    read_secret: Callable[[str], str] = getpass.getpass
    write: Callable[[str], None] = _write_stdout


class UsageError(Exception):
    """A command was used wrongly. The message is safe to show."""


# Errors whose messages are fixed strings written to be shown to the user.
# Anything else is unexpected, and only the generic message is shown.
_SAFE_ERRORS = (UsageError, StorageError, AccountError, PolicyError)


class Command(NamedTuple):
    run: Callable[[str], None]  # called with the rest of the line
    summary: str


class Repl:
    """The read-eval-print loop."""

    def __init__(self, accounts: Accounts, console: Console | None = None) -> None:
        self.accounts = accounts
        self.console = Console() if console is None else console
        self.session: Session | None = None
        self.running = False

    @property
    def prompt(self) -> str:
        if self.session is None:
            return PROMPT
        return f"yunarpass:{self.session.username}> "

    def commands(self) -> dict[str, Command]:
        """The allow-list: the commands of the current state."""
        if self.session is None:
            return {
                "register": Command(self.register, "Create an account and its vault"),
                "login": Command(self.login, "Unlock your vault"),
                "help": Command(self.help, "Show this list"),
                "quit": Command(self.quit, "Exit"),
            }
        return {
            "help": Command(self.help, "Show this list"),
            "quit": Command(self.quit, "Lock the vault and exit"),
        }

    def say(self, *lines: str) -> None:
        """Print each argument as one line, sanitized."""
        self.console.write("".join(sanitize(line) + "\n" for line in lines))

    def run(self) -> int:
        """Read and run commands until quit, Ctrl-C or the end of input."""
        self.running = True
        self.say(f"yunarpass {__version__}. Type help to see the commands.")
        try:
            while self.running:
                try:
                    line = self.console.read_line(sanitize(self.prompt))
                except (EOFError, KeyboardInterrupt):
                    self.say("")  # end the prompt's line
                    break
                self.execute(line)
        finally:
            self.lock()  # however the loop ends, the DEK is wiped
        return 0

    def lock(self) -> None:
        """Close the session, if there is one: the DEK is wiped (T13)."""
        if self.session is not None:
            self.session.close()
            self.session = None
            self.say("Vault locked.")

    def execute(self, line: str) -> None:
        """Run one command line. Errors are reported here and never raised."""
        if len(line) > MAX_LINE:
            self.say(f"Error: a line can be at most {MAX_LINE} characters.")
            return
        words = line.split(maxsplit=1)
        if not words:
            return  # an empty line does nothing; it never repeats the last command
        command = self.commands().get(words[0])
        if command is None:
            # The line is not printed back: it may be a password typed at the
            # wrong prompt.
            self.say(UNKNOWN_COMMAND)
            return
        try:
            command.run(words[1].strip() if len(words) > 1 else "")
        except (EOFError, KeyboardInterrupt):
            self.say("", "Cancelled.")
        except _SAFE_ERRORS as error:
            self.say(f"Error: {error}.")
        except Exception:
            self.say(GENERIC_ERROR)

    def register(self, args: str) -> None:
        _no_arguments("register", args)
        username = self.console.read_line("Username: ").strip()
        # Checked before the password is typed, so a taken name costs no typing.
        self.accounts.check_new_username(username)
        password = self.console.read_secret(
            f"Master password (at least {policy.MIN_LENGTH} characters): "
        )
        policy.check_master_password(password)
        if self.console.read_secret("Repeat the master password: ") != password:
            raise UsageError("the two passwords are different, so nothing was created")
        self.say("Creating the vault...")
        recovery_key = self.accounts.register(username, password)
        del password
        self.say(
            "",
            "Account created. This is your recovery key:",
            "",
            f"    {recovery_key}",
            "",
            "Write it down on paper and keep it somewhere safe. If you forget the master",
            "password, it is the only way back into your vault, and anyone who has it can",
            "open the vault. It is shown only now and is not stored anywhere.",
        )
        # Pressing Ctrl-C here must not report the account as cancelled.
        with contextlib.suppress(EOFError, KeyboardInterrupt):
            self.console.read_line("Press Enter once you have written it down.")
        self.say("", "Log in with: login")

    def login(self, args: str) -> None:
        _no_arguments("login", args)
        username = self.console.read_line("Username: ").strip()
        password = self.console.read_secret("Master password: ")
        try:
            self.session = self.accounts.login(username, password)
        except LoginError:
            # One message for an unknown user, a wrong password and a damaged
            # vault (T4).
            self.say(LOGIN_FAILED)
            return
        finally:
            del password
        saved = self.session.counter
        # The counter lets the user notice an older copy put back in place (T9).
        self.say(f"Vault unlocked. Saved {saved} {'time' if saved == 1 else 'times'}.")

    def help(self, args: str) -> None:
        _no_arguments("help", args)
        commands = self.commands()
        width = max(map(len, commands))
        lines = (f"  {name:<{width}}  {command.summary}" for name, command in commands.items())
        self.say("Commands:", *lines)

    def quit(self, args: str) -> None:
        _no_arguments("quit", args)
        self.running = False


def _no_arguments(name: str, args: str) -> None:
    # The arguments are never printed: they might be a secret.
    if args:
        raise UsageError(f"{name} takes no arguments")


USAGE = """\
usage: yunarpass

Starts the yunarpass prompt; type help there to see the commands. yunarpass
takes no command-line arguments, so no secret is ever typed into the shell.
"""


def main(argv: Sequence[str] | None = None) -> int:
    """Run the program. Returns the exit status."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--version"]:
        print(f"yunarpass {__version__}")
        return 0
    if args in (["-h"], ["--help"]):
        print(USAGE, end="")
        return 0
    if args:
        # Not echoed: whatever was typed may be a secret.
        print(USAGE, end="", file=sys.stderr)
        return 2
    try:
        # Created owner-only, or checked and refused if it is a link or open to
        # other users, before anything else happens.
        accounts = Accounts(DataDir.open())
    except StorageError as error:
        print(f"Error: {error}.", file=sys.stderr)
        return 1
    try:
        return Repl(accounts).run()
    except KeyboardInterrupt:
        print()
        return 0
    except Exception:
        print(GENERIC_ERROR, file=sys.stderr)
        return 1
