"""The interactive prompt (REPL): the UI layer over the core (DESIGN.md §2).

- Commands come from an allow-list for the current state. A line longer than
  MAX_LINE characters is refused before it is parsed (T19).
- Secrets are read only at masked prompts. No command takes a secret as an
  argument, and the program takes no arguments at all, so a secret cannot end
  up in the shell history or the process list (T3, T16).
- Every line printed goes through sanitize() (text.py), which removes control
  characters and terminal escape sequences. Text from a user or a file cannot
  move the cursor, clear the screen or retitle the window (T19).
- Passwords are never printed (T25). A stored or generated password goes to
  the clipboard, which is cleared after 20 seconds, on lock and on exit (T18).
- An unexpected error becomes one generic message, never a traceback (T17).
  Ctrl-C cancels the command in progress; at the prompt, Ctrl-C and end of
  input exit cleanly.

It is a small loop rather than the standard library's cmd.Cmd, whose defaults
do not fit a password manager: an empty line repeats the last command, an
unknown command is printed back, and command names cannot contain a dash.
"""

import contextlib
import getpass
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from yunarpass import __version__, entries, policy, secrets_gen
from yunarpass.clipboard import ClipboardError, ClipboardGuard, system_clipboard
from yunarpass.entries import MASK, EntryError, EntryView
from yunarpass.policy import PolicyError
from yunarpass.session import Session, VaultLockedError
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
_SAFE_ERRORS = (
    UsageError,
    StorageError,
    AccountError,
    PolicyError,
    EntryError,
    VaultLockedError,
    ClipboardError,
)

# Typed at an entry's password prompt, it fills in a generated password.
GENERATE = "gen"


class Command(NamedTuple):
    run: Callable[[str], None]  # called with the rest of the line
    summary: str
    arguments: str = ""  # shown by help, e.g. "<name>"


class Repl:
    """The read-eval-print loop."""

    def __init__(
        self,
        accounts: Accounts,
        console: Console | None = None,
        clipboard: ClipboardGuard | None = None,
    ) -> None:
        self.accounts = accounts
        self.console = Console() if console is None else console
        self.clipboard = ClipboardGuard(system_clipboard()) if clipboard is None else clipboard
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
            "add": Command(self.add, "Add a login entry", "<name>"),
            "list": Command(self.list_entries, "List the entries"),
            "show": Command(self.show, "Show an entry; the password stays masked", "<name>"),
            "copy": Command(self.copy, "Copy an entry's password to the clipboard", "<name>"),
            "edit": Command(self.edit, "Change an entry", "<name>"),
            "rm": Command(self.rm, "Delete an entry", "<name>"),
            "gen": Command(self.gen, "Copy a new random password to the clipboard", "[length]"),
            "passwd": Command(self.passwd, "Change the master password"),
            "help": Command(self.help, "Show this list"),
            "quit": Command(self.quit, "Lock the vault and exit"),
        }

    def say(self, *lines: str) -> None:
        """Print each argument as one line, sanitized."""
        self.console.write("".join(sanitize(line) + "\n" for line in lines))

    def ask(self, prompt: str) -> str:
        """Read a line that is not a secret, without surrounding spaces."""
        return self.console.read_line(sanitize(prompt)).strip()

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
        """Clear our copy from the clipboard (T18) and close the session: the DEK is wiped (T13)."""
        try:
            self.clipboard.clear()
        except ClipboardError as error:
            self.say(f"Error: {error}.")
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

    def _unlocked(self) -> Session:
        if self.session is None:
            raise VaultLockedError
        return self.session

    def add(self, args: str) -> None:
        session = self._unlocked()
        # Each answer is checked as soon as it is typed, the name first.
        name = _entry_name("add", args)
        username = entries.check_username(self.ask("Username: "))
        typed = self.console.read_secret(f"Password (or {GENERATE} to generate one): ")
        password = self._entry_password(typed)
        url = entries.check_url(self.ask("URL: "))
        notes = entries.check_notes(self.ask("Notes: "))
        session.add(name, username=username, password=password, url=url, notes=notes)
        self.say(f"Added {name}.")

    def _entry_password(self, typed: str) -> str:
        """A generated password for "gen"; otherwise the typed one, checked and typed again."""
        if typed == GENERATE:
            self.say(
                f"Generated a {secrets_gen.DEFAULT_LENGTH}-character password. It is not shown;"
                " copy puts it on the clipboard."
            )
            return secrets_gen.generate_password()
        password = entries.check_password(typed)
        if self.console.read_secret("Repeat the password: ") != password:
            raise UsageError("the two passwords are different, so nothing was saved")
        return password

    def _only(self, command: str, args: str) -> EntryView:
        """The one entry named in the arguments."""
        session = self._unlocked()
        matches = session.find(_entry_name(command, args))
        if not matches:
            raise EntryError("there is no entry with that name")
        if len(matches) > 1:
            raise UsageError("several entries have that name")
        return session.view(matches[0].id)

    def list_entries(self, args: str) -> None:
        _no_arguments("list", args)
        summaries = self._unlocked().summaries()
        if not summaries:
            self.say("The vault is empty. Add an entry with: add <name>")
            return
        width = max(len(summary.name) for summary in summaries)
        count = len(summaries)
        self.say(
            f"{count} {'entry' if count == 1 else 'entries'}:",
            *(f"  {summary.name:<{width}}  {summary.type}" for summary in summaries),
        )

    def show(self, args: str) -> None:
        view = self._only("show", args)
        notes = view.notes.split("\n")
        rows = [
            ("Name", view.name),
            ("Type", view.type),
            ("Username", view.username),
            ("Password", MASK),  # always the mask: the view has no password (T25)
            ("URL", view.url),
            ("Created", _time(view.created)),
            ("Modified", _time(view.modified)),
            ("Notes", notes[0]),
        ]
        self.say(
            *(f"  {label + ':':<10}{value}".rstrip() for label, value in rows),
            *(f"  {'':<10}{line}".rstrip() for line in notes[1:]),
        )

    def edit(self, args: str) -> None:
        session = self._unlocked()
        view = self._only("edit", args)
        self.say(f"Editing {view.name}. Press Enter to keep a value, or type - to clear it.")
        new_name: str | None = self.ask(f"Name [{view.name}]: ")
        if not new_name or new_name == view.name:
            new_name = None
        else:
            entries.check_name(new_name)
        username = self._changed("Username", view.username, entries.check_username)
        typed = self.console.read_secret(
            f"Password (Enter keeps the current one, {GENERATE} generates a new one): "
        )
        password = self._entry_password(typed) if typed else None
        url = self._changed("URL", view.url, entries.check_url)
        notes = self._changed("Notes", view.notes, entries.check_notes)
        if (new_name, username, password, url, notes) == (None,) * 5:
            self.say("Nothing changed.")
            return
        session.update(
            view.id,
            name=new_name,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )
        self.say(f"Saved the changes to {new_name or view.name}.")

    def _changed(self, label: str, current: str, check: Callable[[str], str]) -> str | None:
        """Ask for a new value: None keeps the current one, and - clears it."""
        answer = self.ask(f"{label} [{_brief(current)}]: ")
        if not answer:
            return None
        value = check("" if answer == "-" else answer)
        return None if value == current else value

    def rm(self, args: str) -> None:
        session = self._unlocked()
        view = self._only("rm", args)
        if self.ask(f"Type {view.name} again to delete it: ") != view.name:
            self.say("The names are different, so nothing was deleted.")
            return
        session.remove(view.id)
        self.say(f"Deleted {view.name}.")

    def copy(self, args: str) -> None:
        session = self._unlocked()
        view = self._only("copy", args)
        name = view.name
        session.copy_password(view.id, self.clipboard)
        self.say(
            f"Copied the password of {name}. "
            f"The clipboard is cleared in {self.clipboard.seconds:g} seconds."
        )

    def gen(self, args: str) -> None:
        self._unlocked()
        length = _password_length(args)
        self.clipboard.copy(secrets_gen.generate_password(length))
        self.say(
            f"Copied a new {length}-character password. "
            f"The clipboard is cleared in {self.clipboard.seconds:g} seconds."
        )

    def passwd(self, args: str) -> None:
        _no_arguments("passwd", args)
        session = self._unlocked()
        current = self.console.read_secret("Current master password: ")
        new = self.console.read_secret(
            f"New master password (at least {policy.MIN_LENGTH} characters): "
        )
        policy.check_master_password(new)
        if self.console.read_secret("Repeat the new master password: ") != new:
            raise UsageError("the two new passwords are different, so nothing was changed")
        self.say("Changing the master password...")
        # The current password is checked here, in the same call: no
        # interface can change the password without it.
        self.accounts.change_password(session, current, new)
        del current, new
        self.say("Master password changed. Your recovery key stays the same.")

    def help(self, args: str) -> None:
        _no_arguments("help", args)
        usage = {
            f"{name} {command.arguments}".strip(): command.summary
            for name, command in self.commands().items()
        }
        width = max(map(len, usage))
        self.say("Commands:", *(f"  {form:<{width}}  {summary}" for form, summary in usage.items()))

    def quit(self, args: str) -> None:
        _no_arguments("quit", args)
        self.running = False


def _no_arguments(name: str, args: str) -> None:
    # The arguments are never printed: they might be a secret.
    if args:
        raise UsageError(f"{name} takes no arguments")


def _entry_name(command: str, args: str) -> str:
    """The one argument of an entry command. An invalid name is not printed back."""
    if not args:
        raise UsageError(f"{command} needs the name of an entry: {command} <name>")
    return entries.check_name(args)


_LENGTH = re.compile(r"[0-9]{1,3}")


def _password_length(args: str) -> int:
    """The optional argument of gen. A refused argument is not printed back."""
    if not args:
        return secrets_gen.DEFAULT_LENGTH
    if _LENGTH.fullmatch(args) and (secrets_gen.MIN_LENGTH <= int(args) <= secrets_gen.MAX_LENGTH):
        return int(args)
    raise UsageError(
        f"gen takes a length from {secrets_gen.MIN_LENGTH} to {secrets_gen.MAX_LENGTH}: "
        "gen [length]"
    )


def _time(stamp: str) -> str:
    """2026-10-11T15:02:03Z as 2026-10-11 15:02 UTC."""
    return f"{stamp[:10]} {stamp[11:16]} UTC"


def _brief(value: str, limit: int = 40) -> str:
    """The start of a value, short enough to show in a prompt."""
    first = value.split("\n", 1)[0]
    return value if first == value and len(value) <= limit else first[:limit] + "..."


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
