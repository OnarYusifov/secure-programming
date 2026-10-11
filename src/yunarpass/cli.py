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
- After five minutes without input the vault locks itself (T15): a timer
  thread wipes the DEK and clears the clipboard. The line typed next is not
  run; the user is told that the vault locked instead. Input that arrives
  after the timeout, such as on a computer that slept, locks the vault before
  anything else happens.
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
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from yunarpass import __version__, entries, policy, secrets_gen
from yunarpass.autolock import IdleTimer
from yunarpass.clipboard import (
    CallLater,
    Cancel,
    ClipboardError,
    ClipboardGuard,
    system_clipboard,
    thread_timer,
)
from yunarpass.entries import MASK, EntryError, EntrySummary, EntryView
from yunarpass.policy import PolicyError
from yunarpass.session import Session, VaultLockedError
from yunarpass.storage import DataDir, StorageError
from yunarpass.text import sanitize
from yunarpass.users import AccountError, Accounts, LoginError

MAX_LINE = 256  # characters in one command line

PROMPT = "yunarpass> "
LOGIN_FAILED = "Login failed."
RECOVERY_FAILED = "Recovery failed."
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
# How an entry command names its entry: a name, or the start of an ID.
_REF = "<name or ID>"


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
        idle: IdleTimer | None = None,
        call_later: CallLater | None = None,
    ) -> None:
        self.accounts = accounts
        self.console = Console() if console is None else console
        self.clipboard = ClipboardGuard(system_clipboard()) if clipboard is None else clipboard
        self.idle = IdleTimer() if idle is None else idle
        self._call_later = thread_timer if call_later is None else call_later
        self.session: Session | None = None
        self.running = False
        # Auto-lock (T15). The idle check runs on a timer thread; _state guards
        # the session and the fields below between it and the loop. It is
        # never held while waiting for input.
        self._state = threading.Lock()
        self._watch = 0  # counts up whenever a session starts or ends
        self._stop_watch: Cancel | None = None
        self._auto_locked = False

    @property
    def prompt(self) -> str:
        session = self.session  # read once: the timer may clear it at any time
        if session is None:
            return PROMPT
        return f"yunarpass:{session.username}> "

    def commands(self) -> dict[str, Command]:
        """The allow-list: the commands of the current state."""
        if self.session is None:
            return {
                "register": Command(self.register, "Create an account and its vault"),
                "login": Command(self.login, "Unlock your vault"),
                "recover": Command(
                    self.recover, "Unlock with the recovery key and set a new master password"
                ),
                "help": Command(self.help, "Show this list"),
                "quit": Command(self.quit, "Exit"),
            }
        return {
            "add": Command(self.add, "Add a login entry", "<name>"),
            "list": Command(self.list_entries, "List the entries"),
            "show": Command(self.show, "Show an entry; the password stays masked", _REF),
            "copy": Command(self.copy, "Copy an entry's password to the clipboard", _REF),
            "edit": Command(self.edit, "Change an entry", _REF),
            "rm": Command(self.rm, "Delete an entry", _REF),
            "gen": Command(self.gen, "Copy a new random password to the clipboard", "[length]"),
            "passwd": Command(self.passwd, "Change the master password"),
            "lock": Command(self.lock, "Lock the vault and clear the clipboard"),
            "help": Command(self.help, "Show this list"),
            "quit": Command(self.quit, "Lock the vault and exit"),
        }

    def say(self, *lines: str) -> None:
        """Print each argument as one line, sanitized."""
        self.console.write("".join(sanitize(line) + "\n" for line in lines))

    def ask(self, prompt: str) -> str:
        """Read a line that is not a secret, without surrounding spaces."""
        return self.read_line(sanitize(prompt)).strip()

    def read_line(self, prompt: str) -> str:
        """Read a line. Any input, even Ctrl-C, counts as activity for auto-lock."""
        try:
            return self.console.read_line(prompt)
        finally:
            self._input_arrived()

    def read_secret(self, prompt: str) -> str:
        """Read a secret at a masked prompt. Counts as activity, like read_line."""
        try:
            return self.console.read_secret(prompt)
        finally:
            self._input_arrived()

    def run(self) -> int:
        """Read and run commands until quit, Ctrl-C or the end of input."""
        self.running = True
        self.say(f"yunarpass {__version__}. Type help to see the commands.")
        try:
            while self.running:
                try:
                    line = self.read_line(sanitize(self.prompt))
                except (EOFError, KeyboardInterrupt):
                    self.say("")  # end the prompt's line
                    break
                self.execute(line)
        finally:
            self.lock()  # however the loop ends, the DEK is wiped
        return 0

    def lock(self, args: str = "") -> None:
        """The lock command, also run whenever the loop ends: back to the login prompt."""
        _no_arguments("lock", args)
        with self._state:
            session = self._detach()
        try:
            self._close(session)
        except ClipboardError as error:
            self.say(f"Error: {error}.")
        if session is not None:
            self.say("Vault locked.")

    def _close(self, session: Session | None) -> None:
        """Wipe the session's DEK (T13), then clear our copy from the clipboard (T18).

        In this order: closing waits for a copy in progress to finish, and the
        clear then takes that copy off the clipboard too. Raises
        ClipboardError, after the session is closed.
        """
        if session is not None:
            session.close()
        self.clipboard.clear()

    # --- Auto-lock (UC6, T15) ----------------------------------------------------------

    def _unlock(self, session: Session) -> None:
        """Make the session current, to be locked once the user is idle for too long."""
        with self._state:
            self.session = session
            self.idle.touch()
            self._watch += 1
            self._schedule(self._watch)

    def _schedule(self, watch: int) -> None:
        # Called with self._state held.
        self._stop_watch = self._call_later(self.idle.remaining(), lambda: self._check_idle(watch))

    def _check_idle(self, watch: int) -> None:
        """On the timer's thread: lock the vault if the user has been idle long enough.

        Nothing is printed here, because the loop is waiting for input on the
        main thread. The next line typed gets the notice instead.
        """
        with self._state:
            if watch != self._watch:
                return  # set for a session that has ended since
            if not self.idle.expired():
                self._schedule(watch)  # there was input since: check again when it can be due
                return
            session = self._detach(auto=True)
        self._close_quietly(session)

    def _input_arrived(self) -> None:
        """Count an input as activity, unless the vault has been idle too long already.

        The timer can run late, for example on a computer that slept, so the
        idle time is checked here as well: input that comes after the timeout
        never reaches the unlocked vault.
        """
        with self._state:
            expired = self.session is not None and self.idle.expired()
            session = self._detach(auto=True) if expired else None
            self.idle.touch()
        if session is not None:
            self._close_quietly(session)

    def _detach(self, *, auto: bool = False) -> Session | None:
        """Take the session out of use and stop watching it. Called with self._state held."""
        session, self.session = self.session, None
        self._watch += 1
        if self._stop_watch is not None:
            self._stop_watch()
            self._stop_watch = None
        if auto and session is not None:
            self._auto_locked = True
        return session

    def _close_quietly(self, session: Session | None) -> None:
        # A clipboard error has nobody to go to here. The guard keeps its copy
        # and tries again at the next lock or at exit, which report errors.
        with contextlib.suppress(ClipboardError):
            self._close(session)

    def _report_auto_lock(self) -> bool:
        """Say once that the vault locked itself. Returns whether it had."""
        with self._state:
            locked, self._auto_locked = self._auto_locked, False
        if locked:
            self.say(
                f"Vault locked after {_duration(self.idle.timeout)} without input. "
                "Log in again to continue."
            )
        return locked

    # --- Commands ----------------------------------------------------------------------

    def execute(self, line: str) -> None:
        """Run one command line. Errors are reported here and never raised.

        A line typed after the vault locked itself is not run: it was meant
        for the unlocked vault. The user is told what happened instead.
        """
        if self._report_auto_lock():
            return
        self._run(line)
        self._report_auto_lock()  # if it locked while the command waited for input

    def _run(self, line: str) -> None:
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
        username = self.read_line("Username: ").strip()
        # Checked before the password is typed, so a taken name costs no typing.
        self.accounts.check_new_username(username)
        password = self.read_secret(f"Master password (at least {policy.MIN_LENGTH} characters): ")
        policy.check_master_password(password)
        if self.read_secret("Repeat the master password: ") != password:
            raise UsageError("the two passwords are different, so nothing was created")
        self.say("Creating the vault...")
        recovery_key = self.accounts.register(username, password)
        del password
        self._show_recovery_key("Account created. This is your recovery key:", recovery_key)
        self.say("", "Log in with: login")

    def _show_recovery_key(self, heading: str, recovery_key: str) -> None:
        """Print a recovery key, the one time it is shown, and wait until it is written down."""
        self.say(
            "",
            heading,
            "",
            f"    {recovery_key}",
            "",
            "Write it down on paper and keep it somewhere safe. If you forget the master",
            "password, it is the only way back into your vault, and anyone who has it can",
            "open the vault. It is shown only now and is not stored anywhere.",
        )
        # Pressing Ctrl-C here must not report the command as cancelled: it
        # has already been carried out.
        with contextlib.suppress(EOFError, KeyboardInterrupt):
            self.read_line("Press Enter once you have written it down.")

    def login(self, args: str) -> None:
        _no_arguments("login", args)
        username = self.read_line("Username: ").strip()
        password = self.read_secret("Master password: ")
        try:
            session = self.accounts.login(username, password)
        except LoginError:
            # One message for an unknown user, a wrong password and a damaged
            # vault (T4).
            self.say(LOGIN_FAILED)
            return
        finally:
            del password
        self._unlock(session)
        self._say_unlocked(session)

    def _say_unlocked(self, session: Session) -> None:
        saved = session.counter
        # The counter lets the user notice an older copy put back in place (T9).
        self.say(f"Vault unlocked. Saved {saved} {'time' if saved == 1 else 'times'}.")

    def recover(self, args: str) -> None:
        _no_arguments("recover", args)
        username = self.read_line("Username: ").strip()
        # Masked like a password: whoever sees the key can open the vault (T5).
        key = self.read_secret("Recovery key: ")
        new = self.read_secret(f"New master password (at least {policy.MIN_LENGTH} characters): ")
        policy.check_master_password(new)
        if self.read_secret("Repeat the new master password: ") != new:
            raise UsageError("the two new passwords are different, so nothing was changed")
        self.say("Checking the recovery key...")
        try:
            session, recovery_key = self.accounts.recover(username, key, new)
        except LoginError:
            # One message for an unknown user, a wrong or malformed key and a
            # damaged vault (T4).
            self.say(RECOVERY_FAILED)
            return
        finally:
            del key, new
        # Watched from now on, while the key is on the screen: a user who walks
        # away from it still gets the auto-lock.
        self._unlock(session)
        self._show_recovery_key(
            "Master password changed. The old recovery key no longer works; this is the new one:",
            recovery_key,
        )
        self._say_unlocked(session)

    def _unlocked(self) -> Session:
        session = self.session  # read once: the timer may clear it at any time
        if session is None:
            raise VaultLockedError
        return session

    def add(self, args: str) -> None:
        session = self._unlocked()
        # Each answer is checked as soon as it is typed, the name first.
        name = _entry_name("add", args)
        username = entries.check_username(self.ask("Username: "))
        typed = self.read_secret(f"Password (or {GENERATE} to generate one): ")
        password = self._entry_password(typed)
        url = entries.check_url(self.ask("URL: "))
        notes = entries.check_notes(self.ask("Notes: "))
        added = session.add(name, username=username, password=password, url=url, notes=notes)
        self.say(f"Added {name} ({added.short_id}).")

    def _entry_password(self, typed: str) -> str:
        """A generated password for "gen"; otherwise the typed one, checked and typed again."""
        if typed == GENERATE:
            self.say(
                f"Generated a {secrets_gen.DEFAULT_LENGTH}-character password. It is not shown;"
                " copy puts it on the clipboard."
            )
            return secrets_gen.generate_password()
        password = entries.check_password(typed)
        if self.read_secret("Repeat the password: ") != password:
            raise UsageError("the two passwords are different, so nothing was saved")
        return password

    def _pick(self, command: str, args: str, *, change: bool) -> EntryView | None:
        """The entry the user means by a name or an ID, or None if none was chosen (T29).

        If several entries match, a command that changes or deletes one stops
        and shows their IDs; one that only reads asks which one is meant.
        """
        session = self._unlocked()
        ref = _entry_ref(command, args)
        matches = session.find(ref)
        if not matches:
            raise EntryError("there is no entry with that name or ID")
        if len(matches) == 1:
            return session.view(matches[0].id)
        if all(entries.key(match.name) == entries.key(ref) for match in matches):
            heading = f"{len(matches)} entries are named {ref}:"
        else:
            heading = f"{len(matches)} entries have an ID that starts with {ref.lower()}:"
        rows = _rows(matches)
        if change:
            self.say(
                heading,
                *(f"  {row}" for row in rows),
                "To change or delete one of them, use its ID, "
                f"for example: {command} {matches[0].short_id}",
            )
            return None
        self.say(heading, *(f"  {number}) {row}" for number, row in enumerate(rows, 1)))
        answer = self.ask(f"Which one (1-{len(matches)}, Enter cancels)? ")
        if not answer:
            self.say("Cancelled.")
            return None
        if not _NUMBER.fullmatch(answer) or not 1 <= int(answer) <= len(matches):
            raise UsageError(f"type a number from 1 to {len(matches)}")
        return session.view(matches[int(answer) - 1].id)

    def list_entries(self, args: str) -> None:
        _no_arguments("list", args)
        summaries = self._unlocked().summaries()
        if not summaries:
            self.say("The vault is empty. Add an entry with: add <name>")
            return
        count = len(summaries)
        self.say(
            f"{count} {'entry' if count == 1 else 'entries'}:",
            *(f"  {row}" for row in _rows(summaries)),
        )

    def show(self, args: str) -> None:
        view = self._pick("show", args, change=False)
        if view is None:
            return
        notes = view.notes.split("\n")
        self.say(
            *_fields(
                ("ID", view.short_id),
                ("Name", view.name),
                ("Type", view.type),
                ("Username", view.username),
                ("Password", MASK),  # always the mask: the view has no password (T25)
                ("URL", view.url),
                ("Created", _time(view.created)),
                ("Modified", _time(view.modified)),
                ("Notes", notes[0]),
            ),
            *(f"  {'':<10}{line}".rstrip() for line in notes[1:]),
        )

    def edit(self, args: str) -> None:
        session = self._unlocked()
        view = self._pick("edit", args, change=True)
        if view is None:
            return
        self.say(
            f"Editing {view.name} ({view.short_id}). "
            "Press Enter to keep a value, or type - to clear it."
        )
        new_name: str | None = self.ask(f"Name [{view.name}]: ")
        if not new_name or new_name == view.name:
            new_name = None
        else:
            entries.check_name(new_name)
        username = self._changed("Username", view.username, entries.check_username)
        typed = self.read_secret(
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
        self.say(f"Saved the changes to {new_name or view.name} ({view.short_id}).")

    def _changed(self, label: str, current: str, check: Callable[[str], str]) -> str | None:
        """Ask for a new value: None keeps the current one, and - clears it."""
        answer = self.ask(f"{label} [{_brief(current)}]: ")
        if not answer:
            return None
        value = check("" if answer == "-" else answer)
        return None if value == current else value

    def rm(self, args: str) -> None:
        session = self._unlocked()
        view = self._pick("rm", args, change=True)
        if view is None:
            return
        # The entry itself, so the user sees which one they are about to lose.
        self.say(
            *_fields(
                ("ID", view.short_id),
                ("Name", view.name),
                ("Username", view.username),
                ("URL", view.url),
            )
        )
        if self.ask("Type yes to delete this entry: ").lower() != "yes":
            self.say("Nothing was deleted.")
            return
        session.remove(view.id)
        self.say(f"Deleted {view.name} ({view.short_id}).")

    def copy(self, args: str) -> None:
        session = self._unlocked()
        view = self._pick("copy", args, change=False)
        if view is None:
            return
        session.copy_password(view.id, self.clipboard)
        self.say(
            f"Copied the password of {view.name} ({view.short_id}). "
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
        current = self.read_secret("Current master password: ")
        new = self.read_secret(f"New master password (at least {policy.MIN_LENGTH} characters): ")
        policy.check_master_password(new)
        if self.read_secret("Repeat the new master password: ") != new:
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
    """The name argument of add. An invalid name is not printed back."""
    if not args:
        raise UsageError(f"{command} needs the name of the new entry: {command} <name>")
    return entries.check_name(args)


def _entry_ref(command: str, args: str) -> str:
    """A name or an ID, the argument of an entry command. An invalid one is not printed back."""
    if not args:
        raise UsageError(f"{command} needs an entry's name or ID: {command} {_REF}")
    return entries.check_name(args)  # an ID is letters and digits, so it passes too


def _rows(summaries: list[EntrySummary]) -> list[str]:
    """One aligned line per entry: short ID, name, type and username."""
    id_width = max(len(s.short_id) for s in summaries)
    name_width = max(len(s.name) for s in summaries)
    type_width = max(len(s.type) for s in summaries)
    return [
        f"{s.short_id:<{id_width}}  {s.name:<{name_width}}  {s.type:<{type_width}}  "
        f"{_brief(s.username)}".rstrip()
        for s in summaries
    ]


def _fields(*rows: tuple[str, str]) -> list[str]:
    """Label and value pairs as aligned lines."""
    return [f"  {label + ':':<10}{value}".rstrip() for label, value in rows]


# Only ASCII digits: str.isdigit() would also accept "²" or "٣".
_NUMBER = re.compile(r"[0-9]{1,3}")


def _password_length(args: str) -> int:
    """The optional argument of gen. A refused argument is not printed back."""
    if not args:
        return secrets_gen.DEFAULT_LENGTH
    if _NUMBER.fullmatch(args) and (secrets_gen.MIN_LENGTH <= int(args) <= secrets_gen.MAX_LENGTH):
        return int(args)
    raise UsageError(
        f"gen takes a length from {secrets_gen.MIN_LENGTH} to {secrets_gen.MAX_LENGTH}: "
        "gen [length]"
    )


def _duration(seconds: float) -> str:
    """300 as "5 minutes", 90 as "90 seconds"."""
    if seconds >= 60 and seconds % 60 == 0:
        minutes = int(seconds // 60)
        return f"{minutes} {'minute' if minutes == 1 else 'minutes'}"
    return f"{seconds:g} {'second' if seconds == 1 else 'seconds'}"


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
