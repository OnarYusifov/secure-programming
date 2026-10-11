"""The interactive prompt (REPL): the UI layer over the core (DESIGN.md §2).

- Commands come from an allow-list for the current state. A line longer than
  MAX_LINE characters is refused before it is parsed (T19).
- Secrets are read only at masked prompts. No command takes a secret as an
  argument, and the program takes no arguments at all, so a secret cannot end
  up in the shell history or the process list (T3, T16).
- Every line printed goes through sanitize(), which removes control characters
  and terminal escape sequences. Text from a user or a file cannot move the
  cursor, clear the screen or retitle the window (T19).
- An unexpected error becomes one generic message, never a traceback (T17).
  Ctrl-C cancels the command in progress; at the prompt, Ctrl-C and end of
  input exit cleanly.

It is a small loop rather than the standard library's cmd.Cmd, whose defaults
do not fit a password manager: an empty line repeats the last command, an
unknown command is printed back, and command names cannot contain a dash.
"""

import getpass
import re
import sys
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from yunarpass import __version__
from yunarpass.storage import StorageError

MAX_LINE = 256  # characters in one command line

PROMPT = "yunarpass> "
GENERIC_ERROR = "Something went wrong and the command did not complete."
UNKNOWN_COMMAND = "Unknown command. Type help to see the commands."

# Terminal escape sequences (ECMA-48), removed whole: CSI (colours, cursor
# movement, erasing the screen), the string commands OSC, DCS, SOS, PM and APC
# (window title, hyperlinks), and every other escape.
_ESCAPE_SEQUENCE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b[\]PX^_][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b[ -/]*[0-~]"
)
# Control characters (C0, DEL, C1) and the line and paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Zl", "Zp"})
# Bidirectional controls change the order in which text is displayed, so a
# name could look like something else on screen ("Trojan Source").
_BIDI_CONTROLS = frozenset(
    map(chr, [0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])
)


def sanitize(text: str) -> str:
    """Return text that is safe to print on a terminal.

    Escape sequences are removed whole, then every remaining control character
    (including ESC, CR, LF, TAB and DEL), the Unicode line and paragraph
    separators and the bidirectional controls.
    """
    text = _ESCAPE_SEQUENCE.sub("", text)
    return "".join(
        char
        for char in text
        if unicodedata.category(char) not in _UNSAFE_CATEGORIES and char not in _BIDI_CONTROLS
    )


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
_SAFE_ERRORS = (UsageError, StorageError)


class Command(NamedTuple):
    run: Callable[[str], None]  # called with the rest of the line
    summary: str


class Repl:
    """The read-eval-print loop."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = Console() if console is None else console
        self.running = False

    @property
    def prompt(self) -> str:
        return PROMPT

    def commands(self) -> dict[str, Command]:
        """The allow-list: the commands of the current state."""
        return {
            "help": Command(self.help, "Show this list"),
            "quit": Command(self.quit, "Exit"),
        }

    def say(self, *lines: str) -> None:
        """Print each argument as one line, sanitized."""
        self.console.write("".join(sanitize(line) + "\n" for line in lines))

    def run(self) -> int:
        """Read and run commands until quit, Ctrl-C or the end of input."""
        self.running = True
        self.say(f"yunarpass {__version__}. Type help to see the commands.")
        while self.running:
            try:
                line = self.console.read_line(sanitize(self.prompt))
            except (EOFError, KeyboardInterrupt):
                self.say("")  # end the prompt's line
                break
            self.execute(line)
        return 0

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
        return Repl().run()
    except KeyboardInterrupt:
        print()
        return 0
    except Exception:
        print(GENERIC_ERROR, file=sys.stderr)
        return 1
