"""Login entries (UC3): their fields, the limits and the checks.

In the decrypted body an entry is a JSON object with exactly these fields:

    {"id": "<32 hex>", "type": "login", "name": "github", "username": "...",
     "password": "...", "url": "...", "notes": "...",
     "created": "2026-10-11T15:02:00Z", "modified": "2026-10-11T15:02:00Z"}

Every field is checked against an allow-list or a limit when an entry is built
or edited, and again when a vault is opened (T19). The name is the only field
used to find an entry, so it is restricted to a small ASCII alphabet. The other
text fields may hold any character except those that sanitize() would remove
from the output (text.is_unsafe); notes may also have line breaks.

The password is in LoginEntry only. The views handed to a user interface,
EntryView and EntrySummary, have no password field at all, so no interface can
show what it never receives (T25).
"""

import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import NamedTuple

from yunarpass import text, vaultfile
from yunarpass.vaultfile import VaultFormatError

LOGIN = "login"

# Explicit ASCII ranges, used with fullmatch only (see vaultfile.USERNAME).
NAME = re.compile(r"[A-Za-z0-9._@-]{1,64}")
NAME_RULE = (
    "an entry name has 1 to 64 characters: letters, digits, '.', '_', '@' and '-', without spaces"
)

MAX_USERNAME = 256
MAX_PASSWORD = 1024
MAX_URL = 2048
MAX_NOTES = 4096

# Shown in place of every password. Always the same, so it does not reveal
# the password's length.
MASK = "********"

_ID = re.compile(r"[0-9a-f]{32}")
_ID_BYTES = 16
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_FIELDS = frozenset(
    {"id", "type", "name", "username", "password", "url", "notes", "created", "modified"}
)


class EntryError(Exception):
    """An entry was refused. The message names the rule, never the value."""


def check_name(name: object) -> str:
    """Return the name if it is on the allow-list; otherwise raise EntryError."""
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise EntryError(NAME_RULE)
    return name


def _check_text(value: object, what: str, limit: int, *, line_breaks: bool = False) -> str:
    if not isinstance(value, str):
        raise EntryError(f"the {what} is not text")
    if len(value) > limit:
        raise EntryError(f"the {what} can have at most {limit} characters")
    if any(text.is_unsafe(char) and not (line_breaks and char == "\n") for char in value):
        raise EntryError(f"the {what} contains a control character")
    return value


def check_username(value: object) -> str:
    return _check_text(value, "username", MAX_USERNAME)


def check_password(value: object) -> str:
    password = _check_text(value, "password", MAX_PASSWORD)
    if not password:
        raise EntryError("an entry needs a password")
    return password


def check_url(value: object) -> str:
    return _check_text(value, "URL", MAX_URL)


def check_notes(value: object) -> str:
    return _check_text(value, "notes", MAX_NOTES, line_breaks=True)


def _check_time(value: object, what: str) -> str:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise EntryError(f"the {what} time is not allowed")
    try:
        datetime.strptime(value, _TIME_FORMAT)  # a real date and time, not 2026-02-31
    except ValueError:
        raise EntryError(f"the {what} time is not allowed") from None
    return value


def timestamp(now: datetime | None = None) -> str:
    """The current time in UTC, to the second, as stored in an entry."""
    return (datetime.now(UTC) if now is None else now.astimezone(UTC)).strftime(_TIME_FORMAT)


def key(name: str) -> str:
    """What makes two names the same: case does not matter (names are ASCII)."""
    return name.lower()


class EntrySummary(NamedTuple):
    """What `list` shows: the name and the type."""

    name: str
    type: str


@dataclass(frozen=True, slots=True)
class EntryView:
    """What `show` shows: every field except the password."""

    name: str
    type: str
    username: str
    url: str
    notes: str
    created: str
    modified: str


@dataclass(frozen=True, slots=True)
class LoginEntry:
    """A login entry. Every field is checked when it is built (EntryError)."""

    id: str
    name: str
    username: str
    # repr=False: an entry printed while debugging does not show its password.
    password: str = field(repr=False)
    url: str
    notes: str
    created: str
    modified: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _ID.fullmatch(self.id):
            raise EntryError("the entry ID is not allowed")
        check_name(self.name)
        check_username(self.username)
        check_password(self.password)
        check_url(self.url)
        check_notes(self.notes)
        _check_time(self.created, "created")
        _check_time(self.modified, "modified")

    @property
    def type(self) -> str:
        return LOGIN

    def summary(self) -> EntrySummary:
        return EntrySummary(self.name, self.type)

    def view(self) -> EntryView:
        return EntryView(
            self.name, self.type, self.username, self.url, self.notes, self.created, self.modified
        )

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "created": self.created,
            "modified": self.modified,
        }


def new_login(name: str, *, username: str, password: str, url: str, notes: str) -> LoginEntry:
    """A new login entry with a random ID. Raises EntryError if a field is not allowed."""
    now = timestamp()
    return LoginEntry(
        id=secrets.token_hex(_ID_BYTES),
        name=name,
        username=username,
        password=password,
        url=url,
        notes=notes,
        created=now,
        modified=now,
    )


def from_json(value: object) -> LoginEntry:
    """Parse an entry from the decrypted body. Raises VaultFormatError if it is malformed."""
    doc = vaultfile.fields(value, _FIELDS, "entry")
    if doc["type"] != LOGIN:
        raise VaultFormatError("entry.type: not supported")
    fields = {name: doc[name] for name in _FIELDS - {"type"}}
    try:
        return LoginEntry(**fields)  # type: ignore[arg-type]  # each one is checked
    except EntryError:
        raise VaultFormatError("entry: a field is not allowed") from None
