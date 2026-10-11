"""Tests for login entries: the allow-list, the limits and strict loading (T19, T25)."""

import dataclasses
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from yunarpass import entries
from yunarpass.entries import EntryError, LoginEntry
from yunarpass.vaultfile import VaultFormatError

FIELDS = {"username": "alice@example.com", "url": "https://github.com", "notes": "personal"}


def github(name: str = "github", **changes: str) -> LoginEntry:
    return entries.new_login(name, **{**FIELDS, "password": "s3cret-Password!", **changes})


# --- Names ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["a", "github", "GitHub", "mail.google.com", "me@work", "a_b-c", "x" * 64]
)
def test_allowed_names(name: str) -> None:
    assert entries.check_name(name) == name
    assert github(name=name).name == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "x" * 65,
        "two words",
        "../github",
        "a/b",
        "a\\b",
        "github\n",
        "\x1b[2Jgithub",
        "gíthub",  # not ASCII
        "github‮",
        "ｇithub",  # a full-width letter
        None,
    ],
)
def test_names_off_the_allow_list_are_refused(name: object) -> None:
    with pytest.raises(EntryError) as caught:
        entries.check_name(name)
    assert str(caught.value) == entries.NAME_RULE


def test_names_compare_without_case() -> None:
    assert entries.key("GitHub") == entries.key("github")


# --- Fields --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("username", entries.MAX_USERNAME),
        ("password", entries.MAX_PASSWORD),
        ("url", entries.MAX_URL),
        ("notes", entries.MAX_NOTES),
    ],
)
def test_each_field_has_a_length_limit(field: str, limit: int) -> None:
    assert getattr(github(**{field: "x" * limit}), field) == "x" * limit
    with pytest.raises(EntryError, match=f"at most {limit} characters"):
        github(**{field: "x" * (limit + 1)})


@pytest.mark.parametrize("field", ["username", "password", "url", "notes"])
@pytest.mark.parametrize("char", ["\x00", "\x1b", "\r", "\t", "\x7f", "\x9b", " ", "‮"])
def test_control_characters_are_refused_in_every_field(field: str, char: str) -> None:
    with pytest.raises(EntryError, match="contains a control character"):
        github(**{field: f"a{char}b"})


def test_only_the_notes_may_have_line_breaks() -> None:
    assert github(notes="first line\nsecond line").notes == "first line\nsecond line"
    for field in ("username", "password", "url"):
        with pytest.raises(EntryError):
            github(**{field: "a\nb"})


def test_any_printable_text_is_allowed() -> None:
    entry = github(username="jürgen ✓", password="pass wörd 日本 😀", notes="  spaced  ")
    assert entry.password == "pass wörd 日本 😀"


def test_an_entry_needs_a_password() -> None:
    with pytest.raises(EntryError, match="needs a password"):
        github(password="")


def test_the_other_fields_may_be_empty() -> None:
    entry = github(username="", url="", notes="")
    assert (entry.username, entry.url, entry.notes) == ("", "", "")


def test_error_messages_do_not_repeat_the_value() -> None:
    for field in ("username", "password", "url", "notes"):
        with pytest.raises(EntryError) as caught:
            github(**{field: "SECRET\x1b" + "x" * 5000})
        assert "SECRET" not in str(caught.value)


def test_a_new_entry_gets_a_random_id_and_the_current_time() -> None:
    first, second = github(), github()
    assert re.fullmatch(r"[0-9a-f]{32}", first.id)
    assert first.id != second.id
    created = datetime.strptime(first.created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert abs(datetime.now(UTC) - created) < timedelta(minutes=1)
    assert first.modified == first.created


def test_timestamps_are_utc() -> None:
    tallinn = timezone(timedelta(hours=3))
    assert entries.timestamp(datetime(2026, 10, 11, 18, 2, 3, tzinfo=tallinn)) == (
        "2026-10-11T15:02:03Z"
    )


# --- What a user interface gets (T25) ------------------------------------------------


def test_views_have_no_password() -> None:
    entry = github()
    view = entry.view()
    assert "password" not in {f.name for f in dataclasses.fields(view)}
    assert entry.password not in repr(view)
    assert entry.summary() == ("github", "login")


def test_the_repr_of_an_entry_hides_the_password() -> None:
    entry = github()
    assert entry.password not in repr(entry)


def test_the_mask_does_not_depend_on_the_password() -> None:
    assert entries.MASK == "********"


# --- Loading from the body (T19) -----------------------------------------------------


def test_json_round_trip() -> None:
    entry = github(notes="two\nlines")
    doc = entry.to_json()
    assert doc["type"] == "login"
    assert set(doc) == {
        "id", "type", "name", "username", "password", "url", "notes", "created", "modified",
    }  # fmt: skip
    assert entries.from_json(doc) == entry


def _changed(**changes: object) -> dict[str, object]:
    doc = github().to_json()
    doc.update(changes)
    return {name: value for name, value in doc.items() if value is not ...}


@pytest.mark.parametrize(
    "doc",
    [
        None,
        [],
        "github",
        _changed(type="totp"),
        _changed(type=None),
        _changed(extra="field"),
        _changed(notes=...),  # missing
        _changed(id="not hex"),
        _changed(id="A" * 32),
        _changed(name="two words"),
        _changed(name=7),
        _changed(username=None),
        _changed(password=""),
        _changed(password=["list"]),
        _changed(url="\x1b]0;title\x07"),
        _changed(notes="x" * (entries.MAX_NOTES + 1)),
        _changed(created="2026-10-11 15:02:03"),
        _changed(created="2026-02-31T15:02:03Z"),
        _changed(modified="2026-10-11T15:02:03+00:00"),
        _changed(modified=1760194923),
    ],
)
def test_malformed_entries_are_refused(doc: object) -> None:
    with pytest.raises(VaultFormatError) as caught:
        entries.from_json(doc)
    assert "s3cret" not in str(caught.value)
