"""Tests for the recovery key and the password generator (threats T5, T20)."""

import re
from collections.abc import Callable

import pytest

from yunarpass.secrets_gen import (
    format_recovery_key,
    new_recovery_key,
    parse_recovery_key,
)

FORMATTED = re.compile(r"([A-Z2-7]{4}-){7}[A-Z2-7]{4}")

# --- Recovery key (T5) -----------------------------------------------------------


def test_new_recovery_keys_are_160_random_bits() -> None:
    first, second = new_recovery_key(), new_recovery_key()
    assert len(first) == 20
    assert first != second


def test_format_is_eight_groups_of_four() -> None:
    text = format_recovery_key(new_recovery_key())
    assert FORMATTED.fullmatch(text)
    assert len(text) == 39


def test_format_known_answer() -> None:
    assert format_recovery_key(bytes(20)) == "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"
    assert format_recovery_key(b"\xff" * 20) == "7777-7777-7777-7777-7777-7777-7777-7777"


def test_format_parse_round_trip() -> None:
    for _ in range(200):
        raw = new_recovery_key()
        assert parse_recovery_key(format_recovery_key(raw)) == raw


@pytest.mark.parametrize(
    "transform",
    [
        str.lower,
        lambda t: t.replace("-", ""),
        lambda t: t.replace("-", " "),
        lambda t: f"  {t.lower()}  ",
        lambda t: t.replace("-", "")[:16].lower() + "-" + t.replace("-", "")[16:],
    ],
)
def test_parse_ignores_case_spaces_and_dashes(transform: Callable[[str], str]) -> None:
    raw = new_recovery_key()
    typed = transform(format_recovery_key(raw))
    assert parse_recovery_key(typed) == raw


@pytest.mark.parametrize(
    "typed",
    [
        "",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA",  # 31 characters
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAAA",  # 33 characters
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA0",  # 0 is not Base32
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA1",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA8",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA==",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAА",  # Cyrillic A
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAÉ",  # E with accent
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA\n",
        "AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA",
        "-" * 40 + "A" * 32,  # right letters, but over the 64-character input limit
    ],
)
def test_parse_refuses_malformed_input(typed: str) -> None:
    with pytest.raises(ValueError, match="not a valid recovery key"):
        parse_recovery_key(typed)


def test_parse_refuses_non_text() -> None:
    with pytest.raises(ValueError):
        parse_recovery_key(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  # type: ignore[arg-type]


@pytest.mark.parametrize("raw", [bytes(19), bytes(21), "a" * 20])
def test_format_refuses_wrong_sizes(raw: bytes) -> None:
    with pytest.raises(ValueError):
        format_recovery_key(raw)
