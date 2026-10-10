"""Tests for the recovery key and the password generator (threats T5, T20)."""

import ast
import re
import string
from collections.abc import Callable
from pathlib import Path

import pytest

from yunarpass import secrets_gen
from yunarpass.secrets_gen import (
    ALPHABET,
    CHARACTER_CLASSES,
    format_recovery_key,
    generate_password,
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


# --- Password generator (T20) ------------------------------------------------------


def test_default_length_is_20() -> None:
    assert len(generate_password()) == 20


@pytest.mark.parametrize("length", [12, 13, 64, 128])
def test_lengths_within_bounds(length: int) -> None:
    assert len(generate_password(length)) == length


@pytest.mark.parametrize("length", [0, -1, 11, 129, 10_000, True, 20.0, "20"])
def test_lengths_out_of_bounds_are_refused(length: int) -> None:
    with pytest.raises(ValueError):
        generate_password(length)


def test_every_password_has_every_class_and_only_alphabet_characters() -> None:
    for _ in range(1000):
        password = generate_password(12)  # the shortest length is the hardest case
        assert set(password) <= set(ALPHABET)
        for cls in CHARACTER_CLASSES:
            assert any(char in cls for char in password)


def test_classes_are_not_in_fixed_positions() -> None:
    # Rejection sampling: any class can appear anywhere, including the first slot.
    first_chars = {generate_password()[0] for _ in range(2000)}
    for cls in CHARACTER_CLASSES:
        assert first_chars & set(cls)


def test_every_alphabet_character_gets_used() -> None:
    seen = set("".join(generate_password() for _ in range(1000)))
    assert seen == set(ALPHABET)


def test_passwords_do_not_repeat() -> None:
    assert len({generate_password() for _ in range(1000)}) == 1000


def test_alphabet_has_no_quotes_backslash_backtick_or_whitespace() -> None:
    assert not set(ALPHABET) & set("'\"\\` \t\n")
    assert len(ALPHABET) == len(set(ALPHABET)) == 90
    assert set(string.ascii_letters + string.digits) <= set(ALPHABET)


def test_module_never_imports_random() -> None:
    # bandit (B311) flags `random` too; this keeps the rule even if bandit's
    # configuration changes.
    tree = ast.parse(Path(secrets_gen.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "random" not in imported
    assert "secrets" in imported
