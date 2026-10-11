"""Tests for the output sanitizer and its character rule (threat T19)."""

import pytest

from yunarpass import text


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
        ("‮exe.txt", "exe.txt"),
        ("isolate⁦d⁩", "isolated"),
        ("line separator ", "lineseparator"),
        ("lone\ud800surrogate", "lonesurrogate"),
        ("café ✓ 日本語", "café ✓ 日本語"),
    ],
)
def test_sanitize_removes_escape_sequences_and_control_characters(raw: str, shown: str) -> None:
    assert text.sanitize(raw) == shown


@pytest.mark.parametrize(
    "char", ["\x00", "\t", "\n", "\r", "\x1b", "\x7f", "\x9b", " ", "‮", "\ud800"]
)
def test_unsafe_characters(char: str) -> None:
    assert text.is_unsafe(char)


@pytest.mark.parametrize("char", ["a", " ", "~", "é", "✓", "日", "\U0001f600"])
def test_safe_characters(char: str) -> None:
    assert not text.is_unsafe(char)
