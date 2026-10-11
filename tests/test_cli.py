"""Tests for the REPL (threats T3, T16, T17, T19)."""

import pytest

from yunarpass import cli

# --- Output sanitizer (T19) ----------------------------------------------------------


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
        ("\u202eexe.txt", "exe.txt"),
        ("isolate\u2066d\u2069", "isolated"),
        ("line\u2028separator\u2029", "lineseparator"),
        ("café ✓ 日本語", "café ✓ 日本語"),
    ],
)
def test_sanitize_removes_escape_sequences_and_control_characters(raw: str, shown: str) -> None:
    assert cli.sanitize(raw) == shown
