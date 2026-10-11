"""The interactive prompt (REPL): the UI layer over the core (DESIGN.md §2).

Every line printed goes through sanitize(), which removes control characters
and terminal escape sequences. Text from a user or a file cannot move the
cursor, clear the screen or retitle the window (T19).
"""

import re
import unicodedata

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
