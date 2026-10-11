"""Characters that must not reach a terminal (T19).

sanitize() cleans text before it is printed. is_unsafe() is the same rule for
a single character, so that input can refuse what output would remove
(entries.py).
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
# Control characters (C0, DEL, C1), the line and paragraph separators, and
# lone surrogates, which cannot be encoded for output at all.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Zl", "Zp", "Cs"})
# Bidirectional controls change the order in which text is displayed, so a
# name could look like something else on screen ("Trojan Source").
_BIDI_CONTROLS = frozenset(
    map(chr, [0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])
)


def is_unsafe(char: str) -> bool:
    """Whether a character is one that sanitize() removes.

    That is a control character (including ESC, CR, LF, TAB and DEL), a
    Unicode line or paragraph separator, a lone surrogate or a bidirectional
    control.
    """
    return unicodedata.category(char) in _UNSAFE_CATEGORIES or char in _BIDI_CONTROLS


def sanitize(text: str) -> str:
    """Return text that is safe to print on a terminal.

    Escape sequences are removed whole, then every remaining unsafe character
    (is_unsafe).
    """
    text = _ESCAPE_SEQUENCE.sub("", text)
    return "".join(char for char in text if not is_unsafe(char))
