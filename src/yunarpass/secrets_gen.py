"""Secrets meant for people: the paper recovery key and generated passwords.

All randomness comes from the `secrets` module (the OS CSPRNG), never from
`random`, whose output can be predicted from earlier output (T20).
"""

import base64
import re
import secrets
import string

from yunarpass.crypto import RECOVERY_KEY_BYTES

# --- Recovery key (UC1, UC8, T5) ---------------------------------------------

# 160 bits in Base32 (RFC 4648: A-Z and 2-7) are exactly 32 characters, so there
# is no padding. Base32 has no 0, 1, 8 or 9, which are easy to misread on paper.
RECOVERY_KEY_CHARS = 32
RECOVERY_KEY_GROUP = 4

# What the user may type: Base32 letters in either case, spaces and dashes, and
# not absurdly long. Everything else is refused before any processing.
_RECOVERY_INPUT = re.compile(r"[A-Za-z2-7 -]{1,64}")


def new_recovery_key() -> bytes:
    """Return 160 random bits for a new recovery key."""
    return secrets.token_bytes(RECOVERY_KEY_BYTES)


def format_recovery_key(raw: bytes) -> str:
    """Format a recovery key for writing down: ABCD-EFGH-... (8 groups of 4)."""
    if not isinstance(raw, bytes) or len(raw) != RECOVERY_KEY_BYTES:
        raise ValueError("a recovery key is 20 bytes")
    text = base64.b32encode(raw).decode("ascii")
    groups = (text[i : i + RECOVERY_KEY_GROUP] for i in range(0, len(text), RECOVERY_KEY_GROUP))
    return "-".join(groups)


def parse_recovery_key(text: str) -> bytes:
    """Read a recovery key as the user typed it.

    Case does not matter, and spaces and dashes are ignored. Anything else, or the
    wrong number of characters, raises ValueError.
    """
    if not isinstance(text, str) or not _RECOVERY_INPUT.fullmatch(text):
        raise ValueError("not a valid recovery key")
    compact = text.replace(" ", "").replace("-", "").upper()
    if len(compact) != RECOVERY_KEY_CHARS:
        raise ValueError("not a valid recovery key")
    return base64.b32decode(compact)


# --- Password generator (UC5, T20) ----------------------------------------------

# Symbols without quotes, backslash, backtick or space, which web forms and shells
# often handle badly. 26 + 26 + 10 + 28 = 90 characters, about 6.5 bits each.
SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
CHARACTER_CLASSES = (string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS)
ALPHABET = "".join(CHARACTER_CLASSES)

DEFAULT_LENGTH = 20  # about 130 bits
MIN_LENGTH = 12
MAX_LENGTH = 128


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    """Return a random password with at least one character from each class.

    Every character is drawn from the whole alphabet, and a candidate that misses
    a class is thrown away and drawn again (rejection sampling). Forcing, say, a
    digit into a fixed position would make the passwords easier to guess.
    """
    if not isinstance(length, int) or isinstance(length, bool):
        raise ValueError("length must be a whole number")
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")
    while True:
        candidate = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if all(any(char in cls for char in candidate) for cls in CHARACTER_CLASSES):
            return candidate
