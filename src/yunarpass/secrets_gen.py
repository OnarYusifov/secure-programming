"""Secrets meant for people: the paper recovery key and generated passwords.

All randomness comes from the `secrets` module (the OS CSPRNG), never from
`random`, whose output can be predicted from earlier output (T20).
"""

import base64
import re
import secrets

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
