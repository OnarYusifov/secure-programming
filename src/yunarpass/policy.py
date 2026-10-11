"""Master-password policy (UC1, UC7; T1).

A master password has at least 12 and at most 1024 characters, and is not one
of the 10 000 most common passwords, compared without regard to case. Length
is counted after NFC normalization, the form the KDF hashes, so an accented
letter typed as two code points counts as one character.

The list is SecLists' 10k-most-common.txt, shipped unchanged as package data;
data/common-passwords.LICENSE names its source and licence.
"""

import functools
import unicodedata
from importlib import resources

MIN_LENGTH = 12
MAX_LENGTH = 1024
COMMON_PASSWORDS_FILE = "common-passwords.txt"


class PolicyError(Exception):
    """The password breaks a rule. The message names the rule, never the password."""


@functools.cache
def _common_passwords() -> frozenset[str]:
    text = resources.files("yunarpass").joinpath("data", COMMON_PASSWORDS_FILE).read_text("ascii")
    return frozenset(line.casefold() for line in text.splitlines() if line)


def is_common(password: str) -> bool:
    """Whether the password is on the common-password list, ignoring case."""
    return unicodedata.normalize("NFC", password).casefold() in _common_passwords()


def check_master_password(password: str) -> None:
    """Raise PolicyError unless the password is allowed as a master password."""
    length = len(unicodedata.normalize("NFC", password))
    if length < MIN_LENGTH:
        raise PolicyError(f"the master password must have at least {MIN_LENGTH} characters")
    if length > MAX_LENGTH:
        raise PolicyError(f"the master password can have at most {MAX_LENGTH} characters")
    if is_common(password):
        raise PolicyError("the master password is one of the 10 000 most common passwords")
