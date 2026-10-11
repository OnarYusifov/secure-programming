"""Tests for the master-password policy (threat T1)."""

from importlib import resources

import pytest

from yunarpass import policy
from yunarpass.policy import PolicyError


@pytest.mark.parametrize(
    "password",
    [
        "a" * 12,
        "correct horse battery staple",
        "x" * policy.MAX_LENGTH,
        chr(0xE9) * 12,  # 12 precomposed accented letters
        "".join(map(chr, range(0x430, 0x43C))),  # 12 Cyrillic letters
    ],
)
def test_allowed_passwords(password: str) -> None:
    policy.check_master_password(password)


@pytest.mark.parametrize(
    ("password", "rule"),
    [
        ("", "at least 12"),
        ("a" * 11, "at least 12"),
        # Six accented letters typed as letter + combining accent: twelve code
        # points, but only six characters once normalized.
        (("e" + chr(0x301)) * 6, "at least 12"),
        ("x" * (policy.MAX_LENGTH + 1), "at most 1024"),
        ("unbelievable", "most common"),
        ("UnBeLiEvAbLe", "most common"),
        ("SCANDINAVIAN", "most common"),
    ],
)
def test_refused_passwords_name_the_rule(password: str, rule: str) -> None:
    with pytest.raises(PolicyError, match=rule) as caught:
        policy.check_master_password(password)
    if password:
        assert password not in str(caught.value)


def test_the_common_list_is_complete_and_ignores_case() -> None:
    assert len(policy._common_passwords()) > 9900
    for password in ("password", "123456", "qwerty", "PASSWORD", "Dragon"):
        assert policy.is_common(password)
    assert not policy.is_common("correct horse battery staple")


def test_the_list_ships_with_its_source_and_licence() -> None:
    data = resources.files("yunarpass").joinpath("data")
    notice = data.joinpath("common-passwords.LICENSE").read_text("utf-8")
    assert "SecLists" in notice
    assert "MIT License" in notice
    assert data.joinpath(policy.COMMON_PASSWORDS_FILE).is_file()
