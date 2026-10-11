"""Tests for the unlocked session (threats T9, T13)."""

import pytest

from yunarpass import crypto, vaultfile
from yunarpass.session import Session
from yunarpass.vaultfile import Body, VaultFile

ENTRIES: tuple[dict[str, object], ...] = ({"name": "github"},)


@pytest.fixture(scope="module")
def created() -> tuple[VaultFile, bytearray]:
    return vaultfile.create("alice", "correct horse battery staple", bytes(20), Body(3, ENTRIES))


def test_a_session_knows_its_user_and_counter(created: tuple[VaultFile, bytearray]) -> None:
    vault, dek = created
    session = Session(vault, bytearray(dek), Body(3, ENTRIES))
    assert session.username == "alice"
    assert session.counter == 3
    assert session.body.entries == ENTRIES
    assert not session.closed


def test_close_wipes_the_dek_and_drops_the_entries(created: tuple[VaultFile, bytearray]) -> None:
    vault, dek = created
    buffer = bytearray(dek)
    session = Session(vault, buffer, Body(3, ENTRIES))
    session.close()
    assert buffer == bytearray(crypto.KEY_BYTES)  # zeroed in place
    assert session.body == Body()
    assert session.closed
    session.close()  # a second close is harmless
    assert session.closed
