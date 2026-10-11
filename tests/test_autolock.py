"""Tests for the idle timer behind auto-lock (UC6; threat T15)."""

import math

import pytest

from yunarpass.autolock import AUTO_LOCK_SECONDS, IdleTimer


class Clocks:
    """A monotonic clock and a wall clock that move only when told."""

    def __init__(self) -> None:
        self.monotonic = 100.0
        self.wall = 1_800_000_000.0

    def timer(self, timeout: float = AUTO_LOCK_SECONDS) -> IdleTimer:
        return IdleTimer(timeout, lambda: self.monotonic, lambda: self.wall)

    def advance(self, seconds: float) -> None:
        self.monotonic += seconds
        self.wall += seconds


@pytest.fixture
def clocks() -> Clocks:
    return Clocks()


def test_the_limit_is_five_minutes() -> None:
    assert AUTO_LOCK_SECONDS == 300
    assert IdleTimer().timeout == AUTO_LOCK_SECONDS


@pytest.mark.parametrize("timeout", [0.05, 60, AUTO_LOCK_SECONDS])
def test_the_timeout_can_be_lowered(timeout: float) -> None:
    assert IdleTimer(timeout).timeout == timeout


@pytest.mark.parametrize("timeout", [AUTO_LOCK_SECONDS + 1, math.inf, 0, -1, math.nan])
def test_the_timeout_cannot_be_raised_or_switched_off(timeout: float) -> None:
    with pytest.raises(ValueError, match="at most 300 seconds"):
        IdleTimer(timeout)


def test_the_time_left_counts_down_to_zero(clocks: Clocks) -> None:
    timer = clocks.timer()
    assert timer.remaining() == 300
    clocks.advance(299.5)
    assert timer.remaining() == 0.5
    assert not timer.expired()
    clocks.advance(0.5)
    assert timer.remaining() == 0
    assert timer.expired()
    clocks.advance(1000)
    assert timer.remaining() == 0  # never below zero


def test_input_starts_the_idle_time_again(clocks: Clocks) -> None:
    timer = clocks.timer()
    clocks.advance(200)
    timer.touch()
    assert timer.idle() == 0
    clocks.advance(299)
    assert timer.remaining() == 1
    assert not timer.expired()


def test_time_asleep_counts_although_the_monotonic_clock_stopped(clocks: Clocks) -> None:
    timer = clocks.timer()
    clocks.monotonic += 10
    clocks.wall += 3600  # the computer slept for an hour
    assert timer.expired()


def test_a_wall_clock_set_back_does_not_keep_the_vault_open(clocks: Clocks) -> None:
    timer = clocks.timer()
    clocks.wall -= 3600
    clocks.monotonic += 300
    assert timer.expired()


def test_a_wall_clock_set_forward_locks_early(clocks: Clocks) -> None:
    timer = clocks.timer()
    clocks.wall += 300
    assert timer.expired()


def test_the_real_clocks() -> None:
    timer = IdleTimer()
    assert 299 < timer.remaining() <= 300
    timer.touch()
    assert not timer.expired()
