"""Auto-lock (UC6): how long an unlocked vault has been left alone (T15).

An unlocked vault locks itself after AUTO_LOCK_SECONDS without input. The
limit is a constant, like the KDF floor: a user interface may lock sooner,
never later.

IdleTimer only measures. It starts no thread and locks nothing: the user
interface touches it on every input, and checks it from a timer of its own
(the CLI from a thread timer, the GUI from a Qt timer).

Idle time is measured on two clocks, and the time is up when either says so.
The monotonic clock cannot be moved by setting the system time, but on some
systems it stops while the computer sleeps; the wall clock keeps counting
through sleep. So a computer that slept with the vault unlocked finds it
locked when it wakes, a clock that jumps forward can only lock the vault
early, and a clock set back cannot keep it open.
"""

import time
from collections.abc import Callable

AUTO_LOCK_SECONDS = 300.0  # 5 minutes


class IdleTimer:
    """The time since the last input, against a timeout."""

    def __init__(
        self,
        timeout: float = AUTO_LOCK_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        """Raises ValueError unless 0 < timeout <= AUTO_LOCK_SECONDS."""
        if not 0 < timeout <= AUTO_LOCK_SECONDS:  # NaN fails too
            raise ValueError(
                f"the auto-lock timeout must be above 0 and at most {AUTO_LOCK_SECONDS:g} seconds"
            )
        self.timeout = timeout
        self._clocks = (clock, wall_clock)
        # One tuple, replaced whole: touch() runs on the input thread while a
        # timer may read it on another.
        self._last = self._now()

    def _now(self) -> tuple[float, float]:
        clock, wall_clock = self._clocks
        return clock(), wall_clock()

    def touch(self) -> None:
        """Note an input: the idle time starts again from zero."""
        self._last = self._now()

    def idle(self) -> float:
        """Seconds since the last input, on whichever clock counted more."""
        return max(now - last for now, last in zip(self._now(), self._last, strict=True))

    def remaining(self) -> float:
        """Seconds until the timeout, never below zero."""
        return max(self.timeout - self.idle(), 0.0)

    def expired(self) -> bool:
        return self.remaining() == 0.0
