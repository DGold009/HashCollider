"""Shared building blocks for collision-search strategies."""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import ClassVar

from ..config import DEFAULT_MAX_STORED, PROGRESS_LOG_INTERVAL
from ..errors import ConfigurationError
from .results import SearchStatus

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SearchLimits:
    """Resource limits for one search. ``None`` means "no limit"."""

    max_attempts: int | None = None
    max_seconds: float | None = None
    max_stored: int | None = DEFAULT_MAX_STORED

    def __post_init__(self) -> None:
        for name in ("max_attempts", "max_stored"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 1
            ):
                raise ConfigurationError(f"{name} must be a positive integer (got {value!r})")
        if self.max_seconds is not None:
            if isinstance(self.max_seconds, bool) or not isinstance(self.max_seconds, int | float):
                raise ConfigurationError("max_seconds must be a number")
            if not self.max_seconds > 0:  # also rejects NaN
                raise ConfigurationError(f"max_seconds must be positive (got {self.max_seconds!r})")


@dataclass
class SearchProgress:
    """Live counters, refreshed at every checkpoint of a running search."""

    attempts: int = 0
    elapsed_seconds: float = 0.0
    stored: int = 0
    duplicates: int = 0


@dataclass
class SearchContext:
    """Everything a strategy needs to run its hot loop."""

    digest: Callable[[bytes], bytes]
    """Full-digest function of the base algorithm."""
    nbytes: int
    """Leading digest bytes that contain the effective bits."""
    shift: int
    """Right shift that drops surplus low bits from those bytes."""
    limits: SearchLimits
    stop_event: threading.Event
    check_interval: int
    progress: SearchProgress = field(default_factory=SearchProgress)


@dataclass(frozen=True)
class RawSearchResult:
    """Low-level result returned by a strategy to the engine."""

    status: SearchStatus
    attempts: int
    elapsed_seconds: float
    stored: int
    duplicates: int
    input_a: bytes | None = None
    input_b: bytes | None = None
    digest_a: bytes | None = None
    digest_b: bytes | None = None


def checkpoint(
    ctx: SearchContext, attempts: int, stored: int, duplicates: int, start: float
) -> SearchStatus | None:
    """Update live progress and decide whether the search must end.

    Called every ``ctx.check_interval`` attempts (not on every hash, to keep
    overhead negligible). Returns a terminal status or ``None`` to continue.
    """
    now = time.perf_counter()
    elapsed = now - start
    progress = ctx.progress
    progress.attempts = attempts
    progress.elapsed_seconds = elapsed
    progress.stored = stored
    progress.duplicates = duplicates
    if ctx.stop_event.is_set():
        return SearchStatus.STOPPED
    max_seconds = ctx.limits.max_seconds
    if max_seconds is not None and elapsed >= max_seconds:
        return SearchStatus.TIMEOUT
    if attempts % PROGRESS_LOG_INTERVAL == 0 and logger.isEnabledFor(logging.DEBUG):
        rate = attempts / elapsed if elapsed > 0 else 0.0
        logger.debug(
            "progress: %d attempts, %.2f s, %.0f hashes/s, %d stored digests",
            attempts,
            elapsed,
            rate,
            stored,
        )
    return None


class SearchStrategy(ABC):
    """A collision-search method (birthday, brute-force, ...)."""

    name: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]

    @abstractmethod
    def expected_attempts(self, bits: int) -> float:
        """Expected number of hash evaluations to find a collision."""

    def expected_stored_entries(self, bits: int) -> float:
        """Expected number of digests held in memory."""
        return 1.0

    @abstractmethod
    def success_probability(self, attempts: int, bits: int) -> float:
        """Probability of having found a collision after *attempts* hashes."""

    @abstractmethod
    def search(self, messages: Iterable[bytes], ctx: SearchContext) -> RawSearchResult:
        """Run the search loop over *messages*."""
