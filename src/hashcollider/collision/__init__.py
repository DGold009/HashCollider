"""Collision search: engine, strategies, results and verification."""

from __future__ import annotations

from .base import SearchContext, SearchLimits, SearchProgress, SearchStrategy
from .birthday import (
    BirthdayStrategy,
    attempts_for_probability,
    birthday_bound,
    collision_probability,
    expected_birthday_attempts,
)
from .brute_force import (
    BruteForceStrategy,
    brute_force_success_probability,
    expected_brute_force_attempts,
)
from .engine import (
    METHOD_NAMES,
    STRATEGIES,
    CollisionEngine,
    SearchEstimate,
    get_strategy,
    normalize_method,
)
from .results import CollisionResult, SearchOutcome, SearchStatistics, SearchStatus
from .verify import VerificationCheck, VerificationResult, verify_collision

__all__ = [
    "METHOD_NAMES",
    "STRATEGIES",
    "BirthdayStrategy",
    "BruteForceStrategy",
    "CollisionEngine",
    "CollisionResult",
    "SearchContext",
    "SearchEstimate",
    "SearchLimits",
    "SearchOutcome",
    "SearchProgress",
    "SearchStatistics",
    "SearchStatus",
    "SearchStrategy",
    "VerificationCheck",
    "VerificationResult",
    "attempts_for_probability",
    "birthday_bound",
    "brute_force_success_probability",
    "collision_probability",
    "expected_birthday_attempts",
    "expected_brute_force_attempts",
    "get_strategy",
    "normalize_method",
    "verify_collision",
]
