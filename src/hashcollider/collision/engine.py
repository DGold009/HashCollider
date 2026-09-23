"""The reusable collision engine.

``CollisionEngine`` wires together a hash algorithm, an effective bit length
(truncation), an input generator and a search strategy, and enforces the
safety limits (feasibility checks, attempt/time/memory limits, Ctrl+C).

Example::

    engine = CollisionEngine("sha256", bits=16, generator=SequentialGenerator())
    outcome = engine.run()
    if outcome.found:
        print(outcome.collision.truncated_hash)
"""

from __future__ import annotations

import logging
import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .._version import __version__
from ..config import (
    CHECK_INTERVAL,
    DEFAULT_BITS,
    DEFAULT_MAX_STORED,
    DEFAULT_METHOD,
    ESTIMATED_ENTRY_OVERHEAD_BYTES,
    HARD_MAX_BITS,
    REFERENCE_HASH_RATE,
    SAFE_MAX_BITS,
)
from ..errors import (
    ConfigurationError,
    GeneratorExhaustedError,
    InfeasibleSearchError,
    MaxAttemptsReachedError,
    MaxTimeReachedError,
    SearchEndedError,
    SearchInterruptedError,
    SearchStoppedError,
)
from ..generators import InputGenerator, SequentialGenerator
from ..hashing import AlgorithmRegistry, HashAlgorithm, TruncatedHash
from .base import RawSearchResult, SearchContext, SearchLimits, SearchProgress, SearchStrategy
from .birthday import BirthdayStrategy, birthday_bound
from .brute_force import BruteForceStrategy
from .results import (
    CollisionResult,
    SearchOutcome,
    SearchStatistics,
    SearchStatus,
    utc_timestamp,
)

logger = logging.getLogger(__name__)

STRATEGIES: Mapping[str, type[SearchStrategy]] = MappingProxyType(
    {
        BirthdayStrategy.name: BirthdayStrategy,
        BruteForceStrategy.name: BruteForceStrategy,
    }
)
METHOD_NAMES: tuple[str, ...] = tuple(STRATEGIES)

_SEARCH_END_ERRORS: Mapping[SearchStatus, type[SearchEndedError]] = MappingProxyType(
    {
        SearchStatus.MAX_ATTEMPTS: MaxAttemptsReachedError,
        SearchStatus.TIMEOUT: MaxTimeReachedError,
        SearchStatus.EXHAUSTED: GeneratorExhaustedError,
        SearchStatus.STOPPED: SearchStoppedError,
        SearchStatus.INTERRUPTED: SearchInterruptedError,
    }
)

_SECONDS_PER_YEAR = 365.25 * 24 * 3600


def normalize_method(method: str) -> str:
    """Return the canonical method name (``"brute_force"`` -> ``"brute-force"``)."""
    key = method.strip().lower().replace("_", "-")
    if key == "bruteforce":
        key = "brute-force"
    if key not in STRATEGIES:
        raise ConfigurationError(
            f"Unknown search method: {method!r}. Choose from: {', '.join(METHOD_NAMES)}"
        )
    return key


def get_strategy(method: str) -> SearchStrategy:
    """Instantiate the strategy for *method*."""
    return STRATEGIES[normalize_method(method)]()


@dataclass(frozen=True)
class SearchEstimate:
    """Pre-flight estimate of a search's cost."""

    algorithm_display_name: str
    method: str
    bits: int
    output_bits: int
    expected_attempts: float
    birthday_bound: float
    expected_stored_entries: float
    estimated_memory_bytes: float
    safe_max_bits: int
    hard_max_bits: int
    input_space_size: int | None

    @property
    def space_size(self) -> int:
        """Size of the effective output space, ``2**bits``."""
        return 1 << self.bits

    @property
    def requires_force(self) -> bool:
        return self.bits > self.safe_max_bits

    @property
    def infeasible(self) -> bool:
        return self.bits > self.hard_max_bits

    @property
    def input_space_may_be_too_small(self) -> bool:
        """``True`` if the generator may run out of inputs before a likely collision."""
        return (
            self.input_space_size is not None and self.input_space_size < 3 * self.expected_attempts
        )

    def seconds_at(self, hashes_per_second: float) -> float:
        """Expected duration at a given hash rate."""
        return self.expected_attempts / hashes_per_second


def infeasibility_message(estimate: SearchEstimate) -> str:
    """Explain why a search is refused outright."""
    exponent = math.log2(estimate.expected_attempts)
    years = estimate.seconds_at(REFERENCE_HASH_RATE) / _SECONDS_PER_YEAR
    name = estimate.algorithm_display_name
    if estimate.bits == estimate.output_bits:
        scope = f"the full {estimate.output_bits}-bit {name} output"
    else:
        scope = f"the first {estimate.bits} bits of {name}"
    lines = [
        f"A {estimate.method} collision search in {scope} is computationally infeasible "
        "for this tool.",
        f"Expected work: about 2^{exponent:.1f} (~{estimate.expected_attempts:.3g}) hash "
        f"evaluations - roughly {years:.3g} years at {REFERENCE_HASH_RATE:.0e} hashes/second.",
        f"HashCollider refuses {estimate.method} searches above {estimate.hard_max_bits} "
        "effective bits, even with --force.",
    ]
    if estimate.bits == estimate.output_bits and name in ("MD5", "SHA-1"):
        lines.append(
            f"Real-world {name} collisions are produced by dedicated cryptanalytic attacks, "
            "not by generic birthday search; HashCollider does not implement those attacks."
        )
    lines.append("Use a reduced effective size instead, for example --bits 16 to --bits 32.")
    return "\n".join(lines)


def force_required_message(estimate: SearchEstimate) -> str:
    """Explain why a search needs ``--force``."""
    exponent = math.log2(estimate.expected_attempts)
    return (
        f"{estimate.bits} effective bits exceeds the safe default of {estimate.safe_max_bits} "
        f"bits for the {estimate.method} method.\n"
        f"Expected work: about 2^{exponent:.1f} (~{estimate.expected_attempts:,.0f}) hashes"
        + (
            f" and ~{estimate.estimated_memory_bytes / 2**20:,.0f} MiB of memory"
            if estimate.method == BirthdayStrategy.name
            else ""
        )
        + ".\nRe-run with --force if you really want this (consider --max-seconds and "
        "--max-stored)."
    )


class CollisionEngine:
    """Search for two different inputs whose truncated digests are equal.

    Args:
        algorithm: algorithm name (e.g. ``"sha256"``) or a full-size
            :class:`HashAlgorithm` instance.
        bits: effective bit length (``None`` means the full digest size).
        generator: input generator; defaults to :class:`SequentialGenerator`.
        method: ``"birthday"`` (default) or ``"brute-force"``.
        max_attempts: stop after this many hash evaluations (``None`` = no limit).
        max_seconds: stop after this many seconds (``None`` = no limit).
        max_stored: maximum digests kept in memory by the birthday search.
        force: allow searches above the safe bit-length defaults.
        registry: algorithm registry used to resolve names.
        check_interval: attempts between time/stop checks (power of two).
    """

    def __init__(
        self,
        algorithm: str | HashAlgorithm = "sha256",
        bits: int | None = DEFAULT_BITS,
        generator: InputGenerator | None = None,
        *,
        method: str = DEFAULT_METHOD,
        max_attempts: int | None = None,
        max_seconds: float | None = None,
        max_stored: int | None = DEFAULT_MAX_STORED,
        force: bool = False,
        registry: AlgorithmRegistry | None = None,
        check_interval: int = CHECK_INTERVAL,
    ) -> None:
        if isinstance(algorithm, TruncatedHash):
            raise ConfigurationError(
                "Pass the full algorithm and the effective size via 'bits', not a TruncatedHash"
            )
        if isinstance(algorithm, HashAlgorithm):
            base = algorithm
        else:
            base = (registry or AlgorithmRegistry()).get(algorithm)
        self._truncated = TruncatedHash(base, base.output_bits if bits is None else bits)
        self._generator = generator if generator is not None else SequentialGenerator()
        self._method = normalize_method(method)
        self._strategy = STRATEGIES[self._method]()
        self._limits = SearchLimits(max_attempts, max_seconds, max_stored)
        if check_interval < 1 or check_interval & (check_interval - 1):
            raise ConfigurationError("check_interval must be a power of two")
        self._check_interval = check_interval
        self._force = bool(force)
        self._stop_event = threading.Event()
        self._progress = SearchProgress()
        self._running = False
        self._last_outcome: SearchOutcome | None = None

    # -- read-only properties -------------------------------------------

    @property
    def algorithm(self) -> HashAlgorithm:
        """The full-size base algorithm."""
        return self._truncated.base

    @property
    def truncated(self) -> TruncatedHash:
        """The effective (truncated) hash being searched."""
        return self._truncated

    @property
    def bits(self) -> int:
        return self._truncated.bits

    @property
    def generator(self) -> InputGenerator:
        return self._generator

    @property
    def method(self) -> str:
        return self._method

    @property
    def strategy(self) -> SearchStrategy:
        return self._strategy

    @property
    def limits(self) -> SearchLimits:
        return self._limits

    @property
    def running(self) -> bool:
        return self._running

    @property
    def last_outcome(self) -> SearchOutcome | None:
        return self._last_outcome

    # -- estimates and safety -------------------------------------------

    def estimate(self) -> SearchEstimate:
        """Estimate the expected cost of the search before running it."""
        bits = self.bits
        expected = self._strategy.expected_attempts(bits)
        stored = min(
            self._strategy.expected_stored_entries(bits),
            float(self._limits.max_stored) if self._limits.max_stored is not None else math.inf,
        )
        entry_bytes = ESTIMATED_ENTRY_OVERHEAD_BYTES + (self._generator.input_length or 32)
        return SearchEstimate(
            algorithm_display_name=self.algorithm.display_name,
            method=self._method,
            bits=bits,
            output_bits=self.algorithm.output_bits,
            expected_attempts=expected,
            birthday_bound=birthday_bound(bits),
            expected_stored_entries=stored,
            estimated_memory_bytes=stored * entry_bytes,
            safe_max_bits=SAFE_MAX_BITS[self._method],
            hard_max_bits=HARD_MAX_BITS[self._method],
            input_space_size=self._generator.input_space_size(),
        )

    def check_feasibility(self) -> SearchEstimate:
        """Raise :class:`InfeasibleSearchError` for unrealistic searches.

        Searches above the hard limit are always refused; searches above the
        safe default require ``force=True``.
        """
        estimate = self.estimate()
        if estimate.infeasible:
            raise InfeasibleSearchError(infeasibility_message(estimate))
        if estimate.requires_force and not self._force:
            raise InfeasibleSearchError(force_required_message(estimate))
        return estimate

    # -- running -----------------------------------------------------------

    def run(self) -> SearchOutcome:
        """Run the search until a collision is found or a limit ends it.

        Never raises for limits or Ctrl+C: the returned
        :class:`SearchOutcome` carries the status and all statistics
        collected so far.
        """
        if self._running:
            raise RuntimeError("this engine is already running a search")
        self.check_feasibility()
        self._stop_event.clear()
        self._progress = SearchProgress()
        truncated = self._truncated
        ctx = SearchContext(
            digest=self.algorithm.digest_function(),
            nbytes=truncated.nbytes,
            shift=truncated.shift,
            limits=self._limits,
            stop_event=self._stop_event,
            check_interval=self._check_interval,
            progress=self._progress,
        )
        logger.debug(
            "starting %s search: %s, %d bits, generator=%s, limits=%s",
            self._method,
            self.algorithm.display_name,
            self.bits,
            self._generator,
            self._limits,
        )
        self._running = True
        try:
            raw = self._strategy.search(iter(self._generator), ctx)
        finally:
            self._running = False

        self._progress.attempts = raw.attempts
        self._progress.elapsed_seconds = raw.elapsed_seconds
        self._progress.stored = raw.stored
        self._progress.duplicates = raw.duplicates
        statistics = self.statistics()
        collision = None
        if raw.status is SearchStatus.FOUND:
            collision = self._build_result(raw, statistics)
        outcome = SearchOutcome(status=raw.status, statistics=statistics, collision=collision)
        self._last_outcome = outcome
        logger.debug("search ended: %s after %d attempts", raw.status.value, raw.attempts)
        return outcome

    def find_collision(self) -> CollisionResult:
        """Run the search and return the collision.

        Raises:
            MaxAttemptsReachedError, MaxTimeReachedError, GeneratorExhaustedError,
            SearchStoppedError, SearchInterruptedError: when no collision was
                found. The exception's ``statistics`` attribute holds the counters.
        """
        outcome = self.run()
        if outcome.collision is not None:
            return outcome.collision
        error = _SEARCH_END_ERRORS[outcome.status]
        raise error(outcome.status.message, outcome.statistics)

    def stop(self) -> None:
        """Ask a running search to stop at its next checkpoint (thread-safe)."""
        self._stop_event.set()

    def statistics(self) -> SearchStatistics:
        """Current (live or final) search statistics."""
        progress = self._progress
        return SearchStatistics(
            attempts=progress.attempts,
            elapsed_seconds=progress.elapsed_seconds,
            stored_digests=progress.stored,
            duplicate_inputs=progress.duplicates,
        )

    # -- helpers -------------------------------------------------------------

    def _build_result(self, raw: RawSearchResult, statistics: SearchStatistics) -> CollisionResult:
        truncated = self._truncated
        if (
            raw.input_a is None
            or raw.input_b is None
            or raw.digest_a is None
            or raw.digest_b is None
        ):  # pragma: no cover - defensive
            raise RuntimeError("strategy reported a collision without its inputs")
        value_a = truncated.truncate(raw.digest_a)
        value_b = truncated.truncate(raw.digest_b)
        if raw.input_a == raw.input_b or value_a != value_b:  # pragma: no cover - defensive
            raise RuntimeError("internal error: strategy returned an invalid collision")
        return CollisionResult(
            algorithm=self.algorithm.name,
            effective_bits=truncated.bits,
            input_a=raw.input_a,
            input_b=raw.input_b,
            algorithm_display_name=self.algorithm.display_name,
            output_bits=self.algorithm.output_bits,
            method=self._method,
            generator=self._generator.name,
            generator_params=self._generator.describe(),
            hash_a=raw.digest_a.hex(),
            hash_b=raw.digest_b.hex(),
            truncated_hash=truncated.format_value(value_a),
            attempts=statistics.attempts,
            elapsed_seconds=statistics.elapsed_seconds,
            hashes_per_second=statistics.hashes_per_second,
            timestamp=utc_timestamp(),
            tool_version=__version__,
        )
