"""Benchmarking: repeated collision searches and raw hash throughput."""

from __future__ import annotations

import os
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass

from ..collision.engine import CollisionEngine, SearchEstimate, get_strategy, normalize_method
from ..collision.results import SearchStatus
from ..config import (
    BENCHMARK_DEFAULT_ITERATIONS,
    BENCHMARK_DEFAULT_MAX_SECONDS,
    BENCHMARK_DEFAULT_RAW_HASHES,
    DEFAULT_BITS,
    DEFAULT_MAX_STORED,
    DEFAULT_METHOD,
    DEFAULT_RANDOM_LENGTH,
)
from ..errors import ConfigurationError
from ..formatting import format_count, format_rate, format_table
from ..generators import InputGenerator, RandomGenerator, SeededRandomGenerator
from ..generators.base import validate_input_length
from ..hashing import AlgorithmRegistry, HashAlgorithm, validate_bits


@dataclass(frozen=True)
class BenchmarkConfig:
    """Parameters of a benchmark session."""

    algorithms: tuple[str, ...] = ("sha256",)
    bits: int = DEFAULT_BITS
    iterations: int = BENCHMARK_DEFAULT_ITERATIONS
    input_length: int = DEFAULT_RANDOM_LENGTH
    method: str = DEFAULT_METHOD
    seed: int | None = None
    max_attempts: int | None = None
    max_seconds: float | None = BENCHMARK_DEFAULT_MAX_SECONDS
    max_stored: int | None = DEFAULT_MAX_STORED
    raw_hashes: int = BENCHMARK_DEFAULT_RAW_HASHES
    force: bool = False

    def __post_init__(self) -> None:
        if not self.algorithms:
            raise ConfigurationError("At least one algorithm is required")
        iterations = self.iterations
        if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
            raise ConfigurationError(f"Iterations must be a positive integer (got {iterations!r})")
        validate_input_length(self.input_length)
        if self.raw_hashes < 0:
            raise ConfigurationError("raw_hashes must not be negative")
        object.__setattr__(self, "method", normalize_method(self.method))


@dataclass(frozen=True)
class BenchmarkRun:
    """One collision search inside a benchmark."""

    status: SearchStatus
    attempts: int
    elapsed_seconds: float

    @property
    def found(self) -> bool:
        return self.status is SearchStatus.FOUND


@dataclass(frozen=True)
class AlgorithmBenchmark:
    """Aggregated benchmark results for one algorithm."""

    algorithm: str
    display_name: str
    bits: int
    method: str
    expected_attempts: float
    runs: tuple[BenchmarkRun, ...]
    raw_hashes_per_second: float | None = None

    @property
    def found_runs(self) -> tuple[BenchmarkRun, ...]:
        return tuple(run for run in self.runs if run.found)

    @property
    def found_count(self) -> int:
        return len(self.found_runs)

    @property
    def total_attempts(self) -> int:
        return sum(run.attempts for run in self.runs)

    @property
    def total_elapsed(self) -> float:
        return sum(run.elapsed_seconds for run in self.runs)

    @property
    def mean_attempts(self) -> float | None:
        """Mean attempts over runs that found a collision."""
        found = self.found_runs
        return statistics.fmean(run.attempts for run in found) if found else None

    @property
    def median_attempts(self) -> float | None:
        found = self.found_runs
        return float(statistics.median(run.attempts for run in found)) if found else None

    @property
    def stdev_attempts(self) -> float | None:
        found = self.found_runs
        if len(found) < 2:
            return None
        return statistics.stdev(run.attempts for run in found)

    @property
    def mean_elapsed(self) -> float | None:
        found = self.found_runs
        return statistics.fmean(run.elapsed_seconds for run in found) if found else None

    @property
    def hashes_per_second(self) -> float:
        """Aggregate search throughput: all attempts / all search time."""
        elapsed = self.total_elapsed
        return self.total_attempts / elapsed if elapsed > 0 else 0.0

    @property
    def attempts_ratio(self) -> float | None:
        """Observed mean attempts divided by the theoretical expectation."""
        mean = self.mean_attempts
        return None if mean is None else mean / self.expected_attempts


@dataclass(frozen=True)
class BenchmarkReport:
    """All results of a benchmark session."""

    config: BenchmarkConfig
    results: tuple[AlgorithmBenchmark, ...]
    interrupted: bool = False


def measure_hash_rate(algorithm: HashAlgorithm, input_length: int, count: int) -> float:
    """Measure raw digest throughput (hashes/second) for inputs of *input_length* bytes."""
    if count <= 0:
        return 0.0
    data = os.urandom(input_length)
    digest = algorithm.digest_function()
    start = time.perf_counter()
    for _ in range(count):
        digest(data)
    elapsed = time.perf_counter() - start
    return count / elapsed if elapsed > 0 else 0.0


class BenchmarkRunner:
    """Run repeated collision searches for one or more algorithms.

    Each iteration uses a fresh random generator so that iterations are
    independent. Without a seed the inputs come from the CSPRNG; with a
    seed, iteration *i* uses ``SeededRandomGenerator(seed + i)`` for
    reproducibility (not cryptographically secure).
    """

    def __init__(self, config: BenchmarkConfig, registry: AlgorithmRegistry | None = None) -> None:
        self._config = config
        self._registry = registry or AlgorithmRegistry()
        self._algorithms = [self._registry.get(name) for name in config.algorithms]
        for algorithm in self._algorithms:
            validate_bits(config.bits, algorithm)

    @property
    def config(self) -> BenchmarkConfig:
        return self._config

    @property
    def algorithms(self) -> list[HashAlgorithm]:
        return list(self._algorithms)

    def _generator(self, iteration: int) -> InputGenerator:
        cfg = self._config
        if cfg.seed is None:
            return RandomGenerator(cfg.input_length)
        return SeededRandomGenerator(cfg.input_length, cfg.seed + iteration)

    def _engine(self, algorithm: HashAlgorithm, generator: InputGenerator) -> CollisionEngine:
        cfg = self._config
        return CollisionEngine(
            algorithm,
            cfg.bits,
            generator,
            method=cfg.method,
            max_attempts=cfg.max_attempts,
            max_seconds=cfg.max_seconds,
            max_stored=cfg.max_stored,
            force=cfg.force,
            registry=self._registry,
        )

    def check_feasibility(self) -> list[SearchEstimate]:
        """Validate every configured search up front (raises on unsafe settings)."""
        return [
            self._engine(algorithm, self._generator(0)).check_feasibility()
            for algorithm in self._algorithms
        ]

    def run(self, progress: Callable[[HashAlgorithm], None] | None = None) -> BenchmarkReport:
        """Run the benchmark. Ctrl+C stops it and returns partial results."""
        cfg = self._config
        expected = get_strategy(cfg.method).expected_attempts(cfg.bits)
        results: list[AlgorithmBenchmark] = []
        interrupted = False
        for algorithm in self._algorithms:
            if progress is not None:
                progress(algorithm)
            raw_rate: float | None = None
            runs: list[BenchmarkRun] = []
            try:
                if cfg.raw_hashes:
                    raw_rate = measure_hash_rate(algorithm, cfg.input_length, cfg.raw_hashes)
            except KeyboardInterrupt:
                interrupted = True
            if not interrupted:
                for iteration in range(cfg.iterations):
                    outcome = self._engine(algorithm, self._generator(iteration)).run()
                    stats = outcome.statistics
                    runs.append(BenchmarkRun(outcome.status, stats.attempts, stats.elapsed_seconds))
                    if outcome.status is SearchStatus.INTERRUPTED:
                        interrupted = True
                        break
            results.append(
                AlgorithmBenchmark(
                    algorithm=algorithm.name,
                    display_name=algorithm.display_name,
                    bits=cfg.bits,
                    method=cfg.method,
                    expected_attempts=expected,
                    runs=tuple(runs),
                    raw_hashes_per_second=raw_rate,
                )
            )
            if interrupted:
                break
        return BenchmarkReport(config=cfg, results=tuple(results), interrupted=interrupted)


def benchmark_table(results: tuple[AlgorithmBenchmark, ...] | list[AlgorithmBenchmark]) -> str:
    """Render benchmark results as an aligned text table."""
    headers = [
        "Algorithm",
        "Bits",
        "Runs",
        "Found",
        "Mean attempts",
        "Median",
        "Expected",
        "Obs/Exp",
        "Mean time (s)",
        "Search H/s",
        "Raw H/s",
    ]
    rows = []
    for result in results:
        mean = result.mean_attempts
        median = result.median_attempts
        ratio = result.attempts_ratio
        mean_elapsed = result.mean_elapsed
        rows.append(
            [
                result.display_name,
                str(result.bits),
                str(len(result.runs)),
                str(result.found_count),
                "-" if mean is None else f"{mean:,.1f}",
                "-" if median is None else f"{median:,.0f}",
                format_count(result.expected_attempts),
                "-" if ratio is None else f"{ratio:.2f}",
                "-" if mean_elapsed is None else f"{mean_elapsed:.6f}",
                format_rate(result.hashes_per_second),
                "-"
                if result.raw_hashes_per_second is None
                else format_rate(result.raw_hashes_per_second),
            ]
        )
    return format_table(headers, rows, align=["l"] + ["r"] * (len(headers) - 1))
