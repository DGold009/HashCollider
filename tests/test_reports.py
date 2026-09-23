"""Tests for Markdown report generation and benchmark calculations."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from hashcollider.benchmark import (
    AlgorithmBenchmark,
    BenchmarkConfig,
    BenchmarkRun,
    BenchmarkRunner,
    benchmark_table,
    measure_hash_rate,
)
from hashcollider.collision import CollisionEngine, CollisionResult, SearchStatus, verify_collision
from hashcollider.errors import ConfigurationError, InfeasibleSearchError, InvalidBitLengthError
from hashcollider.explain import TOPICS, birthday_table, explain
from hashcollider.generators import SequentialGenerator
from hashcollider.hashing import get_algorithm
from hashcollider.reports import generate_report, headline, write_report


@pytest.fixture(scope="module")
def sha256_collision() -> CollisionResult:
    return CollisionEngine("sha256", 16, SequentialGenerator(length=32)).find_collision()


@pytest.fixture(scope="module")
def md5_collision() -> CollisionResult:
    return CollisionEngine("md5", 12, SequentialGenerator()).find_collision()


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def test_report_sections(sha256_collision: CollisionResult) -> None:
    report = generate_report(sha256_collision, verify_collision(sha256_collision), source="c.json")
    for heading in (
        "# HashCollider Collision Report",
        "## 1. Experiment information",
        "## 2. Algorithm and effective hash size",
        "## 3. Input details",
        "## 4. Collision values",
        "## 5. Search statistics",
        "## 6. Verification",
        "## 7. Why the collision occurred",
        "## 8. Security interpretation",
        "## 9. Limitations",
    ):
        assert heading in report, heading
    assert sha256_collision.input_a.hex() in report
    assert sha256_collision.input_b.hex() in report
    assert sha256_collision.hash_a in report
    assert sha256_collision.hash_b in report
    assert "Collision verification: PASS" in report
    assert "sequential" in report
    assert f"{sha256_collision.attempts:,}" in report


def test_report_is_cryptographically_precise(sha256_collision: CollisionResult) -> None:
    report = generate_report(sha256_collision, verify_collision(sha256_collision))
    assert (
        "Only the selected truncated output space was searched. "
        "The full SHA-256 digests remain different." in report
    )
    assert (
        "A collision was found in the first 16 bits of SHA-256. This does not constitute "
        "a collision in the full SHA-256 output." in report
    )
    lowered = report.lower()
    assert "sha-256 is broken" not in lowered
    assert "broke sha-256" not in lowered


def test_report_for_legacy_algorithm(md5_collision: CollisionResult) -> None:
    report = generate_report(md5_collision, verify_collision(md5_collision))
    assert "MD5 is considered cryptographically broken" in report
    assert "does **not** demonstrate those attacks" in report
    assert "The full MD5 digests remain different." in report


def test_report_for_failed_verification(sha256_collision: CollisionResult) -> None:
    forged = replace(sha256_collision, input_b=sha256_collision.input_a)
    verification = verify_collision(forged)
    report = generate_report(forged, verification)
    assert "Verification FAILED" in report
    assert "Collision verification: FAIL" in report
    assert "Only the selected truncated output space was searched" in report  # limitations
    assert "A collision was found in the first" not in report


def test_headline_names_effective_bits() -> None:
    record = CollisionEngine("sha256", 8, SequentialGenerator()).find_collision()
    text = headline(verify_collision(record))
    assert "first 8 bits of SHA-256" in text
    assert "does not constitute a collision in the full SHA-256 output" in text


def test_report_for_minimal_record(sha256_collision: CollisionResult) -> None:
    minimal = CollisionResult(
        algorithm="sha256",
        effective_bits=16,
        input_a=sha256_collision.input_a,
        input_b=sha256_collision.input_b,
    )
    report = generate_report(minimal, verify_collision(minimal))
    assert "_not recorded_" in report
    assert "Collision verification: PASS" in report


def test_write_report_creates_directories(
    tmp_path: Path, sha256_collision: CollisionResult
) -> None:
    markdown = generate_report(sha256_collision, verify_collision(sha256_collision))
    path = write_report(markdown, tmp_path / "reports" / "collision-report.md")
    assert path.read_text(encoding="utf-8") == markdown


# ---------------------------------------------------------------------------
# Explanations
# ---------------------------------------------------------------------------


def test_explain_collision_covers_required_points() -> None:
    text = explain("collision")
    for phrase in (
        "cryptographic hash function",
        "What is a collision",
        "Why do collisions matter",
        "birthday paradox",
        "2^(b/2)",
        "reducing the output size",
        "does NOT imply",
        "This does not\n   constitute a collision in the full SHA-256 output.",
    ):
        assert phrase in text, phrase


@pytest.mark.parametrize("topic", list(TOPICS))
def test_every_topic_renders(topic: str) -> None:
    assert explain(topic).strip()


def test_explain_unknown_topic() -> None:
    with pytest.raises(KeyError):
        explain("nonsense")


def test_birthday_table_contents() -> None:
    table = birthday_table((16, 256))
    assert "65,536" in table
    assert "256" in table
    assert "years" in table


# ---------------------------------------------------------------------------
# Benchmark calculations
# ---------------------------------------------------------------------------


def _bench(attempts: list[int], statuses: list[SearchStatus] | None = None) -> AlgorithmBenchmark:
    statuses = statuses or [SearchStatus.FOUND] * len(attempts)
    runs = tuple(
        BenchmarkRun(status, count, count / 1000.0)
        for status, count in zip(statuses, attempts, strict=True)
    )
    return AlgorithmBenchmark(
        algorithm="sha256",
        display_name="SHA-256",
        bits=16,
        method="birthday",
        expected_attempts=320.0,
        runs=runs,
        raw_hashes_per_second=2_000_000.0,
    )


def test_benchmark_statistics() -> None:
    bench = _bench([100, 200, 300, 400])
    assert bench.found_count == 4
    assert bench.total_attempts == 1000
    assert bench.mean_attempts == 250
    assert bench.median_attempts == 250
    assert bench.stdev_attempts == pytest.approx(129.0994, rel=1e-4)
    assert bench.mean_elapsed == pytest.approx(0.25)
    assert bench.hashes_per_second == pytest.approx(1000.0)
    assert bench.attempts_ratio == pytest.approx(250 / 320)


def test_benchmark_statistics_ignore_unfinished_runs_for_means() -> None:
    bench = _bench([100, 5000], [SearchStatus.FOUND, SearchStatus.TIMEOUT])
    assert bench.found_count == 1
    assert bench.mean_attempts == 100
    assert bench.stdev_attempts is None
    assert bench.total_attempts == 5100  # throughput still counts every hash


def test_benchmark_statistics_no_found_runs() -> None:
    bench = _bench([10], [SearchStatus.MAX_ATTEMPTS])
    assert bench.mean_attempts is None
    assert bench.attempts_ratio is None
    assert "-" in benchmark_table([bench])


def test_benchmark_table_renders() -> None:
    table = benchmark_table([_bench([100, 200])])
    assert "SHA-256" in table
    assert "Mean attempts" in table
    assert "2,000,000" in table


def test_measure_hash_rate() -> None:
    assert measure_hash_rate(get_algorithm("sha256"), 32, 2000) > 0
    assert measure_hash_rate(get_algorithm("sha256"), 32, 0) == 0.0


def test_benchmark_runner_small_run() -> None:
    config = BenchmarkConfig(
        algorithms=("sha256", "md5"), bits=8, iterations=5, input_length=16, raw_hashes=1000
    )
    report = BenchmarkRunner(config).run()
    assert not report.interrupted
    assert [r.algorithm for r in report.results] == ["sha256", "md5"]
    for result in report.results:
        assert len(result.runs) == 5
        assert result.found_count == 5
        assert all(run.attempts <= 2**8 + 1 for run in result.runs)
        assert result.raw_hashes_per_second and result.raw_hashes_per_second > 0


def test_benchmark_runner_seeded_is_reproducible() -> None:
    config = BenchmarkConfig(algorithms=("sha256",), bits=10, iterations=4, seed=123, raw_hashes=0)
    first = BenchmarkRunner(config).run().results[0]
    second = BenchmarkRunner(config).run().results[0]
    assert [r.attempts for r in first.runs] == [r.attempts for r in second.runs]
    assert first.raw_hashes_per_second is None


def test_benchmark_config_validation() -> None:
    with pytest.raises(ConfigurationError):
        BenchmarkConfig(iterations=0)
    with pytest.raises(ConfigurationError):
        BenchmarkConfig(algorithms=())
    with pytest.raises(ConfigurationError):
        BenchmarkConfig(input_length=0)
    with pytest.raises(ConfigurationError):
        BenchmarkConfig(method="nope")
    with pytest.raises(InvalidBitLengthError):
        BenchmarkRunner(BenchmarkConfig(algorithms=("md5",), bits=200))


def test_benchmark_feasibility_check() -> None:
    runner = BenchmarkRunner(BenchmarkConfig(bits=48))
    with pytest.raises(InfeasibleSearchError):
        runner.check_feasibility()
