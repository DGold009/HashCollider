"""Tests for the collision engine, strategies and birthday mathematics."""

from __future__ import annotations

import hashlib
import math
import threading

import pytest

from hashcollider.collision import (
    CollisionEngine,
    SearchLimits,
    SearchStatus,
    attempts_for_probability,
    birthday_bound,
    brute_force_success_probability,
    collision_probability,
    expected_birthday_attempts,
    expected_brute_force_attempts,
    normalize_method,
    verify_collision,
)
from hashcollider.errors import (
    ConfigurationError,
    GeneratorExhaustedError,
    InfeasibleSearchError,
    InvalidBitLengthError,
    MaxAttemptsReachedError,
    MaxTimeReachedError,
    SearchInterruptedError,
    UnsupportedAlgorithmError,
)
from hashcollider.generators import (
    SeededRandomGenerator,
    SequentialGenerator,
    StructuredGenerator,
)
from hashcollider.hashing import get_algorithm

# ---------------------------------------------------------------------------
# Birthday mathematics
# ---------------------------------------------------------------------------


def test_birthday_bound_is_sqrt_of_space() -> None:
    assert birthday_bound(16) == 256
    assert birthday_bound(32) == 65536
    assert birthday_bound(8) == 16
    assert math.isclose(birthday_bound(15), math.sqrt(2**15))


def test_expected_birthday_attempts() -> None:
    assert math.isclose(expected_birthday_attempts(16), math.sqrt(math.pi / 2 * 2**16) + 2 / 3)
    assert 320 < expected_birthday_attempts(16) < 322


def test_collision_probability_properties() -> None:
    assert collision_probability(0, 16) == 0.0
    assert collision_probability(1, 16) == 0.0
    # At the birthday bound the probability is about 1 - e^(-1/2) ~ 39%.
    assert 0.38 < collision_probability(256, 16) < 0.40
    values = [collision_probability(n, 16) for n in (10, 100, 300, 1000, 5000)]
    assert values == sorted(values)
    assert collision_probability(5000, 16) > 0.99


def test_classic_birthday_problem() -> None:
    # 23 people, 365 days: ~50%. Our formula uses 2^b, so check the underlying maths.
    p = -math.expm1(-23 * 22 / (2 * 365))
    assert 0.49 < p < 0.51


def test_attempts_for_probability_round_trip() -> None:
    n = attempts_for_probability(0.5, 32)
    assert math.isclose(collision_probability(round(n), 32), 0.5, abs_tol=0.001)
    with pytest.raises(ValueError):
        attempts_for_probability(1.0, 16)


def test_brute_force_expectations() -> None:
    assert expected_brute_force_attempts(16) == 2**16 + 1
    assert brute_force_success_probability(1, 16) == 0.0
    assert 0.62 < brute_force_success_probability(2**16 + 1, 16) < 0.64  # 1 - 1/e


def test_normalize_method() -> None:
    assert normalize_method("birthday") == "birthday"
    assert normalize_method("brute_force") == "brute-force"
    assert normalize_method("BruteForce") == "brute-force"
    with pytest.raises(ConfigurationError, match="Unknown search method"):
        normalize_method("rainbow")


# ---------------------------------------------------------------------------
# Known small collision (deterministic): SHA-256 truncated to 8 bits
# ---------------------------------------------------------------------------


def test_known_small_collision_sha256_8_bits() -> None:
    engine = CollisionEngine("sha256", bits=8, generator=SequentialGenerator())
    result = engine.find_collision()

    a, b = result.input_a, result.input_b
    assert a != b
    # Independently recompute with hashlib - do not trust the engine's values.
    digest_a = hashlib.sha256(a).digest()
    digest_b = hashlib.sha256(b).digest()
    assert digest_a[0] == digest_b[0]
    assert digest_a != digest_b  # a truncated collision, not a full SHA-256 collision
    assert result.hash_a == digest_a.hex()
    assert result.hash_b == digest_b.hex()
    assert result.truncated_hash == f"{digest_a[0]:02x}"
    # Pigeonhole: 257 distinct inputs always contain an 8-bit collision.
    assert 2 <= result.attempts <= 2**8 + 1
    assert verify_collision(result).passed

    # Deterministic generator -> identical, reproducible result.
    again = CollisionEngine("sha256", bits=8, generator=SequentialGenerator()).find_collision()
    assert (again.input_a, again.input_b, again.attempts) == (a, b, result.attempts)


@pytest.mark.parametrize(
    "name",
    [
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
    ],
)
def test_birthday_finds_collision_for_every_algorithm(name: str) -> None:
    engine = CollisionEngine(name, bits=12, generator=SequentialGenerator())
    result = engine.find_collision()
    algorithm = get_algorithm(name)
    full_a, full_b = algorithm.digest(result.input_a), algorithm.digest(result.input_b)
    assert result.input_a != result.input_b
    assert int.from_bytes(full_a[:2], "big") >> 4 == int.from_bytes(full_b[:2], "big") >> 4
    assert full_a != full_b
    assert result.algorithm == name
    assert result.effective_bits == 12
    assert result.output_bits == algorithm.output_bits


@pytest.mark.parametrize("bits", [1, 3, 8, 12, 16, 20])
def test_birthday_various_bit_sizes(bits: int) -> None:
    result = CollisionEngine("sha256", bits, SeededRandomGenerator(16, seed=bits)).find_collision()
    assert verify_collision(result).passed
    assert result.attempts <= 2**bits + 1


def test_brute_force_uses_first_input_as_target() -> None:
    generator = SequentialGenerator()
    result = CollisionEngine(
        "sha256", bits=8, generator=generator, method="brute-force"
    ).find_collision()
    first = next(iter(generator))
    assert result.input_a == first
    assert result.input_b != first
    assert hashlib.sha256(result.input_a).digest()[0] == hashlib.sha256(result.input_b).digest()[0]
    assert verify_collision(result).passed
    assert result.method == "brute-force"


def test_result_fields_are_complete() -> None:
    result = CollisionEngine("sha256", 16, SequentialGenerator(length=32)).find_collision()
    assert result.algorithm == "sha256"
    assert result.algorithm_display_name == "SHA-256"
    assert result.output_bits == 256
    assert result.effective_bits == 16
    assert result.method == "birthday"
    assert result.generator == "sequential"
    assert result.generator_params["width"] == 17
    assert result.input_length == 32
    assert len(result.hash_a or "") == 64
    assert len(result.truncated_hash or "") == 4
    assert result.attempts is not None and result.attempts > 1
    assert result.elapsed_seconds is not None and result.elapsed_seconds >= 0
    assert result.hashes_per_second is not None and result.hashes_per_second >= 0
    assert result.timestamp and result.timestamp.endswith("+00:00")
    assert result.full_digests_equal is False
    assert result.is_truncated is True


def test_run_returns_outcome_with_statistics() -> None:
    engine = CollisionEngine("sha256", 16, SequentialGenerator())
    outcome = engine.run()
    assert outcome.found
    assert outcome.status is SearchStatus.FOUND
    assert outcome.statistics.attempts == outcome.collision.attempts
    assert engine.statistics().attempts == outcome.statistics.attempts
    assert outcome.statistics.stored_digests == outcome.statistics.attempts - 1
    assert engine.last_outcome is outcome
    assert not engine.running


# ---------------------------------------------------------------------------
# Duplicate inputs are not collisions
# ---------------------------------------------------------------------------


def test_duplicate_inputs_are_not_collisions(scripted) -> None:
    generator = scripted(repeat=b"same input", count=1000)
    outcome = CollisionEngine("sha256", 8, generator).run()
    assert outcome.status is SearchStatus.EXHAUSTED
    assert outcome.collision is None
    assert outcome.statistics.attempts == 1000
    assert outcome.statistics.duplicate_inputs == 999
    assert outcome.statistics.stored_digests == 1


def test_duplicates_rejected_by_brute_force(scripted) -> None:
    generator = scripted(repeat=b"same input", count=50)
    outcome = CollisionEngine("sha256", 8, generator, method="brute-force").run()
    assert outcome.status is SearchStatus.EXHAUSTED
    assert outcome.statistics.duplicate_inputs == 49


def test_collision_found_after_duplicates(scripted) -> None:
    # Find two distinct inputs that collide in 8 bits, then feed duplicates first.
    seen: dict[int, bytes] = {}
    pair = None
    for i in range(300):
        message = f"msg-{i}".encode()
        key = hashlib.sha256(message).digest()[0]
        if key in seen:
            pair = (seen[key], message)
            break
        seen[key] = message
    assert pair is not None
    first, second = pair
    generator = scripted([first, first, first, second])
    outcome = CollisionEngine("sha256", 8, generator).run()
    assert outcome.found
    assert (outcome.collision.input_a, outcome.collision.input_b) == (first, second)
    assert outcome.statistics.duplicate_inputs == 2
    assert outcome.statistics.attempts == 4


# ---------------------------------------------------------------------------
# Limits, interruption and stopping
# ---------------------------------------------------------------------------


def test_max_attempts_limit(scripted) -> None:
    engine = CollisionEngine("sha256", 16, scripted(repeat=b"x"), max_attempts=500)
    outcome = engine.run()
    assert outcome.status is SearchStatus.MAX_ATTEMPTS
    assert outcome.statistics.attempts == 500
    with pytest.raises(MaxAttemptsReachedError, match="Maximum attempt limit reached") as info:
        engine.find_collision()
    assert info.value.statistics is not None
    assert info.value.statistics.attempts == 500


def test_max_attempts_limit_brute_force(scripted) -> None:
    outcome = CollisionEngine(
        "sha256", 16, scripted(repeat=b"x"), method="brute-force", max_attempts=1
    ).run()
    assert outcome.status is SearchStatus.MAX_ATTEMPTS
    assert outcome.statistics.attempts == 1


def test_max_attempts_on_real_search() -> None:
    outcome = CollisionEngine("sha256", 32, SequentialGenerator(), max_attempts=10).run()
    assert outcome.status is SearchStatus.MAX_ATTEMPTS
    assert outcome.statistics.attempts == 10


@pytest.mark.parametrize("method", ["birthday", "brute-force"])
def test_timeout_limit(scripted, method: str) -> None:
    engine = CollisionEngine(
        "sha256", 16, scripted(repeat=b"never collides"), method=method, max_seconds=0.05
    )
    outcome = engine.run()
    assert outcome.status is SearchStatus.TIMEOUT
    assert outcome.statistics.elapsed_seconds >= 0.05
    assert outcome.statistics.attempts > 0
    with pytest.raises(MaxTimeReachedError, match="Maximum execution time reached"):
        engine.find_collision()


@pytest.mark.parametrize("method", ["birthday", "brute-force"])
def test_keyboard_interrupt_preserves_statistics(scripted, method: str) -> None:
    generator = scripted(repeat=b"dup", count=100, then_raise=KeyboardInterrupt())
    engine = CollisionEngine("sha256", 16, generator, method=method)
    outcome = engine.run()
    assert outcome.status is SearchStatus.INTERRUPTED
    assert outcome.statistics.attempts == 100
    assert outcome.statistics.duplicate_inputs == 99
    assert engine.statistics().attempts == 100


def test_keyboard_interrupt_error_from_find_collision(scripted) -> None:
    generator = scripted(repeat=b"dup", count=10, then_raise=KeyboardInterrupt())
    with pytest.raises(SearchInterruptedError) as info:
        CollisionEngine("sha256", 16, generator).find_collision()
    assert info.value.exit_code == 130
    assert info.value.statistics.attempts == 10


def test_stop_request(scripted) -> None:
    holder: dict[str, CollisionEngine] = {}

    def hook(index: int) -> None:
        if index == 5000:
            holder["engine"].stop()

    engine = CollisionEngine("sha256", 16, scripted(repeat=b"x", hook=hook), check_interval=256)
    holder["engine"] = engine
    outcome = engine.run()
    assert outcome.status is SearchStatus.STOPPED
    assert 5000 < outcome.statistics.attempts <= 5000 + 256 + 1


def test_stop_from_another_thread(scripted) -> None:
    engine = CollisionEngine("sha256", 16, scripted(repeat=b"x"), max_seconds=30)
    timer = threading.Timer(0.05, engine.stop)
    timer.start()
    try:
        outcome = engine.run()
    finally:
        timer.cancel()
    assert outcome.status is SearchStatus.STOPPED


def test_generator_exhausted() -> None:
    generator = StructuredGenerator(prefix="x", start=0, width=1)  # only 10 inputs
    engine = CollisionEngine("sha256", 32, generator)
    outcome = engine.run()
    assert outcome.status is SearchStatus.EXHAUSTED
    assert outcome.statistics.attempts == 10
    with pytest.raises(GeneratorExhaustedError):
        engine.find_collision()


def test_empty_generator(scripted) -> None:
    for method in ("birthday", "brute-force"):
        outcome = CollisionEngine("sha256", 8, scripted([]), method=method).run()
        assert outcome.status is SearchStatus.EXHAUSTED
        assert outcome.statistics.attempts == 0


def test_max_stored_bounds_memory() -> None:
    engine = CollisionEngine("sha256", 32, SequentialGenerator(), max_stored=10, max_attempts=1000)
    outcome = engine.run()
    assert outcome.status is SearchStatus.MAX_ATTEMPTS
    assert outcome.statistics.stored_digests == 10


def test_max_stored_search_remains_correct() -> None:
    # Only 20 digests stored, but later inputs are still compared against them.
    engine = CollisionEngine("sha256", 8, SequentialGenerator(), max_stored=20)
    result = engine.find_collision()
    assert verify_collision(result).passed
    assert engine.statistics().stored_digests <= 20


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_attempts": 0},
        {"max_attempts": -5},
        {"max_seconds": 0},
        {"max_seconds": -1.0},
        {"max_seconds": float("nan")},
        {"max_stored": 0},
        {"check_interval": 1000},
    ],
)
def test_invalid_limits(kwargs: dict) -> None:
    with pytest.raises(ConfigurationError):
        CollisionEngine("sha256", 16, **kwargs)


def test_search_limits_defaults() -> None:
    limits = SearchLimits()
    assert limits.max_attempts is None
    assert limits.max_seconds is None
    assert limits.max_stored is not None


# ---------------------------------------------------------------------------
# Feasibility safeguards
# ---------------------------------------------------------------------------


def test_full_sha256_search_is_refused_even_with_force() -> None:
    engine = CollisionEngine("sha256", bits=None, force=True)
    assert engine.bits == 256
    with pytest.raises(InfeasibleSearchError, match="computationally infeasible"):
        engine.run()


def test_full_md5_search_explains_cryptanalysis() -> None:
    with pytest.raises(InfeasibleSearchError, match="dedicated cryptanalytic attacks"):
        CollisionEngine("md5", bits=128, force=True).check_feasibility()


def test_large_birthday_search_requires_force() -> None:
    engine = CollisionEngine("sha256", bits=40)
    estimate = engine.estimate()
    assert estimate.requires_force
    assert not estimate.infeasible
    with pytest.raises(InfeasibleSearchError, match="--force"):
        engine.check_feasibility()
    CollisionEngine("sha256", bits=40, force=True).check_feasibility()


def test_large_brute_force_search_requires_force() -> None:
    with pytest.raises(InfeasibleSearchError, match="--force"):
        CollisionEngine("sha256", bits=28, method="brute-force").check_feasibility()
    with pytest.raises(InfeasibleSearchError, match="infeasible"):
        CollisionEngine("sha256", bits=40, method="brute-force", force=True).check_feasibility()


def test_estimate_values() -> None:
    estimate = CollisionEngine("sha256", bits=16).estimate()
    assert estimate.birthday_bound == 256
    assert math.isclose(estimate.expected_attempts, expected_birthday_attempts(16))
    assert estimate.space_size == 65536
    assert estimate.estimated_memory_bytes > 0
    brute = CollisionEngine("sha256", bits=16, method="brute-force").estimate()
    assert brute.expected_attempts == 2**16 + 1
    assert brute.expected_stored_entries == 1


def test_input_space_warning_flag() -> None:
    small = CollisionEngine("sha256", 24, StructuredGenerator(prefix="a", width=2)).estimate()
    assert small.input_space_may_be_too_small
    large = CollisionEngine("sha256", 16, SequentialGenerator()).estimate()
    assert not large.input_space_may_be_too_small


def test_invalid_algorithm_and_bits() -> None:
    with pytest.raises(UnsupportedAlgorithmError):
        CollisionEngine("sha-999", 16)
    with pytest.raises(InvalidBitLengthError):
        CollisionEngine("sha256", 0)
    with pytest.raises(InvalidBitLengthError):
        CollisionEngine("md5", 129)
    with pytest.raises(ConfigurationError):
        CollisionEngine("sha256", 16, method="magic")


def test_engine_rejects_truncated_algorithm_instance() -> None:
    with pytest.raises(ConfigurationError):
        CollisionEngine(get_algorithm("sha256", bits=16), 16)


def test_engine_accepts_algorithm_instance() -> None:
    engine = CollisionEngine(get_algorithm("sha3-256"), 8)
    assert engine.algorithm.name == "sha3-256"
    assert engine.find_collision().algorithm == "sha3-256"
