"""Tests for input generators."""

from __future__ import annotations

from itertools import islice

import pytest

from hashcollider.errors import ConfigurationError, InvalidInputLengthError
from hashcollider.generators import (
    RandomGenerator,
    SeededRandomGenerator,
    SequentialGenerator,
    StructuredGenerator,
    create_generator,
    ignored_options,
)


def take(generator, n: int) -> list[bytes]:
    return list(islice(iter(generator), n))


# ---------------------------------------------------------------------------
# Random (CSPRNG)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [1, 2, 16, 32, 100, 5000])
def test_random_generator_length(length: int) -> None:
    items = take(RandomGenerator(length), 50)
    assert len(items) == 50
    assert all(isinstance(item, bytes) and len(item) == length for item in items)


def test_random_generator_outputs_are_distinct() -> None:
    items = take(RandomGenerator(32), 5000)
    assert len(set(items)) == len(items)


def test_random_generator_is_not_reproducible() -> None:
    generator = RandomGenerator(32)
    assert take(generator, 10) != take(generator, 10)


def test_random_generator_metadata() -> None:
    generator = RandomGenerator(4)
    assert generator.cryptographically_secure
    assert not generator.deterministic
    assert generator.input_length == 4
    assert generator.input_space_size() == 2**32
    assert generator.describe()["length"] == 4


@pytest.mark.parametrize("length", [0, -1, -100])
def test_random_generator_rejects_non_positive_length(length: int) -> None:
    with pytest.raises(InvalidInputLengthError, match="Input length must be positive"):
        RandomGenerator(length)


@pytest.mark.parametrize("length", [1.5, "32", None, True])
def test_random_generator_rejects_non_integer_length(length: object) -> None:
    with pytest.raises(InvalidInputLengthError):
        RandomGenerator(length)  # type: ignore[arg-type]


def test_random_generator_rejects_huge_length() -> None:
    with pytest.raises(InvalidInputLengthError, match="exceeds"):
        RandomGenerator(10**9)


# ---------------------------------------------------------------------------
# Seeded random (reproducible, NOT cryptographic)
# ---------------------------------------------------------------------------


def test_seeded_generator_is_reproducible() -> None:
    assert take(SeededRandomGenerator(16, seed=42), 100) == take(
        SeededRandomGenerator(16, seed=42), 100
    )
    generator = SeededRandomGenerator(16, seed=7)
    assert take(generator, 20) == take(generator, 20)


def test_seeded_generator_different_seeds_differ() -> None:
    first = take(SeededRandomGenerator(16, seed=1), 10)
    assert first != take(SeededRandomGenerator(16, seed=2), 10)


def test_seeded_generator_is_flagged_insecure() -> None:
    generator = SeededRandomGenerator(8, seed=1)
    assert not generator.cryptographically_secure
    assert generator.deterministic
    assert "NOT cryptographically secure" in generator.describe()["source"]
    assert generator.describe()["seed"] == 1


def test_seeded_generator_rejects_bad_seed() -> None:
    with pytest.raises(ConfigurationError):
        SeededRandomGenerator(8, seed="abc")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Sequential
# ---------------------------------------------------------------------------


def test_sequential_default_format() -> None:
    assert take(SequentialGenerator(), 3) == [
        b"collision-test-00000001",
        b"collision-test-00000002",
        b"collision-test-00000003",
    ]


def test_sequential_is_deterministic() -> None:
    generator = SequentialGenerator()
    assert take(generator, 100) == take(generator, 100)
    assert generator.deterministic


def test_sequential_with_length() -> None:
    generator = SequentialGenerator(length=32)
    items = take(generator, 5)
    assert all(len(item) == 32 for item in items)
    assert items[0] == b"collision-test-" + b"1".rjust(17, b"0")
    assert generator.input_length == 32


def test_sequential_start() -> None:
    assert take(SequentialGenerator(start=41), 2) == [
        b"collision-test-00000041",
        b"collision-test-00000042",
    ]


@pytest.mark.parametrize("length", [1, 10, 15])
def test_sequential_rejects_too_short_length(length: int) -> None:
    with pytest.raises(InvalidInputLengthError, match="too short"):
        SequentialGenerator(length=length)


@pytest.mark.parametrize("length", [0, -5])
def test_sequential_rejects_non_positive_length(length: int) -> None:
    with pytest.raises(InvalidInputLengthError, match="positive"):
        SequentialGenerator(length=length)


def test_sequential_conflicting_length_and_width() -> None:
    with pytest.raises(ConfigurationError, match="conflicts"):
        SequentialGenerator(length=32, width=5)


def test_sequential_inputs_are_unique() -> None:
    items = take(SequentialGenerator(), 10_000)
    assert len(set(items)) == 10_000


# ---------------------------------------------------------------------------
# Structured
# ---------------------------------------------------------------------------


def test_structured_default_format() -> None:
    assert take(StructuredGenerator(), 2) == [b"experiment-000001", b"experiment-000002"]


def test_structured_custom_prefix_start_width_suffix() -> None:
    generator = StructuredGenerator(prefix="lab-", start=98, width=3, suffix=".txt")
    assert take(generator, 3) == [b"lab-098.txt", b"lab-099.txt", b"lab-100.txt"]
    assert generator.input_length == len(b"lab-000.txt")
    assert generator.describe() == {
        "prefix": "lab-",
        "suffix": ".txt",
        "start": 98,
        "width": 3,
        "length": 11,
    }


def test_structured_percent_in_prefix_is_literal() -> None:
    assert take(StructuredGenerator(prefix="100%-", width=2), 1) == [b"100%-01"]


def test_structured_exhausts_after_counter_range() -> None:
    generator = StructuredGenerator(prefix="x", start=0, width=1)
    items = list(generator)
    assert items == [f"x{i}".encode() for i in range(10)]
    assert generator.input_space_size() == 10


def test_structured_for_length() -> None:
    generator = StructuredGenerator.for_length(20, prefix="experiment-")
    assert generator.width == 9
    assert all(len(item) == 20 for item in take(generator, 3))


def test_structured_for_length_too_short() -> None:
    with pytest.raises(InvalidInputLengthError, match="too short"):
        StructuredGenerator.for_length(5, prefix="experiment-")


def test_structured_input_at() -> None:
    generator = StructuredGenerator(prefix="p", start=5, width=2)
    assert generator.input_at(0) == b"p05"
    assert generator.input_at(94) == b"p99"
    with pytest.raises(IndexError):
        generator.input_at(95)


@pytest.mark.parametrize(
    "kwargs",
    [{"width": 0}, {"width": -1}, {"start": -1}, {"start": 1000, "width": 3}],
)
def test_structured_rejects_invalid_parameters(kwargs: dict) -> None:
    with pytest.raises(ConfigurationError):
        StructuredGenerator(**kwargs)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def test_create_generator_random_default_length() -> None:
    generator = create_generator("random")
    assert isinstance(generator, RandomGenerator)
    assert generator.input_length == 32


def test_create_generator_random_with_seed_is_seeded() -> None:
    generator = create_generator("random", length=8, seed=3)
    assert isinstance(generator, SeededRandomGenerator)
    assert generator.seed == 3


def test_create_generator_sequential_length() -> None:
    generator = create_generator("sequential", length=32)
    assert isinstance(generator, SequentialGenerator)
    assert generator.input_length == 32


def test_create_generator_structured() -> None:
    generator = create_generator("structured", prefix="run-", start=5, width=4)
    assert take(generator, 1) == [b"run-0005"]
    derived = create_generator("structured", prefix="run-", length=12)
    assert derived.input_length == 12


def test_create_generator_structured_conflict() -> None:
    with pytest.raises(ConfigurationError, match="conflicts"):
        create_generator("structured", prefix="run-", width=4, length=30)


def test_create_generator_unknown() -> None:
    with pytest.raises(ConfigurationError, match="Unknown generator"):
        create_generator("quantum")


def test_create_generator_invalid_length() -> None:
    with pytest.raises(InvalidInputLengthError):
        create_generator("random", length=0)


def test_ignored_options() -> None:
    assert ignored_options("random", seed=1, prefix="x") == ["--prefix"]
    assert ignored_options("sequential", seed=1, start=3) == ["--seed"]
    assert ignored_options("structured", prefix="a", width=3) == []
