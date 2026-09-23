"""Input generators and a factory used by the CLI."""

from __future__ import annotations

from ..config import (
    DEFAULT_RANDOM_LENGTH,
    SEQUENTIAL_DEFAULT_START,
    STRUCTURED_DEFAULT_PREFIX,
    STRUCTURED_DEFAULT_START,
    STRUCTURED_DEFAULT_WIDTH,
)
from ..errors import ConfigurationError
from .base import InputGenerator, validate_input_length
from .random import SEEDED_WARNING, RandomGenerator, SeededRandomGenerator
from .sequential import SequentialGenerator
from .structured import StructuredGenerator

GENERATOR_NAMES: tuple[str, ...] = ("random", "sequential", "structured")


def create_generator(
    name: str,
    *,
    length: int | None = None,
    seed: int | None = None,
    prefix: str | None = None,
    suffix: str | None = None,
    start: int | None = None,
    width: int | None = None,
) -> InputGenerator:
    """Build a generator from CLI-style options.

    * ``random``: :class:`RandomGenerator` (CSPRNG), or
      :class:`SeededRandomGenerator` when *seed* is given (reproducible,
      NOT cryptographically secure). *length* defaults to 32 bytes.
    * ``sequential``: ``collision-test-`` + counter; *length* sets the total size.
    * ``structured``: *prefix* + counter (*start*, *width*) + *suffix*.

    Options that do not apply to the chosen generator are ignored; use
    :func:`ignored_options` to report them to the user.
    """
    key = name.strip().lower()
    if key == "random":
        size = DEFAULT_RANDOM_LENGTH if length is None else length
        if seed is not None:
            return SeededRandomGenerator(size, seed)
        return RandomGenerator(size)
    if key == "sequential":
        return SequentialGenerator(
            length=length,
            start=SEQUENTIAL_DEFAULT_START if start is None else start,
            width=width,
        )
    if key == "structured":
        prefix_value = STRUCTURED_DEFAULT_PREFIX if prefix is None else prefix
        suffix_value = "" if suffix is None else suffix
        start_value = STRUCTURED_DEFAULT_START if start is None else start
        if width is None and length is not None:
            return StructuredGenerator.for_length(
                length, prefix=prefix_value, start=start_value, suffix=suffix_value
            )
        generator = StructuredGenerator(
            prefix=prefix_value,
            start=start_value,
            width=STRUCTURED_DEFAULT_WIDTH if width is None else width,
            suffix=suffix_value,
        )
        if length is not None and generator.input_length != length:
            raise ConfigurationError(
                f"--length {length} conflicts with prefix/width/suffix, which produce "
                f"{generator.input_length}-byte inputs"
            )
        return generator
    raise ConfigurationError(
        f"Unknown generator: {name!r}. Choose from: {', '.join(GENERATOR_NAMES)}"
    )


def ignored_options(
    name: str,
    *,
    seed: int | None = None,
    prefix: str | None = None,
    suffix: str | None = None,
    start: int | None = None,
    width: int | None = None,
) -> list[str]:
    """Return the names of options that the generator *name* does not use."""
    given = {
        "--seed": seed,
        "--prefix": prefix,
        "--suffix": suffix,
        "--start": start,
        "--width": width,
    }
    used = {
        "random": {"--seed"},
        "sequential": {"--start", "--width"},
        "structured": {"--prefix", "--suffix", "--start", "--width"},
    }.get(name.strip().lower(), set())
    return [option for option, value in given.items() if value is not None and option not in used]


__all__ = [
    "GENERATOR_NAMES",
    "SEEDED_WARNING",
    "InputGenerator",
    "RandomGenerator",
    "SeededRandomGenerator",
    "SequentialGenerator",
    "StructuredGenerator",
    "create_generator",
    "ignored_options",
    "validate_input_length",
]
