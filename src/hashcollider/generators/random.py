"""Random input generators.

* :class:`RandomGenerator` uses the :mod:`secrets` module (the operating
  system CSPRNG). It is unpredictable and **not** reproducible.
* :class:`SeededRandomGenerator` uses :class:`random.Random` (Mersenne
  Twister) seeded with a user value. It is reproducible and **NOT
  cryptographically secure** - it exists only so experiments can be repeated.
"""

from __future__ import annotations

import random as _stdlib_random
import secrets
from collections.abc import Iterator
from typing import Any

from ..config import DEFAULT_RANDOM_LENGTH
from ..errors import ConfigurationError
from .base import InputGenerator, validate_input_length

SEEDED_WARNING = (
    "Seeded random generation uses Python's random.Random (Mersenne Twister). "
    "It is intended for reproducible experiments only and is NOT cryptographically "
    "secure. Omit --seed to use the cryptographically secure 'secrets' module."
)

_TARGET_CHUNK_BYTES = 64 * 1024


def _batch_count(length: int) -> int:
    """How many inputs to draw from the RNG per call (amortises call overhead)."""
    return max(1, min(1024, _TARGET_CHUNK_BYTES // length))


class RandomGenerator(InputGenerator):
    """Cryptographically strong random inputs from :func:`secrets.token_bytes`."""

    name = "random"

    def __init__(self, length: int = DEFAULT_RANDOM_LENGTH) -> None:
        self._length = validate_input_length(length)

    def __iter__(self) -> Iterator[bytes]:
        length = self._length
        chunk = length * _batch_count(length)
        token_bytes = secrets.token_bytes
        while True:
            buffer = token_bytes(chunk)
            for offset in range(0, chunk, length):
                yield buffer[offset : offset + length]

    @property
    def input_length(self) -> int:
        return self._length

    def input_space_size(self) -> int:
        return 256**self._length

    @property
    def cryptographically_secure(self) -> bool:
        return True

    def describe(self) -> dict[str, Any]:
        return {"length": self._length, "source": "secrets (CSPRNG)"}


class SeededRandomGenerator(InputGenerator):
    """Reproducible pseudo-random inputs. **Not cryptographically secure.**"""

    name = "seeded-random"

    def __init__(self, length: int = DEFAULT_RANDOM_LENGTH, seed: int = 0) -> None:
        self._length = validate_input_length(length)
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ConfigurationError(f"Seed must be an integer (got {seed!r})")
        self._seed = seed

    def __iter__(self) -> Iterator[bytes]:
        length = self._length
        chunk = length * _batch_count(length)
        randbytes = _stdlib_random.Random(self._seed).randbytes
        while True:
            buffer = randbytes(chunk)
            for offset in range(0, chunk, length):
                yield buffer[offset : offset + length]

    @property
    def seed(self) -> int:
        return self._seed

    @property
    def input_length(self) -> int:
        return self._length

    def input_space_size(self) -> int:
        return 256**self._length

    @property
    def deterministic(self) -> bool:
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "length": self._length,
            "seed": self._seed,
            "source": "random.Random (NOT cryptographically secure)",
        }
