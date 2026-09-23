"""Common interface for input generators."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any, ClassVar

from ..config import MAX_INPUT_LENGTH
from ..errors import InvalidInputLengthError


def validate_input_length(length: object) -> int:
    """Validate a generated-input length in bytes and return it.

    Raises:
        InvalidInputLengthError: if *length* is not an integer in
            ``1 .. MAX_INPUT_LENGTH``.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise InvalidInputLengthError(f"Input length must be an integer (got {length!r})")
    if length <= 0:
        raise InvalidInputLengthError(f"Input length must be positive (got {length})")
    if length > MAX_INPUT_LENGTH:
        raise InvalidInputLengthError(
            f"Input length {length} exceeds the maximum of {MAX_INPUT_LENGTH} bytes"
        )
    return length


class InputGenerator(ABC):
    """Produces a stream of candidate inputs (``bytes``) for a collision search.

    Iterating a generator starts a *fresh* stream. Deterministic generators
    produce the same sequence on every iteration, which makes experiments
    reproducible.

    Future multiprocessing support can be added by giving each worker an
    independent generator (e.g. disjoint counter ranges or distinct seeds).
    """

    name: ClassVar[str] = "generator"

    @abstractmethod
    def __iter__(self) -> Iterator[bytes]:
        """Yield candidate inputs."""

    @property
    def input_length(self) -> int | None:
        """Length of every generated input in bytes, or ``None`` if variable."""
        return None

    def input_space_size(self) -> int | None:
        """Number of distinct inputs the generator can produce (``None`` if unknown)."""
        return None

    @property
    def deterministic(self) -> bool:
        """``True`` if every iteration yields the same sequence."""
        return False

    @property
    def cryptographically_secure(self) -> bool:
        """``True`` if inputs come from a cryptographically secure RNG."""
        return False

    def describe(self) -> dict[str, Any]:
        """JSON-serialisable parameters, stored with discovered collisions."""
        return {}

    def __repr__(self) -> str:
        params = ", ".join(f"{k}={v!r}" for k, v in self.describe().items())
        return f"{type(self).__name__}({params})"
