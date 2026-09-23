"""Structured ``prefix + counter + suffix`` input generator."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..config import (
    MAX_INPUT_LENGTH,
    STRUCTURED_DEFAULT_PREFIX,
    STRUCTURED_DEFAULT_START,
    STRUCTURED_DEFAULT_WIDTH,
)
from ..errors import ConfigurationError, InvalidInputLengthError
from .base import InputGenerator, validate_input_length


def _to_bytes(value: str | bytes, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ConfigurationError(f"{field} must be str or bytes (got {type(value).__name__})")


class StructuredGenerator(InputGenerator):
    """Deterministic inputs of the form ``prefix + zero-padded counter + suffix``.

    Example with ``prefix="experiment-"``, ``start=1``, ``width=6``::

        b"experiment-000001", b"experiment-000002", ...

    The counter never exceeds ``10**width - 1``, so every input has the same
    length and every input is distinct. When the counter range is used up the
    generator is exhausted.
    """

    name = "structured"

    def __init__(
        self,
        prefix: str | bytes = STRUCTURED_DEFAULT_PREFIX,
        start: int = STRUCTURED_DEFAULT_START,
        width: int = STRUCTURED_DEFAULT_WIDTH,
        suffix: str | bytes = b"",
    ) -> None:
        self._prefix = _to_bytes(prefix, "prefix")
        self._suffix = _to_bytes(suffix, "suffix")
        if isinstance(width, bool) or not isinstance(width, int) or width < 1:
            raise ConfigurationError(f"Counter width must be a positive integer (got {width!r})")
        if width > MAX_INPUT_LENGTH:
            raise ConfigurationError(f"Counter width {width} is unreasonably large")
        if isinstance(start, bool) or not isinstance(start, int) or start < 0:
            raise ConfigurationError(
                f"Counter start must be a non-negative integer (got {start!r})"
            )
        self._width = width
        self._start = start
        self._stop = 10**width
        if start >= self._stop:
            raise ConfigurationError(f"Counter start {start} does not fit in {width} digit(s)")
        validate_input_length(len(self._prefix) + width + len(self._suffix))
        self._format = (
            self._prefix.replace(b"%", b"%%")
            + b"%0"
            + str(width).encode("ascii")
            + b"d"
            + self._suffix.replace(b"%", b"%%")
        )

    @classmethod
    def for_length(
        cls,
        length: int,
        prefix: str | bytes = STRUCTURED_DEFAULT_PREFIX,
        start: int = STRUCTURED_DEFAULT_START,
        suffix: str | bytes = b"",
    ) -> StructuredGenerator:
        """Create a generator whose inputs are exactly *length* bytes long.

        The counter width is derived as ``length - len(prefix) - len(suffix)``.
        """
        validate_input_length(length)
        fixed = len(_to_bytes(prefix, "prefix")) + len(_to_bytes(suffix, "suffix"))
        width = length - fixed
        if width < 1:
            raise InvalidInputLengthError(
                f"Input length {length} is too short for the prefix/suffix "
                f"({fixed} bytes); it must be at least {fixed + 1}"
            )
        return cls(prefix=prefix, start=start, width=width, suffix=suffix)

    def __iter__(self) -> Iterator[bytes]:
        fmt = self._format
        for counter in range(self._start, self._stop):
            yield fmt % counter

    def input_at(self, index: int) -> bytes:
        """Return the input at position *index* of the sequence (0-based)."""
        counter = self._start + index
        if not self._start <= counter < self._stop:
            raise IndexError(index)
        return self._format % counter

    @property
    def prefix(self) -> bytes:
        return self._prefix

    @property
    def suffix(self) -> bytes:
        return self._suffix

    @property
    def start(self) -> int:
        return self._start

    @property
    def width(self) -> int:
        return self._width

    @property
    def input_length(self) -> int:
        return len(self._prefix) + self._width + len(self._suffix)

    def input_space_size(self) -> int:
        return self._stop - self._start

    @property
    def deterministic(self) -> bool:
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "prefix": self._prefix.decode("utf-8", "backslashreplace"),
            "suffix": self._suffix.decode("utf-8", "backslashreplace"),
            "start": self._start,
            "width": self._width,
            "length": self.input_length,
        }
