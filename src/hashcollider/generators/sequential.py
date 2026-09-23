"""Sequential ``collision-test-NNNNNNNN`` input generator."""

from __future__ import annotations

from ..config import SEQUENTIAL_DEFAULT_START, SEQUENTIAL_DEFAULT_WIDTH, SEQUENTIAL_PREFIX
from ..errors import ConfigurationError, InvalidInputLengthError
from .base import validate_input_length
from .structured import StructuredGenerator


class SequentialGenerator(StructuredGenerator):
    """Deterministic, reproducible inputs::

        b"collision-test-00000001", b"collision-test-00000002", ...

    If *length* is given, the counter width is chosen so that every input is
    exactly *length* bytes (``len("collision-test-") == 15``, so the minimum
    length is 16).
    """

    name = "sequential"
    PREFIX = SEQUENTIAL_PREFIX.encode("ascii")

    def __init__(
        self,
        length: int | None = None,
        start: int = SEQUENTIAL_DEFAULT_START,
        width: int | None = None,
    ) -> None:
        prefix_len = len(self.PREFIX)
        if width is None:
            if length is None:
                width = SEQUENTIAL_DEFAULT_WIDTH
            else:
                validate_input_length(length)
                width = length - prefix_len
                if width < 1:
                    raise InvalidInputLengthError(
                        f"Input length {length} is too short for the sequential generator "
                        f"(prefix {SEQUENTIAL_PREFIX!r} is {prefix_len} bytes); "
                        f"use at least {prefix_len + 1}"
                    )
        elif length is not None and prefix_len + width != length:
            raise ConfigurationError(
                f"--length {length} conflicts with --width {width} "
                f"(prefix {prefix_len} + width {width} = {prefix_len + width} bytes)"
            )
        super().__init__(prefix=self.PREFIX, start=start, width=width)
