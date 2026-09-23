"""Abstract hash-algorithm interface and the truncated-output wrapper.

:class:`HashAlgorithm` is the extension point for new hash functions: a
subclass only has to provide ``name``, ``display_name``, ``output_bits`` and
``digest()``.

:class:`TruncatedHash` turns any algorithm into a reduced "effective" hash
that keeps only the first *b* bits of the full digest. This is what makes
collision demonstrations realistic: a collision in the first 16 bits of
SHA-256 can be found in milliseconds, while a collision in the full 256-bit
output is computationally infeasible.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from ..errors import InvalidBitLengthError


class HashAlgorithm(ABC):
    """Common interface for every hash algorithm used by HashCollider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Canonical machine-readable identifier, e.g. ``"sha256"``."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human readable name, e.g. ``"SHA-256"``."""

    @property
    @abstractmethod
    def output_bits(self) -> int:
        """Size of the digest in bits."""

    @abstractmethod
    def digest(self, data: bytes) -> bytes:
        """Return the raw digest of *data*."""

    # ------------------------------------------------------------------
    # Convenience API shared by all algorithms
    # ------------------------------------------------------------------

    @property
    def output_bytes(self) -> int:
        """Size of the digest in bytes (rounded up)."""
        return (self.output_bits + 7) // 8

    @property
    def is_legacy(self) -> bool:
        """``True`` if the algorithm has known practical collision attacks."""
        return False

    @property
    def security_warning(self) -> str | None:
        """Educational warning text for weak algorithms, otherwise ``None``."""
        return None

    def hash(self, data: bytes) -> bytes:
        """Alias for :meth:`digest`."""
        return self.digest(data)

    def hexdigest(self, data: bytes) -> str:
        """Return the digest of *data* as lowercase hexadecimal."""
        return self.digest(data).hex()

    def digest_function(self) -> Callable[[bytes], bytes]:
        """Return a fast callable ``bytes -> digest`` for tight search loops."""
        return self.digest

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.name!r})"


def validate_bits(bits: object, algorithm: HashAlgorithm) -> int:
    """Validate an effective bit length for *algorithm* and return it.

    Raises:
        InvalidBitLengthError: if *bits* is not an integer in
            ``1 .. algorithm.output_bits``.
    """
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise InvalidBitLengthError(f"Invalid bit length: {bits!r} (must be an integer)")
    if not 1 <= bits <= algorithm.output_bits:
        raise InvalidBitLengthError(
            f"Invalid bit length: {bits}. {algorithm.display_name} supports "
            f"effective bit lengths from 1 to {algorithm.output_bits}."
        )
    return bits


class TruncatedHash(HashAlgorithm):
    """Keep only the first ``bits`` bits of another algorithm's digest.

    The truncated value is the integer formed by the *most significant*
    ``bits`` bits of the full digest. For byte-aligned sizes (8, 16, 24, ...)
    this is exactly the first ``bits / 4`` hex characters of the full
    hexdigest; for other sizes (e.g. 12) it is the leading bits, right-aligned.

    Two inputs whose truncated values are equal collide *in the truncated
    output space only*. Their full digests are (almost always) different.
    """

    def __init__(self, base: HashAlgorithm, bits: int) -> None:
        if isinstance(base, TruncatedHash):
            raise TypeError("TruncatedHash must wrap a full (non-truncated) algorithm")
        self._base = base
        self._bits = validate_bits(bits, base)
        self._nbytes = (self._bits + 7) // 8
        self._shift = self._nbytes * 8 - self._bits
        self._hex_width = (self._bits + 3) // 4

    # -- HashAlgorithm interface ---------------------------------------

    @property
    def name(self) -> str:
        return f"{self._base.name}/{self._bits}"

    @property
    def display_name(self) -> str:
        if self.is_full:
            return self._base.display_name
        return f"{self._base.display_name} (first {self._bits} bits)"

    @property
    def output_bits(self) -> int:
        return self._bits

    def digest(self, data: bytes) -> bytes:
        """Return the truncated value encoded big-endian in ``ceil(bits/8)`` bytes."""
        return self.value(data).to_bytes(self._nbytes, "big")

    def hexdigest(self, data: bytes) -> str:
        return self.format_value(self.value(data))

    @property
    def is_legacy(self) -> bool:
        return self._base.is_legacy

    @property
    def security_warning(self) -> str | None:
        return self._base.security_warning

    # -- truncation specific API ---------------------------------------

    @property
    def base(self) -> HashAlgorithm:
        """The full-size algorithm being truncated."""
        return self._base

    @property
    def bits(self) -> int:
        """Effective bit length."""
        return self._bits

    @property
    def nbytes(self) -> int:
        """Number of leading digest bytes needed to extract ``bits`` bits."""
        return self._nbytes

    @property
    def shift(self) -> int:
        """Right shift applied to the leading bytes to drop surplus bits."""
        return self._shift

    @property
    def is_full(self) -> bool:
        """``True`` when no truncation happens (bits == full digest size)."""
        return self._bits == self._base.output_bits

    @property
    def space_size(self) -> int:
        """Number of possible truncated values, ``2 ** bits``."""
        return 1 << self._bits

    def truncate(self, full_digest: bytes) -> int:
        """Extract the truncated integer value from a *full* digest."""
        return int.from_bytes(full_digest[: self._nbytes], "big") >> self._shift

    def value(self, data: bytes) -> int:
        """Hash *data* with the base algorithm and return the truncated integer."""
        return self.truncate(self._base.digest(data))

    def format_value(self, value: int) -> str:
        """Format a truncated value as zero-padded hex (``ceil(bits/4)`` digits)."""
        return f"{value:0{self._hex_width}x}"

    def format_binary(self, value: int) -> str:
        """Format a truncated value as a ``bits``-wide binary string."""
        return f"{value:0{self._bits}b}"

    def __repr__(self) -> str:
        return f"TruncatedHash({self._base.name!r}, bits={self._bits})"
