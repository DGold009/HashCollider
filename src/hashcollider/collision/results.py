"""Result and statistics data structures for collision searches."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ..config import FORMAT_VERSION
from ..errors import InvalidCollisionFileError


class SearchStatus(str, Enum):
    """Why a search ended."""

    FOUND = "found"
    MAX_ATTEMPTS = "max_attempts"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"
    STOPPED = "stopped"
    EXHAUSTED = "exhausted"

    @property
    def message(self) -> str:
        return _STATUS_MESSAGES[self]


_STATUS_MESSAGES = {
    SearchStatus.FOUND: "Collision found",
    SearchStatus.MAX_ATTEMPTS: "Maximum attempt limit reached",
    SearchStatus.TIMEOUT: "Maximum execution time reached",
    SearchStatus.INTERRUPTED: "Search interrupted",
    SearchStatus.STOPPED: "Search stopped",
    SearchStatus.EXHAUSTED: "Input generator exhausted before a collision was found",
}


@dataclass(frozen=True)
class SearchStatistics:
    """Performance counters of a (possibly unfinished) search.

    ``elapsed_seconds`` is measured with :func:`time.perf_counter`, a
    monotonic high-resolution clock, never with wall-clock timestamps.
    """

    attempts: int = 0
    elapsed_seconds: float = 0.0
    stored_digests: int = 0
    duplicate_inputs: int = 0

    @property
    def hashes_per_second(self) -> float:
        """Hash evaluations per second (0.0 if no measurable time elapsed)."""
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.attempts / self.elapsed_seconds


def utc_timestamp() -> str:
    """Current UTC time as an ISO-8601 string (for records, not for timing)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def printable_text(data: bytes) -> str | None:
    """Return *data* as text if it is entirely printable ASCII, else ``None``."""
    if all(0x20 <= byte <= 0x7E for byte in data):
        return data.decode("ascii")
    return None


@dataclass(frozen=True)
class CollisionResult:
    """A discovered (or loaded) collision in an effective hash space.

    Only ``algorithm``, ``effective_bits``, ``input_a`` and ``input_b`` are
    required; everything else is metadata that may be absent in hand-written
    collision files. Stored hash values are informational only - verification
    always recomputes them.
    """

    algorithm: str
    effective_bits: int
    input_a: bytes
    input_b: bytes
    algorithm_display_name: str | None = None
    output_bits: int | None = None
    method: str | None = None
    generator: str | None = None
    generator_params: dict[str, Any] = field(default_factory=dict)
    hash_a: str | None = None
    hash_b: str | None = None
    truncated_hash: str | None = None
    attempts: int | None = None
    elapsed_seconds: float | None = None
    hashes_per_second: float | None = None
    timestamp: str | None = None
    tool_version: str | None = None

    # -- derived properties --------------------------------------------

    @property
    def display_name(self) -> str:
        return self.algorithm_display_name or self.algorithm

    @property
    def input_length(self) -> int | None:
        """Common input length in bytes, or ``None`` if the inputs differ in length."""
        if len(self.input_a) == len(self.input_b):
            return len(self.input_a)
        return None

    @property
    def is_truncated(self) -> bool | None:
        """``True`` if the effective size is smaller than the full digest."""
        if self.output_bits is None:
            return None
        return self.effective_bits < self.output_bits

    @property
    def full_digests_equal(self) -> bool | None:
        """Whether the *stored* full digests are equal (``None`` if not stored)."""
        if not self.hash_a or not self.hash_b:
            return None
        return self.hash_a.lower() == self.hash_b.lower()

    # -- serialisation --------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the versioned JSON structure (inputs hex encoded)."""
        return {
            "format_version": FORMAT_VERSION,
            "tool": "hashcollider",
            "tool_version": self.tool_version,
            "algorithm": self.algorithm,
            "algorithm_display_name": self.algorithm_display_name,
            "output_bits": self.output_bits,
            "effective_bits": self.effective_bits,
            "method": self.method,
            "generator": self.generator,
            "generator_params": dict(self.generator_params),
            "input_encoding": "hex",
            "input_a": self.input_a.hex(),
            "input_b": self.input_b.hex(),
            "input_a_text": printable_text(self.input_a),
            "input_b_text": printable_text(self.input_b),
            "input_length_a": len(self.input_a),
            "input_length_b": len(self.input_b),
            "hash_a": self.hash_a,
            "hash_b": self.hash_b,
            "truncated_hash": self.truncated_hash,
            "full_digests_equal": self.full_digests_equal,
            "attempts": self.attempts,
            "elapsed_seconds": self.elapsed_seconds,
            "hashes_per_second": self.hashes_per_second,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CollisionResult:
        """Parse and validate a collision record.

        Raises:
            InvalidCollisionFileError: for missing/ill-typed fields or an
                unsupported ``format_version``.
        """
        if not isinstance(data, Mapping):
            raise InvalidCollisionFileError("Collision file must contain a JSON object")
        if "format_version" not in data:
            raise InvalidCollisionFileError("Collision file is missing 'format_version'")
        version = data["format_version"]
        if isinstance(version, bool) or version != FORMAT_VERSION:
            raise InvalidCollisionFileError(
                f"Unsupported collision file format_version {version!r} "
                f"(this release supports version {FORMAT_VERSION})"
            )
        required = ("algorithm", "effective_bits", "input_a", "input_b")
        missing = [key for key in required if key not in data]
        if missing:
            raise InvalidCollisionFileError(
                f"Collision file is missing required field(s): {', '.join(missing)}"
            )
        encoding = data.get("input_encoding", "hex")
        params = data.get("generator_params") or {}
        if not isinstance(params, Mapping):
            raise InvalidCollisionFileError("'generator_params' must be an object")
        return cls(
            algorithm=_require_str(data, "algorithm"),
            effective_bits=_require_int(data, "effective_bits"),
            input_a=_decode_input(data["input_a"], encoding, "input_a"),
            input_b=_decode_input(data["input_b"], encoding, "input_b"),
            algorithm_display_name=_optional(data, "algorithm_display_name", str),
            output_bits=_optional(data, "output_bits", int),
            method=_optional(data, "method", str),
            generator=_optional(data, "generator", str),
            generator_params=dict(params),
            hash_a=_optional(data, "hash_a", str),
            hash_b=_optional(data, "hash_b", str),
            truncated_hash=_optional(data, "truncated_hash", str),
            attempts=_optional(data, "attempts", int),
            elapsed_seconds=_optional(data, "elapsed_seconds", float),
            hashes_per_second=_optional(data, "hashes_per_second", float),
            timestamp=_optional(data, "timestamp", str),
            tool_version=_optional(data, "tool_version", str),
        )


@dataclass(frozen=True)
class SearchOutcome:
    """Everything a finished search produced."""

    status: SearchStatus
    statistics: SearchStatistics
    collision: CollisionResult | None = None

    @property
    def found(self) -> bool:
        return self.status is SearchStatus.FOUND and self.collision is not None


# -- parsing helpers -------------------------------------------------------


def _require_str(data: Mapping[str, Any], key: str) -> str:
    value = data[key]
    if not isinstance(value, str) or not value:
        raise InvalidCollisionFileError(f"'{key}' must be a non-empty string")
    return value


def _require_int(data: Mapping[str, Any], key: str) -> int:
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidCollisionFileError(f"'{key}' must be an integer")
    return value


def _optional(data: Mapping[str, Any], key: str, kind: type) -> Any:
    value = data.get(key)
    if value is None:
        return None
    if kind is float and isinstance(value, int) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, bool) or not isinstance(value, kind):
        raise InvalidCollisionFileError(f"'{key}' must be of type {kind.__name__}")
    return value


def _decode_input(value: Any, encoding: Any, key: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidCollisionFileError(f"'{key}' must be a string")
    if encoding == "hex":
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise InvalidCollisionFileError(f"'{key}' is not valid hexadecimal") from exc
    if encoding in ("utf-8", "utf8"):
        return value.encode("utf-8")
    raise InvalidCollisionFileError(
        f"Unsupported input_encoding {encoding!r} (use 'hex' or 'utf-8')"
    )
