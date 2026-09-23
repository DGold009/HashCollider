"""Independent verification of collision records.

Verification never trusts stored hash values: both inputs are re-hashed and
the truncated digests are recomputed from scratch. Stored values are only
checked for *consistency* with the recomputed ones.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..hashing import AlgorithmRegistry, TruncatedHash
from .results import CollisionResult


@dataclass(frozen=True)
class VerificationCheck:
    """One verification criterion and whether it passed."""

    description: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of :func:`verify_collision` with all recomputed values."""

    record: CollisionResult
    algorithm_display_name: str
    output_bits: int
    effective_bits: int
    recomputed_hash_a: str
    recomputed_hash_b: str
    recomputed_truncated_a: str
    recomputed_truncated_b: str
    checks: tuple[VerificationCheck, ...]

    @property
    def passed(self) -> bool:
        """``True`` only if every check passed."""
        return all(check.passed for check in self.checks)

    @property
    def failures(self) -> tuple[VerificationCheck, ...]:
        return tuple(check for check in self.checks if not check.passed)

    @property
    def full_digests_equal(self) -> bool:
        """Whether the recomputed *full* digests are identical."""
        return self.recomputed_hash_a == self.recomputed_hash_b

    @property
    def is_truncated(self) -> bool:
        return self.effective_bits < self.output_bits


def verify_collision(
    record: CollisionResult, registry: AlgorithmRegistry | None = None
) -> VerificationResult:
    """Recompute both digests and check that *record* is a genuine collision.

    A record passes when:

    1. ``input_a != input_b`` (identical inputs are duplicates, not collisions);
    2. the recomputed truncated digests are equal;
    3. any stored metadata (full hashes, truncated hash, output size) is
       consistent with the recomputed values.

    Raises:
        UnsupportedAlgorithmError: unknown algorithm in the record.
        InvalidBitLengthError: effective bit length out of range.
    """
    algorithm = (registry or AlgorithmRegistry()).get(record.algorithm)
    truncated = TruncatedHash(algorithm, record.effective_bits)
    bits = truncated.bits

    digest_a = algorithm.digest(record.input_a)
    digest_b = algorithm.digest(record.input_b)
    value_a = truncated.truncate(digest_a)
    value_b = truncated.truncate(digest_b)
    hex_a = truncated.format_value(value_a)
    hex_b = truncated.format_value(value_b)

    checks = [
        VerificationCheck(
            "input A and input B are different",
            record.input_a != record.input_b,
            ""
            if record.input_a != record.input_b
            else "identical inputs are a duplicate, not a collision",
        ),
        VerificationCheck(
            f"recomputed {bits}-bit truncated digests are equal",
            value_a == value_b,
            f"A={hex_a} B={hex_b}",
        ),
    ]
    if record.output_bits is not None:
        checks.append(
            VerificationCheck(
                "stored output size matches the algorithm",
                record.output_bits == algorithm.output_bits,
                f"stored {record.output_bits}, {algorithm.display_name} has "
                f"{algorithm.output_bits}",
            )
        )
    if record.hash_a:
        checks.append(
            VerificationCheck(
                "stored hash_a matches the recomputed digest",
                record.hash_a.strip().lower() == digest_a.hex(),
            )
        )
    if record.hash_b:
        checks.append(
            VerificationCheck(
                "stored hash_b matches the recomputed digest",
                record.hash_b.strip().lower() == digest_b.hex(),
            )
        )
    if record.truncated_hash:
        checks.append(
            VerificationCheck(
                "stored truncated_hash matches the recomputed value",
                _hex_equals(record.truncated_hash, value_a),
                f"stored {record.truncated_hash}, recomputed {hex_a}",
            )
        )

    return VerificationResult(
        record=record,
        algorithm_display_name=algorithm.display_name,
        output_bits=algorithm.output_bits,
        effective_bits=bits,
        recomputed_hash_a=digest_a.hex(),
        recomputed_hash_b=digest_b.hex(),
        recomputed_truncated_a=hex_a,
        recomputed_truncated_b=hex_b,
        checks=tuple(checks),
    )


def _hex_equals(stored: str, value: int) -> bool:
    try:
        return int(stored.strip(), 16) == value
    except ValueError:
        return False
