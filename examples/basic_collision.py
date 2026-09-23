#!/usr/bin/env python3
"""Find and verify a collision in the first 16 bits of SHA-256.

Run from the repository root:

    python3 examples/basic_collision.py

This is a collision in a *truncated* 16-bit output space. The full SHA-256
digests of the two inputs are different.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import hashcollider  # noqa: F401
except ImportError:  # allow running without `pip install -e .`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hashcollider import CollisionEngine, SequentialGenerator, verify_collision  # noqa: E402


def main() -> None:
    engine = CollisionEngine("sha256", bits=16, generator=SequentialGenerator(length=32))
    estimate = engine.estimate()
    print(f"Expected attempts (birthday): ~{estimate.expected_attempts:.0f}")
    print(f"Birthday bound sqrt(2^16):     {estimate.birthday_bound:.0f}")

    result = engine.find_collision()
    print(f"\nCollision after {result.attempts} attempts ({result.elapsed_seconds:.4f} s)")
    print(f"Input A: {result.input_a.decode()}")
    print(f"Input B: {result.input_b.decode()}")
    print(f"SHA-256(A) = {result.hash_a}")
    print(f"SHA-256(B) = {result.hash_b}")
    print(f"First 16 bits of both: {result.truncated_hash}")

    verification = verify_collision(result)
    print(f"\nVerification: {'PASS' if verification.passed else 'FAIL'}")
    print(f"Full digests equal: {verification.full_digests_equal}")
    print(
        "A collision was found in the first 16 bits of SHA-256. "
        "This does not constitute a collision in the full SHA-256 output."
    )


if __name__ == "__main__":
    main()
