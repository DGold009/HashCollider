#!/usr/bin/env python3
"""Compare observed collision costs with the birthday bound.

For several effective sizes, run repeated birthday searches (and a few
brute-force searches) on truncated SHA-256 and compare the observed mean
number of attempts with the theory:

    birthday:     E[n] ~ sqrt(pi/2 * 2^b)
    brute force:  E[n] ~ 2^b

Run from the repository root:

    python3 examples/birthday_attack.py
"""

from __future__ import annotations

import statistics
import sys
from pathlib import Path

try:
    import hashcollider  # noqa: F401
except ImportError:  # allow running without `pip install -e .`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hashcollider import CollisionEngine, SeededRandomGenerator  # noqa: E402
from hashcollider.collision import (  # noqa: E402
    collision_probability,
    expected_birthday_attempts,
    expected_brute_force_attempts,
)

TRIALS = 30


def mean_attempts(bits: int, method: str, trials: int) -> float:
    counts = []
    for trial in range(trials):
        # Seeded for reproducibility only - NOT cryptographically secure.
        generator = SeededRandomGenerator(16, seed=1000 * bits + trial)
        result = CollisionEngine("sha256", bits, generator, method=method).find_collision()
        counts.append(result.attempts)
    return statistics.fmean(counts)


def main() -> None:
    print(f"Birthday search on truncated SHA-256 ({TRIALS} trials each)\n")
    print(f"{'bits':>4}  {'observed mean':>13}  {'expected':>10}  {'ratio':>6}")
    for bits in (8, 12, 16, 20):
        observed = mean_attempts(bits, "birthday", TRIALS)
        expected = expected_birthday_attempts(bits)
        print(f"{bits:>4}  {observed:>13.1f}  {expected:>10.1f}  {observed / expected:>6.2f}")

    print("\nBrute-force (fixed target) on truncated SHA-256 (10 trials each)\n")
    print(f"{'bits':>4}  {'observed mean':>13}  {'expected':>10}  {'ratio':>6}")
    for bits in (8, 12):
        observed = mean_attempts(bits, "brute-force", 10)
        expected = expected_brute_force_attempts(bits)
        print(f"{bits:>4}  {observed:>13.1f}  {expected:>10.1f}  {observed / expected:>6.2f}")

    print("\nProbability of at least one 16-bit collision after n inputs:")
    for n in (50, 100, 256, 300, 500, 1000):
        print(f"  n = {n:>5}: {collision_probability(n, 16):7.2%}")
    print("\nThese are statistical expectations; individual searches vary.")


if __name__ == "__main__":
    main()
