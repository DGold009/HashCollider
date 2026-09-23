r"""Brute-force (fixed-target) collision search.

The first generated input becomes the *target*. Every following input is
hashed and compared against the target's truncated digest until a different
input matches it. Because each attempt matches with probability ``2**-b``,
the expected number of attempts is about ``2**b`` - quadratically more than
the birthday search (``~2**(b/2)``) - but memory use is constant.

Comparing the two methods side by side is one of the clearest ways to see
*why* the birthday paradox matters.
"""

from __future__ import annotations

import math
import time
from collections.abc import Iterable

from .base import RawSearchResult, SearchContext, SearchStrategy, checkpoint
from .results import SearchStatus


def expected_brute_force_attempts(bits: int) -> float:
    """Expected hashes including the target itself: ``2**bits + 1``."""
    return 2.0**bits + 1.0


def brute_force_success_probability(attempts: int, bits: int) -> float:
    """Probability that ``attempts - 1`` candidates contain a match for the target."""
    if attempts < 2:
        return 0.0
    return -math.expm1((attempts - 1) * math.log1p(-(2.0**-bits)))


class BruteForceStrategy(SearchStrategy):
    """Compare every new input against one fixed target digest."""

    name = "brute-force"
    title = "Brute-force (fixed-target) search"
    description = (
        "Fixes the first input as a target and hashes candidates until a different "
        "input matches its truncated digest. Expected cost ~ 2^b hashes; constant memory."
    )

    def expected_attempts(self, bits: int) -> float:
        return expected_brute_force_attempts(bits)

    def expected_stored_entries(self, bits: int) -> float:
        return 1.0

    def success_probability(self, attempts: int, bits: int) -> float:
        return brute_force_success_probability(attempts, bits)

    def search(self, messages: Iterable[bytes], ctx: SearchContext) -> RawSearchResult:
        digest = ctx.digest
        nbytes = ctx.nbytes
        shift = ctx.shift
        from_bytes = int.from_bytes
        max_attempts = ctx.limits.max_attempts if ctx.limits.max_attempts is not None else -1
        mask = ctx.check_interval - 1

        attempts = 0
        stored = 0
        duplicates = 0
        status = SearchStatus.EXHAUSTED
        input_a = input_b = digest_a = digest_b = None

        start = time.perf_counter()
        try:
            iterator = iter(messages)
            target = next(iterator, None)
            if target is not None:
                attempts = 1
                stored = 1
                target_digest = digest(target)
                target_key = from_bytes(target_digest[:nbytes], "big") >> shift
                if attempts == max_attempts:
                    status = SearchStatus.MAX_ATTEMPTS
                else:
                    for message in iterator:
                        attempts += 1
                        full = digest(message)
                        if from_bytes(full[:nbytes], "big") >> shift == target_key:
                            if message != target:
                                status = SearchStatus.FOUND
                                input_a, input_b = target, message
                                digest_a, digest_b = target_digest, full
                                break
                            duplicates += 1
                        if attempts == max_attempts:
                            status = SearchStatus.MAX_ATTEMPTS
                            break
                        if not attempts & mask:
                            ended = checkpoint(ctx, attempts, stored, duplicates, start)
                            if ended is not None:
                                status = ended
                                break
        except KeyboardInterrupt:
            status = SearchStatus.INTERRUPTED
        elapsed = time.perf_counter() - start

        return RawSearchResult(
            status=status,
            attempts=attempts,
            elapsed_seconds=elapsed,
            stored=stored,
            duplicates=duplicates,
            input_a=input_a,
            input_b=input_b,
            digest_a=digest_a,
            digest_b=digest_b,
        )
