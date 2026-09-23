r"""Birthday collision search and birthday-bound mathematics.

For an ideal hash with ``N = 2**b`` equally likely outputs, the probability
that ``n`` random inputs contain at least one colliding pair is

.. math::  p(n) \approx 1 - e^{-n(n-1)/(2N)}

and the expected number of inputs until the first collision is

.. math::  E[n] \approx \sqrt{\pi N / 2} \approx 1.2533 \cdot 2^{b/2}.

The rule of thumb ``n ~ sqrt(2**b) = 2**(b/2)`` (the *birthday bound*) is the
number of attempts at which a collision becomes likely (p ~ 39%). Both are
statistical expectations - an individual search may need fewer or more
attempts.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Iterable

from .base import RawSearchResult, SearchContext, SearchStrategy, checkpoint
from .results import SearchStatus

logger = logging.getLogger(__name__)


def birthday_bound(bits: int) -> float:
    """Birthday-bound approximation ``sqrt(2**bits) = 2**(bits/2)``."""
    return 2.0 ** (bits / 2)


def expected_birthday_attempts(bits: int) -> float:
    """Expected hashes until the first collision: ``sqrt(pi/2 * 2**bits) + 2/3``."""
    return math.sqrt(math.pi / 2 * 2.0**bits) + 2.0 / 3.0


def collision_probability(attempts: int, bits: int) -> float:
    """Approximate probability that *attempts* random inputs contain a collision."""
    if attempts < 2:
        return 0.0
    space = 2.0**bits
    return -math.expm1(-attempts * (attempts - 1) / (2.0 * space))


def attempts_for_probability(probability: float, bits: int) -> float:
    """Number of inputs needed to reach a collision with the given probability."""
    if not 0.0 < probability < 1.0:
        raise ValueError("probability must be strictly between 0 and 1")
    return math.sqrt(2.0 * 2.0**bits * -math.log1p(-probability))


class BirthdayStrategy(SearchStrategy):
    """Store every truncated digest; stop when a new *different* input repeats one.

    A dictionary maps ``truncated_digest -> input``. For each new input:

    * digest not seen before  -> remember it;
    * digest seen, different input -> **collision**;
    * digest seen, identical input -> duplicate input, *not* a collision.

    Memory grows with the number of stored digests. When ``max_stored`` is
    reached, new digests are no longer stored but are still compared against
    the stored ones, so the search stays correct with bounded memory (it just
    becomes less efficient).
    """

    name = "birthday"
    title = "Birthday search"
    description = (
        "Remembers every truncated digest and stops when a different input maps "
        "to an already-seen digest. Expected cost ~ sqrt(pi/2 * 2^b) hashes; "
        "memory grows with the number of attempts."
    )

    def expected_attempts(self, bits: int) -> float:
        return expected_birthday_attempts(bits)

    def expected_stored_entries(self, bits: int) -> float:
        return expected_birthday_attempts(bits)

    def success_probability(self, attempts: int, bits: int) -> float:
        return collision_probability(attempts, bits)

    def search(self, messages: Iterable[bytes], ctx: SearchContext) -> RawSearchResult:
        digest = ctx.digest
        nbytes = ctx.nbytes
        shift = ctx.shift
        from_bytes = int.from_bytes
        max_attempts = ctx.limits.max_attempts if ctx.limits.max_attempts is not None else -1
        max_stored = ctx.limits.max_stored if ctx.limits.max_stored is not None else -1
        mask = ctx.check_interval - 1

        seen: dict[int, bytes] = {}
        attempts = 0
        stored = 0
        duplicates = 0
        status = SearchStatus.EXHAUSTED
        input_a = input_b = digest_a = digest_b = None

        start = time.perf_counter()
        try:
            for message in messages:
                attempts += 1
                full = digest(message)
                key = from_bytes(full[:nbytes], "big") >> shift
                previous = seen.get(key)
                if previous is None:
                    if stored != max_stored:
                        seen[key] = message
                        stored += 1
                        if stored == max_stored:
                            logger.warning(
                                "Reached the limit of %d stored digests; new digests are no "
                                "longer stored (memory stays bounded, search continues).",
                                max_stored,
                            )
                elif previous != message:
                    status = SearchStatus.FOUND
                    input_a, input_b = previous, message
                    digest_a, digest_b = digest(previous), full
                    break
                else:
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
