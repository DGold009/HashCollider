"""Educational explanations printed by ``hashcollider explain <topic>``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType

from .collision.birthday import birthday_bound, expected_birthday_attempts
from .collision.brute_force import expected_brute_force_attempts
from .formatting import format_count, format_long_duration, format_table

_COLLISION = """\
HASH COLLISIONS - AN INTRODUCTION
=================================

1. What is a cryptographic hash function?
   A hash function H maps an input of any length to a fixed-size output
   (the digest). SHA-256, for example, always produces 256 bits. A
   *cryptographic* hash function must additionally be:
     - preimage resistant:        given h, it is infeasible to find m with H(m) = h;
     - second-preimage resistant: given m1, it is infeasible to find m2 != m1
                                  with H(m2) = H(m1);
     - collision resistant:       it is infeasible to find ANY pair m1 != m2
                                  with H(m1) = H(m2).

2. What is a collision?
   Two different inputs with the same digest:

       input_A != input_B   and   H(input_A) == H(input_B)

   Collisions always EXIST (infinitely many inputs, finitely many digests -
   the pigeonhole principle). Collision resistance means they are
   infeasible to FIND.

3. Why do collisions matter?
   Digital signatures, certificates, software updates, version control and
   integrity checks sign or compare the hash instead of the data. If an
   attacker can produce two different documents with the same hash, a
   signature on the harmless one is also valid for the malicious one.
   Practical collisions against MD5 enabled a rogue CA certificate (2008)
   and the Flame malware (2012); SHA-1 fell to practical collisions in 2017.

4. The birthday paradox
   In a room of only 23 people, the chance that two share a birthday is
   already above 50%, although there are 365 possible birthdays. The reason:
   with n people there are n(n-1)/2 PAIRS, and the number of pairs grows
   quadratically. The same happens with hash outputs.

5. Why the expected collision cost is about 2^(b/2)
   For an ideal b-bit hash there are N = 2^b possible outputs. After n
   random inputs the probability of at least one collision is roughly

       p(n) ~ 1 - exp(-n(n-1) / (2N))

   which becomes significant when n is around sqrt(N) = sqrt(2^b) = 2^(b/2).
   The expected number of inputs until the first collision is
   sqrt(pi/2 * 2^b) ~ 1.25 * 2^(b/2). So a 256-bit hash offers only about
   128 bits of collision security. In contrast, finding a match for ONE
   fixed target (a second preimage by brute force) costs about 2^b.

6. Why reducing the output size makes collisions easy to demonstrate
   HashCollider can keep only the first b bits of a digest. The cost then
   shrinks from 2^(256/2) to 2^(b/2):

       b =  16 bits  ->  ~2^8  =         256 attempts  (instant)
       b =  32 bits  ->  ~2^16 =      65,536 attempts  (well under a second)
       b =  64 bits  ->  ~2^32 = 4.3 billion attempts  (hours, and far too much RAM)
       b = 256 bits  ->  ~2^128 attempts               (infeasible)

7. A truncated collision is NOT a collision of the full algorithm
   If SHA-256(x) and SHA-256(y) agree in their first 16 bits, that is a
   collision of the 16-bit function "first 16 bits of SHA-256" - nothing
   more. The full 256-bit digests are still different:

       SHA-256(x)[:16 bits] == SHA-256(y)[:16 bits]
       does NOT imply
       SHA-256(x) == SHA-256(y)

   "A collision was found in the first 16 bits of SHA-256. This does not
   constitute a collision in the full SHA-256 output."

   The same experiment would succeed for ANY 16-bit hash; it demonstrates
   the birthday bound, not a weakness of SHA-256.

Try it:
   hashcollider collide --algorithm sha256 --bits 16 --generator sequential
   hashcollider explain birthday
"""

_TRUNCATION = """\
TRUNCATION AND EFFECTIVE HASH SIZE
==================================

HashCollider's --bits b option keeps only the b most significant bits of
the full digest. For byte-aligned sizes this is simply a prefix of the hex
digest:

    SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    first 16 bits    = 2cf2
    first  8 bits    = 2c

For other sizes (e.g. 12 bits) the leading bits are taken and shown
right-aligned in hex (12 bits -> 3 hex digits: 2cf).

The truncated function T_b(m) = first_b_bits(H(m)) behaves like a b-bit hash
with only 2^b possible outputs, so its collision resistance is about 2^(b/2).

Important:
  * A collision of T_b is not a collision of H.
  * Systems that truncate hashes (short IDs, short fingerprints, 32-bit
    checksums) get exactly this reduced security - that is the practical
    lesson of these experiments.
  * Verification (hashcollider verify) recomputes both full digests and the
    truncated values, and reports whether the FULL digests are equal
    (for a truncated demonstration they are not).
"""

_METHODS = """\
COLLISION SEARCH METHODS
========================

birthday (default)
    Generate inputs m1, m2, m3, ... and remember every truncated digest in a
    dictionary {digest -> input}. As soon as a new input produces a digest
    that was already seen AND the input is different, a collision is found.
    If the input is identical it is a duplicate input, which is ignored.
      expected attempts : ~ sqrt(pi/2 * 2^b)  (birthday bound ~ 2^(b/2))
      memory            : grows with attempts (limit with --max-stored)

brute-force (fixed target)
    Take the first input as the target and hash candidates until a
    different input matches the target's truncated digest.
      expected attempts : ~ 2^b
      memory            : constant

Running both methods at the same --bits shows the difference between
2^(b/2) and 2^b - the entire point of the birthday paradox:

    hashcollider collide --bits 16 --method birthday
    hashcollider collide --bits 16 --method brute-force
"""

_SEARCH_LIMIT_NOTE = """\
Durations assume 1 million hashes/second, roughly what a single-threaded
Python search loop achieves on a modern CPU core (memory, not time, is the
first limit for large birthday searches). Expectations are averages;
single runs vary.
"""


_TABLE_BITS = (8, 12, 16, 20, 24, 32, 40, 48, 64, 128, 256)


def birthday_table(bits_values: Sequence[int] = _TABLE_BITS) -> str:
    """Table of expected birthday/brute-force costs for several effective sizes."""
    rows = []
    for bits in bits_values:
        expected = expected_birthday_attempts(bits)
        rows.append(
            [
                str(bits),
                format_count(2.0**bits),
                format_count(birthday_bound(bits)),
                format_count(expected),
                format_long_duration(expected / 1e6),
                format_count(expected_brute_force_attempts(bits)),
            ]
        )
    return format_table(
        [
            "Bits",
            "Output space 2^b",
            "sqrt(2^b)",
            "Expected (birthday)",
            "Time @1M H/s",
            "Expected (brute force)",
        ],
        rows,
        align=["r", "r", "r", "r", "l", "r"],
    )


def _birthday_text() -> str:
    return (
        "THE BIRTHDAY BOUND\n"
        "==================\n\n"
        "For an ideal b-bit hash (N = 2^b outputs), after n random inputs:\n\n"
        "    P(collision) ~ 1 - exp(-n(n-1) / (2N))\n"
        "    P = 50%  at  n ~ 1.1774 * sqrt(N)\n"
        "    E[n]     ~  sqrt(pi/2 * N) ~ 1.2533 * sqrt(N)\n\n"
        "The approximation n ~ sqrt(2^b) = 2^(b/2) is the 'birthday bound'. It is an\n"
        "expectation, NOT a guarantee: a particular search may need fewer or more attempts.\n"
        "The pigeonhole principle only guarantees a collision after 2^b + 1 distinct inputs.\n\n"
        + birthday_table()
        + "\n\n"
        + _SEARCH_LIMIT_NOTE
    )


TOPICS: Mapping[str, str] = MappingProxyType(
    {
        "collision": "What hash collisions are and why truncated collisions are not full ones",
        "birthday": "The birthday paradox and a table of expected costs",
        "truncation": "How --bits truncation works",
        "methods": "Birthday vs brute-force search",
    }
)


def explain(topic: str = "collision") -> str:
    """Return the explanation text for *topic*."""
    key = topic.strip().lower()
    if key == "collision":
        return _COLLISION
    if key == "birthday":
        return _birthday_text()
    if key == "truncation":
        return _TRUNCATION
    if key == "methods":
        return _METHODS
    raise KeyError(topic)
