"""HashCollider - an educational hash collision research tool.

HashCollider demonstrates hash collisions in *reduced* (truncated) output
spaces, e.g. "the first 16 bits of SHA-256". A collision in a truncated
output space is **not** a collision in the full algorithm: the full digests
of the two inputs remain different.

Typical library usage::

    from hashcollider import CollisionEngine, SequentialGenerator

    engine = CollisionEngine("sha256", bits=16, generator=SequentialGenerator())
    result = engine.find_collision()
    print(result.input_a, result.input_b, result.truncated_hash)
"""

from __future__ import annotations

from ._version import __version__
from .collision import (
    CollisionEngine,
    CollisionResult,
    SearchOutcome,
    SearchStatistics,
    SearchStatus,
    verify_collision,
)
from .generators import (
    RandomGenerator,
    SeededRandomGenerator,
    SequentialGenerator,
    StructuredGenerator,
    create_generator,
)
from .hashing import AlgorithmRegistry, HashAlgorithm, TruncatedHash, get_algorithm

__all__ = [
    "AlgorithmRegistry",
    "CollisionEngine",
    "CollisionResult",
    "HashAlgorithm",
    "RandomGenerator",
    "SearchOutcome",
    "SearchStatistics",
    "SearchStatus",
    "SeededRandomGenerator",
    "SequentialGenerator",
    "StructuredGenerator",
    "TruncatedHash",
    "__version__",
    "create_generator",
    "get_algorithm",
    "verify_collision",
]
