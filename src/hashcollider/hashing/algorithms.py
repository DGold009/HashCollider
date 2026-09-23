"""Built-in hashlib-backed algorithms and the algorithm registry."""

from __future__ import annotations

import functools
import hashlib
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from ..errors import UnsupportedAlgorithmError
from .base import HashAlgorithm, TruncatedHash

_GENERIC_SEARCH_NOTE = (
    "Note: any collision HashCollider shows for {name} is a generic birthday or "
    "brute-force collision in a reduced (truncated) output space. It is NOT a "
    "cryptanalytic {name} collision and does not reproduce the published attacks."
)

_MD5_WARNING = (
    "MD5 is cryptographically broken. Practical collision attacks have been public "
    "since 2004 (Wang et al.), and chosen-prefix MD5 collisions have been used in real "
    "attacks (a rogue CA certificate in 2008, the Flame malware in 2012). Do not use "
    "MD5 for signatures, certificates, integrity protection or any other "
    "security-sensitive purpose."
)

_SHA1_WARNING = (
    "SHA-1 is broken for collision resistance. The first public SHA-1 collision was "
    "published in 2017 (SHAttered, Stevens et al.) and a practical chosen-prefix "
    "collision in 2020 (Leurent & Peyrin). NIST has deprecated SHA-1 for digital "
    "signatures. Do not use SHA-1 for new security-sensitive applications."
)


@dataclass(frozen=True)
class AlgorithmInfo:
    """Static metadata describing a supported algorithm."""

    name: str
    display_name: str
    hashlib_name: str
    output_bits: int
    family: str
    status: str
    """``"broken"`` (practical collisions known) or ``"secure"``."""
    recommended: bool
    aliases: tuple[str, ...] = ()
    notes: str = ""
    warning: str | None = None

    @property
    def generic_collision_bits(self) -> int:
        """Generic (birthday-bound) collision cost exponent, ``output_bits / 2``."""
        return self.output_bits // 2

    @property
    def status_label(self) -> str:
        return "BROKEN (collisions)" if self.status == "broken" else "secure"


BUILTIN_ALGORITHMS: tuple[AlgorithmInfo, ...] = (
    AlgorithmInfo(
        "md5",
        "MD5",
        "md5",
        128,
        "MD5",
        "broken",
        False,
        notes="Legacy 128-bit Merkle-Damgard hash. Collisions are practical.",
        warning=_MD5_WARNING,
    ),
    AlgorithmInfo(
        "sha1",
        "SHA-1",
        "sha1",
        160,
        "SHA-1",
        "broken",
        False,
        notes="Legacy 160-bit Merkle-Damgard hash. Collisions are practical.",
        warning=_SHA1_WARNING,
    ),
    AlgorithmInfo(
        "sha224",
        "SHA-224",
        "sha224",
        224,
        "SHA-2",
        "secure",
        True,
        notes="Truncated SHA-256 variant with a different IV; 112-bit collision security.",
    ),
    AlgorithmInfo(
        "sha256",
        "SHA-256",
        "sha256",
        256,
        "SHA-2",
        "secure",
        True,
        notes="The most widely deployed modern hash; 128-bit collision security.",
    ),
    AlgorithmInfo(
        "sha384",
        "SHA-384",
        "sha384",
        384,
        "SHA-2",
        "secure",
        True,
        notes="Truncated SHA-512 variant; resists length-extension attacks.",
    ),
    AlgorithmInfo(
        "sha512",
        "SHA-512",
        "sha512",
        512,
        "SHA-2",
        "secure",
        True,
        notes="64-bit word SHA-2 variant; often faster than SHA-256 on 64-bit CPUs.",
    ),
    AlgorithmInfo(
        "sha3-224",
        "SHA3-224",
        "sha3_224",
        224,
        "SHA-3",
        "secure",
        True,
        notes="Keccak sponge construction (FIPS 202).",
    ),
    AlgorithmInfo(
        "sha3-256",
        "SHA3-256",
        "sha3_256",
        256,
        "SHA-3",
        "secure",
        True,
        notes="Keccak sponge construction (FIPS 202).",
    ),
    AlgorithmInfo(
        "sha3-384",
        "SHA3-384",
        "sha3_384",
        384,
        "SHA-3",
        "secure",
        True,
        notes="Keccak sponge construction (FIPS 202).",
    ),
    AlgorithmInfo(
        "sha3-512",
        "SHA3-512",
        "sha3_512",
        512,
        "SHA-3",
        "secure",
        True,
        notes="Keccak sponge construction (FIPS 202).",
    ),
)


def normalize_name(name: str) -> str:
    """Normalise an algorithm name for lookup (``"SHA3_256"`` -> ``"sha3256"``)."""
    return re.sub(r"[\s_\-]", "", name.strip().lower())


class HashlibAlgorithm(HashAlgorithm):
    """A :class:`HashAlgorithm` backed by Python's :mod:`hashlib`."""

    def __init__(self, info: AlgorithmInfo) -> None:
        self._info = info
        self._constructor = self._resolve_constructor(info)
        actual_bits = self._constructor(b"").digest_size * 8
        if actual_bits != info.output_bits:  # pragma: no cover - defensive
            raise UnsupportedAlgorithmError(
                f"{info.display_name}: hashlib reports {actual_bits} bits, "
                f"expected {info.output_bits}"
            )

    @staticmethod
    def _resolve_constructor(info: AlgorithmInfo) -> Callable[..., object]:
        constructor = getattr(hashlib, info.hashlib_name, None)
        if constructor is None:
            constructor = functools.partial(hashlib.new, info.hashlib_name)
        try:
            constructor(b"")
        except ValueError:
            # FIPS-restricted OpenSSL builds reject MD5/SHA-1 unless the caller
            # declares a non-security use. HashCollider is exactly that.
            constructor = functools.partial(constructor, usedforsecurity=False)
            try:
                constructor(b"")
            except ValueError as exc:
                raise UnsupportedAlgorithmError(
                    f"{info.display_name} is not available in this Python build: {exc}"
                ) from exc
        return constructor

    @property
    def info(self) -> AlgorithmInfo:
        """Static metadata for this algorithm."""
        return self._info

    @property
    def name(self) -> str:
        return self._info.name

    @property
    def display_name(self) -> str:
        return self._info.display_name

    @property
    def output_bits(self) -> int:
        return self._info.output_bits

    @property
    def is_legacy(self) -> bool:
        return self._info.status == "broken"

    @property
    def security_warning(self) -> str | None:
        if self._info.warning is None:
            return None
        return f"{self._info.warning}\n{_GENERIC_SEARCH_NOTE.format(name=self.display_name)}"

    def digest(self, data: bytes) -> bytes:
        return self._constructor(data).digest()

    def digest_function(self) -> Callable[[bytes], bytes]:
        constructor = self._constructor

        def _digest(data: bytes) -> bytes:
            return constructor(data).digest()

        return _digest


class AlgorithmRegistry:
    """Lookup table from algorithm names (and aliases) to algorithms.

    A fresh registry contains the built-in algorithms. Additional algorithms
    can be registered on a *private* registry instance, which keeps the
    library free of global mutable state::

        registry = AlgorithmRegistry()
        registry.register(my_info)
    """

    def __init__(self, infos: Iterable[AlgorithmInfo] = BUILTIN_ALGORITHMS) -> None:
        self._infos: dict[str, AlgorithmInfo] = {}
        self._lookup: dict[str, str] = {}
        self._cache: dict[str, HashAlgorithm] = {}
        for info in infos:
            self.register(info)

    def register(self, info: AlgorithmInfo) -> None:
        """Register an algorithm (and its aliases)."""
        keys = {normalize_name(info.name), normalize_name(info.display_name)}
        keys.update(normalize_name(alias) for alias in info.aliases)
        for key in keys:
            existing = self._lookup.get(key)
            if existing is not None and existing != info.name:
                raise ValueError(f"name {key!r} already registered for {existing!r}")
        self._infos[info.name] = info
        for key in keys:
            self._lookup[key] = info.name

    def resolve(self, name: str) -> AlgorithmInfo:
        """Return metadata for *name* (case/punctuation insensitive)."""
        canonical = self._lookup.get(normalize_name(name))
        if canonical is None:
            raise UnsupportedAlgorithmError(
                f"Unsupported algorithm: {name!r}. Supported algorithms: {', '.join(self.names())}"
            )
        return self._infos[canonical]

    def get(self, name: str) -> HashAlgorithm:
        """Return the (cached) algorithm instance for *name*."""
        info = self.resolve(name)
        algorithm = self._cache.get(info.name)
        if algorithm is None:
            algorithm = HashlibAlgorithm(info)
            self._cache[info.name] = algorithm
        return algorithm

    def names(self) -> list[str]:
        """Canonical names of all registered algorithms, in registration order."""
        return list(self._infos)

    def infos(self) -> list[AlgorithmInfo]:
        """Metadata of all registered algorithms, in registration order."""
        return list(self._infos.values())

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and normalize_name(name) in self._lookup

    def __iter__(self) -> Iterator[AlgorithmInfo]:
        return iter(self.infos())


def get_algorithm(
    name: str, bits: int | None = None, registry: AlgorithmRegistry | None = None
) -> HashAlgorithm:
    """Return an algorithm by name, optionally truncated to *bits* bits.

    ``get_algorithm("sha256")`` returns full SHA-256;
    ``get_algorithm("sha256", bits=16)`` returns a :class:`TruncatedHash`.
    """
    algorithm = (registry or AlgorithmRegistry()).get(name)
    if bits is None:
        return algorithm
    return TruncatedHash(algorithm, bits)


def list_algorithms(registry: AlgorithmRegistry | None = None) -> list[AlgorithmInfo]:
    """Return metadata for all supported algorithms."""
    return (registry or AlgorithmRegistry()).infos()
