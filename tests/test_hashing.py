"""Tests for hash algorithms and truncation."""

from __future__ import annotations

import hashlib

import pytest

from hashcollider.errors import InvalidBitLengthError, UnsupportedAlgorithmError
from hashcollider.hashing import (
    BUILTIN_ALGORITHMS,
    AlgorithmRegistry,
    HashAlgorithm,
    TruncatedHash,
    get_algorithm,
    list_algorithms,
)

ALL_NAMES = [info.name for info in BUILTIN_ALGORITHMS]

# Standard test vectors for the empty string.
EMPTY_VECTORS = {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha224": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha384": (
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
        "274edebfe76f65fbd51ad2f14898b95b"
    ),
    "sha512": (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ),
    "sha3-224": "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
    "sha3-256": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "sha3-384": (
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
        "c3713831264adb47fb6bd1e058d5f004"
    ),
    "sha3-512": (
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    ),
}

HELLO_VECTORS = {
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
}

HASHLIB_NAMES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha3-224": "sha3_224",
    "sha3-256": "sha3_256",
    "sha3-384": "sha3_384",
    "sha3-512": "sha3_512",
}


def test_all_ten_algorithms_are_supported() -> None:
    assert set(ALL_NAMES) == set(EMPTY_VECTORS)
    assert len(list_algorithms()) == 10


@pytest.mark.parametrize("name", ALL_NAMES)
def test_empty_string_vectors(name: str) -> None:
    assert get_algorithm(name).hexdigest(b"") == EMPTY_VECTORS[name]


@pytest.mark.parametrize("name", sorted(HELLO_VECTORS))
def test_hello_vectors(name: str) -> None:
    assert get_algorithm(name).hexdigest(b"hello") == HELLO_VECTORS[name]


@pytest.mark.parametrize("name", ALL_NAMES)
def test_matches_hashlib_for_arbitrary_data(name: str) -> None:
    data = bytes(range(256)) * 3
    expected = hashlib.new(HASHLIB_NAMES[name], data).digest()
    algorithm = get_algorithm(name)
    assert algorithm.digest(data) == expected
    assert algorithm.hash(data) == expected
    assert algorithm.digest_function()(data) == expected


@pytest.mark.parametrize("name", ALL_NAMES)
def test_digest_length_matches_output_bits(name: str) -> None:
    algorithm = get_algorithm(name)
    digest = algorithm.digest(b"abc")
    assert len(digest) * 8 == algorithm.output_bits
    assert algorithm.output_bytes == len(digest)


@pytest.mark.parametrize("name", ALL_NAMES)
def test_hexdigest_is_lowercase_hex_of_correct_length(name: str) -> None:
    algorithm = get_algorithm(name)
    hexdigest = algorithm.hexdigest(b"abc")
    assert len(hexdigest) == algorithm.output_bits // 4
    assert all(c in "0123456789abcdef" for c in hexdigest)
    assert bytes.fromhex(hexdigest) == algorithm.digest(b"abc")


@pytest.mark.parametrize(
    "alias, canonical",
    [
        ("SHA-256", "sha256"),
        ("sha_256", "sha256"),
        ("Sha256", "sha256"),
        ("SHA3-256", "sha3-256"),
        ("sha3_256", "sha3-256"),
        ("SHA-1", "sha1"),
        ("MD5", "md5"),
    ],
)
def test_aliases(alias: str, canonical: str) -> None:
    assert get_algorithm(alias).name == canonical


@pytest.mark.parametrize("name", ["", "sha999", "blake3", "crc32", "rot13"])
def test_unsupported_algorithm(name: str) -> None:
    with pytest.raises(UnsupportedAlgorithmError, match="Unsupported algorithm"):
        get_algorithm(name)


def test_legacy_flags_and_warnings() -> None:
    for name in ("md5", "sha1"):
        algorithm = get_algorithm(name)
        assert algorithm.is_legacy
        assert algorithm.security_warning is not None
        assert "NOT a cryptanalytic" in algorithm.security_warning
    for name in ("sha256", "sha3-512"):
        algorithm = get_algorithm(name)
        assert not algorithm.is_legacy
        assert algorithm.security_warning is None


def test_registry_is_isolated_and_extensible() -> None:
    registry = AlgorithmRegistry(infos=BUILTIN_ALGORITHMS[:1])
    assert registry.names() == ["md5"]
    assert "md5" in registry
    assert "sha256" not in registry
    assert "sha256" in AlgorithmRegistry()
    with pytest.raises(UnsupportedAlgorithmError):
        registry.get("sha256")


def test_registry_caches_instances() -> None:
    registry = AlgorithmRegistry()
    assert registry.get("sha256") is registry.get("SHA-256")


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------

HELLO_SHA256 = hashlib.sha256(b"hello").digest()


def test_truncate_8_bits_is_first_byte() -> None:
    truncated = TruncatedHash(get_algorithm("sha256"), 8)
    assert truncated.value(b"hello") == HELLO_SHA256[0] == 0x2C
    assert truncated.hexdigest(b"hello") == "2c"
    assert truncated.digest(b"hello") == HELLO_SHA256[:1]


def test_truncate_16_bits_is_first_two_bytes() -> None:
    truncated = get_algorithm("sha256", bits=16)
    assert isinstance(truncated, TruncatedHash)
    assert truncated.hexdigest(b"hello") == "2cf2"
    assert truncated.digest(b"hello") == HELLO_SHA256[:2]
    assert truncated.output_bits == 16


def test_truncate_12_bits_is_first_three_hex_digits() -> None:
    truncated = TruncatedHash(get_algorithm("sha256"), 12)
    assert truncated.hexdigest(b"hello") == "2cf"
    assert truncated.value(b"hello") == 0x2CF
    assert truncated.format_binary(truncated.value(b"hello")) == "001011001111"
    assert truncated.nbytes == 2
    assert truncated.shift == 4


@pytest.mark.parametrize("bits", [1, 2, 3, 5, 7, 8, 9, 13, 16, 20, 24, 31, 32, 63, 64, 100, 255])
def test_truncation_equals_leading_bits(bits: int) -> None:
    truncated = TruncatedHash(get_algorithm("sha256"), bits)
    full = int.from_bytes(HELLO_SHA256, "big")
    assert truncated.value(b"hello") == full >> (256 - bits)
    assert truncated.value(b"hello") < 2**bits
    assert len(truncated.hexdigest(b"hello")) == (bits + 3) // 4
    assert truncated.space_size == 2**bits


@pytest.mark.parametrize("name", ALL_NAMES)
def test_full_size_truncation_is_identity(name: str) -> None:
    algorithm = get_algorithm(name)
    truncated = TruncatedHash(algorithm, algorithm.output_bits)
    assert truncated.is_full
    assert truncated.digest(b"abc") == algorithm.digest(b"abc")
    assert truncated.hexdigest(b"abc") == algorithm.hexdigest(b"abc")


def test_truncated_display_name_and_properties() -> None:
    truncated = TruncatedHash(get_algorithm("sha256"), 16)
    assert truncated.display_name == "SHA-256 (first 16 bits)"
    assert truncated.base.name == "sha256"
    assert not truncated.is_full
    assert isinstance(truncated, HashAlgorithm)


def test_truncated_values_differ_from_full_digest_equality() -> None:
    """Equal truncated values do not imply equal full digests."""
    truncated = TruncatedHash(get_algorithm("sha256"), 4)
    seen: dict[int, bytes] = {}
    for i in range(100):
        message = f"m{i}".encode()
        value = truncated.value(message)
        if value in seen:
            other = seen[value]
            assert hashlib.sha256(message).digest() != hashlib.sha256(other).digest()
            return
        seen[value] = message
    pytest.fail("pigeonhole principle guarantees a 4-bit collision within 17 inputs")


@pytest.mark.parametrize("bits", [0, -1, -16, 257, 1000])
def test_invalid_bit_lengths(bits: int) -> None:
    with pytest.raises(InvalidBitLengthError, match="Invalid bit length"):
        TruncatedHash(get_algorithm("sha256"), bits)


@pytest.mark.parametrize("bits", [16.0, "16", None, True])
def test_non_integer_bit_lengths(bits: object) -> None:
    with pytest.raises(InvalidBitLengthError):
        TruncatedHash(get_algorithm("sha256"), bits)  # type: ignore[arg-type]


def test_md5_rejects_more_than_128_bits() -> None:
    with pytest.raises(InvalidBitLengthError, match="1 to 128"):
        get_algorithm("md5", bits=129)


def test_cannot_truncate_a_truncated_hash() -> None:
    truncated = TruncatedHash(get_algorithm("sha256"), 16)
    with pytest.raises(TypeError):
        TruncatedHash(truncated, 8)  # type: ignore[arg-type]
