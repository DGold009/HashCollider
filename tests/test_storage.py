"""Tests for JSON storage and collision verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from hashcollider.collision import CollisionEngine, CollisionResult, verify_collision
from hashcollider.config import FORMAT_VERSION
from hashcollider.errors import (
    CollisionFileNotFoundError,
    InvalidBitLengthError,
    InvalidCollisionFileError,
    StorageError,
    UnsupportedAlgorithmError,
)
from hashcollider.generators import SequentialGenerator
from hashcollider.hashing import TruncatedHash, get_algorithm
from hashcollider.storage import collision_to_json, load_collision, save_collision


@pytest.fixture(scope="module")
def collision() -> CollisionResult:
    return CollisionEngine("sha256", 16, SequentialGenerator(length=32)).find_collision()


def _non_colliding_partner(message: bytes, bits: int = 16) -> bytes:
    """Return an input whose truncated SHA-256 differs from *message*'s."""
    truncated = TruncatedHash(get_algorithm("sha256"), bits)
    target = truncated.value(message)
    for i in range(1000):
        candidate = message + str(i).encode()
        if truncated.value(candidate) != target:
            return candidate
    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def test_save_and_load_round_trip(tmp_path: Path, collision: CollisionResult) -> None:
    path = save_collision(collision, tmp_path / "collision.json")
    assert path.exists()
    loaded = load_collision(path)
    assert loaded == collision


def test_saved_json_structure(tmp_path: Path, collision: CollisionResult) -> None:
    path = save_collision(collision, tmp_path / "c.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["format_version"] == FORMAT_VERSION == 1
    for key in (
        "algorithm",
        "effective_bits",
        "generator",
        "input_a",
        "input_b",
        "hash_a",
        "hash_b",
        "truncated_hash",
        "attempts",
        "elapsed_seconds",
        "hashes_per_second",
        "timestamp",
    ):
        assert key in data, key
    assert data["algorithm"] == "sha256"
    assert data["effective_bits"] == 16
    assert data["input_encoding"] == "hex"
    assert bytes.fromhex(data["input_a"]) == collision.input_a
    assert data["input_a_text"] == collision.input_a.decode()
    assert data["full_digests_equal"] is False


def test_save_creates_parent_directories(tmp_path: Path, collision: CollisionResult) -> None:
    path = save_collision(collision, tmp_path / "a" / "b" / "c.json")
    assert path.is_file()
    assert not (tmp_path / "a" / "b" / "c.json.tmp").exists()


def test_save_refuses_overwrite_when_requested(tmp_path: Path, collision: CollisionResult) -> None:
    path = save_collision(collision, tmp_path / "c.json")
    with pytest.raises(StorageError, match="overwrite"):
        save_collision(collision, path, overwrite=False)
    save_collision(collision, path)  # default overwrites


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CollisionFileNotFoundError, match="does not exist"):
        load_collision(tmp_path / "missing.json")


def test_load_directory(tmp_path: Path) -> None:
    with pytest.raises(StorageError):
        load_collision(tmp_path)


def test_load_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(InvalidCollisionFileError, match="not valid JSON"):
        load_collision(path)


def test_load_non_object_json(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(InvalidCollisionFileError, match="JSON object"):
        load_collision(path)


@pytest.mark.parametrize("version", [None, 0, 2, "1", True])
def test_unsupported_format_version(version: object) -> None:
    data = {"algorithm": "sha256", "effective_bits": 8, "input_a": "00", "input_b": "01"}
    if version is not None:
        data["format_version"] = version
    with pytest.raises(InvalidCollisionFileError, match="format_version"):
        CollisionResult.from_dict(data)


@pytest.mark.parametrize("missing", ["algorithm", "effective_bits", "input_a", "input_b"])
def test_missing_required_fields(missing: str) -> None:
    data = {
        "format_version": 1,
        "algorithm": "sha256",
        "effective_bits": 8,
        "input_a": "00",
        "input_b": "01",
    }
    del data[missing]
    with pytest.raises(InvalidCollisionFileError, match=missing):
        CollisionResult.from_dict(data)


@pytest.mark.parametrize(
    "field, value",
    [
        ("input_a", "zz"),
        ("input_a", 42),
        ("effective_bits", "16"),
        ("effective_bits", 16.5),
        ("algorithm", ""),
        ("attempts", "many"),
        ("input_encoding", "base64"),
        ("generator_params", [1, 2]),
    ],
)
def test_invalid_field_values(field: str, value: object) -> None:
    data = {
        "format_version": 1,
        "algorithm": "sha256",
        "effective_bits": 8,
        "input_a": "00",
        "input_b": "01",
    }
    data[field] = value
    with pytest.raises(InvalidCollisionFileError):
        CollisionResult.from_dict(data)


def test_minimal_hand_written_record_utf8() -> None:
    record = CollisionResult.from_dict(
        {
            "format_version": 1,
            "algorithm": "SHA-256",
            "effective_bits": 8,
            "input_encoding": "utf-8",
            "input_a": "hello",
            "input_b": "world",
        }
    )
    assert record.input_a == b"hello"
    assert record.hash_a is None
    assert record.attempts is None


def test_collision_to_json_is_valid_json(collision: CollisionResult) -> None:
    assert json.loads(collision_to_json(collision))["format_version"] == 1


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def test_verify_real_collision(collision: CollisionResult) -> None:
    verification = verify_collision(collision)
    assert verification.passed
    assert verification.failures == ()
    assert verification.recomputed_truncated_a == verification.recomputed_truncated_b
    assert not verification.full_digests_equal
    assert verification.is_truncated
    assert verification.recomputed_hash_a == hashlib.sha256(collision.input_a).hexdigest()


def test_verify_loaded_file(tmp_path: Path, collision: CollisionResult) -> None:
    path = save_collision(collision, tmp_path / "c.json")
    assert verify_collision(load_collision(path)).passed


def test_verify_fails_for_identical_inputs(collision: CollisionResult) -> None:
    record = replace(collision, input_b=collision.input_a, hash_b=collision.hash_a)
    verification = verify_collision(record)
    assert not verification.passed
    assert any("different" in check.description for check in verification.failures)


def test_verify_fails_for_non_colliding_inputs(collision: CollisionResult) -> None:
    partner = _non_colliding_partner(collision.input_a)
    record = replace(collision, input_b=partner, hash_b=None)
    verification = verify_collision(record)
    assert not verification.passed
    assert any("truncated digests are equal" in c.description for c in verification.failures)


def test_verify_does_not_trust_stored_hashes(collision: CollisionResult) -> None:
    """Stored values claiming a collision must not make a non-collision pass."""
    partner = _non_colliding_partner(collision.input_a)
    forged = replace(
        collision,
        input_b=partner,
        hash_b=collision.hash_a,  # lie: claim B has A's digest
        truncated_hash=collision.truncated_hash,
    )
    verification = verify_collision(forged)
    assert not verification.passed
    assert verification.recomputed_hash_b == hashlib.sha256(partner).hexdigest()


def test_verify_detects_tampered_metadata(collision: CollisionResult) -> None:
    tampered = replace(collision, hash_a="00" * 32)
    verification = verify_collision(tampered)
    assert not verification.passed
    assert any("hash_a" in c.description for c in verification.failures)

    wrong_size = replace(collision, output_bits=512)
    assert not verify_collision(wrong_size).passed

    wrong_truncated = replace(collision, truncated_hash="not-hex")
    assert not verify_collision(wrong_truncated).passed


def test_verify_without_stored_hashes(collision: CollisionResult) -> None:
    minimal = CollisionResult(
        algorithm="sha256",
        effective_bits=16,
        input_a=collision.input_a,
        input_b=collision.input_b,
    )
    verification = verify_collision(minimal)
    assert verification.passed
    assert len(verification.checks) == 2


def test_verify_unknown_algorithm_and_bad_bits(collision: CollisionResult) -> None:
    with pytest.raises(UnsupportedAlgorithmError):
        verify_collision(replace(collision, algorithm="sha999"))
    with pytest.raises(InvalidBitLengthError):
        verify_collision(replace(collision, effective_bits=0))
