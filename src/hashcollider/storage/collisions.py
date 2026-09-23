"""Save and load collision records as versioned JSON files."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..collision.results import CollisionResult
from ..errors import CollisionFileNotFoundError, InvalidCollisionFileError, StorageError

logger = logging.getLogger(__name__)


def collision_to_json(result: CollisionResult) -> str:
    """Serialise *result* to pretty-printed JSON text."""
    return json.dumps(result.to_dict(), indent=2) + "\n"


def save_collision(result: CollisionResult, path: str | Path, *, overwrite: bool = True) -> Path:
    """Write *result* to *path* atomically and return the path.

    The file is first written to a temporary sibling and then renamed, so an
    interrupted write never leaves a truncated collision file behind.

    Raises:
        StorageError: if the file exists and ``overwrite`` is false, or on I/O errors.
    """
    target = Path(path)
    if target.exists() and not overwrite:
        raise StorageError(f"Refusing to overwrite existing file: {target}")
    temporary = target.with_name(target.name + ".tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(collision_to_json(result), encoding="utf-8")
        temporary.replace(target)
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        reason = exc.strerror or exc
        raise StorageError(f"Could not write collision file {target}: {reason}") from exc
    logger.debug("saved collision to %s", target)
    return target


def load_collision(path: str | Path) -> CollisionResult:
    """Load and validate a collision record from *path*.

    Raises:
        CollisionFileNotFoundError: the file does not exist.
        InvalidCollisionFileError: the content is not a valid collision record.
        StorageError: the path is not a readable file.
    """
    source = Path(path)
    if not source.exists():
        raise CollisionFileNotFoundError(f"Collision file does not exist: {source}")
    if not source.is_file():
        raise StorageError(f"Not a regular file: {source}")
    try:
        text = source.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidCollisionFileError(f"{source} is not UTF-8 encoded JSON") from exc
    except OSError as exc:
        raise StorageError(f"Could not read {source}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidCollisionFileError(
            f"{source} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})"
        ) from exc
    return CollisionResult.from_dict(data)
