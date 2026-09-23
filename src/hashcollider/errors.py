"""Exception hierarchy for expected, user-facing errors.

Every error a user can trigger through normal CLI use derives from
:class:`HashColliderError`. The CLI catches these, prints a one-line message
(no stack trace) and exits with the error's ``exit_code``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .config import EXIT_FAILURE, EXIT_INTERRUPTED, EXIT_NOT_FOUND, EXIT_USAGE

if TYPE_CHECKING:
    from .collision.results import SearchStatistics


class HashColliderError(Exception):
    """Base class for all expected HashCollider errors."""

    exit_code: int = EXIT_FAILURE


# --- configuration / usage errors (exit code 2) ---------------------------


class ConfigurationError(HashColliderError):
    """Invalid parameters or an unsafe configuration."""

    exit_code = EXIT_USAGE


class UnsupportedAlgorithmError(ConfigurationError):
    """The requested hash algorithm is not supported."""


class InvalidBitLengthError(ConfigurationError):
    """The effective bit length is outside the valid range."""


class InvalidInputLengthError(ConfigurationError):
    """The requested input length is not a positive, reasonable integer."""


class InvalidInputError(ConfigurationError):
    """User supplied input data could not be interpreted."""


class InfeasibleSearchError(ConfigurationError):
    """The search is computationally unrealistic (or needs ``--force``)."""


# --- searches that ended without a collision (exit code 3 / 130) ----------


class SearchEndedError(HashColliderError):
    """A search stopped before finding a collision.

    The statistics collected so far are preserved in :attr:`statistics`.
    """

    exit_code = EXIT_NOT_FOUND

    def __init__(self, message: str, statistics: SearchStatistics | None = None) -> None:
        super().__init__(message)
        self.statistics = statistics


class MaxAttemptsReachedError(SearchEndedError):
    """Maximum attempt limit reached."""


class MaxTimeReachedError(SearchEndedError):
    """Maximum execution time reached."""


class GeneratorExhaustedError(SearchEndedError):
    """The input generator produced no further inputs."""


class SearchStoppedError(SearchEndedError):
    """The search was stopped programmatically via ``CollisionEngine.stop()``."""


class SearchInterruptedError(SearchEndedError):
    """The search was interrupted by the user (Ctrl+C)."""

    exit_code = EXIT_INTERRUPTED


# --- storage / verification errors (exit code 1) ---------------------------


class StorageError(HashColliderError):
    """A collision file could not be read or written."""


class CollisionFileNotFoundError(StorageError):
    """The collision file does not exist."""


class InvalidCollisionFileError(StorageError):
    """The collision file is malformed or uses an unsupported format."""


class VerificationFailedError(HashColliderError):
    """Collision verification failed."""
