"""Central configuration constants.

All defaults live here so the CLI, the engine, the benchmark runner and the
documentation share a single source of truth. Nothing in this module is
mutated at runtime; mappings are exposed as read-only ``MappingProxyType``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

# --------------------------------------------------------------------------
# Process exit codes
# --------------------------------------------------------------------------
EXIT_OK = 0
"""Command completed successfully (collision found, verification passed, ...)."""
EXIT_FAILURE = 1
"""Generic failure: verification failed, file error, ..."""
EXIT_USAGE = 2
"""Invalid arguments or an unsafe/infeasible configuration (same code argparse uses)."""
EXIT_NOT_FOUND = 3
"""A search ended without a collision (attempt/time limit, generator exhausted)."""
EXIT_INTERRUPTED = 130
"""The user pressed Ctrl+C (128 + SIGINT, the shell convention)."""

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------
DEFAULT_ALGORITHM = "sha256"
DEFAULT_BITS = 16
DEFAULT_METHOD = "birthday"
DEFAULT_GENERATOR = "sequential"
DEFAULT_RANDOM_LENGTH = 32
DEFAULT_OUTPUT_FILE = Path("collision.json")
DEFAULT_REPORT_FILE = Path("reports") / "collision-report.md"

DEFAULT_MAX_SECONDS = 300.0
"""Default wall-time limit for ``collide`` (0 on the CLI disables it)."""
DEFAULT_MAX_STORED = 2_000_000
"""Default cap on digests kept in memory by the birthday search."""

CHECK_INTERVAL = 1024
"""Attempts between time-limit / stop-request checks (must be a power of two)."""
PROGRESS_LOG_INTERVAL = 1 << 18
"""Attempts between debug progress messages when ``--verbose`` is active."""

MAX_INPUT_LENGTH = 1 << 20
"""Largest generated input length accepted (1 MiB)."""

# Safety limits for collision searches, keyed by method name.
# Above SAFE_MAX_BITS a search needs --force; above HARD_MAX_BITS it is refused.
SAFE_MAX_BITS: Mapping[str, int] = MappingProxyType({"birthday": 36, "brute-force": 24})
HARD_MAX_BITS: Mapping[str, int] = MappingProxyType({"birthday": 64, "brute-force": 32})

ESTIMATED_ENTRY_OVERHEAD_BYTES = 120
"""Rough CPython memory cost of one dict entry (int key + bytes object + slot)."""

REFERENCE_HASH_RATE = 1e9
"""Hash rate (hashes/second) used when explaining how long infeasible searches take."""

# --------------------------------------------------------------------------
# Generators
# --------------------------------------------------------------------------
SEQUENTIAL_PREFIX = "collision-test-"
SEQUENTIAL_DEFAULT_WIDTH = 8
SEQUENTIAL_DEFAULT_START = 1
STRUCTURED_DEFAULT_PREFIX = "experiment-"
STRUCTURED_DEFAULT_WIDTH = 6
STRUCTURED_DEFAULT_START = 1

# --------------------------------------------------------------------------
# Benchmark
# --------------------------------------------------------------------------
BENCHMARK_DEFAULT_ITERATIONS = 20
BENCHMARK_DEFAULT_RAW_HASHES = 100_000
BENCHMARK_DEFAULT_MAX_SECONDS = 60.0

# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
FORMAT_VERSION = 1
"""Version of the collision JSON file format written by this release."""
