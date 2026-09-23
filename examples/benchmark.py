#!/usr/bin/env python3
"""Benchmark collision searches across several algorithms.

Run from the repository root:

    python3 examples/benchmark.py
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import hashcollider  # noqa: F401
except ImportError:  # allow running without `pip install -e .`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hashcollider.benchmark import (  # noqa: E402
    BenchmarkConfig,
    BenchmarkRunner,
    benchmark_table,
)


def main() -> None:
    config = BenchmarkConfig(
        algorithms=("md5", "sha1", "sha256", "sha512", "sha3-256"),
        bits=16,
        iterations=25,
        input_length=32,
    )
    runner = BenchmarkRunner(config)
    runner.check_feasibility()
    report = runner.run(progress=lambda alg: print(f"benchmarking {alg.display_name} ..."))
    print()
    print(benchmark_table(report.results))
    print(
        "\nNote: speed differences come from the hash implementations. The number of "
        "attempts depends only on the effective size (16 bits), not on the algorithm."
    )


if __name__ == "__main__":
    main()
