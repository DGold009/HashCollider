# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/).

## [0.1.0]

Initial release.

### Added

- `HashAlgorithm` interface, `AlgorithmRegistry` and hashlib-backed MD5, SHA-1, SHA-224,
  SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384 and SHA3-512.
- `TruncatedHash`: configurable effective output size (first *b* bits of any digest).
- Collision engine (`CollisionEngine`) with `run()`, `find_collision()`, `stop()`,
  `statistics()` and `estimate()`.
- Search methods: birthday search (dictionary of truncated digests, duplicate-input
  rejection) and fixed-target brute-force search.
- Input generators: CSPRNG random (`secrets`), seeded random (reproducible, documented as
  non-cryptographic), sequential (`collision-test-N`) and structured (prefix + counter +
  suffix).
- Safety: pre-flight estimates (birthday bound, expected attempts, memory), safe defaults
  requiring `--force`, hard limits for infeasible searches, `--max-attempts`,
  `--max-seconds`, `--max-stored`, clean Ctrl+C handling that preserves statistics.
- Versioned JSON collision files (`format_version: 1`) with atomic writes.
- Independent verification that recomputes all digests and detects forged or inconsistent
  files.
- Markdown reports with statistics, verification, explanation, security interpretation
  and limitations.
- Benchmark runner comparing algorithms and observed vs. expected attempts.
- CLI commands: `algorithms`, `hash`, `collide`, `verify`, `report`, `benchmark`,
  `explain`; `--verbose` logging; documented exit codes.
- MD5/SHA-1 educational security warnings.
- Test suite (pytest), GitHub Actions workflow, Makefile, documentation and examples.

### Not included (future work)

- Multiprocessing (`--workers N`). The strategy/generator design allows independent worker
  streams (disjoint counter ranges or distinct seeds), but a parallel birthday search needs
  a shared or merged digest table to be efficient. It was left out of 0.1.0 because
  correctness is more important than parallelism.
- GPU acceleration, CSV/SQLite storage, visualisations and probability graphs, statistical
  analysis tooling, web dashboard, plugin loading.
