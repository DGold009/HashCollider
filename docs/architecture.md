# Architecture

HashCollider is a small, layered Python package with no third-party runtime dependencies.

```text
            +--------------------------------------+
            |  CLI  (cli.py, argparse)             |
            |  hash | collide | verify | report |  |
            |  benchmark | algorithms | explain    |
            +------------------+-------------------+
                               |
                               v
            +--------------------------------------+
            |  Collision Engine (collision/)       |
            |  CollisionEngine -> SearchStrategy   |
            |  (birthday | brute-force)            |
            +---------+------------------+---------+
                      |                  |
                      v                  v
       +---------------------+   +----------------------+
       |  Hash Algorithm     |   |  Input Generator     |
       |  (hashing/)         |   |  (generators/)       |
       |  HashAlgorithm      |   |  random | seeded     |
       |  TruncatedHash      |   |  sequential          |
       |  AlgorithmRegistry  |   |  structured          |
       +---------------------+   +----------------------+
                               |
                               v
            +--------------------------------------+
            |  Storage / Verification / Reports    |
            |  storage/  collision/verify.py       |
            |  reports/  benchmark/                |
            +--------------------------------------+
```

Data flows downward: the CLI parses options, builds an algorithm, a generator and an engine,
runs the search and hands the resulting `CollisionResult` to storage, verification and
reporting.

## Package layout

```text
src/hashcollider/
  __init__.py          public API re-exports
  __main__.py          `python3 -m hashcollider`
  _version.py          version string (single source of truth)
  cli.py               argparse CLI, output formatting, exit codes
  config.py            constants and defaults (read-only)
  errors.py            exception hierarchy with exit codes
  formatting.py        ASCII tables and number formatting
  explain.py           educational texts (`hashcollider explain`)
  hashing/
    base.py            HashAlgorithm interface, TruncatedHash, validate_bits
    algorithms.py      AlgorithmInfo metadata, HashlibAlgorithm, AlgorithmRegistry
  collision/
    base.py            SearchStrategy interface, SearchLimits, SearchContext, checkpoint
    birthday.py        BirthdayStrategy + birthday-bound mathematics
    brute_force.py     BruteForceStrategy + brute-force mathematics
    engine.py          CollisionEngine, SearchEstimate, feasibility checks
    results.py         SearchStatus, SearchStatistics, CollisionResult, SearchOutcome
    verify.py          verify_collision (independent recomputation)
  generators/
    base.py            InputGenerator interface, validate_input_length
    random.py          RandomGenerator (secrets), SeededRandomGenerator (random.Random)
    sequential.py      SequentialGenerator (collision-test-NNNN)
    structured.py      StructuredGenerator (prefix + counter + suffix)
  storage/
    collisions.py      save_collision / load_collision (versioned JSON)
  benchmark/
    runner.py          BenchmarkRunner, statistics, raw hash-rate measurement
  reports/
    generator.py       Markdown report generation
```

## Modules

### CLI (`cli.py`)

- Builds the parser (`build_parser()`); `main(argv)` returns an exit code instead of calling
  `sys.exit`, which keeps it testable.
- Catches every `HashColliderError` and prints `Error: <message>` to stderr - no stack
  traces for user errors. `--verbose` adds debug logging (including the traceback) on stderr.
- Output is plain ASCII. Warnings (MD5/SHA-1, seeded randomness, ignored options) go to
  stderr so stdout stays clean.
- Exit codes: 0 success, 1 failure, 2 usage/infeasible, 3 not found, 130 Ctrl+C.

### Hash algorithms (`hashing/`)

- `HashAlgorithm` is the extension point. Subclasses implement `name`, `display_name`,
  `output_bits` and `digest(data)`; `hash()`, `hexdigest()`, `digest_function()` and
  `output_bytes` come for free.
- `HashlibAlgorithm` wraps a hashlib constructor. On FIPS-restricted builds it retries MD5 /
  SHA-1 with `usedforsecurity=False`.
- `AlgorithmRegistry` maps names and aliases (case/punctuation-insensitive) to algorithms.
  It is an ordinary object - create your own instance to register extra algorithms, so
  there is no global mutable registry.
- `TruncatedHash(base, bits)` keeps the most significant `bits` bits:
  `int.from_bytes(digest[:ceil(bits/8)], "big") >> shift`. It is itself a `HashAlgorithm`.

### Input generators (`generators/`)

- `InputGenerator.__iter__` yields `bytes`; each iteration starts a fresh stream.
- Metadata: `input_length`, `input_space_size()`, `deterministic`,
  `cryptographically_secure`, `describe()` (stored in collision files).
- `RandomGenerator` batches `secrets.token_bytes` calls for speed while staying a CSPRNG.
- `SeededRandomGenerator` uses `random.Random(seed)` - reproducible, **not** secure.
- `StructuredGenerator` precomputes a `bytes` format string (`prefix%0Nd suffix`), so each
  input costs a single formatting operation; it stops at `10**width` to keep inputs unique
  and fixed-length. `SequentialGenerator` is a structured generator with the prefix
  `collision-test-`.

### Collision engine (`collision/`)

- `CollisionEngine(algorithm, bits, generator, method=..., max_attempts=..., max_seconds=...,
  max_stored=..., force=...)`.
- `estimate()` computes expected attempts, the birthday bound, memory and input-space size.
- `check_feasibility()` enforces `SAFE_MAX_BITS` (needs `force`) and `HARD_MAX_BITS`
  (always refused) from `config.py`.
- `run()` returns a `SearchOutcome` and never raises for limits or Ctrl+C;
  `find_collision()` raises a specific `SearchEndedError` subclass carrying the statistics.
- `stop()` sets a `threading.Event` checked at every checkpoint; `statistics()` returns live
  or final counters.
- Strategies own the hot loop. They receive a `SearchContext` (digest function, truncation
  parameters, limits, stop event) and return a `RawSearchResult`. Limits, stop requests and
  progress logging are checked every `CHECK_INTERVAL` (1024) attempts, not per hash.
- `KeyboardInterrupt` is caught inside the loop, so interrupted searches still report
  attempts, elapsed time and hash rate.

### Storage, verification and reports

- `save_collision` writes JSON atomically (temporary file + rename); `load_collision`
  validates structure and `format_version`.
- `verify_collision` re-hashes both inputs, checks `input_a != input_b` and equal truncated
  values, and checks stored metadata for consistency. Stored hashes are never trusted.
- `generate_report` builds a Markdown report from a record and its verification result.

### Benchmark

`BenchmarkRunner` runs `iterations` independent searches per algorithm (fresh CSPRNG
generator each, or `seed + i` when seeded), measures raw digest throughput separately and
aggregates mean/median/stdev attempts, observed/expected ratio and hash rates.

## Extension points (future work)

| Future feature | Where it plugs in |
| --- | --- |
| Additional hash functions (BLAKE2, BLAKE3, ...) | new `HashAlgorithm` subclass + `AlgorithmRegistry.register` |
| Multiprocessing | a new strategy/engine that gives each worker a disjoint generator (e.g. structured generators with disjoint counter ranges or distinct seeds) and merges digest tables; `SearchContext` already isolates per-search state |
| GPU acceleration | a strategy that hashes batches on the device; the engine only needs a `RawSearchResult` |
| CSV / SQLite storage | new module in `storage/` round-tripping `CollisionResult.to_dict()` |
| Statistics, probability graphs, visualisation | consume `BenchmarkReport` / `collision.birthday` functions |
| Web dashboard | call the library API (`CollisionEngine`, `verify_collision`) instead of the CLI |
| Plugins | entry points that register `AlgorithmInfo` / strategies into a registry instance |
