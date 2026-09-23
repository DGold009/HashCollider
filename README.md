# HashCollider

**An educational hash collision research tool for Kali Linux (and any Linux with Python 3.10+).**

HashCollider demonstrates, measures and explains hash collisions. It finds real,
independently verifiable collisions in **reduced (truncated) output spaces** such as
"the first 16 bits of SHA-256", compares search methods (birthday vs. brute force),
benchmarks algorithms and produces Markdown reports.

> **Cryptographic accuracy first.** A collision in the first *b* bits of SHA-256 is
> **not** a collision of SHA-256. HashCollider never claims otherwise: every result
> shows both the truncated values (equal) and the full digests (different). Searching
> for collisions in full-size SHA-256 needs about 2^128 hash evaluations and is
> computationally infeasible - the tool refuses such searches and explains why.

---

## Features

- **10 hash algorithms** via Python's `hashlib`: MD5, SHA-1, SHA-224, SHA-256, SHA-384,
  SHA-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512 - behind a clean `HashAlgorithm`
  interface that makes adding algorithms easy.
- **Truncated hash mode** (`--bits N`): keep only the first N bits of any digest to create
  a small, realistic "effective" hash space.
- **Two collision-search methods**
  - `birthday` - stores seen digests, expected cost ~ sqrt(pi/2 * 2^b);
  - `brute-force` - fixed target, expected cost ~ 2^b, constant memory.
- **Three input generators**: `random` (CSPRNG via `secrets`), `sequential`
  (`collision-test-00000001`, ...) and `structured` (prefix + counter + suffix).
  Optional `--seed` for reproducible (explicitly **non-cryptographic**) random inputs.
- **Correct collision detection**: identical inputs are counted as duplicates, never as
  collisions.
- **Safety limits**: pre-flight cost estimates, safe defaults (needs `--force` above
  them), hard limits for infeasible searches, `--max-attempts`, `--max-seconds`,
  `--max-stored` (bounded memory) and clean **Ctrl+C** handling that keeps statistics.
- **Performance measurement** with a monotonic high-resolution clock
  (`time.perf_counter`) and a `benchmark` command that compares algorithms against theory.
- **Versioned JSON storage** (`format_version: 1`) and **independent verification** that
  recomputes every digest and never trusts stored values.
- **Markdown reports** with statistics, verification, explanation, security
  interpretation and limitations.
- **Educational mode**: `hashcollider explain collision|birthday|truncation|methods`.
- **Security warnings** for MD5 and SHA-1.
- **No third-party runtime dependencies** - standard library only.

## Requirements

- Kali Linux (current rolling release) or another Linux distribution
- Python 3.10 or newer (`python3 --version`)
- `python3-venv` for virtual environments (`sudo apt install python3-venv` if missing)
- x86_64 (any architecture supported by CPython works)

## Installation

```bash
git clone <repository>
cd hashcollider
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

`requirements.txt` is intentionally empty of packages: HashCollider only uses the
standard library. For development (tests and linting):

```bash
pip install -r requirements-dev.txt    # pytest, ruff
```

A non-editable install (`pip install .`) works too. See
[docs/installation.md](docs/installation.md) for details and
[docs/troubleshooting.md](docs/troubleshooting.md) if something goes wrong.

Without installing, you can run the module directly from the repository root:

```bash
PYTHONPATH=src python3 -m hashcollider --help
```

## Quick start

```bash
hashcollider algorithms                                   # list algorithms
hashcollider hash --algorithm sha256 --input "hello"      # full digest
hashcollider hash --algorithm sha256 --input "hello" --bits 16   # + first 16 bits
hashcollider collide --algorithm sha256 --bits 16 --generator sequential --length 32
hashcollider verify collision.json                        # recompute and check
hashcollider report collision.json                        # -> reports/collision-report.md
hashcollider benchmark --algorithm sha256 --bits 16 --iterations 100
hashcollider explain collision                            # the theory, in the terminal
```

`python3 -m hashcollider ...` is equivalent to `hashcollider ...`.

## Example collision: SHA-256 truncated to 16 bits

```bash
hashcollider collide --algorithm sha256 --bits 16 --generator sequential --length 32
```

What happens:

1. The **sequential generator** produces 32-byte inputs
   `collision-test-00000000000000001`, `collision-test-00000000000000002`, ...
   (deterministic, so the experiment is reproducible).
2. Each input is hashed with **full SHA-256** (256 bits). Only the **first 16 bits** of the
   digest are kept - an effective hash space of 2^16 = 65,536 values.
3. The **birthday search** remembers every 16-bit value it has seen. When a *different*
   input produces a value already seen, a collision has been found. The birthday bound
   predicts this after about sqrt(2^16) = 256 inputs (expected mean ~ 322); the exact number
   varies from run to run and is a statistical expectation, not a guarantee.
4. The tool prints both inputs, both **full** SHA-256 digests (different) and the
   **truncated** 16-bit values (equal), and saves everything to `collision.json`.

Actual output (the generator is deterministic, so you get the same inputs and digests;
only the timing and hash rate depend on your machine):

```text
HashCollider
----------------------------------------------------------------
Algorithm:      SHA-256 (256-bit digest)
Effective bits: 16 (search space 2^16 = 65,536 values)
Method:         Birthday search
Generator:      sequential (prefix 'collision-test-', start 1, width 17)
Input length:   32 bytes
Limits:         no attempt limit, max 300 s, max 2,000,000 stored digests

Expected effort
  Birthday bound:    sqrt(2^16) = 2^8 ~ 256 attempts
  Expected attempts: ~322 (sqrt(pi/2 * 2^16), mean for the birthday search)
  Memory estimate:   ~47.7 KiB for ~322 stored digests
  These are statistical expectations, not guarantees: a particular search
  may need fewer or more attempts.

Searching for collision... (press Ctrl+C to stop)

Attempts:      292
Time elapsed:  0.000319 seconds
Hashes/sec:    914,500

Collision found
----------------------------------------------------------------
Input A (hex):  636f6c6c6973696f6e2d746573742d3030303030303030303030303030313632
Input A (text): collision-test-00000000000000162
Input B (hex):  636f6c6c6973696f6e2d746573742d3030303030303030303030303030323932
Input B (text): collision-test-00000000000000292

Full hash A:    60a68c9310e65d382a9df70f6cccde231a53ef15db2d26e7c8397f80ee38baee
Full hash B:    60a6b9e7f549cdc29c3a7cb9e5230dd95ad6945b943269c040b4aa4505413d9e
Truncated hash A (first 16 bits): 60a6
Truncated hash B (first 16 bits): 60a6

Result: COLLISION in the 16-bit effective hash space (first 16 bits of SHA-256).
Full SHA-256 digests: DIFFERENT.
A collision was found in the first 16 bits of SHA-256. This does not constitute a collision in the full SHA-256 output.

Saved collision to collision.json
Verify it with:     hashcollider verify collision.json
Create a report:    hashcollider report collision.json
```

Input #292 is the first input whose 16-bit prefix (`60a6`) was already seen, namely for
input #162. The full digests share only their first four hex digits.

In other words: `SHA-256(A)[:16 bits] == SHA-256(B)[:16 bits]` does **not** mean
`SHA-256(A) == SHA-256(B)`. The experiment demonstrates the birthday bound, which applies
to *any* 16-bit hash - it says nothing about the strength of SHA-256 itself.

## Commands

| Command | Purpose |
| --- | --- |
| `hashcollider algorithms` | List supported algorithms, digest sizes, generic collision cost, security status. |
| `hashcollider hash` | Hash `--input TEXT`, `--hex HEX` or `--file PATH` with `--algorithm NAME` (or `all`); `--bits N` also shows the truncated value in hex and binary. |
| `hashcollider collide` | Search for a collision in the first `--bits` bits. Options: `--algorithm`, `--bits`, `--method {birthday,brute-force}`, `--generator {random,sequential,structured}`, `--length`, `--prefix`, `--suffix`, `--start`, `--width`, `--seed`, `--max-attempts`, `--max-seconds`, `--max-stored`, `--force`, `--output`, `--no-save`. |
| `hashcollider verify FILE` | Recompute both digests and check `input_A != input_B` and `truncated(A) == truncated(B)`; prints `Collision verification: PASS` or `FAIL`. |
| `hashcollider report FILE` | Verify and write a Markdown report (default `reports/collision-report.md`; `--output PATH`, `--stdout`). |
| `hashcollider benchmark` | Repeated searches with fresh random inputs: `--algorithm` (repeatable, comma-separated or `all`), `--bits`, `--iterations`, `--input-length`, `--method`, `--seed`, `--raw-hashes`, limits. Prints a comparison table. |
| `hashcollider explain [TOPIC]` | Educational text: `collision` (default), `birthday`, `truncation`, `methods`. |

Global options: `--version`, `-v/--verbose` (debug logging on stderr; accepted before or
after the command). Every command has `--help`.

Exit codes: `0` success, `1` failure (verification failed, file errors), `2` invalid
arguments or unsafe/infeasible configuration, `3` search ended without a collision
(attempt/time limit or exhausted generator), `130` interrupted with Ctrl+C.

Full reference: [docs/usage.md](docs/usage.md). More walkthroughs:
[docs/examples.md](docs/examples.md).

## Safety limits

| Method | Safe default (no `--force`) | Hard limit (always refused above) |
| --- | --- | --- |
| birthday | up to 36 effective bits (~3.3e5 expected attempts) | 64 bits |
| brute-force | up to 24 effective bits (~1.7e7 expected attempts) | 32 bits |

Before every search HashCollider prints the birthday bound sqrt(2^b), the expected number of
attempts and a memory estimate. Defaults: `--max-seconds 300`, `--max-stored 2,000,000`
(both `0` = unlimited).

## Architecture

```text
CLI (cli.py) -> CollisionEngine -> HashAlgorithm / TruncatedHash
                     |          -> InputGenerator
                     v
             Storage (JSON) / Verification / Reports / Benchmark
```

See [docs/architecture.md](docs/architecture.md).

## Theory

Hash functions, preimages, second preimages, collisions, the birthday paradox and why
truncation reduces collision resistance to about 2^(b/2):
[docs/collision-theory.md](docs/collision-theory.md). Algorithm details:
[docs/algorithms.md](docs/algorithms.md). Performance: [docs/performance.md](docs/performance.md).

## Security

HashCollider is intended for **cybersecurity education, cryptographic experimentation and
authorized research**. It contains no exploit payloads, no third-party collision binaries
and no cryptanalytic attack implementations. See [SECURITY.md](SECURITY.md) for
vulnerability reporting and [docs/security.md](docs/security.md) for responsible use.

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

The suite covers every algorithm (standard test vectors), truncation, both search methods,
duplicate rejection, a deterministic 8-bit SHA-256 collision that is verified
independently with `hashlib`, all generators, JSON storage, verification (including forged
files), reports, benchmark statistics, attempt/time limits, Ctrl+C handling (in-process
and, on Linux, with a real `SIGINT`) and CLI error handling. `make lint` runs `ruff`.

## Limitations

- **Full-size collisions are out of reach.** Generic collision search on an n-bit hash
  costs about 2^(n/2) evaluations: 2^64 for MD5, 2^80 for SHA-1, 2^128 for SHA-256. Python
  computes roughly 10^6 hashes per second per core, so HashCollider is practical up to about
  40-48 effective bits for birthday search (memory is the next limit) and about 24-32 bits
  for brute force.
- **Generic attacks only.** Real MD5/SHA-1 collisions come from dedicated cryptanalysis
  (differential attacks). HashCollider does not implement them; its MD5/SHA-1 collisions are
  generic truncated collisions, exactly as easy as for SHA-256 at the same bit length.
- **Single-threaded.** Multiprocessing (`--workers`) is not implemented in 0.1.0; the engine
  is structured so it can be added later (see [CHANGELOG.md](CHANGELOG.md)).
- **Memory.** The birthday search keeps one entry per attempt (roughly 150 bytes each);
  `--max-stored` bounds this at the cost of efficiency.
- Expected attempt counts are averages for an ideal hash; individual runs vary widely.

## License

MIT - see [LICENSE](LICENSE). Contributions welcome: [CONTRIBUTING.md](CONTRIBUTING.md),
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
