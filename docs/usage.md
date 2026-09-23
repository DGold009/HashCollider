# Usage

```text
hashcollider [--version] [-v] <command> [options]
python3 -m hashcollider [--version] [-v] <command> [options]
```

`-v/--verbose` enables debug logging on stderr and may appear before or after the command.
Every command supports `--help`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success (collision found, verification passed, ...) |
| 1 | failure: verification failed, collision file missing or invalid, write errors |
| 2 | invalid arguments or an unsafe/infeasible configuration |
| 3 | search ended without a collision (attempt limit, time limit, exhausted generator) |
| 130 | interrupted with Ctrl+C |

## `algorithms`

```bash
hashcollider algorithms
hashcollider algorithms --verbose     # adds a short note per algorithm
```

Lists every algorithm with its digest size, generic collision cost 2^(n/2), security status
and whether it is recommended. Names are case-insensitive and punctuation-insensitive:
`SHA-256`, `sha_256` and `sha256` are the same.

## `hash`

```bash
hashcollider hash --algorithm sha256 --input "hello"
hashcollider hash --algorithm sha256 --input "hello" --bits 16
hashcollider hash --algorithm sha3-256 --hex 68656c6c6f
hashcollider hash --algorithm sha512 --file /etc/hostname
hashcollider hash --algorithm all --input "hello" --bits 8
```

| Option | Description |
| --- | --- |
| `-a, --algorithm NAME` | algorithm or `all` (default `sha256`) |
| `-i, --input TEXT` | text, encoded as UTF-8 |
| `--hex HEX` | raw bytes given as hex |
| `-f, --file PATH` | hash a file's contents |
| `-b, --bits N` | also show the first N bits (hex and binary) |

Exactly one of `--input`, `--hex`, `--file` is required.

## `collide`

```bash
hashcollider collide --algorithm sha256 --bits 16 --generator sequential --length 32
hashcollider collide --algorithm sha256 --bits 16 --generator random --length 32
hashcollider collide --bits 20 --generator random --seed 42        # reproducible, NOT secure
hashcollider collide --bits 24 --generator structured --prefix "exp-" --width 8
hashcollider collide --bits 16 --method brute-force
hashcollider collide --bits 40 --force --max-seconds 120 --max-stored 3000000
```

| Option | Default | Description |
| --- | --- | --- |
| `-a, --algorithm` | `sha256` | hash algorithm |
| `-b, --bits` | `16` | effective (truncated) size in bits, 1 .. digest size |
| `-m, --method` | `birthday` | `birthday` or `brute-force` |
| `-g, --generator` | `sequential` | `random`, `sequential` or `structured` |
| `-l, --length` | see below | input length in bytes |
| `--prefix` | `experiment-` | structured: prefix |
| `--suffix` | none | structured: suffix |
| `--start` | `1` | sequential/structured: first counter value |
| `--width` | see below | sequential/structured: counter digits |
| `--seed` | none | random: reproducible `random.Random` seed (**not cryptographically secure**) |
| `--max-attempts N` | unlimited | stop after N hashes (`0` = unlimited) |
| `--max-seconds S` | `300` | stop after S seconds (`0` = unlimited) |
| `--max-stored N` | `2,000,000` | birthday: max digests kept in memory (`0` = unlimited) |
| `--force` | off | allow sizes above the safe defaults |
| `-o, --output` | `collision.json` | where to save the collision |
| `--no-save` | off | do not write a file |

Length/width rules:

- `random`: `--length` defaults to 32 bytes.
- `sequential`: inputs are `collision-test-` + counter. Without `--length` the counter has
  8 digits (`collision-test-00000001`, 23 bytes). With `--length L` the counter width is
  `L - 15`, so `L` must be at least 16.
- `structured`: `prefix + counter + suffix`; the width defaults to 6, or is derived from
  `--length` when only the length is given.

Options that do not apply to the selected generator are ignored with a warning.

Before searching, `collide` prints the birthday bound sqrt(2^b), the expected number of
attempts for the chosen method and (for birthday) a memory estimate. These are statistical
expectations, not guarantees.

Safety limits:

| Method | Needs `--force` above | Always refused above |
| --- | --- | --- |
| birthday | 36 bits | 64 bits |
| brute-force | 24 bits | 32 bits |

When the birthday search reaches `--max-stored`, it stops storing new digests but keeps
comparing new inputs against the stored ones - still correct, with bounded memory, but
less efficient.

Pressing **Ctrl+C** stops the search and prints:

```text
Search interrupted.
Attempts: ...
Elapsed: ...
Hashes/sec: ...
```

## `verify`

```bash
hashcollider verify collision.json
```

Loads the file, **recomputes** both full digests and the truncated values, and checks:

1. `input_a != input_b`;
2. `truncated(input_a) == truncated(input_b)` (recomputed);
3. stored `hash_a`, `hash_b`, `truncated_hash` and `output_bits` (when present) match the
   recomputed values.

It then reports whether the *full* digests are equal (for truncated demonstrations they are
not) and prints `Collision verification: PASS` (exit 0) or `Collision verification: FAIL`
(exit 1).

## `report`

```bash
hashcollider report collision.json                          # reports/collision-report.md
hashcollider report collision.json --output my-report.md
hashcollider report collision.json --stdout > report.md
```

The report re-verifies the collision and contains experiment information, algorithm and
effective size, input details, collision values, statistics, verification, an explanation,
a security interpretation and limitations. Exit code 1 if verification fails (the report
is still written and says so).

## `benchmark`

```bash
hashcollider benchmark --algorithm sha256 --bits 16 --iterations 100
hashcollider benchmark -a md5 -a sha1 -a sha256 -a sha3-256 --bits 16 --iterations 50
hashcollider benchmark --algorithm all --bits 20 --iterations 10
hashcollider benchmark --bits 12 --method brute-force --iterations 20
```

| Option | Default | Description |
| --- | --- | --- |
| `-a, --algorithm` | `sha256` | repeatable, comma-separated, or `all` |
| `-b, --bits` | `16` | effective size |
| `-n, --iterations` | `20` | searches per algorithm |
| `-l, --input-length` | `32` | random input length |
| `-m, --method` | `birthday` | search method |
| `--seed` | none | base seed; iteration i uses seed + i (not cryptographic) |
| `--raw-hashes N` | `100,000` | hashes for the raw throughput measurement (`0` skips) |
| `--max-attempts`, `--max-seconds`, `--max-stored` | unlimited, `60`, `2,000,000` | per search |
| `--force` | off | allow sizes above safe defaults |

Table columns: runs, runs that found a collision, mean and median attempts (successful
runs), theoretical expectation, observed/expected ratio, mean time per search, search
throughput (including bookkeeping) and raw hashing throughput.

## `explain`

```bash
hashcollider explain              # same as: explain collision
hashcollider explain birthday     # birthday bound and a table of costs
hashcollider explain truncation
hashcollider explain methods
```

## Collision file format (version 1)

```json
{
  "format_version": 1,
  "tool": "hashcollider",
  "tool_version": "0.1.0",
  "algorithm": "sha256",
  "algorithm_display_name": "SHA-256",
  "output_bits": 256,
  "effective_bits": 16,
  "method": "birthday",
  "generator": "sequential",
  "generator_params": {"prefix": "collision-test-", "suffix": "", "start": 1, "width": 17, "length": 32},
  "input_encoding": "hex",
  "input_a": "...",
  "input_b": "...",
  "input_a_text": "collision-test-...",
  "input_b_text": "collision-test-...",
  "input_length_a": 32,
  "input_length_b": 32,
  "hash_a": "...",
  "hash_b": "...",
  "truncated_hash": "...",
  "full_digests_equal": false,
  "attempts": 284,
  "elapsed_seconds": 0.0042,
  "hashes_per_second": 67619.0,
  "timestamp": "2026-01-01T12:00:00+00:00"
}
```

Required fields: `format_version`, `algorithm`, `effective_bits`, `input_a`, `input_b`.
Everything else is optional metadata. `input_encoding` may be `hex` (default) or `utf-8`,
so you can write test files by hand:

```json
{"format_version": 1, "algorithm": "sha256", "effective_bits": 8,
 "input_encoding": "utf-8", "input_a": "hello", "input_b": "world"}
```

## Library API

```python
from hashcollider import CollisionEngine, SequentialGenerator, verify_collision
from hashcollider.storage import save_collision

engine = CollisionEngine("sha256", bits=16, generator=SequentialGenerator(length=32))
print(engine.estimate().expected_attempts)
result = engine.find_collision()          # or: outcome = engine.run()
assert verify_collision(result).passed
save_collision(result, "collision.json")
```
