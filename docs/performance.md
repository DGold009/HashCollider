# Performance

## What is measured

| Metric | Meaning |
| --- | --- |
| `hashes_attempted` / "Attempts" | number of inputs hashed by the search (each attempt = one full digest computation) |
| `elapsed_seconds` | search duration measured with `time.perf_counter()` - a monotonic, high-resolution clock. Wall-clock timestamps are only used to label results, never for timing |
| `hashes_per_second` | `attempts / elapsed_seconds` (0 if no measurable time elapsed) |

Two different rates appear in `hashcollider benchmark`:

- **Search H/s** - throughput of the complete search loop: input generation, hashing,
  truncation, dictionary lookup/insertion and limit checks.
- **Raw H/s** - throughput of hashing alone (the same input hashed repeatedly), an upper
  bound for the search rate.

The difference between them is the Python overhead of the search itself.

## Hashes per second

A single CPython thread typically achieves somewhere between a few hundred thousand and a
few million hashes per second for short inputs. The exact figure depends on everything
listed below, so always measure on your own machine:

```bash
hashcollider benchmark --algorithm all --bits 16 --iterations 20
```

## CPU effects

- **Hardware acceleration**: OpenSSL uses SHA extensions (Intel SHA-NI, ARMv8 crypto) when
  present, which can make SHA-1/SHA-256 considerably faster than SHA-512 or SHA-3.
- **64-bit word size**: without SHA-NI, SHA-512 is often faster than SHA-256 per byte on
  x86_64 because it processes 128-byte blocks with 64-bit arithmetic.
- **Frequency scaling and thermal throttling**: laptops and VMs vary between runs; repeat
  benchmarks and compare medians.
- **Virtual machines**: Kali in VirtualBox/VMware may be slower and noisier than bare metal,
  and may not expose SHA-NI to the guest.
- **Single core**: HashCollider 0.1.0 uses one thread. Other load on that core reduces the
  measured rate.
- **Python version**: newer CPython versions have lower interpreter overhead.

## Input length

Hash cost grows with the number of compression-function blocks: 64-byte blocks for MD5,
SHA-1 and SHA-224/256; 128-byte blocks for SHA-384/512; 144/136/104/72-byte rates for
SHA3-224/256/384/512. Inputs up to roughly one block cost about the same; longer inputs cost
proportionally more. For short inputs, Python call overhead dominates and all algorithms look
similar. Try:

```bash
hashcollider benchmark --algorithm sha256 --bits 16 --input-length 16
hashcollider benchmark --algorithm sha256 --bits 16 --input-length 4096
```

## Effective bit length

The effective size `b` does **not** change the cost of one hash - the full digest is always
computed and then truncated. It changes the **number of hashes** needed:

| Method | Expected attempts | Growth per extra bit |
| --- | --- | --- |
| birthday | `sqrt(pi/2 * 2^b) ~ 1.25 * 2^(b/2)` | x1.41 |
| brute-force | `2^b` | x2 |

Every 2 extra bits double the birthday cost; every extra bit doubles the brute-force cost.

## Expected collision attempts

HashCollider prints the expectation before each search, and `hashcollider explain birthday`
prints a full table. These are averages; single searches vary widely (for the birthday
search the standard deviation is about half of the mean). The benchmark's `Obs/Exp` column
compares the observed mean with theory and converges to 1 as the number of iterations grows.

## Memory usage

| Method | Memory |
| --- | --- |
| birthday | one dictionary entry per stored digest: roughly 100-150 bytes of CPython overhead plus the input length |
| brute-force | constant (only the target) |

Approximate birthday memory (32-byte inputs):

| Effective bits | Expected stored entries | Approximate memory |
| --- | --- | --- |
| 16 | ~320 | ~50 KiB |
| 32 | ~82,000 | ~12 MiB |
| 40 | ~1.3 million | ~200 MiB |
| 48 | ~21 million | ~3 GiB |

Safeguards:

- `--max-stored N` (default 2,000,000) caps the dictionary. When full, new digests are no
  longer stored but are still compared against the stored ones, so the search stays correct
  with bounded memory while becoming less efficient.
- The birthday method needs `--force` above 36 bits and is refused above 64 bits.

## Overheads HashCollider avoids

- no external processes or shell commands;
- no per-attempt printing or logging (progress is logged at most every 262,144 attempts
  with `--verbose`);
- limits and stop requests are checked every 1,024 attempts rather than on every hash;
- no serialisation until a result is saved;
- truncated digests are stored as Python integers in a `dict` (O(1) lookup);
- random inputs are drawn from the OS CSPRNG in batches and sliced.

## Future work

Parallel search (`--workers`) and GPU acceleration are not part of 0.1.0; see
[architecture.md](architecture.md#extension-points-future-work).
