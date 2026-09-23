# Examples

All commands assume an activated virtual environment with HashCollider installed
(`pip install -e .`). Replace `hashcollider` with `python3 -m hashcollider` if you prefer.

## 1. Hash a string and look at truncated values

```bash
hashcollider hash --algorithm sha256 --input "hello" --bits 16
```

The full SHA-256 digest of `hello` is
`2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`; its first 16 bits are
`2cf2` (binary `0010110011110010`). Compare all algorithms at once:

```bash
hashcollider hash --algorithm all --input "hello" --bits 16
```

## 2. The standard workflow

```bash
hashcollider collide --algorithm sha256 --bits 16 --generator sequential --length 32
hashcollider verify collision.json
hashcollider report collision.json
less reports/collision-report.md
```

The sequential generator is deterministic, so this experiment produces the same collision on
every machine. The verify step recomputes everything; the report explains the result and why
it is **not** a collision of full SHA-256.

## 3. Watch the birthday bound grow

```bash
for b in 8 12 16 20 24 28 32; do
  hashcollider collide --bits "$b" --generator random --no-save | grep -E "Effective bits|Attempts:"
done
```

Each +4 bits multiplies the expected attempts by about 4 (the cost grows like 2^(b/2)).

## 4. Birthday vs. brute force

```bash
hashcollider collide --bits 16 --method birthday    --no-save
hashcollider collide --bits 16 --method brute-force --no-save
hashcollider benchmark --bits 12 --iterations 30 --method birthday
hashcollider benchmark --bits 12 --iterations 30 --method brute-force
```

Birthday search needs a few hundred attempts at 16 bits; fixed-target brute force needs tens
of thousands (~2^16).

## 5. Reproducible random experiments

```bash
hashcollider collide --bits 24 --generator random --length 16 --seed 1337 -o seeded.json
hashcollider collide --bits 24 --generator random --length 16 --seed 1337 -o seeded2.json
```

Both runs find the same pair. The seeded generator uses Python's Mersenne Twister and is
**not cryptographically secure** - HashCollider prints a warning. Without `--seed`, inputs
come from the `secrets` module.

## 6. Structured inputs

```bash
hashcollider collide --bits 20 --generator structured --prefix "invoice-" --suffix ".pdf" --width 8
```

Inputs look like `invoice-00000001.pdf`, `invoice-00000002.pdf`, ... - useful to show that
meaningful-looking inputs collide just as easily in a small output space.

## 7. Compare algorithms

```bash
hashcollider benchmark --algorithm md5 --algorithm sha1 --algorithm sha256 --algorithm sha3-256 \
    --bits 16 --iterations 50
hashcollider benchmark --algorithm all --bits 20 --iterations 10
```

The attempt counts are statistically the same for every algorithm (they depend only on the
effective size); the hash rates differ.

## 8. Limits and interruption

```bash
hashcollider collide --bits 32 --max-attempts 1000          # stops, exit code 3
hashcollider collide --bits 40 --force --max-seconds 10     # stops after 10 s unless lucky
hashcollider collide --bits 48 --force --max-stored 500000  # bounded memory; Ctrl+C to stop
hashcollider collide --bits 256                             # refused: infeasible
```

Press Ctrl+C during a long search: the tool prints `Search interrupted.` with the attempts,
elapsed time and hash rate collected so far, and exits with code 130.

## 9. Verify a hand-written or tampered file

```bash
cat > pair.json <<'EOF'
{"format_version": 1, "algorithm": "sha256", "effective_bits": 8,
 "input_encoding": "utf-8", "input_a": "hello", "input_b": "world"}
EOF
hashcollider verify pair.json      # FAIL unless the first 8 bits really match
```

Editing `input_b` or any stored hash in a real `collision.json` makes verification fail,
because every value is recomputed.

## 10. Learn the theory

```bash
hashcollider explain collision
hashcollider explain birthday
hashcollider explain truncation
hashcollider explain methods
```

## Python examples

The `examples/` directory contains scripts that use the library API directly (they also run
without installation):

```bash
python3 examples/basic_collision.py    # find + verify a 16-bit SHA-256 collision
python3 examples/birthday_attack.py    # observed vs. theoretical attempts for several sizes
python3 examples/benchmark.py          # compare algorithms
```
