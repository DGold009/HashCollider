# Supported algorithms

All algorithms are provided by Python's [`hashlib`](https://docs.python.org/3/library/hashlib.html)
module. On Kali Linux, CPython's `hashlib` uses OpenSSL for these algorithms (CPython also
ships built-in fallback implementations). No third-party packages are involved.

"Generic collision cost" is the birthday bound 2^(n/2) for an ideal n-bit hash. It is the
best any hash of that size can offer against collision search.

| Name | Digest | Family | Generic collision cost | Status | Recommended |
| --- | --- | --- | --- | --- | --- |
| `md5` | 128 bits | MD5 | 2^64 | broken (practical collisions) | **no** |
| `sha1` | 160 bits | SHA-1 | 2^80 | broken (practical collisions) | **no** |
| `sha224` | 224 bits | SHA-2 | 2^112 | secure | yes |
| `sha256` | 256 bits | SHA-2 | 2^128 | secure | yes |
| `sha384` | 384 bits | SHA-2 | 2^192 | secure | yes |
| `sha512` | 512 bits | SHA-2 | 2^256 | secure | yes |
| `sha3-224` | 224 bits | SHA-3 | 2^112 | secure | yes |
| `sha3-256` | 256 bits | SHA-3 | 2^128 | secure | yes |
| `sha3-384` | 384 bits | SHA-3 | 2^192 | secure | yes |
| `sha3-512` | 512 bits | SHA-3 | 2^256 | secure | yes |

Any of them can be truncated with `--bits N` (1 <= N <= digest size). A truncated algorithm
has a generic collision cost of about 2^(N/2) - regardless of which algorithm is truncated.

---

## MD5

- **Digest size:** 128 bits
- **General purpose:** designed (1992) as a general-purpose cryptographic hash; today seen
  mostly in legacy checksums and non-security deduplication.
- **Security status:** **broken for collision resistance.** Practical collisions were
  published in 2004 (Wang et al.); chosen-prefix collisions followed (Stevens et al.,
  2007) and were used in real attacks, including a rogue CA certificate (2008) and the
  Flame malware (2012). Collisions can be computed in seconds on ordinary hardware.
  No practical preimage attack is known, but that does not make it safe to use.
- **Python implementation:** `hashlib.md5` (retried with `usedforsecurity=False` on
  FIPS-restricted builds).
- **Recommended for modern security applications:** **No.**

## SHA-1

- **Digest size:** 160 bits
- **General purpose:** formerly the standard hash for signatures, certificates and TLS; still
  found in legacy systems and historically in Git object IDs.
- **Security status:** **broken for collision resistance.** First public collision in 2017
  (SHAttered, Stevens et al.); a practical chosen-prefix collision in 2020 (Leurent &
  Peyrin, "SHA-1 is a Shambles"). NIST has deprecated SHA-1 for digital signatures and plans
  to retire it completely.
- **Python implementation:** `hashlib.sha1`.
- **Recommended for modern security applications:** **No.**

## SHA-224

- **Digest size:** 224 bits
- **General purpose:** SHA-2 variant (FIPS 180-4) computed like SHA-256 with a different
  initial value and a truncated output.
- **Security status:** no practical attacks; 112-bit generic collision security.
- **Python implementation:** `hashlib.sha224`.
- **Recommended:** Yes (acceptable), although SHA-256 or larger is usually preferred.

## SHA-256

- **Digest size:** 256 bits
- **General purpose:** the most widely deployed modern hash (TLS, code signing, package
  managers, blockchains, HMAC-SHA-256, ...).
- **Security status:** no practical collision, preimage or second-preimage attacks;
  128-bit generic collision security. Like all Merkle-Damgard hashes it allows length-extension
  of `H(secret || message)` - use HMAC for keyed hashing.
- **Python implementation:** `hashlib.sha256`.
- **Recommended:** Yes.

## SHA-384

- **Digest size:** 384 bits
- **General purpose:** SHA-512 computed with a different initial value and truncated output;
  common in high-assurance TLS configurations.
- **Security status:** no practical attacks; 192-bit generic collision security; resistant to
  length extension because the output is truncated.
- **Python implementation:** `hashlib.sha384`.
- **Recommended:** Yes.

## SHA-512

- **Digest size:** 512 bits
- **General purpose:** 64-bit-word SHA-2 variant, often faster than SHA-256 on 64-bit CPUs
  without SHA-256 hardware acceleration.
- **Security status:** no practical attacks; 256-bit generic collision security (use HMAC for
  keyed hashing because of length extension).
- **Python implementation:** `hashlib.sha512`.
- **Recommended:** Yes.

## SHA3-224, SHA3-256, SHA3-384, SHA3-512

- **Digest sizes:** 224, 256, 384, 512 bits
- **General purpose:** SHA-3 (FIPS 202, 2015) based on the Keccak sponge construction - a
  design completely different from SHA-2, standardised as a diverse alternative.
- **Security status:** no practical attacks; generic collision security of half the digest
  size; not vulnerable to length extension.
- **Python implementation:** `hashlib.sha3_224`, `hashlib.sha3_256`, `hashlib.sha3_384`,
  `hashlib.sha3_512`.
- **Recommended:** Yes.

---

## What HashCollider shows for MD5 and SHA-1

When you select MD5 or SHA-1, HashCollider prints an educational warning. Note that any
collision the tool finds for them is a **generic** collision in a **truncated** output
space. It is found exactly as quickly as for SHA-256 at the same effective size and is
**not** a cryptanalytic MD5/SHA-1 collision. HashCollider does not implement the published
MD5/SHA-1 attacks and does not ship collision payloads. The `verify` command can, however,
verify externally supplied full-size collision pairs (with `effective_bits` equal to the
digest size), because verification simply recomputes the digests.

## Adding an algorithm

```python
from hashcollider.hashing import AlgorithmInfo, AlgorithmRegistry

registry = AlgorithmRegistry()
registry.register(
    AlgorithmInfo("blake2b", "BLAKE2b-512", "blake2b", 512, "BLAKE2", "secure", True)
)
algorithm = registry.get("blake2b")
```

For hash functions not in `hashlib`, subclass `HashAlgorithm` and implement `name`,
`display_name`, `output_bits` and `digest()`.
