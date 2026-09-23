# Responsible use

HashCollider is intended for:

- **cybersecurity education** - teaching hash functions, collisions and the birthday bound;
- **cryptographic experimentation** - measuring how truncation and output size affect
  collision resistance;
- **authorized research** - on systems and data you own or are explicitly permitted to test.

## What HashCollider is - and is not

HashCollider finds *generic* collisions in *reduced* (truncated) output spaces. Such
collisions are easy for **any** hash function and reveal nothing about the strength of the
full algorithm:

> A collision was found in the first 16 bits of SHA-256. This does not constitute a
> collision in the full SHA-256 output.

HashCollider does **not**:

- break SHA-256, SHA-3 or any other full-size hash - it refuses full-size searches and
  explains why they are infeasible;
- implement cryptanalytic attacks on MD5 or SHA-1 (differential or chosen-prefix
  collision attacks);
- ship collision binaries, exploit payloads or forged certificates;
- contain features for attacking third-party systems.

## Guidelines

1. Only run experiments on systems you own or are explicitly authorized to use. Long
   searches consume CPU and memory; on shared machines, use `--max-seconds`,
   `--max-attempts` and `--max-stored`.
2. Describe results precisely. Always state the effective bit length and that the full
   digests differ. Never present a truncated collision as a break of the full algorithm.
3. Treat MD5 and SHA-1 as broken for security purposes. The warnings HashCollider prints are
   there for a reason: do not use these algorithms for signatures, certificates, integrity
   protection or password storage.
4. Do not use hashes for passwords directly. Use a dedicated password hashing function
   (Argon2id, scrypt, bcrypt, PBKDF2).
5. Do not truncate security-relevant hashes. The lesson of every HashCollider experiment is
   that a *b*-bit hash offers only about 2^(b/2) collision resistance.
6. Seeded randomness (`--seed`) is for reproducible experiments only. It uses Python's
   Mersenne Twister and is not cryptographically secure; the default random generator uses
   the `secrets` module.

## Legal note

Laws and institutional policies on security testing differ between countries and
organisations. You are responsible for ensuring that your use of this tool is lawful and
authorized.

## Reporting vulnerabilities in HashCollider

See [SECURITY.md](../SECURITY.md).
