# Contributing to HashCollider

Thank you for helping improve HashCollider! This project is an educational tool, so
correctness and clear explanations matter more than raw speed.

## Ground rules

- Keep the project **educational and responsible**: no exploit payloads, no third-party
  collision binaries, no tooling aimed at attacking third-party systems (see
  [docs/security.md](docs/security.md)).
- Be **cryptographically precise**. Never describe a truncated collision as a collision of
  the full algorithm. "A collision was found in the first 16 bits of SHA-256" is correct;
  "SHA-256 is broken" is not.
- Keep runtime dependencies at **zero** (standard library only) unless there is a strong,
  documented reason.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Forking and setting up

1. Fork the repository on GitHub and clone your fork:

   ```bash
   git clone <your-fork-url>
   cd HashCollider
   python3 -m venv .venv
   source .venv/bin/activate
   make install          # pip install -r requirements-dev.txt && pip install -e .
   ```

2. Add the original repository as `upstream` so you can keep your fork current:

   ```bash
   git remote add upstream <original-repository-url>
   git fetch upstream
   ```

## Branches

- `main` is always releasable; never commit to it directly in your fork's pull requests.
- Create one branch per change, named after its purpose:
  - `feature/<short-name>` for new functionality,
  - `fix/<short-name>` for bug fixes,
  - `docs/<short-name>` for documentation-only changes.
- Rebase on `upstream/main` before opening a pull request.

## Testing

Every change must keep the test suite green:

```bash
make test        # or: pytest
make lint        # ruff check
make format      # ruff format + safe autofixes
```

- Add tests for new behaviour and for every fixed bug (a test that fails without the fix).
- Collision tests must be **deterministic** (use the sequential/structured generators or
  `SeededRandomGenerator`) and must verify results independently with `hashlib`. Never
  hard-code a collision you have not verified.
- Keep tests fast: prefer small effective sizes (8-16 bits).
- Tests must pass on Linux (the project targets Kali Linux). Platform-specific tests must be
  skipped cleanly elsewhere.

## Code style

- Python 3.10+, type hints on all public functions, docstrings for public APIs.
- `ruff` enforces formatting and lint rules (configuration in `pyproject.toml`,
  line length 100).
- Prefer `dataclasses`, `pathlib.Path`, and the exception classes in
  `src/hashcollider/errors.py`. User-facing errors must derive from `HashColliderError`
  so the CLI can print them without a stack trace.
- No global mutable state, no shell commands, no hard-coded paths.
- Keep the search hot loops free of per-attempt logging, printing or serialisation.
- CLI output is plain ASCII.

## Pull requests

1. Keep pull requests focused - one logical change each.
2. Describe *what* changed and *why*; link related issues.
3. Update documentation (`README.md`, `docs/`) and `CHANGELOG.md` (under an
   "Unreleased" heading) when behaviour changes.
4. Confirm that `make test` and `make lint` pass.
5. Be ready to iterate on review feedback.

## Reporting issues

Open a GitHub issue and include:

- HashCollider version (`hashcollider --version`), Python version (`python3 --version`) and
  OS (e.g. `cat /etc/os-release`);
- the exact command you ran and the full output;
- what you expected to happen.

Please **do not** report security vulnerabilities in public issues - follow
[SECURITY.md](SECURITY.md) instead.
