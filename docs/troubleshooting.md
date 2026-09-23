# Troubleshooting

## Python version problems

HashCollider needs Python 3.10 or newer.

```bash
python3 --version
```

- `ERROR: Package 'hashcollider' requires a different Python` - your `python3` is older than
  3.10. Update Kali (`sudo apt update && sudo apt full-upgrade`) or install a newer Python.
- `SyntaxError` mentioning `|` in type hints - you are running Python < 3.10.
- Make sure the virtual environment was created with the right interpreter:
  `.venv/bin/python --version`.

## Permission problems

- `error: externally-managed-environment` - Kali protects the system Python (PEP 668). Do
  not use `sudo pip`; create a virtual environment instead (see below) or use `pipx`.
- `Permission denied` when writing `collision.json` or `reports/` - run the command in a
  directory you own (e.g. your home directory or the repository), or choose another location
  with `--output`.
- Never run HashCollider with `sudo`; it needs no privileges.

## Virtual environments

```bash
sudo apt install -y python3-venv     # if "ensurepip is not available"
python3 -m venv .venv
source .venv/bin/activate            # bash/zsh; for fish: source .venv/bin/activate.fish
which python                         # should point into .venv/
```

- Forgot to activate? The prompt shows `(.venv)` when active. Re-run `source .venv/bin/activate`
  in every new terminal.
- Broken venv after a Python upgrade: `rm -rf .venv` and recreate it.
- `The virtual environment was not created successfully because ensurepip is not available`:
  install `python3-venv`, then delete the half-created folder (`rm -rf .venv`) and run
  `python3 -m venv .venv` again.

## Package installation

- `cd: no such file or directory: hashcollider` - the repository clones into `HashCollider`
  and Linux paths are case-sensitive: `cd HashCollider`. If that `cd` failed, the following
  commands ran in the wrong directory, which causes the next two errors.
- `Could not open requirements file` or `... does not appear to be a Python project` - you
  are not in the repository folder. `cd` into it (`ls` should show `pyproject.toml`).

- `pip install -e .` fails with an old pip/setuptools: upgrade them inside the venv:
  `python -m pip install --upgrade pip setuptools`.
- Offline machine: HashCollider has no runtime dependencies, but building needs `setuptools`
  (normally downloaded automatically). Alternatively run without installing:
  `PYTHONPATH=src python3 -m hashcollider ...`.
- `pip install -r requirements.txt` installs nothing - that is expected; the file only
  documents that there are no runtime dependencies.

## pytest failures

- `pytest: command not found` - install the dev requirements in the active venv:
  `pip install -r requirements-dev.txt`, or use `python -m pytest`.
- `ModuleNotFoundError: No module named 'hashcollider'` - run pytest from the repository root
  (the configuration in `pyproject.toml` adds `src/` to the path) or install the package with
  `pip install -e .`.
- Run a single test verbosely: `pytest tests/test_collision.py -k keyboard -vv`.
- The Ctrl+C test sends a real `SIGINT` to a child process and is skipped on Windows.
  On a heavily loaded machine it may take a few seconds.
- Please report reproducible failures with the full output (see
  [CONTRIBUTING.md](../CONTRIBUTING.md#reporting-issues)).

## `hashcollider: command not found`

- Activate the virtual environment where you installed it: `source .venv/bin/activate`.
- Check the installation: `pip show hashcollider`.
- If installed with `pip install --user`, make sure `~/.local/bin` is on your `PATH`.
- You can always use `python3 -m hashcollider` instead.

## Error messages

| Message | Meaning / fix |
| --- | --- |
| `Unsupported algorithm: ...` | run `hashcollider algorithms` for valid names |
| `Invalid bit length: ...` | `--bits` must be between 1 and the digest size |
| `Input length must be positive` | `--length` / `--input-length` must be >= 1 |
| `... is too short for the sequential generator` | sequential inputs need at least 16 bytes (`collision-test-` is 15) |
| `... exceeds the safe default ... --force` | the search is large; add `--force` (and limits) if intended |
| `... computationally infeasible` | reduce `--bits`; full-size searches are always refused |
| `Maximum attempt limit reached` | raise `--max-attempts` (0 = unlimited) |
| `Maximum execution time reached` | raise `--max-seconds` (0 = unlimited) |
| `Input generator exhausted ...` | use a larger `--length`/`--width` or the random generator |
| `Collision file does not exist: ...` | check the path passed to `verify`/`report` |
| `Collision verification failed` | the file is not a valid collision (or was modified) |

Add `--verbose` to any command for debug logging (including the internal traceback of an
error).

## Slow performance

- Expected attempts grow as `2^(b/2)` (birthday) or `2^b` (brute force): +2 bits doubles the
  birthday cost. Check the estimate printed before the search.
- Use the `birthday` method for anything above ~20 bits; brute force is intentionally slow.
- Shorter inputs hash faster (`--length 16`).
- Virtual machines and power-saving modes reduce throughput; plug in laptops and close other
  CPU-heavy programs.
- `--verbose` itself is cheap, but printing progress to a slow terminal is not; redirect
  stderr to a file for long runs.
- Very large birthday searches become memory-bound; watch memory with `htop` and use
  `--max-stored`.
