# Installation

## Requirements

| Requirement | Notes |
| --- | --- |
| Kali Linux (rolling) or another Linux distribution | macOS and Windows also work for the pure-Python parts, but Linux is the supported target |
| Python 3.10+ | Kali ships a current Python 3: check with `python3 --version` |
| `python3-venv` | needed for virtual environments |
| `git` | to clone the repository |
| `make` (optional) | for the Makefile shortcuts |

Install the system packages on Kali if they are missing:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git make
```

## Install in a virtual environment (recommended)

Kali marks the system Python as "externally managed" (PEP 668), so `pip install` outside a
virtual environment is refused. Use a venv:

```bash
git clone https://github.com/DGold009/HashCollider.git
cd HashCollider                     # case-sensitive: the clone folder is "HashCollider"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt     # no packages: HashCollider uses only the stdlib
pip install -e .                    # editable install, provides the `hashcollider` command
```

Check the installation:

```bash
hashcollider --version
hashcollider algorithms
python3 -m hashcollider --help
```

### Non-editable install

```bash
pip install .
```

### Development tools

```bash
pip install -r requirements-dev.txt   # pytest, ruff
# or
make install                          # requirements-dev.txt + editable install
pytest
```

## Run without installing

From the repository root:

```bash
PYTHONPATH=src python3 -m hashcollider algorithms
```

The example scripts in `examples/` also work without installation; they add `src/` to the
import path automatically.

## Using pipx (optional)

To get a global `hashcollider` command without activating a venv:

```bash
sudo apt install -y pipx
pipx install .
```

## Uninstall

```bash
pip uninstall hashcollider
deactivate
rm -rf .venv
```

See [troubleshooting.md](troubleshooting.md) for common problems.
