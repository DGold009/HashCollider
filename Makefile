# HashCollider developer commands.
# Requires: python3 (3.10+). `make install` installs pytest and ruff from
# requirements-dev.txt; run it inside a virtual environment:
#
#   python3 -m venv .venv && source .venv/bin/activate && make install

PYTHON ?= python3

.PHONY: help install test lint format run clean

help:
	@echo "make install  - install HashCollider (editable) + dev tools (pytest, ruff)"
	@echo "make test     - run the test suite with pytest"
	@echo "make lint     - check code style with ruff"
	@echo "make format   - format code with ruff"
	@echo "make run      - run a small demo collision experiment"
	@echo "make clean    - remove caches, build output and generated files"

install:
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install -e .

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src tests examples

format:
	$(PYTHON) -m ruff format src tests examples
	$(PYTHON) -m ruff check --fix src tests examples

run:
	PYTHONPATH=src $(PYTHON) -m hashcollider collide --algorithm sha256 --bits 16 --generator sequential --length 32
	PYTHONPATH=src $(PYTHON) -m hashcollider verify collision.json
	PYTHONPATH=src $(PYTHON) -m hashcollider report collision.json

clean:
	rm -rf build dist .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -type d -name "*.egg-info" -prune -exec rm -rf {} +
	rm -f collision.json
	rm -rf reports
