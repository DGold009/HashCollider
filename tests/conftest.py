"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:  # allow running tests without installing the package
    sys.path.insert(0, str(SRC))

from hashcollider.generators import InputGenerator  # noqa: E402


class ScriptedGenerator(InputGenerator):
    """Test generator yielding a fixed list of inputs, then optionally raising.

    ``hook(index)`` is called before each item is yielded (e.g. to call
    ``engine.stop()``). If ``repeat`` is given, ``items`` is ignored and the
    same input is yielded ``repeat`` times (``-1`` = forever).
    """

    name = "scripted"

    def __init__(
        self,
        items: list[bytes] | None = None,
        *,
        repeat: bytes | None = None,
        count: int = -1,
        then_raise: BaseException | None = None,
        hook: Callable[[int], None] | None = None,
    ) -> None:
        self.items = list(items or [])
        self.repeat = repeat
        self.count = count
        self.then_raise = then_raise
        self.hook = hook

    def __iter__(self) -> Iterator[bytes]:
        index = 0
        if self.repeat is not None:
            while self.count < 0 or index < self.count:
                if self.hook is not None:
                    self.hook(index)
                yield self.repeat
                index += 1
        else:
            for item in self.items:
                if self.hook is not None:
                    self.hook(index)
                yield item
                index += 1
        if self.then_raise is not None:
            raise self.then_raise


@pytest.fixture
def scripted() -> type[ScriptedGenerator]:
    """The :class:`ScriptedGenerator` class, for building custom input streams."""
    return ScriptedGenerator


@pytest.fixture
def project_root() -> Path:
    return ROOT
