"""Plain-ASCII helpers for terminal output (tables, numbers, durations).

Output is deliberately ASCII-only so it renders correctly in any terminal
and locale (including minimal ``LANG=C`` containers).
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from .collision.results import printable_text

__all__ = [
    "describe_bytes",
    "format_bytes",
    "format_count",
    "format_duration",
    "format_long_duration",
    "format_power_of_two",
    "format_rate",
    "format_table",
    "key_values",
    "printable_text",
]


def format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    align: Sequence[str] | None = None,
) -> str:
    """Render a simple aligned text table.

    Args:
        headers: column titles.
        rows: cell strings, one sequence per row.
        align: per-column ``"l"`` or ``"r"`` (default: left).
    """
    columns = len(headers)
    alignment = list(align) if align is not None else ["l"] * columns
    widths = [max([len(headers[i])] + [len(row[i]) for row in rows]) for i in range(columns)]

    def render(cells: Sequence[str]) -> str:
        parts = []
        for i, cell in enumerate(cells):
            parts.append(cell.rjust(widths[i]) if alignment[i] == "r" else cell.ljust(widths[i]))
        return "  ".join(parts).rstrip()

    lines = [render(headers), "  ".join("-" * w for w in widths)]
    lines.extend(render(row) for row in rows)
    return "\n".join(lines)


def key_values(pairs: Sequence[tuple[str, str]], indent: int = 0) -> str:
    """Render ``label: value`` pairs with aligned values."""
    if not pairs:
        return ""
    width = max(len(label) for label, _ in pairs) + 1
    pad = " " * indent
    return "\n".join(f"{pad}{(label + ':').ljust(width)} {value}" for label, value in pairs)


def format_count(value: float) -> str:
    """Format a (possibly huge) count: ``65,536`` or ``3.403e+38``."""
    if value < 1e15:
        return f"{round(value):,}"
    return f"{value:.3e}"


def format_power_of_two(value: float) -> str:
    """Express *value* as a power of two, e.g. ``2^16.0``."""
    if value <= 0:
        return "0"
    return f"2^{math.log2(value):.1f}"


def format_rate(hashes_per_second: float) -> str:
    """Format a hash rate with thousands separators."""
    return f"{hashes_per_second:,.0f}"


def format_duration(seconds: float) -> str:
    """Format a measured duration in seconds."""
    if seconds < 1:
        return f"{seconds:.6f} seconds"
    if seconds < 60:
        return f"{seconds:.4f} seconds"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {secs:04.1f}s ({seconds:.1f} seconds)"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {secs:02.0f}s ({seconds:.0f} seconds)"


def format_long_duration(seconds: float) -> str:
    """Format an *estimated* duration that may be astronomically large."""
    if seconds < 1:
        return "less than a second"
    if seconds < 1.5:
        return "about 1 second"
    if seconds < 120:
        return f"about {seconds:.0f} seconds"
    if seconds < 7200:
        return f"about {seconds / 60:.0f} minutes"
    if seconds < 172_800:
        return f"about {seconds / 3600:.1f} hours"
    days = seconds / 86_400
    if days < 730:
        return f"about {days:.0f} days"
    years = days / 365.25
    if years < 1e6:
        return f"about {years:,.0f} years"
    return f"about {years:.2e} years"


def format_bytes(size: float) -> str:
    """Format a byte count using binary units."""
    value = float(size)
    for unit in ("bytes", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "bytes" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"  # pragma: no cover - unreachable


def describe_bytes(data: bytes, limit: int = 64) -> str:
    """Short human description: quoted text if printable ASCII, else hex."""
    text = printable_text(data)
    if text is not None:
        shown = text if len(text) <= limit else text[:limit] + "..."
        return f'"{shown}"'
    hexed = data.hex()
    if len(hexed) > 2 * limit:
        hexed = hexed[: 2 * limit] + "..."
    return f"hex {hexed}"
