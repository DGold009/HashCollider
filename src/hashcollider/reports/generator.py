"""Markdown report generation for collision records."""

from __future__ import annotations

import math
from pathlib import Path

from .._version import __version__
from ..collision.birthday import expected_birthday_attempts
from ..collision.engine import get_strategy
from ..collision.results import CollisionResult, printable_text, utc_timestamp
from ..collision.verify import VerificationResult
from ..errors import ConfigurationError, StorageError
from ..formatting import format_count, format_rate

_NOT_RECORDED = "_not recorded_"


def _code(value: str) -> str:
    return f"`{value}`"


def _fmt_opt(value: object, fmt: str = "{}") -> str:
    return _NOT_RECORDED if value is None else fmt.format(value)


def _table(rows: list[tuple[str, str]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(f"| {name} | {value} |" for name, value in rows)
    return "\n".join(lines)


def headline(verification: VerificationResult) -> str:
    """One-paragraph, cryptographically precise summary of a verified record."""
    name = verification.algorithm_display_name
    bits = verification.effective_bits
    if not verification.passed:
        return (
            "**Verification FAILED.** This file does not describe a valid collision "
            f"in the selected {bits}-bit output space of {name}. See the verification "
            "section for details."
        )
    if verification.is_truncated and not verification.full_digests_equal:
        return (
            f"A collision was found in the first {bits} bits of {name}. This does not "
            f"constitute a collision in the full {name} output. Only the selected "
            f"truncated output space was searched. The full {name} digests remain different."
        )
    if verification.is_truncated:
        return (
            f"The two inputs collide in the first {bits} bits of {name}, and their full "
            f"{verification.output_bits}-bit digests are also identical, i.e. this pair is "
            f"a full {name} collision. Such pairs are not produced by HashCollider's "
            "generic truncated searches; they come from dedicated cryptanalysis."
        )
    return (
        f"The two inputs have identical full {verification.output_bits}-bit {name} digests: "
        f"this is a collision in the complete {name} output. HashCollider's generic search "
        "cannot produce such a pair for full-size digests; it must come from an external "
        "source (for MD5/SHA-1: published cryptanalytic attacks)."
    )


def generate_report(
    record: CollisionResult,
    verification: VerificationResult,
    *,
    source: str | Path | None = None,
) -> str:
    """Return a Markdown report describing *record* and its verification."""
    name = verification.algorithm_display_name
    bits = verification.effective_bits
    output_bits = verification.output_bits
    space = 1 << bits
    method = record.method or "birthday"
    try:
        strategy = get_strategy(method)
    except ConfigurationError:
        strategy = get_strategy("birthday")
    expected = strategy.expected_attempts(bits)
    birthday = 2.0 ** (bits / 2)

    sections: list[str] = []
    sections.append("# HashCollider Collision Report")
    sections.append(
        _table(
            [
                ("Report generated (UTC)", utc_timestamp()),
                ("HashCollider version", __version__),
                ("Source file", _code(str(source)) if source is not None else _NOT_RECORDED),
                ("Verification", "**PASS**" if verification.passed else "**FAIL**"),
            ]
        )
    )
    sections.append("## Summary\n\n" + headline(verification))

    # 1. Experiment information
    params = record.generator_params or {}
    param_text = ", ".join(f"{k}={v}" for k, v in params.items()) if params else _NOT_RECORDED
    sections.append(
        "## 1. Experiment information\n\n"
        + _table(
            [
                ("Search method", f"{strategy.title} (`{strategy.name}`)"),
                ("Generator", _fmt_opt(record.generator, "`{}`")),
                ("Generator parameters", param_text),
                ("Experiment timestamp (UTC)", _fmt_opt(record.timestamp)),
                ("Recorded with HashCollider", _fmt_opt(record.tool_version)),
            ]
        )
    )

    # 2. Algorithm and effective size
    sections.append(
        "## 2. Algorithm and effective hash size\n\n"
        + _table(
            [
                ("Algorithm", f"{name} (`{record.algorithm}`)"),
                ("Full digest size", f"{output_bits} bits"),
                ("Effective (searched) size", f"{bits} bits"),
                ("Effective output space", f"2^{bits} = {format_count(space)} values"),
                (
                    "Birthday bound sqrt(2^b)",
                    f"2^{bits / 2:g} ~ {format_count(birthday)} attempts",
                ),
                (
                    f"Expected attempts ({strategy.name})",
                    f"~{format_count(expected)} (2^{math.log2(expected):.2f})",
                ),
            ]
        )
    )

    # 3. Inputs
    input_rows: list[tuple[str, str]] = []
    for label, data in (("A", record.input_a), ("B", record.input_b)):
        text = printable_text(data)
        input_rows.append((f"Input {label} (hex)", _code(data.hex()) if data else "_empty_"))
        input_rows.append(
            (f"Input {label} (text)", _code(text) if text else "_not printable ASCII_")
        )
        input_rows.append((f"Input {label} length", f"{len(data)} bytes"))
    input_rows.append(("Inputs different", "yes" if record.input_a != record.input_b else "**NO**"))
    sections.append("## 3. Input details\n\n" + _table(input_rows))

    # 4. Collision values
    equal_truncated = verification.recomputed_truncated_a == verification.recomputed_truncated_b
    sections.append(
        "## 4. Collision values (recomputed)\n\n"
        + _table(
            [
                (f"Full {name}(A)", _code(verification.recomputed_hash_a)),
                (f"Full {name}(B)", _code(verification.recomputed_hash_b)),
                (f"First {bits} bits of {name}(A)", _code(verification.recomputed_truncated_a)),
                (f"First {bits} bits of {name}(B)", _code(verification.recomputed_truncated_b)),
                (f"Truncated ({bits}-bit) values equal", "yes" if equal_truncated else "**NO**"),
                (
                    "Full digests equal",
                    "yes" if verification.full_digests_equal else "no (expected)",
                ),
            ]
        )
    )

    # 5. Statistics
    stats_rows = [
        ("Attempts (hash evaluations)", _fmt_opt(record.attempts, "{:,}")),
        ("Execution time", _fmt_opt(record.elapsed_seconds, "{:.6f} seconds")),
        (
            "Hash rate",
            _NOT_RECORDED
            if record.hashes_per_second is None
            else f"{format_rate(record.hashes_per_second)} hashes/second",
        ),
    ]
    if record.attempts:
        stats_rows.append(("Attempts / expected", f"{record.attempts / expected:.2f}"))
        stats_rows.append(
            (
                "Probability of success within this many attempts",
                f"{strategy.success_probability(record.attempts, bits):.1%}",
            )
        )
    sections.append(
        "## 5. Search statistics\n\n"
        + _table(stats_rows)
        + "\n\nTiming uses a monotonic high-resolution clock (`time.perf_counter`). "
        "Hash rates include the bookkeeping of the search loop, not just raw hashing."
    )

    # 6. Verification
    check_lines = [
        f"- [{'x' if check.passed else ' '}] {check.description}"
        + (f" ({check.detail})" if check.detail else "")
        for check in verification.checks
    ]
    sections.append(
        "## 6. Verification\n\n"
        "Both inputs were re-hashed while generating this report; stored hash values "
        "were **not** trusted.\n\n"
        + "\n".join(check_lines)
        + f"\n\n**Collision verification: {'PASS' if verification.passed else 'FAIL'}**"
    )

    # 7. Why it occurred
    sections.append(
        "## 7. Why the collision occurred\n\n"
        f"Only the first {bits} bits of each {name} digest were compared, so every input "
        f"is mapped into a space of just 2^{bits} = {format_count(space)} possible values. "
        "By the pigeonhole principle, any "
        f"{format_count(space + 1)} distinct inputs must contain a collision, and by the "
        "birthday paradox a collision is *expected* much earlier: after about "
        f"sqrt(pi/2 * 2^{bits}) ~ {format_count(expected_birthday_attempts(bits))} "
        "random inputs when every previously seen digest is remembered (birthday search), "
        f"or about 2^{bits} inputs when searching for a match to one fixed target "
        "(brute-force search).\n\n"
        f"Nothing about {name} itself was exploited: the same experiment works for any hash "
        "function, because it relies only on the small size of the searched output space."
    )

    # 8. Security interpretation
    interpretation = [headline(verification)]
    if verification.passed and verification.is_truncated and not verification.full_digests_equal:
        interpretation.append(
            f"Finding `{name}(A)[:{bits} bits] == {name}(B)[:{bits} bits]` does **not** mean "
            f"`{name}(A) == {name}(B)`. A generic collision search on the full {output_bits}-bit "
            f"output would need about 2^{output_bits // 2} hash evaluations, which is "
            "computationally infeasible."
        )
    if record.algorithm in ("md5", "sha1"):
        interpretation.append(
            f"{name} is considered cryptographically broken because dedicated attacks find "
            "full-size collisions far faster than the generic birthday bound. This report "
            f"does **not** demonstrate those attacks: it shows a generic collision in a reduced "
            f"output space, which would be just as easy for any {bits}-bit hash."
        )
    else:
        interpretation.append(
            f"No practical collision attack against full {name} is publicly known. This "
            "experiment does not change that assessment."
        )
    interpretation.append(
        "Practical takeaway: truncating a hash to *b* bits reduces its collision resistance to "
        "about 2^(b/2). Systems that store or compare short hash prefixes (short IDs, "
        "truncated fingerprints) inherit exactly this weakness."
    )
    sections.append("## 8. Security interpretation\n\n" + "\n\n".join(interpretation))

    # 9. Limitations
    sections.append(
        "## 9. Limitations\n\n"
        "- Only the selected truncated output space was searched; nothing is claimed about "
        "the full digest.\n"
        "- Expected attempt counts are statistical expectations for an ideal hash, not "
        "guarantees; individual runs vary widely.\n"
        "- Hash rates depend on the CPU, Python version, OpenSSL build, input length and "
        "system load, and are single-threaded.\n"
        "- The birthday search stores digests in memory; with a `max_stored` limit it stays "
        "correct but becomes less efficient once the limit is reached.\n"
        "- HashCollider implements generic searches only. It does not implement "
        "cryptanalytic attacks on MD5, SHA-1 or any other algorithm."
    )

    sections.append(
        "---\n\n_Generated by HashCollider for cybersecurity education, cryptographic "
        "experimentation and authorized research._"
    )
    return "\n\n".join(sections) + "\n"


def write_report(markdown: str, path: str | Path) -> Path:
    """Write *markdown* to *path* (creating parent directories) and return the path."""
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(markdown, encoding="utf-8")
    except OSError as exc:
        raise StorageError(f"Could not write report {target}: {exc.strerror or exc}") from exc
    return target
