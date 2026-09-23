"""Command-line interface for HashCollider (argparse, standard library only).

Commands::

    hashcollider algorithms
    hashcollider hash       --algorithm sha256 --input "hello" [--bits 16]
    hashcollider collide    --algorithm sha256 --bits 16 --generator sequential
    hashcollider verify     collision.json
    hashcollider report     collision.json
    hashcollider benchmark  --algorithm sha256 --bits 16 --iterations 100
    hashcollider explain    collision
"""

from __future__ import annotations

import argparse
import logging
import math
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from ._version import __version__
from .benchmark import BenchmarkConfig, BenchmarkRunner, benchmark_table
from .collision import (
    METHOD_NAMES,
    CollisionEngine,
    CollisionResult,
    SearchEstimate,
    SearchStatistics,
    SearchStatus,
    verify_collision,
)
from .collision.verify import VerificationResult
from .config import (
    BENCHMARK_DEFAULT_ITERATIONS,
    BENCHMARK_DEFAULT_MAX_SECONDS,
    BENCHMARK_DEFAULT_RAW_HASHES,
    DEFAULT_ALGORITHM,
    DEFAULT_BITS,
    DEFAULT_GENERATOR,
    DEFAULT_MAX_SECONDS,
    DEFAULT_MAX_STORED,
    DEFAULT_METHOD,
    DEFAULT_OUTPUT_FILE,
    DEFAULT_RANDOM_LENGTH,
    DEFAULT_REPORT_FILE,
    EXIT_FAILURE,
    EXIT_INTERRUPTED,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_USAGE,
    MAX_INPUT_LENGTH,
)
from .errors import HashColliderError, InvalidInputError
from .explain import TOPICS, explain
from .formatting import (
    describe_bytes,
    format_bytes,
    format_count,
    format_duration,
    format_power_of_two,
    format_rate,
    format_table,
    key_values,
    printable_text,
)
from .generators import GENERATOR_NAMES, SEEDED_WARNING, create_generator, ignored_options
from .hashing import AlgorithmRegistry, HashAlgorithm, TruncatedHash, validate_bits
from .reports import generate_report, write_report
from .storage import load_collision, save_collision

logger = logging.getLogger(__name__)

PROG = "hashcollider"
BANNER = "HashCollider"
RULE = "-" * 64

_EXIT_CODES_HELP = """\
exit codes:
  0    success (collision found / verification passed)
  1    failure (verification failed, file errors)
  2    invalid arguments or unsafe/infeasible configuration
  3    search ended without a collision (attempt/time limit, generator exhausted)
  130  interrupted with Ctrl+C
"""

_DESCRIPTION = """\
HashCollider - an educational hash collision research tool.

Demonstrates collisions in REDUCED (truncated) hash output spaces, e.g. the
first 16 bits of SHA-256. A collision in a truncated output space is NOT a
collision in the full algorithm: the full digests remain different.
"""

_EPILOG = (
    """\
examples:
  hashcollider algorithms
  hashcollider hash --algorithm sha256 --input "hello" --bits 16
  hashcollider collide --algorithm sha256 --bits 16 --generator sequential --length 32
  hashcollider verify collision.json
  hashcollider report collision.json
  hashcollider benchmark --algorithm sha256 --algorithm md5 --bits 16 --iterations 100
  hashcollider explain collision

"""
    + _EXIT_CODES_HELP
)


# ---------------------------------------------------------------------------
# argparse value types
# ---------------------------------------------------------------------------


def _int_value(text: str) -> int:
    try:
        return int(text, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {text!r}") from None


def _positive_int(text: str) -> int:
    value = _int_value(text)
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive integer, got {value}")
    return value


def _non_negative_int(text: str) -> int:
    value = _int_value(text)
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be zero or a positive integer, got {value}")
    return value


def _non_negative_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {text!r}") from None
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError(f"must be zero or a positive number, got {text}")
    return value


def _bits_value(text: str) -> int:
    value = _int_value(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"Invalid bit length: {value} (must be at least 1)")
    return value


def _length_value(text: str) -> int:
    value = _int_value(text)
    if value <= 0:
        raise argparse.ArgumentTypeError(f"Input length must be positive (got {value})")
    if value > MAX_INPUT_LENGTH:
        raise argparse.ArgumentTypeError(
            f"Input length {value} exceeds the maximum of {MAX_INPUT_LENGTH} bytes"
        )
    return value


def _method_value(text: str) -> str:
    key = text.strip().lower().replace("_", "-")
    if key == "bruteforce":
        key = "brute-force"
    if key not in METHOD_NAMES:
        raise argparse.ArgumentTypeError(
            f"invalid method {text!r} (choose from {', '.join(METHOD_NAMES)})"
        )
    return key


def _optional_limit(value: int | float | None) -> int | float | None:
    """CLI convention: 0 disables a limit."""
    return None if not value else value


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser (exposed for testing and documentation)."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="enable verbose (debug) logging on stderr",
    )

    parser = argparse.ArgumentParser(
        prog=PROG,
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="enable verbose (debug) logging on stderr",
    )
    sub = parser.add_subparsers(title="commands", dest="command", metavar="<command>")

    # algorithms ---------------------------------------------------------
    p = sub.add_parser(
        "algorithms",
        parents=[common],
        help="list supported hash algorithms",
        description="List supported hash algorithms, their digest sizes and security status.",
    )
    p.set_defaults(handler=_cmd_algorithms)

    # hash ---------------------------------------------------------------
    p = sub.add_parser(
        "hash",
        parents=[common],
        help="hash an input (optionally showing a truncated digest)",
        description="Hash text, hex bytes or a file with one algorithm (or 'all').",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='example:\n  hashcollider hash --algorithm sha256 --input "hello" --bits 16',
    )
    p.add_argument(
        "-a",
        "--algorithm",
        default=DEFAULT_ALGORITHM,
        help=f"algorithm name or 'all' (default: {DEFAULT_ALGORITHM})",
    )
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("-i", "--input", dest="text", metavar="TEXT", help="text input (UTF-8)")
    source.add_argument("--hex", dest="hex_input", metavar="HEX", help="input as hexadecimal bytes")
    source.add_argument("-f", "--file", type=Path, metavar="PATH", help="hash a file's contents")
    p.add_argument(
        "-b",
        "--bits",
        type=_bits_value,
        help="also show the digest truncated to its first BITS bits",
    )
    p.set_defaults(handler=_cmd_hash)

    # collide ------------------------------------------------------------
    p = sub.add_parser(
        "collide",
        parents=[common],
        help="search for a collision in a truncated hash space",
        description=(
            "Search for two different inputs whose digests agree in the first BITS bits.\n"
            "This is a collision in the reduced BITS-bit space only - not in the full hash."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  hashcollider collide -a sha256 --bits 16 --generator sequential --length 32\n"
            "  hashcollider collide -a sha256 --bits 16 --generator random --length 32\n"
            "  hashcollider collide --bits 24 --generator structured --prefix exp- --width 8\n"
            "  hashcollider collide --bits 16 --method brute-force\n\n" + _EXIT_CODES_HELP
        ),
    )
    p.add_argument(
        "-a",
        "--algorithm",
        default=DEFAULT_ALGORITHM,
        help=f"hash algorithm (default: {DEFAULT_ALGORITHM})",
    )
    p.add_argument(
        "-b",
        "--bits",
        type=_bits_value,
        default=DEFAULT_BITS,
        help=f"effective (truncated) hash size in bits (default: {DEFAULT_BITS})",
    )
    p.add_argument(
        "-m",
        "--method",
        type=_method_value,
        default=DEFAULT_METHOD,
        metavar="{" + ",".join(METHOD_NAMES) + "}",
        help=f"search method (default: {DEFAULT_METHOD})",
    )
    p.add_argument(
        "-g",
        "--generator",
        choices=GENERATOR_NAMES,
        default=DEFAULT_GENERATOR,
        help=f"input generator (default: {DEFAULT_GENERATOR})",
    )
    p.add_argument(
        "-l",
        "--length",
        type=_length_value,
        metavar="BYTES",
        help=f"input length in bytes (random default: {DEFAULT_RANDOM_LENGTH})",
    )
    p.add_argument("--prefix", help="structured generator: input prefix (default: experiment-)")
    p.add_argument("--suffix", help="structured generator: input suffix (default: none)")
    p.add_argument(
        "--start",
        type=_non_negative_int,
        help="sequential/structured generator: first counter value (default: 1)",
    )
    p.add_argument(
        "--width",
        type=_positive_int,
        help="sequential/structured generator: counter width in digits",
    )
    p.add_argument(
        "--seed",
        type=_int_value,
        help="random generator: seed for REPRODUCIBLE, NON-cryptographic randomness",
    )
    _add_limit_arguments(p, DEFAULT_MAX_SECONDS)
    p.add_argument(
        "--force",
        action="store_true",
        help="allow bit lengths above the safe defaults (still capped by hard limits)",
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"where to save the collision JSON (default: {DEFAULT_OUTPUT_FILE})",
    )
    p.add_argument("--no-save", action="store_true", help="do not save the collision to a file")
    p.set_defaults(handler=_cmd_collide)

    # verify -------------------------------------------------------------
    p = sub.add_parser(
        "verify",
        parents=[common],
        help="independently verify a saved collision",
        description=(
            "Recompute both digests (stored hash values are never trusted) and check that\n"
            "input A != input B and truncated(A) == truncated(B)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("file", type=Path, help="collision JSON file")
    p.set_defaults(handler=_cmd_verify)

    # report -------------------------------------------------------------
    p = sub.add_parser(
        "report",
        parents=[common],
        help="generate a Markdown report for a saved collision",
        description="Verify a collision file and write a Markdown report.",
    )
    p.add_argument("file", type=Path, help="collision JSON file")
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_REPORT_FILE,
        help=f"report path (default: {DEFAULT_REPORT_FILE.as_posix()})",
    )
    p.add_argument("--stdout", action="store_true", help="print the report instead of writing it")
    p.set_defaults(handler=_cmd_report)

    # benchmark ----------------------------------------------------------
    p = sub.add_parser(
        "benchmark",
        parents=[common],
        help="measure collision-search performance",
        description=(
            "Run repeated collision searches (fresh random inputs each iteration) and\n"
            "compare observed attempts with the theoretical expectation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  hashcollider benchmark --algorithm sha256 --bits 16 --iterations 100\n"
            "  hashcollider benchmark --algorithm all --bits 20 --iterations 10\n"
            "  hashcollider benchmark -a md5 -a sha256 -a sha3-256 --bits 16"
        ),
    )
    p.add_argument(
        "-a",
        "--algorithm",
        action="append",
        metavar="NAME",
        help="algorithm to benchmark; repeat, comma-separate or use 'all' "
        f"(default: {DEFAULT_ALGORITHM})",
    )
    p.add_argument(
        "-b",
        "--bits",
        type=_bits_value,
        default=DEFAULT_BITS,
        help=f"effective hash size in bits (default: {DEFAULT_BITS})",
    )
    p.add_argument(
        "-n",
        "--iterations",
        type=_positive_int,
        default=BENCHMARK_DEFAULT_ITERATIONS,
        help=f"collision searches per algorithm (default: {BENCHMARK_DEFAULT_ITERATIONS})",
    )
    p.add_argument(
        "-l",
        "--input-length",
        type=_length_value,
        default=DEFAULT_RANDOM_LENGTH,
        metavar="BYTES",
        help=f"random input length in bytes (default: {DEFAULT_RANDOM_LENGTH})",
    )
    p.add_argument(
        "-m",
        "--method",
        type=_method_value,
        default=DEFAULT_METHOD,
        metavar="{" + ",".join(METHOD_NAMES) + "}",
        help=f"search method (default: {DEFAULT_METHOD})",
    )
    p.add_argument(
        "--seed", type=_int_value, help="base seed for reproducible, NON-cryptographic inputs"
    )
    p.add_argument(
        "--raw-hashes",
        type=_non_negative_int,
        default=BENCHMARK_DEFAULT_RAW_HASHES,
        metavar="N",
        help="hashes used to measure raw throughput; 0 skips it "
        f"(default: {BENCHMARK_DEFAULT_RAW_HASHES:,})",
    )
    _add_limit_arguments(p, BENCHMARK_DEFAULT_MAX_SECONDS, per_run=True)
    p.add_argument("--force", action="store_true", help="allow bit lengths above the safe defaults")
    p.set_defaults(handler=_cmd_benchmark)

    # explain ------------------------------------------------------------
    p = sub.add_parser(
        "explain",
        parents=[common],
        help="educational explanations (collisions, birthday bound, ...)",
        description="Print an educational explanation.\n\ntopics:\n"
        + "\n".join(f"  {name:<11} {text}" for name, text in TOPICS.items()),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "topic",
        nargs="?",
        default="collision",
        choices=list(TOPICS),
        help="topic to explain (default: collision)",
    )
    p.set_defaults(handler=_cmd_explain)

    return parser


def _add_limit_arguments(
    parser: argparse.ArgumentParser, default_seconds: float, per_run: bool = False
) -> None:
    scope = " per search" if per_run else ""
    parser.add_argument(
        "--max-attempts",
        type=_non_negative_int,
        default=None,
        metavar="N",
        help=f"stop after N hash evaluations{scope} (0 = unlimited; default: unlimited)",
    )
    parser.add_argument(
        "--max-seconds",
        type=_non_negative_float,
        default=default_seconds,
        metavar="S",
        help=f"stop after S seconds{scope} (0 = unlimited; default: {default_seconds:g})",
    )
    parser.add_argument(
        "--max-stored",
        type=_non_negative_int,
        default=DEFAULT_MAX_STORED,
        metavar="N",
        help="maximum digests kept in memory by the birthday search "
        f"(0 = unlimited; default: {DEFAULT_MAX_STORED:,})",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


class _StderrHandler(logging.Handler):
    """Logging handler that always writes to the *current* ``sys.stderr``."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stderr.write(self.format(record) + "\n")
        except Exception:  # pragma: no cover - logging must never crash the tool
            self.handleError(record)


def _configure_logging(verbose: bool) -> None:
    package_logger = logging.getLogger("hashcollider")
    package_logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    if not any(isinstance(h, _StderrHandler) for h in package_logger.handlers):
        handler = _StderrHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        package_logger.addHandler(handler)
    package_logger.propagate = False


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(bool(getattr(args, "verbose", False)))
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return EXIT_USAGE
    try:
        return int(handler(args))
    except HashColliderError as exc:
        _error(str(exc))
        logger.debug("error details", exc_info=True)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:  # pragma: no cover - e.g. `hashcollider ... | head`
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return EXIT_FAILURE


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _error(message: str) -> None:
    lines = message.splitlines() or [""]
    print(f"Error: {lines[0]}", file=sys.stderr)
    for line in lines[1:]:
        print(f"       {line}", file=sys.stderr)


def _warn(message: str) -> None:
    lines = message.splitlines() or [""]
    print(f"WARNING: {lines[0]}", file=sys.stderr)
    for line in lines[1:]:
        print(f"         {line}", file=sys.stderr)


def _header(title: str | None = None) -> None:
    print(BANNER if title is None else f"{BANNER} - {title}")
    print(RULE)


def _warn_legacy(algorithm: HashAlgorithm) -> None:
    warning = algorithm.security_warning
    if warning:
        _warn(warning)


def _print_statistics(stats: SearchStatistics) -> None:
    print(f"Attempts:      {stats.attempts:,}")
    print(f"Time elapsed:  {format_duration(stats.elapsed_seconds)}")
    print(f"Hashes/sec:    {format_rate(stats.hashes_per_second)}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _cmd_algorithms(args: argparse.Namespace) -> int:
    registry = AlgorithmRegistry()
    _header("supported hash algorithms")
    rows = [
        [
            info.name,
            info.display_name,
            str(info.output_bits),
            f"2^{info.generic_collision_bits}",
            info.status_label,
            "yes" if info.recommended else "NO",
        ]
        for info in registry.infos()
    ]
    print(
        format_table(
            ["Name", "Algorithm", "Digest bits", "Generic collision cost", "Status", "Recommended"],
            rows,
            align=["l", "l", "r", "r", "l", "l"],
        )
    )
    print()
    print("Notes:")
    print("  * Names are case-insensitive; SHA-256, sha_256 and sha256 are equivalent.")
    print("  * 'Generic collision cost' is the birthday bound 2^(n/2) for an ideal n-bit hash.")
    print("    MD5 and SHA-1 are broken far below this bound by dedicated cryptanalysis.")
    print("  * Any algorithm can be truncated with --bits N to create a small 'effective'")
    print("    hash space for collision experiments. A truncated collision is NOT a")
    print("    collision of the full algorithm.")
    if getattr(args, "verbose", False):
        print()
        for info in registry.infos():
            print(f"  {info.display_name:<9} {info.notes}")
    return EXIT_OK


def _read_hash_input(args: argparse.Namespace) -> bytes:
    if args.text is not None:
        return str(args.text).encode("utf-8")
    if args.hex_input is not None:
        try:
            return bytes.fromhex(args.hex_input)
        except ValueError:
            raise InvalidInputError(f"Invalid hex input: {args.hex_input!r}") from None
    path: Path = args.file
    if not path.is_file():
        raise InvalidInputError(f"Input file does not exist or is not a file: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise InvalidInputError(f"Could not read {path}: {exc.strerror or exc}") from exc


def _cmd_hash(args: argparse.Namespace) -> int:
    registry = AlgorithmRegistry()
    data = _read_hash_input(args)
    if args.algorithm.strip().lower() == "all":
        algorithms = [registry.get(name) for name in registry.names()]
    else:
        algorithms = [registry.get(args.algorithm)]
    bits = args.bits
    for algorithm in algorithms:
        if bits is not None:
            validate_bits(bits, algorithm)

    _header("hash")
    print(key_values([("Input", describe_bytes(data)), ("Input length", f"{len(data)} bytes")]))
    print()
    if len(algorithms) > 1:
        headers = ["Algorithm", "Bits", "Digest (hex)"]
        rows = []
        for algorithm in algorithms:
            digest = algorithm.digest(data)
            row = [algorithm.display_name, str(algorithm.output_bits), digest.hex()]
            if bits is not None:
                truncated = TruncatedHash(algorithm, bits)
                row.append(truncated.format_value(truncated.truncate(digest)))
            rows.append(row)
        if bits is not None:
            headers.append(f"First {bits} bits")
        print(format_table(headers, rows, align=["l", "r", "l", "l"]))
    else:
        algorithm = algorithms[0]
        digest = algorithm.digest(data)
        pairs = [
            ("Algorithm", f"{algorithm.display_name} ({algorithm.output_bits}-bit digest)"),
            ("Full digest", digest.hex()),
        ]
        if bits is not None:
            truncated = TruncatedHash(algorithm, bits)
            value = truncated.truncate(digest)
            pairs.append((f"First {bits} bits (hex)", truncated.format_value(value)))
            pairs.append((f"First {bits} bits (binary)", truncated.format_binary(value)))
        print(key_values(pairs))
        _warn_legacy(algorithm)
    if bits is not None:
        print()
        print(
            f"The truncated value keeps only the first {bits} bits of the full digest "
            f"({format_count(2.0**bits)} possible values)."
        )
    return EXIT_OK


def _print_estimate(estimate: SearchEstimate) -> None:
    bits = estimate.bits
    print("Expected effort")
    lines = [
        (
            "Birthday bound",
            f"sqrt(2^{bits}) = 2^{bits / 2:g} ~ {format_count(estimate.birthday_bound)} attempts",
        )
    ]
    if estimate.method == "birthday":
        lines.append(
            (
                "Expected attempts",
                f"~{format_count(estimate.expected_attempts)} "
                f"(sqrt(pi/2 * 2^{bits}), mean for the birthday search)",
            )
        )
        lines.append(
            (
                "Memory estimate",
                f"~{format_bytes(estimate.estimated_memory_bytes)} for "
                f"~{format_count(estimate.expected_stored_entries)} stored digests",
            )
        )
    else:
        lines.append(
            (
                "Expected attempts",
                f"~{format_count(estimate.expected_attempts)} "
                f"({format_power_of_two(estimate.expected_attempts)}, fixed-target brute force)",
            )
        )
        lines.append(("Memory estimate", "constant (only the target digest is stored)"))
    print(key_values(lines, indent=2))
    print("  These are statistical expectations, not guarantees: a particular search")
    print("  may need fewer or more attempts.")
    if estimate.method != "birthday":
        print("  The birthday bound applies to the birthday method; brute force against a")
        print("  fixed target needs about 2^b attempts instead.")


def _limits_text(args: argparse.Namespace) -> str:
    parts = []
    parts.append(f"max attempts {args.max_attempts:,}" if args.max_attempts else "no attempt limit")
    parts.append(f"max {args.max_seconds:g} s" if args.max_seconds else "no time limit")
    if args.method == "birthday":
        parts.append(
            f"max {args.max_stored:,} stored digests" if args.max_stored else "unlimited storage"
        )
    return ", ".join(parts)


def _print_collision(result: CollisionResult, truncated: TruncatedHash) -> None:
    name = result.display_name
    bits = result.effective_bits
    digest_a = bytes.fromhex(result.hash_a or "")
    digest_b = bytes.fromhex(result.hash_b or "")
    print("Input A (hex):  " + result.input_a.hex())
    text_a = printable_text(result.input_a)
    if text_a is not None:
        print("Input A (text): " + text_a)
    print("Input B (hex):  " + result.input_b.hex())
    text_b = printable_text(result.input_b)
    if text_b is not None:
        print("Input B (text): " + text_b)
    print()
    print(f"Full hash A:    {result.hash_a}")
    print(f"Full hash B:    {result.hash_b}")
    for label, digest in (("A", digest_a), ("B", digest_b)):
        value = truncated.format_value(truncated.truncate(digest))
        print(f"Truncated hash {label} (first {bits} bits): {value}")
    print()
    full_equal = digest_a == digest_b
    if not truncated.is_full:
        print(
            f"Result: COLLISION in the {bits}-bit effective hash space "
            f"(first {bits} bits of {name})."
        )
        if full_equal:  # pragma: no cover - would require a full-digest collision
            print(f"Full {name} digests: IDENTICAL.")
        else:
            print(f"Full {name} digests: DIFFERENT.")
            print(
                f"A collision was found in the first {bits} bits of {name}. This does not "
                f"constitute a collision in the full {name} output."
            )
    else:  # pragma: no cover - full-size searches are refused by the engine
        print(f"Result: collision in the full {bits}-bit {name} output.")


def _cmd_collide(args: argparse.Namespace) -> int:
    registry = AlgorithmRegistry()
    algorithm = registry.get(args.algorithm)
    validate_bits(args.bits, algorithm)
    generator = create_generator(
        args.generator,
        length=args.length,
        seed=args.seed,
        prefix=args.prefix,
        suffix=args.suffix,
        start=args.start,
        width=args.width,
    )
    engine = CollisionEngine(
        algorithm,
        args.bits,
        generator,
        method=args.method,
        max_attempts=_optional_limit(args.max_attempts),
        max_seconds=_optional_limit(args.max_seconds),
        max_stored=_optional_limit(args.max_stored),
        force=args.force,
        registry=registry,
    )
    estimate = engine.estimate()

    _header()
    generator_label = generator.name
    params = generator.describe()
    if "prefix" in params:
        generator_label += (
            f" (prefix {params['prefix']!r}, start {params['start']}, width {params['width']})"
        )
    space = format_count(2.0**args.bits)
    print(
        key_values(
            [
                ("Algorithm", f"{algorithm.display_name} ({algorithm.output_bits}-bit digest)"),
                ("Effective bits", f"{args.bits} (search space 2^{args.bits} = {space} values)"),
                ("Method", engine.strategy.title),
                ("Generator", generator_label),
                (
                    "Input length",
                    f"{generator.input_length} bytes" if generator.input_length else "variable",
                ),
                ("Limits", _limits_text(args)),
            ]
        )
    )
    print()
    for option in ignored_options(
        args.generator,
        seed=args.seed,
        prefix=args.prefix,
        suffix=args.suffix,
        start=args.start,
        width=args.width,
    ):
        _warn(f"{option} is ignored by the {args.generator} generator.")
    if args.seed is not None and args.generator == "random":
        _warn(SEEDED_WARNING)
    _warn_legacy(algorithm)
    _print_estimate(estimate)
    print()

    engine.check_feasibility()  # raises InfeasibleSearchError (exit code 2)
    if estimate.input_space_may_be_too_small:
        _warn(
            f"The generator can only produce {format_count(estimate.input_space_size or 0)} "
            "distinct inputs; it may run out before a collision is likely. "
            "Increase --length/--width."
        )

    print("Searching for collision... (press Ctrl+C to stop)")
    outcome = engine.run()
    stats = outcome.statistics
    print()

    if outcome.status is SearchStatus.INTERRUPTED:
        print("Search interrupted.")
        print(f"Attempts: {stats.attempts:,}")
        print(f"Elapsed: {format_duration(stats.elapsed_seconds)}")
        print(f"Hashes/sec: {format_rate(stats.hashes_per_second)}")
        return EXIT_INTERRUPTED

    _print_statistics(stats)
    if outcome.collision is None:
        print()
        print(f"No collision found: {outcome.status.message}.")
        if outcome.status is SearchStatus.MAX_ATTEMPTS:
            print("Increase --max-attempts (0 = unlimited) to search longer.")
        elif outcome.status is SearchStatus.TIMEOUT:
            print("Increase --max-seconds (0 = unlimited) to search longer.")
        elif outcome.status is SearchStatus.EXHAUSTED:
            print("Use longer inputs (--length / --width) or the random generator.")
        _error(outcome.status.message)
        return EXIT_NOT_FOUND

    result = outcome.collision
    if stats.duplicate_inputs:
        print(
            f"Duplicates:    {stats.duplicate_inputs:,} identical inputs skipped (not collisions)"
        )
    print()
    print("Collision found")
    print(RULE)
    _print_collision(result, engine.truncated)
    if not args.no_save:
        existed = args.output.exists()
        path = save_collision(result, args.output)
        print()
        print(f"Saved collision to {path}" + (" (overwritten)" if existed else ""))
        print(f"Verify it with:     {PROG} verify {path}")
        print(f"Create a report:    {PROG} report {path}")
    return EXIT_OK


def _print_verification(path: Path, verification: VerificationResult) -> None:
    record = verification.record
    name = verification.algorithm_display_name
    bits = verification.effective_bits
    print(
        key_values(
            [
                ("File", str(path)),
                ("Algorithm", f"{name} ({verification.output_bits}-bit digest)"),
                ("Effective bits", str(bits)),
                ("Input A", describe_bytes(record.input_a)),
                ("Input B", describe_bytes(record.input_b)),
                ("Recomputed full hash A", verification.recomputed_hash_a),
                ("Recomputed full hash B", verification.recomputed_hash_b),
                (f"Recomputed first {bits} bits A", verification.recomputed_truncated_a),
                (f"Recomputed first {bits} bits B", verification.recomputed_truncated_b),
            ]
        )
    )
    print()
    print("Checks (stored hash values are never trusted; everything is recomputed):")
    for check in verification.checks:
        marker = "PASS" if check.passed else "FAIL"
        detail = f" - {check.detail}" if check.detail and not check.passed else ""
        print(f"  [{marker}] {check.description}{detail}")
    print()
    if verification.full_digests_equal:
        print(f"Full-digest collision: YES - the full {name} digests are identical.")
    elif verification.passed:
        print(
            f"Full-digest collision: NO - the full {name} digests differ. This is a collision "
            f"in the {bits}-bit truncated output space only."
        )
    else:
        print(f"Full-digest collision: NO - the full {name} digests differ.")


def _cmd_verify(args: argparse.Namespace) -> int:
    _header("collision verification")
    try:
        record = load_collision(args.file)
        verification = verify_collision(record)
    except HashColliderError as exc:
        _error(str(exc))
        print("Collision verification: FAIL")
        return EXIT_FAILURE
    _print_verification(args.file, verification)
    if verification.passed:
        print("Collision verification: PASS")
        return EXIT_OK
    _error("Collision verification failed")
    print("Collision verification: FAIL")
    return EXIT_FAILURE


def _cmd_report(args: argparse.Namespace) -> int:
    record = load_collision(args.file)
    verification = verify_collision(record)
    markdown = generate_report(record, verification, source=args.file)
    if args.stdout:
        print(markdown, end="")
    else:
        path = write_report(markdown, args.output)
        print(f"Report written to {path}")
    status = "PASS" if verification.passed else "FAIL"
    stream = sys.stderr if args.stdout else sys.stdout
    print(f"Collision verification: {status}", file=stream)
    return EXIT_OK if verification.passed else EXIT_FAILURE


def _algorithm_names(values: list[str] | None, registry: AlgorithmRegistry) -> tuple[str, ...]:
    if not values:
        return (DEFAULT_ALGORITHM,)
    names: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if part.lower() == "all":
                names.extend(registry.names())
            else:
                names.append(registry.resolve(part).name)
    unique = tuple(dict.fromkeys(names))
    if not unique:
        raise InvalidInputError("No algorithm given")
    return unique


def _cmd_benchmark(args: argparse.Namespace) -> int:
    registry = AlgorithmRegistry()
    names = _algorithm_names(args.algorithm, registry)
    config = BenchmarkConfig(
        algorithms=names,
        bits=args.bits,
        iterations=args.iterations,
        input_length=args.input_length,
        method=args.method,
        seed=args.seed,
        max_attempts=_optional_limit(args.max_attempts),
        max_seconds=_optional_limit(args.max_seconds),
        max_stored=_optional_limit(args.max_stored),
        raw_hashes=args.raw_hashes,
        force=args.force,
    )
    runner = BenchmarkRunner(config, registry)

    _header("benchmark")
    print(
        key_values(
            [
                ("Algorithms", ", ".join(a.display_name for a in runner.algorithms)),
                ("Effective bits", str(config.bits)),
                ("Method", config.method),
                ("Iterations", f"{config.iterations} per algorithm"),
                ("Input length", f"{config.input_length} bytes"),
                (
                    "Inputs",
                    "secrets (CSPRNG)"
                    if config.seed is None
                    else f"seeded random.Random, base seed {config.seed} (NOT cryptographic)",
                ),
            ]
        )
    )
    print()
    if config.seed is not None:
        _warn(SEEDED_WARNING)
    for algorithm in runner.algorithms:
        if algorithm.is_legacy:
            _warn(
                f"{algorithm.display_name} is cryptographically broken (known collision attacks); "
                "it is benchmarked here for comparison only."
            )
    runner.check_feasibility()

    report = runner.run(
        progress=lambda algorithm: print(f"  benchmarking {algorithm.display_name} ...", flush=True)
    )
    print()
    print(benchmark_table(report.results))
    print()
    print("Columns: 'Mean attempts'/'Median' over runs that found a collision; 'Expected' is the")
    print("theoretical mean; 'Obs/Exp' near 1.00 matches theory. 'Search H/s' includes search")
    print("bookkeeping; 'Raw H/s' is pure hashing. Results vary with CPU, load and Python build.")
    if report.interrupted:
        print()
        print("Benchmark interrupted - partial results shown.")
        return EXIT_INTERRUPTED
    return EXIT_OK


def _cmd_explain(args: argparse.Namespace) -> int:
    print(explain(args.topic), end="")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
