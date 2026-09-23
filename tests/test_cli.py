"""Tests for the command-line interface."""

from __future__ import annotations

import _thread
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from hashcollider import cli
from hashcollider.cli import build_parser, main
from hashcollider.config import EXIT_FAILURE, EXIT_INTERRUPTED, EXIT_NOT_FOUND, EXIT_OK, EXIT_USAGE

HELLO_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def usage_error(capsys: pytest.CaptureFixture[str], *argv: str) -> str:
    with pytest.raises(SystemExit) as info:
        main(list(argv))
    assert info.value.code == EXIT_USAGE
    return capsys.readouterr().err


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parser_builds_all_commands() -> None:
    parser = build_parser()
    for command in ("hash", "collide", "benchmark", "verify", "report", "algorithms", "explain"):
        assert command in parser.format_help()


def test_collide_defaults() -> None:
    args = build_parser().parse_args(["collide"])
    assert args.algorithm == "sha256"
    assert args.bits == 16
    assert args.method == "birthday"
    assert args.generator == "sequential"
    assert args.length is None
    assert args.output == Path("collision.json")
    assert args.verbose is False


def test_verbose_accepted_before_and_after_command() -> None:
    parser = build_parser()
    assert parser.parse_args(["-v", "algorithms"]).verbose is True
    assert parser.parse_args(["collide", "--verbose"]).verbose is True
    assert parser.parse_args(["collide"]).verbose is False


def test_method_aliases() -> None:
    args = build_parser().parse_args(["collide", "--method", "brute_force"])
    assert args.method == "brute-force"


def test_help_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["--help"])
    assert info.value.code == 0
    assert "hashcollider" in capsys.readouterr().out
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys)
    assert code == EXIT_USAGE
    assert "commands" in out


# ---------------------------------------------------------------------------
# algorithms / hash / explain
# ---------------------------------------------------------------------------


def test_algorithms_command(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "algorithms")
    assert code == EXIT_OK
    for name in (
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
    ):
        assert name in out
    assert "BROKEN" in out


def test_hash_known_string(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "hash", "--algorithm", "sha256", "--input", "hello")
    assert code == EXIT_OK
    assert HELLO_SHA256 in out
    assert err == ""


def test_hash_truncated(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "hash", "-a", "SHA-256", "-i", "hello", "--bits", "16")
    assert code == EXIT_OK
    assert "First 16 bits (hex):" in out
    assert "2cf2" in out
    assert "0010110011110010" in out


def test_hash_hex_input_and_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = run(capsys, "hash", "--hex", "68656c6c6f")
    assert code == EXIT_OK and HELLO_SHA256 in out
    path = tmp_path / "hello.txt"
    path.write_bytes(b"hello")
    code, out, _ = run(capsys, "hash", "--file", str(path))
    assert code == EXIT_OK and HELLO_SHA256 in out


def test_hash_all_algorithms(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "hash", "--algorithm", "all", "--input", "hello", "--bits", "8")
    assert code == EXIT_OK
    assert HELLO_SHA256 in out
    assert "SHA3-512" in out


def test_hash_md5_prints_security_warning(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "hash", "--algorithm", "md5", "--input", "hello")
    assert code == EXIT_OK
    assert "WARNING" in err and "MD5 is cryptographically broken" in err


def test_hash_invalid_hex(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "hash", "--hex", "xyz")
    assert code == EXIT_USAGE
    assert "Invalid hex input" in err
    assert "Traceback" not in err


def test_hash_missing_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, "hash", "--file", str(tmp_path / "nope.bin"))
    assert code == EXIT_USAGE
    assert "does not exist" in err


def test_explain_collision(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "explain", "collision")
    assert code == EXIT_OK
    assert "birthday paradox" in out
    assert "does NOT imply" in out


def test_explain_birthday(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "explain", "birthday")
    assert code == EXIT_OK
    assert "sqrt(2^b)" in out


# ---------------------------------------------------------------------------
# Invalid arguments: clean errors, no tracebacks
# ---------------------------------------------------------------------------


def test_unsupported_algorithm(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "collide", "--algorithm", "sha999", "--no-save")
    assert code == EXIT_USAGE
    assert "Unsupported algorithm" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("bits", ["0", "-3", "abc"])
def test_invalid_bits_rejected_by_parser(capsys: pytest.CaptureFixture[str], bits: str) -> None:
    err = usage_error(capsys, "collide", "--bits", bits)
    assert "--bits" in err


def test_bits_larger_than_digest(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "collide", "--algorithm", "md5", "--bits", "200", "--no-save")
    assert code == EXIT_USAGE
    assert "Invalid bit length" in err


@pytest.mark.parametrize("length", ["0", "-1"])
def test_invalid_length(capsys: pytest.CaptureFixture[str], length: str) -> None:
    err = usage_error(capsys, "collide", "--generator", "random", "--length", length)
    assert "Input length must be positive" in err


def test_length_too_short_for_sequential(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "collide", "--length", "4", "--no-save")
    assert code == EXIT_USAGE
    assert "too short" in err


def test_invalid_generator_and_method(capsys: pytest.CaptureFixture[str]) -> None:
    assert "--generator" in usage_error(capsys, "collide", "--generator", "quantum")
    assert "--method" in usage_error(capsys, "collide", "--method", "rainbow")


def test_invalid_iterations(capsys: pytest.CaptureFixture[str]) -> None:
    assert "--iterations" in usage_error(capsys, "benchmark", "--iterations", "0")


def test_full_size_collision_refused(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "collide", "--bits", "256", "--force", "--no-save")
    assert code == EXIT_USAGE
    assert "computationally infeasible" in err
    assert "Searching for collision" not in out


def test_large_search_needs_force(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "collide", "--bits", "48", "--no-save")
    assert code == EXIT_USAGE
    assert "--force" in err


# ---------------------------------------------------------------------------
# collide / verify / report workflow
# ---------------------------------------------------------------------------


def test_collide_verify_report_workflow(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    output = tmp_path / "collision.json"
    code, out, _ = run(
        capsys,
        "collide",
        "--algorithm",
        "sha256",
        "--bits",
        "16",
        "--generator",
        "sequential",
        "--length",
        "32",
        "--output",
        str(output),
    )
    assert code == EXIT_OK
    assert "Collision found" in out
    assert "COLLISION in the 16-bit effective hash space" in out
    assert "Full SHA-256 digests: DIFFERENT" in out
    assert "does not constitute a collision in the full SHA-256 output" in out
    assert "Input length:" in out and "32 bytes" in out
    assert output.is_file()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["format_version"] == 1 and data["effective_bits"] == 16

    code, out, _ = run(capsys, "verify", str(output))
    assert code == EXIT_OK
    assert "Collision verification: PASS" in out
    assert "Full-digest collision: NO" in out

    report = tmp_path / "reports" / "collision-report.md"
    code, out, _ = run(capsys, "report", str(output), "--output", str(report))
    assert code == EXIT_OK
    assert report.is_file()
    assert "Only the selected truncated output space was searched" in report.read_text("utf-8")

    code, out, err = run(capsys, "report", str(output), "--stdout")
    assert code == EXIT_OK
    assert out.startswith("# HashCollider Collision Report")
    assert "Collision verification: PASS" in err


@pytest.mark.parametrize(
    "extra",
    [
        ["--generator", "random", "--length", "32"],
        ["--generator", "random", "--length", "8", "--seed", "1"],
        ["--generator", "structured", "--prefix", "lab-", "--width", "6"],
        ["--method", "brute-force", "--bits", "10"],
    ],
)
def test_collide_variants(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, extra: list[str]
) -> None:
    output = tmp_path / "c.json"
    code, out, err = run(capsys, "collide", *extra, "--output", str(output))
    assert code == EXIT_OK, err
    assert output.is_file()
    if "--seed" in extra:
        assert "NOT cryptographically secure" in err


def test_collide_no_save(capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code, out, _ = run(capsys, "collide", "--bits", "8", "--no-save")
    assert code == EXIT_OK
    assert not (tmp_path / "collision.json").exists()
    assert "Saved collision" not in out


def test_collide_sha1_warning(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, "collide", "-a", "sha1", "-b", "8", "-o", str(tmp_path / "c.json"))
    assert code == EXIT_OK
    assert "SHA-1 is broken for collision resistance" in err
    assert "NOT a cryptanalytic SHA-1 collision" in err


def test_collide_ignored_option_warning(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "collide", "--bits", "8", "--seed", "5", "--no-save")
    assert code == EXIT_OK
    assert "--seed is ignored by the sequential generator" in err


def test_collide_max_attempts(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "collide", "--bits", "32", "--max-attempts", "5", "--no-save")
    assert code == EXIT_NOT_FOUND
    assert "Maximum attempt limit reached" in err
    assert "Attempts:      5" in out


def test_collide_generator_exhausted(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(
        capsys,
        "collide",
        "--bits",
        "32",
        "--generator",
        "structured",
        "--prefix",
        "x",
        "--width",
        "1",
        "--no-save",
    )
    assert code == EXIT_NOT_FOUND
    assert "exhausted" in err


def test_collide_keyboard_interrupt(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, scripted
) -> None:
    generator = scripted(repeat=b"dup", count=250, then_raise=KeyboardInterrupt())
    monkeypatch.setattr(cli, "create_generator", lambda *args, **kwargs: generator)
    code, out, _ = run(capsys, "collide", "--bits", "16", "--no-save")
    assert code == EXIT_INTERRUPTED
    assert "Search interrupted." in out
    assert "Attempts: 250" in out
    assert "Elapsed:" in out
    assert "Hashes/sec:" in out


def test_verify_missing_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, err = run(capsys, "verify", str(tmp_path / "missing.json"))
    assert code == EXIT_FAILURE
    assert "Collision file does not exist" in err
    assert "Collision verification: FAIL" in out


def test_verify_tampered_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    output = tmp_path / "c.json"
    assert run(capsys, "collide", "--bits", "16", "-o", str(output))[0] == EXIT_OK
    data = json.loads(output.read_text(encoding="utf-8"))
    data["input_b"] = data["input_a"]
    output.write_text(json.dumps(data), encoding="utf-8")
    code, out, err = run(capsys, "verify", str(output))
    assert code == EXIT_FAILURE
    assert "Collision verification: FAIL" in out
    assert "Collision verification failed" in err


def test_verify_invalid_json(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("nope", encoding="utf-8")
    code, out, err = run(capsys, "verify", str(path))
    assert code == EXIT_FAILURE
    assert "not valid JSON" in err
    assert "Traceback" not in err


def test_report_missing_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, "report", str(tmp_path / "missing.json"))
    assert code == EXIT_FAILURE
    assert "does not exist" in err


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------


def test_benchmark_command(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys,
        "benchmark",
        "--algorithm",
        "sha256",
        "--algorithm",
        "md5,sha3-256",
        "--bits",
        "8",
        "--iterations",
        "3",
        "--raw-hashes",
        "1000",
    )
    assert code == EXIT_OK
    for name in ("SHA-256", "MD5", "SHA3-256", "Mean attempts", "Raw H/s"):
        assert name in out


def test_benchmark_all_algorithms(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys,
        "benchmark",
        "-a",
        "all",
        "-b",
        "8",
        "-n",
        "2",
        "--raw-hashes",
        "0",
    )
    assert code == EXIT_OK
    assert "SHA3-512" in out


def test_benchmark_invalid_algorithm(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "benchmark", "--algorithm", "nope")
    assert code == EXIT_USAGE
    assert "Unsupported algorithm" in err


# ---------------------------------------------------------------------------
# Real processes: python -m hashcollider and Ctrl+C
# ---------------------------------------------------------------------------


def test_async_ctrl_c_during_real_search(capsys: pytest.CaptureFixture[str]) -> None:
    """Simulate Ctrl+C arriving asynchronously while the hot loop is running."""
    timer = threading.Timer(0.5, _thread.interrupt_main)
    timer.start()
    try:
        code, out, err = run(
            capsys,
            "collide", "--bits", "60", "--force", "--max-seconds", "30",
            "--max-stored", "50000", "--no-save",
        )  # fmt: skip
    finally:
        timer.cancel()
    assert code == EXIT_INTERRUPTED
    assert "Search interrupted." in out
    assert "Attempts:" in out and "Elapsed:" in out and "Hashes/sec:" in out
    assert "Traceback" not in err


def _subprocess_env(project_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    src = str(project_root / "src")
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONUNBUFFERED"] = "1"
    return env


def test_python_dash_m_entry_point(project_root: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "hashcollider", "--help"],
        capture_output=True,
        text=True,
        env=_subprocess_env(project_root),
        timeout=60,
        check=False,
    )
    assert result.returncode == 0
    assert "collide" in result.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT delivery test requires POSIX")
def test_ctrl_c_stops_search_cleanly(project_root: Path, tmp_path: Path) -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hashcollider",
            "collide",
            "--bits",
            "60",
            "--force",
            "--max-seconds",
            "60",
            "--max-stored",
            "50000",
            "--no-save",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_subprocess_env(project_root),
        cwd=tmp_path,
    )
    try:
        assert process.stdout is not None
        deadline = time.monotonic() + 30
        for line in process.stdout:
            if "Searching for collision" in line or time.monotonic() > deadline:
                break
        time.sleep(0.5)
        process.send_signal(signal.SIGINT)
        out, err = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
    assert process.returncode == EXIT_INTERRUPTED, err
    assert "Search interrupted." in out
    assert "Attempts:" in out
    assert "Hashes/sec:" in out
    assert "Traceback" not in err
