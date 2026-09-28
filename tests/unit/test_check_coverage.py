"""Unit test suite for the per-module coverage gate script (scripts/check_coverage.py).

Validates:
1. Pass threshold: exit code 0 when module coverage meets or exceeds threshold.
2. Fail threshold: exit code 1 when module coverage is below threshold.
3. Missing coverage.json: exit code 2 (operational failure).
4. Malformed JSON / missing statements schema: exit code 2 (operational failure).
5. Prefix filtering isolation: ensures only files matching the given prefix are summed.
6. Invalid CLI arguments: exit code 2.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.unit

SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "check_coverage.py"


def _create_coverage_json(path: Path, files: dict[str, dict[str, int]]) -> None:
    """Helper to generate synthetic coverage.json files."""
    data: dict[str, Any] = {
        "meta": {"version": "7.0.0"},
        "files": {},
        "totals": {},
    }
    for file_path, counts in files.items():
        data["files"][file_path] = {
            "summary": {
                "covered_lines": counts["covered"],
                "num_statements": counts["statements"],
                "percent_covered": (
                    (counts["covered"] / counts["statements"] * 100)
                    if counts["statements"] > 0
                    else 0.0
                ),
            }
        }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def test_coverage_gate_passes_above_threshold(tmp_path: Path) -> None:
    """Verify exit code 0 when module coverage is >= threshold."""
    cov_file = tmp_path / "coverage.json"
    _create_coverage_json(
        cov_file,
        {
            "src/fluxpay/ledger/postgres.py": {"covered": 96, "statements": 100},
            "src/fluxpay/ledger/store.py": {"covered": 98, "statements": 100},
        },
    )

    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "src/fluxpay/ledger",
            "95",
            "--file",
            str(cov_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    assert "GATE src/fluxpay/ledger 97.00% >= 95% -> PASS" in proc.stdout


def test_coverage_gate_fails_below_threshold(tmp_path: Path) -> None:
    """Verify exit code 1 when module coverage is < threshold."""
    cov_file = tmp_path / "coverage.json"
    _create_coverage_json(
        cov_file,
        {
            "src/fluxpay/ledger/postgres.py": {"covered": 90, "statements": 100},
            "src/fluxpay/ledger/store.py": {"covered": 94, "statements": 100},
        },
    )

    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "src/fluxpay/ledger",
            "95",
            "--file",
            str(cov_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1
    assert "GATE src/fluxpay/ledger 92.00% >= 95% -> FAIL" in proc.stdout


def test_coverage_gate_missing_file(tmp_path: Path) -> None:
    """Verify exit code 2 when coverage.json file does not exist."""
    missing_file = tmp_path / "nonexistent.json"

    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "src/fluxpay/ledger",
            "95",
            "--file",
            str(missing_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 2
    assert "Operational error: coverage file" in proc.stderr


def test_coverage_gate_malformed_json_syntax(tmp_path: Path) -> None:
    """Verify exit code 2 on invalid JSON syntax."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ this is not valid json }", encoding="utf-8")

    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "src/fluxpay/ledger",
            "95",
            "--file",
            str(bad_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 2
    assert "Operational error: malformed JSON" in proc.stderr


def test_coverage_gate_malformed_missing_statements(tmp_path: Path) -> None:
    """Verify exit code 2 when coverage.json is missing required statement count keys."""
    bad_schema_file = tmp_path / "bad_schema.json"
    data = {
        "files": {
            "src/fluxpay/ledger/store.py": {
                "summary": {"percent_covered": 100.0}  # missing covered_lines, num_statements
            }
        }
    }
    bad_schema_file.write_text(json.dumps(data), encoding="utf-8")

    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "src/fluxpay/ledger",
            "95",
            "--file",
            str(bad_schema_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 2
    assert "Operational error: missing statement counts" in proc.stderr


def test_coverage_gate_prefix_filtering(tmp_path: Path) -> None:
    """Verify that only files matching the exact path prefix are summed."""
    cov_file = tmp_path / "coverage.json"
    _create_coverage_json(
        cov_file,
        {
            # Ledger: 100/100 = 100%
            "src/fluxpay/ledger/store.py": {"covered": 100, "statements": 100},
            # Gateway: 50/100 = 50%
            "src/fluxpay/gateway/router.py": {"covered": 50, "statements": 100},
        },
    )

    # 1. Check ledger: only ledger files counted -> 100% >= 95% -> PASS
    proc_ledger = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "src/fluxpay/ledger",
            "95",
            "--file",
            str(cov_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_ledger.returncode == 0
    assert "GATE src/fluxpay/ledger 100.00% >= 95% -> PASS" in proc_ledger.stdout

    # 2. Check gateway: only gateway files counted -> 50% < 95% -> FAIL
    proc_gateway = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "src/fluxpay/gateway",
            "95",
            "--file",
            str(cov_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_gateway.returncode == 1
    assert "GATE src/fluxpay/gateway 50.00% >= 95% -> FAIL" in proc_gateway.stdout


def test_coverage_gate_invalid_threshold(tmp_path: Path) -> None:
    """Verify exit code 2 when threshold is outside [0, 100]."""
    cov_file = tmp_path / "coverage.json"
    _create_coverage_json(cov_file, {})

    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(SCRIPT_PATH),
            "src/fluxpay/ledger",
            "150",
            "--file",
            str(cov_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "threshold must be in range [0, 100]" in proc.stderr
