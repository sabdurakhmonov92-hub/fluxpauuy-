"""Pure unit tests locking the payload shape, exit code mapping, and single-line guarantee.

TASK 40: HASH-CHAIN VALIDATOR — HOURLY INTEGRITY AUDIT (BLOCK H, PART 2)

Tests:
1. Payload-shape meta-lock: build_report produces valid JSON with exact keys.
2. Superset-of-CLI assertion: all Task 18 CLI verification fields are present plus mode and scope.
3. Exit-code mapping: 0 on ok, 1 on broken chain, 2 on operational exception.
4. Single-line guarantee: output contains no unescaped newlines (Loki dead-man switch requirement).
"""

import asyncio
import json
from datetime import UTC, datetime

import pytest

from fluxpay.ledger.store import ChainVerification
from fluxpay.workers.hash_validator import (
    EXIT_CHAIN_BROKEN,
    EXIT_OK,
    EXIT_OPS_FAILURE,
    build_report,
    determine_exit_code,
    map_exit_code,
)

pytestmark = pytest.mark.unit

# Task 18 CLI JSON report baseline keys
TASK_18_CLI_KEYS = frozenset(
    [
        "ok",
        "last_verified_seq",
        "broken_seq",
        "reason",
        "checked_at",
        "elapsed_ms",
    ]
)

# Task 40 Worker locked exact keys (superset of Task 18)
LOCKED_REPORT_KEYS = frozenset(
    [
        "ok",
        "last_verified_seq",
        "broken_seq",
        "reason",
        "checked_at",
        "elapsed_ms",
        "mode",
        "scope",
    ]
)


def test_build_report_payload_shape_healthy() -> None:
    """Verify healthy ChainVerification produces exact locked keys and superset of CLI."""
    verification = ChainVerification(ok=True, last_verified_seq=100)
    now = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)
    elapsed_ms = 42

    line = build_report(verification, elapsed_ms, now=now)

    # 1. Parses as valid JSON
    data = json.loads(line)

    # 2. Exact keys assertion
    assert frozenset(data.keys()) == LOCKED_REPORT_KEYS

    # 3. Superset of CLI payload assertion
    assert TASK_18_CLI_KEYS.issubset(frozenset(data.keys()))
    assert data["mode"] == "hash_validator"
    assert data["scope"] == "full"

    # 4. Values contract
    assert data["ok"] is True
    assert data["last_verified_seq"] == 100
    assert data["broken_seq"] is None
    assert data["reason"] is None
    assert data["checked_at"] == "2026-09-27T12:00:00Z"
    assert data["elapsed_ms"] == 42


def test_build_report_payload_shape_broken() -> None:
    """Verify broken ChainVerification produces exact locked keys with failure telemetry."""
    verification = ChainVerification(
        ok=False,
        last_verified_seq=42,
        broken_seq=43,
        reason="Cryptographic hash recomputation mismatch at seq=43",
    )
    now = datetime(2026, 9, 27, 13, 30, 0, tzinfo=UTC)
    elapsed_ms = 15

    line = build_report(verification, elapsed_ms, now=now)
    data = json.loads(line)

    assert frozenset(data.keys()) == LOCKED_REPORT_KEYS
    assert TASK_18_CLI_KEYS.issubset(frozenset(data.keys()))
    assert data["ok"] is False
    assert data["last_verified_seq"] == 42
    assert data["broken_seq"] == 43
    assert data["reason"] == "Cryptographic hash recomputation mismatch at seq=43"
    assert data["checked_at"] == "2026-09-27T13:30:00Z"
    assert data["elapsed_ms"] == 15
    assert data["mode"] == "hash_validator"
    assert data["scope"] == "full"


def test_build_report_default_now_handling() -> None:
    """Verify build_report defaults to current UTC time if now is omitted."""
    verification = ChainVerification(ok=True, last_verified_seq=1)
    line = build_report(verification, elapsed_ms=5)
    data = json.loads(line)

    assert "checked_at" in data
    assert data["checked_at"].endswith("Z")


def test_build_report_naive_now_handling() -> None:
    """Verify build_report handles naive datetimes by converting to UTC."""
    verification = ChainVerification(ok=True, last_verified_seq=1)
    naive = datetime(2026, 9, 27, 12, 0, 0)
    line = build_report(verification, elapsed_ms=5, now=naive)
    data = json.loads(line)

    assert data["checked_at"] == "2026-09-27T12:00:00Z"


def test_build_report_single_line_guarantee() -> None:
    """Verify report contains no unescaped newlines in string or byte representation."""
    # Even if reason contains embedded newlines, json serialization escapes them
    verification = ChainVerification(
        ok=False,
        last_verified_seq=10,
        broken_seq=11,
        reason="Line 1 error\nLine 2 trace\r\nLine 3 detail",
    )
    line = build_report(verification, elapsed_ms=8)

    # String contract
    assert "\n" not in line
    assert "\r" not in line

    # Raw bytes contract (Loki ingestion stream)
    raw_bytes = line.encode("utf-8")
    assert b"\n" not in raw_bytes
    assert b"\r" not in raw_bytes

    # Still parses correctly
    parsed = json.loads(line)
    assert parsed["broken_seq"] == 11
    assert "Line 1 error\nLine 2 trace" in parsed["reason"]


def test_exit_code_mapping_pure() -> None:
    """Verify pure exit code mapping contract across all operational states."""
    # State 1: Healthy chain -> EXIT_OK (0)
    ok_verification = ChainVerification(ok=True, last_verified_seq=50)
    assert map_exit_code(ok_verification) == EXIT_OK
    assert determine_exit_code(ok_verification) == EXIT_OK

    # State 2: Broken chain (ok=False) -> EXIT_CHAIN_BROKEN (1)
    broken_verification = ChainVerification(
        ok=False,
        last_verified_seq=10,
        broken_seq=11,
        reason="Mismatch",
    )
    assert map_exit_code(broken_verification) == EXIT_CHAIN_BROKEN
    assert determine_exit_code(broken_verification) == EXIT_CHAIN_BROKEN

    # State 3: Broken chain (broken_seq set even if ok was True) -> EXIT_CHAIN_BROKEN (1)
    anomalous = ChainVerification(ok=True, last_verified_seq=10, broken_seq=11)
    assert map_exit_code(anomalous) == EXIT_CHAIN_BROKEN

    # State 4: Operational failure via exception instance -> EXIT_OPS_FAILURE (2)
    assert map_exit_code(error=ConnectionRefusedError("Dead port")) == EXIT_OPS_FAILURE
    assert map_exit_code(ok_verification, error=RuntimeError("DB crashed")) == EXIT_OPS_FAILURE

    # State 5: Operational failure via exception class -> EXIT_OPS_FAILURE (2)
    assert map_exit_code(error=asyncio.TimeoutError) == EXIT_OPS_FAILURE

    # State 6: Missing verification -> EXIT_OPS_FAILURE (2)
    assert map_exit_code(verification=None) == EXIT_OPS_FAILURE
