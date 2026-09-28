"""Unit test suite for Treasury Hot Wallet Monitor pure domain logic.

TASK 44: TREASURY FOUNDATION: CUSTODY SCHEMA + HOT WALLET MONITOR (BLOCK I)

Tests:
1. Pure threshold math (evaluate matrix): below low, == low, between, == high,
   above high with exact midpoint math (hysteresis), extreme values, and
   threshold ordering validation by construction.
2. Report payload shape-lock: build_report_line produces single-line JSON with
   exact required keys.
3. Pure exit code mapping: 0 on completed monitor run (alert/verdict does not fail process),
   2 on operational exception or missing report.
4. NO-KEYS meta-test: asserts absence of signing credentials, private keys, or
   mnemonic material across treasury modules.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from fluxpay.treasury.monitor import (
    EXIT_OK,
    EXIT_OPS_FAILURE,
    MonitorReport,
    ThresholdVerdict,
    build_report_line,
    evaluate,
    map_exit_code,
)

pytestmark = pytest.mark.unit

LOCKED_TREASURY_REPORT_KEYS = frozenset(
    [
        "mode",
        "rail",
        "hot_balance",
        "cold_balance",
        "verdict",
        "sweep_request_id",
        "synced",
        "alerted",
        "checked_at",
        "elapsed_ms",
    ]
)


# =============================================================================
# 1. PURE THRESHOLD EVALUATION MATRIX
# =============================================================================


def test_evaluate_below_low_water_triggers_topup() -> None:
    """hot < low -> topup_required with suggested = (low * 2) - hot."""
    low = 50_000_000000
    high = 200_000_000000
    hot = 10_000_000000

    verdict = evaluate(hot_balance=hot, low=low, high=high)
    expected_topup = (low * 2) - hot

    assert verdict.action == "topup_required"
    assert verdict.amount == expected_topup
    assert str(expected_topup) in verdict.detail
    assert "below low water" in verdict.detail


def test_evaluate_boundary_at_low_water_is_ok() -> None:
    """hot == low -> ok (strict < boundary law)."""
    low = 50_000_000000
    high = 200_000_000000
    hot = low

    verdict = evaluate(hot_balance=hot, low=low, high=high)
    assert verdict.action == "ok"
    assert verdict.amount == 0
    assert "within operational thresholds" in verdict.detail


def test_evaluate_between_watermarks_is_ok() -> None:
    """low < hot < high -> ok."""
    low = 50_000_000000
    high = 200_000_000000
    hot = 150_000_000000

    verdict = evaluate(hot_balance=hot, low=low, high=high)
    assert verdict.action == "ok"
    assert verdict.amount == 0


def test_evaluate_boundary_at_high_water_is_ok() -> None:
    """hot == high -> ok (strict > boundary law)."""
    low = 50_000_000000
    high = 200_000_000000
    hot = high

    verdict = evaluate(hot_balance=hot, low=low, high=high)
    assert verdict.action == "ok"
    assert verdict.amount == 0


@pytest.mark.parametrize(
    ("low", "high", "hot", "expected_sweep"),
    [
        # Case 1: Default scale (low=50, high=200, hot=300 -> midpoint=125, sweep=175)
        (50_000, 200_000, 300_000, 175_000),
        # Case 2: Even midpoint (low=100, high=500, hot=600 -> midpoint=300, sweep=300)
        (100_000, 500_000, 600_000, 300_000),
        # Case 3: Narrow window (low=20, high=80, hot=100 -> midpoint=50, sweep=50)
        (20, 80, 100, 50),
        # Case 4: Integer division midpoint (low=10, high=31, hot=40 -> midpoint=20, sweep=20)
        (10, 31, 40, 20),
    ],
)
def test_evaluate_above_high_water_triggers_sweep_to_midpoint(
    low: int,
    high: int,
    hot: int,
    expected_sweep: int,
) -> None:
    """hot > high -> sweep_due with sweep = hot - ((low + high) // 2) (hysteresis)."""
    verdict = evaluate(hot_balance=hot, low=low, high=high)

    assert verdict.action == "sweep_due"
    assert verdict.amount == expected_sweep
    assert str(expected_sweep) in verdict.detail
    assert "exceeds high water" in verdict.detail


def test_evaluate_extreme_values() -> None:
    """Zero balance and very large balance evaluate cleanly."""
    low = 100
    high = 1000

    # hot = 0: below low
    v_zero = evaluate(hot_balance=0, low=low, high=high)
    assert v_zero.action == "topup_required"
    assert v_zero.amount == 200

    # hot = 10 billion: above high
    v_huge = evaluate(hot_balance=10_000_000_000, low=low, high=high)
    assert v_huge.action == "sweep_due"
    assert v_huge.amount == 10_000_000_000 - 550


@pytest.mark.parametrize(
    ("low", "high"),
    [
        (100, 100),  # equal
        (100, 50),  # inverted
        (100, 0),  # zero high
        (100, -10),  # negative high
    ],
)
def test_evaluate_threshold_ordering_invariants(low: int, high: int) -> None:
    """high <= low must raise ValueError (construction ordering invariant)."""
    with pytest.raises(ValueError, match="high water threshold"):
        evaluate(hot_balance=50, low=low, high=high)


# =============================================================================
# 2. JSON LINE REPORT SHAPE-LOCK
# =============================================================================


def test_build_report_line_payload_shape() -> None:
    """Verify build_report_line outputs single-line JSON with exact required keys."""
    sweep_id = uuid4()
    verdict = ThresholdVerdict(action="sweep_due", detail="sweep needed", amount=175)
    report = MonitorReport(
        rail="base_usdc",
        hot_balance=300_000_000000,
        cold_balance=1000_000_000000,
        verdict=verdict,
        synced=True,
        alerted=True,
        sweep_request_id=sweep_id,
    )
    now = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)
    elapsed_ms = 35

    line = build_report_line(report, elapsed_ms=elapsed_ms, now=now)

    # 1. Single-line guarantee
    assert "\n" not in line
    assert "\r" not in line

    # 2. Parses as valid JSON
    data = json.loads(line)

    # 3. Exact keys
    assert frozenset(data.keys()) == LOCKED_TREASURY_REPORT_KEYS

    # 4. Values match report
    assert data["mode"] == "treasury_monitor"
    assert data["rail"] == "base_usdc"
    assert data["hot_balance"] == 300_000_000000
    assert data["cold_balance"] == 1000_000_000000
    assert data["verdict"] == "sweep_due"
    assert data["sweep_request_id"] == str(sweep_id)
    assert data["synced"] is True
    assert data["alerted"] is True
    assert data["checked_at"] == "2026-09-27T12:00:00Z"
    assert data["elapsed_ms"] == 35


def test_build_report_line_none_sweep_request_id() -> None:
    """Verify build_report_line handles None sweep_request_id correctly."""
    verdict = ThresholdVerdict(action="ok", detail="ok", amount=0)
    report = MonitorReport(
        rail="base_usdc",
        hot_balance=150,
        cold_balance=1000,
        verdict=verdict,
        synced=True,
        alerted=False,
        sweep_request_id=None,
    )
    line = build_report_line(report, elapsed_ms=10)
    data = json.loads(line)
    assert data["sweep_request_id"] is None
    assert data["alerted"] is False


# =============================================================================
# 3. PURE EXIT CODE MAPPING
# =============================================================================


def test_map_exit_code_contract() -> None:
    """Verify pure exit code mapping contract (0 on ran, 2 on ops failure)."""
    verdict_ok = ThresholdVerdict(action="ok", detail="ok", amount=0)
    report_ok = MonitorReport(
        rail="base_usdc",
        hot_balance=150,
        cold_balance=1000,
        verdict=verdict_ok,
        synced=True,
        alerted=False,
        sweep_request_id=None,
    )
    # Successful run with ok verdict -> 0
    assert map_exit_code(report_ok) == EXIT_OK

    # Run with topup_required / alert fired -> 0 (policy conditions are alert-domain)
    verdict_topup = ThresholdVerdict(action="topup_required", detail="low", amount=50)
    report_alerted = MonitorReport(
        rail="base_usdc",
        hot_balance=10,
        cold_balance=1000,
        verdict=verdict_topup,
        synced=True,
        alerted=True,
        sweep_request_id=None,
    )
    assert map_exit_code(report_alerted) == EXIT_OK

    # Run with unsynced / reader_error -> 0 (observation fail-open; alerts handle it)
    report_unsynced = MonitorReport(
        rail="base_usdc",
        hot_balance=150,
        cold_balance=1000,
        verdict=verdict_ok,
        synced=False,
        alerted=True,
        sweep_request_id=None,
    )
    assert map_exit_code(report_unsynced) == EXIT_OK

    # Operational failure with exception -> 2
    assert map_exit_code(report_ok, error=RuntimeError("DB dead")) == EXIT_OPS_FAILURE
    assert map_exit_code(error=ConnectionRefusedError("Dead port")) == EXIT_OPS_FAILURE

    # Missing report -> 2
    assert map_exit_code(report=None) == EXIT_OPS_FAILURE


# =============================================================================
# 4. NO-KEYS SECURITY META-TEST (THE BLOCK'S SECOND LAW)
# =============================================================================


def test_no_keys_in_treasury_modules() -> None:
    """Security invariant: treasury modules must NEVER contain signing or private key tokens.

    Asserts absolute absence of:
    - "private_key"
    - "signing_key"
    - "mnemonic"
    - "Signer"
    - "Account.from_key"
    Drift alarm for every future contributor (Task 15 blacklist pattern applied to security).
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    treasury_dir = repo_root / "src" / "fluxpay" / "treasury"

    forbidden_tokens = [
        "private_key",
        "signing_key",
        "mnemonic",
        "Signer",
        "Account.from_key",
    ]

    files_to_check = [
        treasury_dir / "monitor.py",
        treasury_dir / "reader.py",
        treasury_dir / "__init__.py",
    ]
    payouts_file = treasury_dir / "payouts.py"
    if payouts_file.exists():
        files_to_check.append(payouts_file)

    for file_path in files_to_check:
        assert file_path.is_file(), f"Expected treasury file not found: {file_path}"
        content = file_path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in content, (
                f"SECURITY VIOLATION: Forbidden token '{token}' discovered in "
                f"{file_path.relative_to(repo_root)}. The server must hold zero signing keys."
            )
