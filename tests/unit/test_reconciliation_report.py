"""Pure unit tests for the reconciliation report model, exit codes, and hygiene contracts.

TASK 41: RECONCILIATION WORKER — DAILY TRUTH AUDIT (BLOCK H, PART 3)

Tests:
1. Report shape meta-lock: build_report produces valid JSON with exact locked keys.
2. Healthy-derivation logic:
   - Zero mismatches + global_balanced=True -> healthy True.
   - Informational system accounts alone -> healthy True.
   - Any balance mismatch -> healthy False.
   - Any counter mismatch -> healthy False.
   - global_balanced=False -> healthy False.
3. Counter mismatch severity classification:
   - redis < db -> 'under'
   - redis > db -> 'over'
   - redis == db -> 'clean'
4. Single-line guarantee: JSON output contains no unescaped newlines (Loki stream requirement).
5. Exit-code mapping: 0 on healthy, 1 on mismatches found, 2 on operational exception.
6. Retention policy literals meta-test: module constants match 30-day requirement.
"""

import json
from typing import Final

import pytest

from fluxpay.workers.reconciliation import (
    EXIT_MISMATCH_FOUND,
    EXIT_MISMATCHES,
    EXIT_OK,
    EXIT_OPS_FAILURE,
    IDEMPOTENCY_RETENTION_DAYS,
    RETENTION_COMPLETED_DAYS,
    RETENTION_FAILED_DAYS,
    BalanceMismatch,
    CounterMismatch,
    ReconcileReport,
    SystemAccountState,
    build_report,
    classify_counter_mismatch,
    compute_healthy,
    determine_exit_code,
    map_exit_code,
)

pytestmark = pytest.mark.unit

# Exact locked report keys emitted by build_report to stdout
LOCKED_REPORT_KEYS: Final[frozenset[str]] = frozenset(
    [
        "mode",
        "checked_at",
        "healthy",
        "accounts_checked",
        "balance_mismatches",
        "counter_mismatches",
        "global_debits",
        "global_credits",
        "global_balanced",
        "purged_idempotency",
        "dead_deliveries",
        "system_accounts",
    ]
)


def test_build_report_payload_shape_healthy() -> None:
    """Verify healthy ReconcileReport produces exact locked keys and valid JSON."""
    report = ReconcileReport(
        checked_at="2026-09-27T04:00:00Z",
        accounts_checked=42,
        balance_mismatches=(),
        counter_mismatches=(),
        global_debits=100_000,
        global_credits=100_000,
        global_balanced=True,
        purged_idempotency=5,
        dead_deliveries=1,
        system_accounts=(
            SystemAccountState(
                account_id="aa51a413-b2f4-5bba-9be1-96ed6c605853",
                cached=50_000_000,
                computed=0,
                implied_genesis=50_000_000,
                owner_type="treasury",
            ),
        ),
        healthy=True,
    )

    line = build_report(report)
    data = json.loads(line)

    assert frozenset(data.keys()) == LOCKED_REPORT_KEYS
    assert data["mode"] == "reconciliation"
    assert data["healthy"] is True
    assert data["checked_at"] == "2026-09-27T04:00:00Z"
    assert data["accounts_checked"] == 42
    assert data["balance_mismatches"] == []
    assert data["counter_mismatches"] == []
    assert data["global_debits"] == 100_000
    assert data["global_credits"] == 100_000
    assert data["global_balanced"] is True
    assert data["purged_idempotency"] == 5
    assert data["dead_deliveries"] == 1
    assert len(data["system_accounts"]) == 1
    assert data["system_accounts"][0]["account_id"] == "aa51a413-b2f4-5bba-9be1-96ed6c605853"
    assert data["system_accounts"][0]["implied_genesis"] == 50_000_000


def test_build_report_payload_shape_mismatches() -> None:
    """Verify mismatched state produces exact locked keys with healthy=False."""
    balance_mismatch = BalanceMismatch(
        account_id="11111111-1111-1111-1111-111111111111",
        owner_type="agent",
        cached_balance=500,
        computed_balance=400,
        delta=100,
    )
    counter_mismatch = CounterMismatch(
        agent_id="22222222-2222-2222-2222-222222222222",
        day="20260927",
        redis_value=1500,
        db_value=1000,
        delta=500,
        reason="over",
    )

    report = ReconcileReport(
        checked_at="2026-09-27T04:00:00Z",
        accounts_checked=10,
        balance_mismatches=(balance_mismatch,),
        counter_mismatches=(counter_mismatch,),
        global_debits=1000,
        global_credits=1000,
        global_balanced=True,
        purged_idempotency=0,
        dead_deliveries=0,
        system_accounts=(),
        healthy=False,
    )

    line = build_report(report)
    data = json.loads(line)

    assert frozenset(data.keys()) == LOCKED_REPORT_KEYS
    assert data["healthy"] is False
    assert len(data["balance_mismatches"]) == 1
    assert data["balance_mismatches"][0]["account_id"] == "11111111-1111-1111-1111-111111111111"
    assert data["balance_mismatches"][0]["delta"] == 100
    assert len(data["counter_mismatches"]) == 1
    assert data["counter_mismatches"][0]["reason"] == "over"
    assert data["counter_mismatches"][0]["delta"] == 500


def test_healthy_derivation_logic() -> None:
    """Test pure healthy derivation across all combinations of inputs."""
    bm = BalanceMismatch("a1", "agent", 10, 5, 5)
    cm = CounterMismatch("c1", "20260927", 10, 5, 5, "over")

    # Case 1: completely clean -> True
    assert compute_healthy((), (), True) is True

    # Case 2: balance mismatch present -> False
    assert compute_healthy((bm,), (), True) is False

    # Case 3: counter mismatch present -> False
    assert compute_healthy((), (cm,), True) is False

    # Case 4: global debits != credits -> False
    assert compute_healthy((), (), False) is False

    # Case 5: informational system account with implied_genesis >= 0 stays healthy
    report = ReconcileReport(
        checked_at="2026-09-27T04:00:00Z",
        accounts_checked=3,
        balance_mismatches=(),
        counter_mismatches=(),
        global_debits=0,
        global_credits=0,
        global_balanced=True,
        purged_idempotency=0,
        dead_deliveries=0,
        system_accounts=(
            SystemAccountState("sys1", 1_000_000, 0, 1_000_000, "system"),
            SystemAccountState("treasury1", 50_000_000, 0, 50_000_000, "treasury"),
        ),
    )
    assert report.healthy is True

    # Case 6: system account with negative implied genesis recorded as balance mismatch -> False
    neg_genesis_bm = BalanceMismatch("sys1", "system", 100, 200, -100)
    report_neg = ReconcileReport(
        checked_at="2026-09-27T04:00:00Z",
        accounts_checked=3,
        balance_mismatches=(neg_genesis_bm,),
        counter_mismatches=(),
        global_debits=200,
        global_credits=200,
        global_balanced=True,
        purged_idempotency=0,
        dead_deliveries=0,
        system_accounts=(SystemAccountState("sys1", 100, 200, -100, "system"),),
    )
    assert report_neg.healthy is False


def test_build_report_single_line_guarantee() -> None:
    """Verify report string and raw bytes contain no unescaped newlines."""
    report = ReconcileReport(
        checked_at="2026-09-27T04:00:00Z",
        accounts_checked=1,
        balance_mismatches=(),
        counter_mismatches=(),
        global_debits=10,
        global_credits=10,
        global_balanced=True,
        purged_idempotency=0,
        dead_deliveries=0,
        system_accounts=(),
        healthy=True,
    )

    line = build_report(report)
    assert "\n" not in line
    assert "\r" not in line

    raw_bytes = line.encode("utf-8")
    assert b"\n" not in raw_bytes
    assert b"\r" not in raw_bytes


def test_counter_mismatch_classification_pure() -> None:
    """Verify pure classification of Redis vs DB counter drift."""
    # Under: Redis < DB (lost increment due to restart/crash)
    assert classify_counter_mismatch(0, 100) == "under"
    assert classify_counter_mismatch(50, 100) == "under"

    # Over: Redis > DB (double increment / phantom settle)
    assert classify_counter_mismatch(100, 0) == "over"
    assert classify_counter_mismatch(150, 100) == "over"

    # Clean: Redis == DB
    assert classify_counter_mismatch(100, 100) == "clean"
    assert classify_counter_mismatch(0, 0) == "clean"


def test_exit_code_mapping_pure() -> None:
    """Verify exit code mapping contracts: 0 ok, 1 mismatch, 2 ops failure."""
    healthy_report = ReconcileReport(
        checked_at="2026-09-27T04:00:00Z",
        accounts_checked=1,
        balance_mismatches=(),
        counter_mismatches=(),
        global_debits=0,
        global_credits=0,
        global_balanced=True,
        purged_idempotency=0,
        dead_deliveries=0,
        system_accounts=(),
        healthy=True,
    )
    assert map_exit_code(healthy_report) == EXIT_OK
    assert determine_exit_code(healthy_report) == EXIT_OK

    unhealthy_report = ReconcileReport(
        checked_at="2026-09-27T04:00:00Z",
        accounts_checked=1,
        balance_mismatches=(BalanceMismatch("a", "agent", 10, 0, 10),),
        counter_mismatches=(),
        global_debits=0,
        global_credits=0,
        global_balanced=True,
        purged_idempotency=0,
        dead_deliveries=0,
        system_accounts=(),
        healthy=False,
    )
    assert map_exit_code(unhealthy_report) == EXIT_MISMATCHES
    assert determine_exit_code(unhealthy_report) == EXIT_MISMATCH_FOUND

    # Direct healthy flags
    assert map_exit_code(healthy=True) == EXIT_OK
    assert map_exit_code(healthy=False) == EXIT_MISMATCHES

    # Operational failures
    assert map_exit_code(error=ConnectionRefusedError("Dead PG port")) == EXIT_OPS_FAILURE
    assert map_exit_code(healthy_report, error=RuntimeError("Valkey down")) == EXIT_OPS_FAILURE
    assert map_exit_code(report=None) == EXIT_OPS_FAILURE


def test_retention_sql_constants_meta() -> None:
    """Meta-test asserting code-side retention policy literals match specification."""
    assert IDEMPOTENCY_RETENTION_DAYS == 30
    assert RETENTION_COMPLETED_DAYS == 30
    assert RETENTION_FAILED_DAYS == 30
    assert EXIT_OK == 0
    assert EXIT_MISMATCHES == 1
    assert EXIT_MISMATCH_FOUND == 1
    assert EXIT_OPS_FAILURE == 2
