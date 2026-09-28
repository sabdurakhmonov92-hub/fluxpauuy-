"""Unit tests verifying pure risk limits evaluation, boundary discipline, and contract invariants.

Validates:
1. Pure evaluate() classifier matrix (allow, single-ceiling, daily-cap, velocity).
2. Exact boundary conditions (strict > for ceilings/caps, >= for velocity).
3. Precedence doctrine: single_tx_ceiling takes precedence over daily_cap.
4. Input validation (positive amounts, timezone-aware datetimes, non-negative counters).
5. DEFAULT_LIMITS synchronization with 0007_limits.sql schema defaults (meta-test).
6. PaymentPolicyError registration, uniqueness, and retryable=False semantics.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from fluxpay.risk.limits import (
    DEFAULT_LIMITS,
    AgentLimits,
    RiskDecision,
    evaluate,
)
from fluxpay.shared.errors import ERROR_REGISTRY, PaymentPolicyError

pytestmark = pytest.mark.unit

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
MIGRATION_0007_PATH: Path = REPO_ROOT / "migrations" / "0007_limits.sql"


@pytest.fixture
def sample_limits() -> AgentLimits:
    """Sample limits matching default platform policy."""
    return AgentLimits(
        agent_id=uuid4(),
        velocity_limit=5,
        velocity_window_s=60,
        max_single_tx_minor=100_000_000,  # $100
        daily_outflow_cap_minor=500_000_000,  # $500
    )


# ==============================================================================
# 1. EVALUATE MATRIX & THREE-TIER BEHAVIOR
# ==============================================================================


def test_evaluate_allowed_tier_1(sample_limits: AgentLimits) -> None:
    """Validate Tier 1: Normal payment within all thresholds is allowed."""
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    decision = evaluate(
        limits=sample_limits,
        amount_minor=10_000_000,  # $10
        outflow_today_minor=50_000_000,  # $50
        recent_count=1,
        now=now,
    )
    assert decision == RiskDecision(allowed=True, quarantined=False, reason=None)


def test_evaluate_single_ceiling_quarantine_tier_3(sample_limits: AgentLimits) -> None:
    """Validate Tier 3: Single transaction exceeding ceiling is quarantined for HITL review."""
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    decision = evaluate(
        limits=sample_limits,
        amount_minor=150_000_000,  # $150 > $100
        outflow_today_minor=0,
        recent_count=1,
        now=now,
    )
    assert decision == RiskDecision(allowed=False, quarantined=True, reason="single_tx_ceiling")


def test_evaluate_daily_cap_quarantine_tier_3(sample_limits: AgentLimits) -> None:
    """Validate Tier 3: Cumulative daily outflow exceeding cap is quarantined for HITL review."""
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    decision = evaluate(
        limits=sample_limits,
        amount_minor=50_000_000,  # $50
        outflow_today_minor=480_000_000,  # $480 + $50 = $530 > $500
        recent_count=1,
        now=now,
    )
    assert decision == RiskDecision(allowed=False, quarantined=True, reason="daily_cap")


def test_evaluate_velocity_transient_reject_tier_2(sample_limits: AgentLimits) -> None:
    """Validate Tier 2: Velocity burst is hard-rejected (transient, no human queue spam)."""
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    decision = evaluate(
        limits=sample_limits,
        amount_minor=10_000_000,
        outflow_today_minor=50_000_000,
        recent_count=5,  # recent_count == velocity_limit (5)
        now=now,
    )
    assert decision == RiskDecision(allowed=False, quarantined=False, reason="velocity")


# ==============================================================================
# 2. EXACT BOUNDARY DISCIPLINE (KAT SPIRIT)
# ==============================================================================


def test_exact_boundary_single_ceiling(sample_limits: AgentLimits) -> None:
    """Validate strict > boundary for single transaction ceiling."""
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)

    # EXACT boundary: amount == max_single_tx_minor -> ALLOWED (strict >)
    decision_exact = evaluate(
        limits=sample_limits,
        amount_minor=100_000_000,
        outflow_today_minor=0,
        recent_count=0,
        now=now,
    )
    assert decision_exact.allowed is True
    assert decision_exact.quarantined is False
    assert decision_exact.reason is None

    # Boundary + 1: amount == max_single_tx_minor + 1 -> QUARANTINED
    decision_plus_one = evaluate(
        limits=sample_limits,
        amount_minor=100_000_001,
        outflow_today_minor=0,
        recent_count=0,
        now=now,
    )
    assert decision_plus_one.allowed is False
    assert decision_plus_one.quarantined is True
    assert decision_plus_one.reason == "single_tx_ceiling"


def test_exact_boundary_daily_cap(sample_limits: AgentLimits) -> None:
    """Validate strict > boundary for cumulative daily outflow cap."""
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)

    # EXACT boundary: outflow + amount == daily_outflow_cap_minor -> ALLOWED (strict >)
    decision_exact = evaluate(
        limits=sample_limits,
        amount_minor=50_000_000,
        outflow_today_minor=450_000_000,  # 450 + 50 = 500
        recent_count=0,
        now=now,
    )
    assert decision_exact.allowed is True
    assert decision_exact.quarantined is False
    assert decision_exact.reason is None

    # Boundary + 1: outflow + amount == daily_outflow_cap_minor + 1 -> QUARANTINED
    decision_plus_one = evaluate(
        limits=sample_limits,
        amount_minor=50_000_001,
        outflow_today_minor=450_000_000,  # 450 + 50.000001 = 500.000001 > 500
        recent_count=0,
        now=now,
    )
    assert decision_plus_one.allowed is False
    assert decision_plus_one.quarantined is True
    assert decision_plus_one.reason == "daily_cap"


def test_exact_boundary_velocity(sample_limits: AgentLimits) -> None:
    """Validate >= boundary for transient velocity threshold."""
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)

    # Boundary - 1: recent_count == velocity_limit - 1 (4 < 5) -> ALLOWED
    decision_minus_one = evaluate(
        limits=sample_limits,
        amount_minor=10_000_000,
        outflow_today_minor=0,
        recent_count=sample_limits.velocity_limit - 1,
        now=now,
    )
    assert decision_minus_one.allowed is True
    assert decision_minus_one.quarantined is False
    assert decision_minus_one.reason is None

    # EXACT boundary: recent_count == velocity_limit (5 == 5) -> REJECTED
    decision_exact = evaluate(
        limits=sample_limits,
        amount_minor=10_000_000,
        outflow_today_minor=0,
        recent_count=sample_limits.velocity_limit,
        now=now,
    )
    assert decision_exact.allowed is False
    assert decision_exact.quarantined is False
    assert decision_exact.reason == "velocity"


# ==============================================================================
# 3. PRECEDENCE DOCTRINE (FIRST MATCH WINS)
# ==============================================================================


def test_precedence_single_ceiling_over_daily_cap(sample_limits: AgentLimits) -> None:
    """When BOTH single_ceiling and daily_cap are breached, single_ceiling wins.

    Design Rationale:
    A transfer that exceeds the single ticket ceiling ($150 > $100) and simultaneously
    pushes today's outflow over the daily cap ($450 + $150 = $600 > $500) receives
    reason='single_tx_ceiling'.
    The single-transaction ceiling is the more specific, acute violation that must be
    presented to the human reviewer as the primary root cause.
    """
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    decision = evaluate(
        limits=sample_limits,
        amount_minor=150_000_000,  # Breaches single ceiling ($150 > $100)
        outflow_today_minor=450_000_000,  # Also breaches daily cap (450 + 150 > 500)
        recent_count=0,
        now=now,
    )
    assert decision.allowed is False
    assert decision.quarantined is True
    assert decision.reason == "single_tx_ceiling"


def test_precedence_ceiling_over_velocity(sample_limits: AgentLimits) -> None:
    """When a high-ticket payment occurs during a velocity burst, ceiling holds.

    Design Rationale:
    Quarantine (HITL) preserves the payment state for human review rather than
    silently dropping a potentially critical high-value transfer as a velocity reject.
    """
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    decision = evaluate(
        limits=sample_limits,
        amount_minor=200_000_000,  # Breaches single ceiling
        outflow_today_minor=0,
        recent_count=10,  # Also breaches velocity limit
        now=now,
    )
    assert decision.allowed is False
    assert decision.quarantined is True
    assert decision.reason == "single_tx_ceiling"


# ==============================================================================
# 4. INPUT VALIDATION DEFENSE
# ==============================================================================


def test_evaluate_input_validation(sample_limits: AgentLimits) -> None:
    """Verify defensive ValueError guards on invalid inputs."""
    aware_now = datetime.now(UTC)
    naive_now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Non-positive amount_minor
    with pytest.raises(ValueError, match="amount_minor must be > 0"):
        evaluate(
            limits=sample_limits,
            amount_minor=0,
            outflow_today_minor=0,
            recent_count=0,
            now=aware_now,
        )

    with pytest.raises(ValueError, match="amount_minor must be > 0"):
        evaluate(
            limits=sample_limits,
            amount_minor=-500,
            outflow_today_minor=0,
            recent_count=0,
            now=aware_now,
        )

    # 2. Timezone-naive datetime
    with pytest.raises(ValueError, match="now must be a timezone-aware datetime"):
        evaluate(
            limits=sample_limits,
            amount_minor=1000,
            outflow_today_minor=0,
            recent_count=0,
            now=naive_now,
        )

    # 3. Negative outflow_today_minor
    with pytest.raises(ValueError, match="outflow_today_minor must be >= 0"):
        evaluate(
            limits=sample_limits,
            amount_minor=1000,
            outflow_today_minor=-1,
            recent_count=0,
            now=aware_now,
        )

    # 4. Negative recent_count
    with pytest.raises(ValueError, match="recent_count must be >= 0"):
        evaluate(
            limits=sample_limits,
            amount_minor=1000,
            outflow_today_minor=0,
            recent_count=-1,
            now=aware_now,
        )


# ==============================================================================
# 5. META-TEST: DEFAULT_LIMITS SYNCHRONIZED WITH MIGRATION 0007_LIMITS.SQL
# ==============================================================================


def test_default_limits_mirrors_migration_schema_defaults() -> None:
    """Meta-test verifying zero drift between Python and PostgreSQL schema defaults."""
    assert MIGRATION_0007_PATH.is_file(), f"Missing migration file: {MIGRATION_0007_PATH}"
    sql_text = MIGRATION_0007_PATH.read_text(encoding="utf-8")

    # Match velocity_limit INT NOT NULL DEFAULT <n>
    m_vel = re.search(r"velocity_limit\s+INT\s+NOT\s+NULL\s+DEFAULT\s+(\d+)", sql_text)
    assert m_vel is not None, "Failed to parse velocity_limit default from 0007_limits.sql"
    sql_velocity_limit = int(m_vel.group(1))

    # Match velocity_window_s INT NOT NULL DEFAULT <n>
    m_win = re.search(r"velocity_window_s\s+INT\s+NOT\s+NULL\s+DEFAULT\s+(\d+)", sql_text)
    assert m_win is not None, "Failed to parse velocity_window_s default from 0007_limits.sql"
    sql_velocity_window_s = int(m_win.group(1))

    # Match max_single_tx_minor BIGINT NOT NULL DEFAULT <n>
    m_single = re.search(r"max_single_tx_minor\s+BIGINT\s+NOT\s+NULL\s+DEFAULT\s+(\d+)", sql_text)
    assert m_single is not None, "Failed to parse max_single_tx_minor default from 0007_limits.sql"
    sql_max_single = int(m_single.group(1))

    # Match daily_outflow_cap_minor BIGINT NOT NULL DEFAULT <n>
    m_daily = re.search(
        r"daily_outflow_cap_minor\s+BIGINT\s+NOT\s+NULL\s+DEFAULT\s+(\d+)", sql_text
    )
    assert m_daily is not None, (
        "Failed to parse daily_outflow_cap_minor default from 0007_limits.sql"
    )
    sql_daily_cap = int(m_daily.group(1))

    assert DEFAULT_LIMITS.velocity_limit == sql_velocity_limit == 5
    assert DEFAULT_LIMITS.velocity_window_s == sql_velocity_window_s == 60
    assert DEFAULT_LIMITS.max_single_tx_minor == sql_max_single == 100_000_000
    assert DEFAULT_LIMITS.daily_outflow_cap_minor == sql_daily_cap == 500_000_000


# ==============================================================================
# 6. PAYMENT POLICY ERROR CONTRACT LOCK
# ==============================================================================


def test_payment_policy_error_registered_and_contract_locked() -> None:
    """Verify PaymentPolicyError conforms to error contract and is properly registered."""
    err = PaymentPolicyError()

    assert err.code == "payment_policy_rejected"
    assert err.status == 422
    assert err.retryable is False
    assert err.message == "payment rejected by risk policy"

    # Registered in ERROR_REGISTRY
    assert err.code in ERROR_REGISTRY
    assert ERROR_REGISTRY[err.code] is PaymentPolicyError

    # Frozen wire payload validation
    payload = err.to_payload()
    assert payload == {
        "error": {
            "code": "payment_policy_rejected",
            "message": "payment rejected by risk policy",
            "retryable": False,
        }
    }
