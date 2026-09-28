"""Unit tests for the risk rules-as-data framework and policy evaluation matrix.

Validates:
1. Each individual rule boundary condition:
   - ceiling_rule: == max -> allow, +1 -> hold 'single_tx_ceiling'
   - daily_cap_rule: == cap -> allow, +1 -> hold 'daily_cap'
   - velocity_rule: == limit - 1 -> allow, == limit -> reject 'velocity'
   - saturation_rule: 4 holds -> allow, 5 holds -> hold 'queue_saturation'
2. Immutable order freeze: meta-test pinning DEFAULT_RULES function sequence.
3. First-non-allow precedence: ceiling breaches take priority over cap and velocity.
4. Defensive PaymentContext invariant validation (negative amounts/counters, naive datetimes).
5. Dynamic rule composition: custom rule tuples evaluate cleanly without modifying codebase.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from fluxpay.risk.limits import AgentLimits
from fluxpay.risk.rules import (
    DEFAULT_RULES,
    PaymentContext,
    RuleResult,
    ceiling_rule,
    daily_cap_rule,
    evaluate_rules,
    saturation_rule,
    velocity_rule,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def baseline_limits() -> AgentLimits:
    """Standard limits fixture matching default financial policy."""
    return AgentLimits(
        agent_id=uuid4(),
        velocity_limit=5,
        velocity_window_s=60,
        max_single_tx_minor=100_000_000,  # $100
        daily_outflow_cap_minor=500_000_000,  # $500
    )


def make_ctx(
    limits: AgentLimits,
    *,
    amount_minor: int = 10_000_000,
    outflow_today_minor: int = 0,
    recent_count: int = 1,
    hold_open_count: int = 0,
    now: datetime | None = None,
) -> PaymentContext:
    """Helper creating valid PaymentContext with defaults."""
    return PaymentContext(
        agent_id=limits.agent_id or uuid4(),
        amount_minor=amount_minor,
        currency="USD",
        limits=limits,
        outflow_today_minor=outflow_today_minor,
        recent_count=recent_count,
        hold_open_count=hold_open_count,
        now=now or datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC),
    )


# ==============================================================================
# 1. INDIVIDUAL RULE BOUNDARIES
# ==============================================================================


def test_ceiling_rule_boundary_pass(baseline_limits: AgentLimits) -> None:
    """Ceiling rule allows transaction strictly equal to max_single_tx_minor."""
    ctx = make_ctx(baseline_limits, amount_minor=baseline_limits.max_single_tx_minor)
    result = ceiling_rule(ctx)
    assert result == RuleResult(verdict="allow", reason=None)


def test_ceiling_rule_boundary_trigger(baseline_limits: AgentLimits) -> None:
    """Ceiling rule holds transaction strictly greater than max_single_tx_minor."""
    ctx = make_ctx(baseline_limits, amount_minor=baseline_limits.max_single_tx_minor + 1)
    result = ceiling_rule(ctx)
    assert result == RuleResult(verdict="hold", reason="single_tx_ceiling")


def test_daily_cap_rule_boundary_pass(baseline_limits: AgentLimits) -> None:
    """Daily cap rule allows when cumulative outflow equals daily_outflow_cap_minor."""
    outflow = 400_000_000
    amount = 100_000_000
    assert outflow + amount == baseline_limits.daily_outflow_cap_minor

    ctx = make_ctx(baseline_limits, amount_minor=amount, outflow_today_minor=outflow)
    result = daily_cap_rule(ctx)
    assert result == RuleResult(verdict="allow", reason=None)


def test_daily_cap_rule_boundary_trigger(baseline_limits: AgentLimits) -> None:
    """Daily cap rule holds when cumulative outflow exceeds daily_outflow_cap_minor by 1."""
    outflow = 400_000_000
    amount = 100_000_001
    assert outflow + amount == baseline_limits.daily_outflow_cap_minor + 1

    ctx = make_ctx(baseline_limits, amount_minor=amount, outflow_today_minor=outflow)
    result = daily_cap_rule(ctx)
    assert result == RuleResult(verdict="hold", reason="daily_cap")


def test_velocity_rule_boundary_pass(baseline_limits: AgentLimits) -> None:
    """Velocity rule allows when recent_count is strictly below velocity_limit."""
    ctx = make_ctx(baseline_limits, recent_count=baseline_limits.velocity_limit - 1)
    result = velocity_rule(ctx)
    assert result == RuleResult(verdict="allow", reason=None)


def test_velocity_rule_boundary_trigger(baseline_limits: AgentLimits) -> None:
    """Velocity rule hard-rejects when recent_count reaches velocity_limit (>= boundary)."""
    ctx = make_ctx(baseline_limits, recent_count=baseline_limits.velocity_limit)
    result = velocity_rule(ctx)
    assert result == RuleResult(verdict="reject", reason="velocity")


def test_saturation_rule_boundary_pass(baseline_limits: AgentLimits) -> None:
    """Saturation rule allows when open holds count is 4 (below threshold 5)."""
    ctx = make_ctx(baseline_limits, hold_open_count=4)
    result = saturation_rule(ctx)
    assert result == RuleResult(verdict="allow", reason=None)


def test_saturation_rule_boundary_trigger(baseline_limits: AgentLimits) -> None:
    """Saturation rule holds when open holds count reaches 5 (queue saturation guard)."""
    ctx = make_ctx(baseline_limits, hold_open_count=5)
    result = saturation_rule(ctx)
    assert result == RuleResult(verdict="hold", reason="queue_saturation")


# ==============================================================================
# 2. ORDER FREEZE & META-TEST
# ==============================================================================


def test_default_rules_order_frozen() -> None:
    """Meta-test pinning the exact function order of DEFAULT_RULES.

    Reordering rules alters product behavior and fraud enforcement semantics.
    Order Invariant: ceiling -> daily_cap -> velocity -> saturation.
    """
    expected_order = (
        "ceiling_rule",
        "daily_cap_rule",
        "velocity_rule",
        "saturation_rule",
    )
    actual_order = tuple(fn.__name__ for fn in DEFAULT_RULES)
    assert actual_order == expected_order, (
        f"DEFAULT_RULES sequence changed! Expected {expected_order}, got {actual_order}"
    )


# ==============================================================================
# 3. PRECEDENCE & FIRST-NON-ALLOW PROOF
# ==============================================================================


def test_first_match_ceiling_beats_cap(baseline_limits: AgentLimits) -> None:
    """When both ceiling and cap are breached, ceiling wins (most specific first)."""
    ctx = make_ctx(
        baseline_limits,
        amount_minor=150_000_000,  # > $100 ceiling
        outflow_today_minor=450_000_000,  # 450 + 150 = 600 > $500 cap
    )
    res = evaluate_rules(ctx, DEFAULT_RULES)
    assert res == RuleResult(verdict="hold", reason="single_tx_ceiling")


def test_first_match_ceiling_beats_velocity(baseline_limits: AgentLimits) -> None:
    """When ceiling and velocity are both breached, ceiling wins."""
    ctx = make_ctx(
        baseline_limits,
        amount_minor=150_000_000,  # > $100 ceiling
        recent_count=10,  # > 5 velocity
    )
    res = evaluate_rules(ctx, DEFAULT_RULES)
    assert res == RuleResult(verdict="hold", reason="single_tx_ceiling")


def test_first_match_cap_beats_velocity(baseline_limits: AgentLimits) -> None:
    """When cap and velocity are both breached, cap wins."""
    ctx = make_ctx(
        baseline_limits,
        amount_minor=50_000_000,  # <= $100 ceiling
        outflow_today_minor=480_000_000,  # 480 + 50 = 530 > $500 cap
        recent_count=10,  # > 5 velocity
    )
    res = evaluate_rules(ctx, DEFAULT_RULES)
    assert res == RuleResult(verdict="hold", reason="daily_cap")


def test_first_match_velocity_beats_saturation(baseline_limits: AgentLimits) -> None:
    """When velocity and saturation are both breached, velocity reject wins."""
    ctx = make_ctx(
        baseline_limits,
        amount_minor=10_000_000,  # within ceiling and cap
        recent_count=5,  # velocity breach
        hold_open_count=8,  # saturation breach
    )
    res = evaluate_rules(ctx, DEFAULT_RULES)
    assert res == RuleResult(verdict="reject", reason="velocity")


# ==============================================================================
# 4. PAYMENT CONTEXT DEFENSIVE VALIDATION
# ==============================================================================


def test_payment_context_rejects_non_positive_amount(baseline_limits: AgentLimits) -> None:
    """PaymentContext rejects amount_minor <= 0."""
    with pytest.raises(ValueError, match="amount_minor must be > 0"):
        make_ctx(baseline_limits, amount_minor=0)

    with pytest.raises(ValueError, match="amount_minor must be > 0"):
        make_ctx(baseline_limits, amount_minor=-500)


def test_payment_context_rejects_naive_datetime(baseline_limits: AgentLimits) -> None:
    """PaymentContext rejects naive datetime without timezone info."""
    naive_dt = datetime(2026, 9, 26, 12, 0, 0)
    with pytest.raises(ValueError, match="now must be a timezone-aware datetime"):
        make_ctx(baseline_limits, now=naive_dt)


def test_payment_context_rejects_negative_counters(baseline_limits: AgentLimits) -> None:
    """PaymentContext rejects negative counters."""
    with pytest.raises(ValueError, match="outflow_today_minor must be >= 0"):
        make_ctx(baseline_limits, outflow_today_minor=-1)

    with pytest.raises(ValueError, match="recent_count must be >= 0"):
        make_ctx(baseline_limits, recent_count=-1)

    with pytest.raises(ValueError, match="hold_open_count must be >= 0"):
        make_ctx(baseline_limits, hold_open_count=-1)


# ==============================================================================
# 5. RULES-AS-DATA COMPOSITION
# ==============================================================================


def test_custom_rules_composition(baseline_limits: AgentLimits) -> None:
    """Demonstrate policy-as-data: injecting custom rule tuple."""
    # A tenant with no velocity check, only saturation and ceiling
    custom_rules = (saturation_rule, ceiling_rule)
    ctx = make_ctx(
        baseline_limits,
        amount_minor=10_000_000,
        recent_count=100,  # would trigger velocity, but velocity rule is absent
        hold_open_count=1,
    )
    res = evaluate_rules(ctx, custom_rules)
    assert res == RuleResult(verdict="allow", reason=None)
