"""Unit tests for Dual-Authorization 2-Man Rule Policy (Task 42 - Pure Logic).

Exercises quorum rules, rejection asymmetry, role gates, duplicate vote classification,
and the HoldNotPendingError registry contract without I/O or network dependencies.
"""

from __future__ import annotations

import pytest

from fluxpay.approvals.service import (
    REJECTS_TERMINAL,
    VOTES_REQUIRED,
    HoldNotPendingError,
    VoteOutcome,
    check_voter_role,
    classify_vote,
    decide_from_votes,
)
from fluxpay.contracts.schemas import ErrorEnvelope
from fluxpay.shared.errors import ERROR_REGISTRY, ForbiddenError


# ------------------------------------------------------------------------------
# 1. PURE VOTE COUNTING & ASYMMETRY (REJECTS_TERMINAL LAW)
# ------------------------------------------------------------------------------
@pytest.mark.unit
def test_policy_constants_frozen() -> None:
    """Validate frozen policy constants for Task 42."""
    assert VOTES_REQUIRED == 2
    assert REJECTS_TERMINAL is True


@pytest.mark.unit
@pytest.mark.parametrize(
    ("votes_for", "votes_against", "expected_outcome"),
    [
        (0, 0, "counted"),
        (1, 0, "counted"),
        (2, 0, "approved_settled"),
        (3, 0, "approved_settled"),
        (0, 1, "rejected"),
        (1, 1, "rejected"),
        (2, 1, "rejected"),  # 2 approves + 1 reject -> rejected (asymmetry)
        (3, 1, "rejected"),  # threshold exceeded but reject present -> rejected
        (0, 2, "rejected"),
        (1, 2, "rejected"),
        (2, 2, "rejected"),
    ],
)
def test_decide_from_votes_pure(votes_for: int, votes_against: int, expected_outcome: str) -> None:
    """Validate quorum evaluation with absolute reject terminal asymmetry.

    Product Decision Law:
    An approver seeing fraud must stop it instantly, never racing a second approver.
    2 approves + 1 reject decisively resolves as rejected.
    """
    assert decide_from_votes(votes_for, votes_against) == expected_outcome


# ------------------------------------------------------------------------------
# 2. ROLE GATE: SUPPORT OPERATOR 403 ENFORCEMENT
# ------------------------------------------------------------------------------
@pytest.mark.unit
def test_check_voter_role_admin_permitted() -> None:
    """Ensure administrator role passes check without error."""
    # Should not raise
    check_voter_role("admin")


@pytest.mark.unit
@pytest.mark.parametrize("invalid_role", ["support", "agent", "merchant", "user", "", "viewer"])
def test_check_voter_role_non_admin_forbidden(invalid_role: str) -> None:
    """Ensure non-admin roles raise ForbiddenError (403 family).

    Separation of Duties Law:
    Support operators can view and debug holds, but cannot approve money movement.
    """
    with pytest.raises(ForbiddenError) as exc_info:
        check_voter_role(invalid_role)

    err = exc_info.value
    assert err.status == 403
    assert err.code == "forbidden"
    assert not err.retryable


# ------------------------------------------------------------------------------
# 3. DUPLICATE VOTE CLASSIFICATION
# ------------------------------------------------------------------------------
@pytest.mark.unit
def test_classify_vote_already_voted() -> None:
    """Validate that already_voted=True immediately classifies as 'already_voted'."""
    assert classify_vote(already_voted=True, votes_for=1, votes_against=0) == "already_voted"
    assert classify_vote(already_voted=True, votes_for=2, votes_against=0) == "already_voted"
    assert classify_vote(already_voted=True, votes_for=0, votes_against=1) == "already_voted"


@pytest.mark.unit
def test_classify_vote_fresh() -> None:
    """Validate that already_voted=False delegates to decide_from_votes."""
    assert classify_vote(already_voted=False, votes_for=1, votes_against=0) == "counted"
    assert classify_vote(already_voted=False, votes_for=2, votes_against=0) == "approved_settled"
    assert classify_vote(already_voted=False, votes_for=1, votes_against=1) == "rejected"


# ------------------------------------------------------------------------------
# 4. HOLD NOT PENDING ERROR REGISTRY CONTRACT
# ------------------------------------------------------------------------------
@pytest.mark.unit
def test_hold_not_pending_error_registered() -> None:
    """Validate that HoldNotPendingError is properly registered in ERROR_REGISTRY."""
    assert HoldNotPendingError.code in ERROR_REGISTRY
    assert ERROR_REGISTRY[HoldNotPendingError.code] is HoldNotPendingError

    err = HoldNotPendingError(details={"hold_id": "test-uuid", "status": "approved"})
    assert err.code == "hold_not_pending"
    assert err.status == 409
    assert err.retryable is False

    # Verify ErrorEnvelope wire contract roundtrip
    payload = err.to_payload()
    envelope = ErrorEnvelope.model_validate(payload)
    assert envelope.error.code == "hold_not_pending"
    assert envelope.error.retryable is False


# ------------------------------------------------------------------------------
# 5. VOTE OUTCOME SHAPE
# ------------------------------------------------------------------------------
@pytest.mark.unit
def test_vote_outcome_immutability_and_dict() -> None:
    """Verify VoteOutcome dataclass slots and dictionary serialization."""
    outcome = VoteOutcome(status="counted", votes_for=1, votes_against=0)
    assert outcome.status == "counted"
    assert outcome.votes_for == 1
    assert outcome.votes_against == 0

    d = outcome.to_dict()
    assert d == {
        "status": "counted",
        "votes_for": 1,
        "votes_against": 0,
    }
