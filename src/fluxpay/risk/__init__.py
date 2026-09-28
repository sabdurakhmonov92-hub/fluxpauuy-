"""Risk engine subsystem: effective financial limits and HITL quarantine queue.

Risk Map:
- limits.py (THIS: financial policy + risk engine):
    Defines per-agent spending ceilings, velocity limits, and daily outflow caps.
    Pure decision core (evaluate) + I/O shell (check_payment) consumed by Task 31's
    payment settlement service BEFORE any ledger entry is created.
- quarantine.py (THIS: Human-In-The-Loop quarantine queue):
    HITL hold queue (payment_holds) storing quarantined payments awaiting manual review.
    Provides idempotent hold placement and atomic approval/rejection primitives.
- Approvals worker = Task 42:
    Consumes pending holds from QuarantineService and coordinates two-man rule decisions
    and idempotent settlement replay.
- Outflow counter reconciliation worker = Task 41:
    Audits Redis outflow counters against PostgreSQL ledger truth as a compensating control.

Layering Invariant:
NO direct imports from gateway. The risk subsystem is a downstream financial control layer;
it must never import gateway middleware, routing, or protocol transport concerns.
"""

from fluxpay.risk.limits import (
    DEFAULT_LIMITS,
    AgentLimits,
    LimitRepo,
    RiskDecision,
    RiskEngine,
    check_payment,
    evaluate,
)
from fluxpay.risk.quarantine import (
    HoldRecord,
    QuarantineService,
)
from fluxpay.shared.errors import PaymentPolicyError

__all__ = [
    "DEFAULT_LIMITS",
    "AgentLimits",
    "HoldRecord",
    "LimitRepo",
    "PaymentPolicyError",
    "QuarantineService",
    "RiskDecision",
    "RiskEngine",
    "check_payment",
    "evaluate",
]
