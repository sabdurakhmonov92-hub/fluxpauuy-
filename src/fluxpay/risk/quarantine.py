"""HITL Quarantine Queue Service managing payment holds.

==============================================================================
CONVERGENCE OF IDEMPOTENCY & APPROVAL (THE SETTLEMENT REPLAY ESSAY)
==============================================================================
A fundamental safety invariant of FluxPay is that MONEY IS NEVER MOVED BY
APPROVAL ALONE.

When a payment breaches a financial policy threshold (Task 28), it is placed
into Human-In-The-Loop (HITL) quarantine via QuarantineService.place_hold.
At that instant:
1. The payment has an active Task 11 idempotency reservation (status='reserved'
   or 'held') bound to the agent's unique idem_key in PostgreSQL/Redis.
2. The payment record is captured in payment_holds with the EXACT same idem_key.
3. No ledger entries have been written; source funds remain untouched.

When an authorized human or multi-party approval process (Task 42) approves the hold:
1. QuarantineService.decide atomically transitions payment_holds.status to 'approved'.
   This is purely an administrative state transition. No money moves in this function.
2. The approval worker (Task 42) takes the approved HoldRecord and invokes Task 31's
   payment settlement pipeline using the ORIGINAL idem_key.
3. Because the settlement pipeline consumes the original idem_key, Task 11's
   idempotency reservation mechanism recognizes this execution as the authoritative
   settlement pass.
4. The entire idempotency stack (Task 11 reservation -> Task 28 quarantine ->
   Task 42 approval -> Task 31 ledger settlement) converges here: approval does not
   invent a second payment flow; it safely unlocks and replays the original one.

==============================================================================
SAFE SINGLE-DECISION PRIMITIVE & 2-MAN RULE PLACEMENT
==============================================================================
QuarantineService.decide provides atomic single-decision semantics with a strict
double-decide guard:
- The UPDATE statement conditions on `status = 'pending'`.
- If two approvers or workers race to decide the same hold, exactly one worker
  succeeds and receives the updated HoldRecord. The other worker receives None.
- Two-person rule (dual authorization / quorum) orchestration belongs to Task 42
  built on TOP of this safe atomic primitive. QuarantineService guarantees that
  the underlying queue state cannot be corrupted or double-decided.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import orjson

from fluxpay.contracts.schemas import CURRENCY_PATTERN

VALID_HOLD_REASONS: Final[frozenset[str]] = frozenset(
    {"single_tx_ceiling", "daily_cap", "velocity", "manual"}
)


@dataclass(frozen=True, slots=True)
class HoldRecord:
    """Immutable representation of a payment hold record."""

    hold_id: UUID
    agent_id: UUID
    idem_key: str
    amount_minor: int
    currency: str
    reason: str
    status: str
    created_at: datetime
    payload: dict[str, Any] = field(default_factory=dict)
    updated_at: datetime | None = None


class QuarantineService:
    """HITL quarantine queue service managing payment holds."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def place_hold(
        self,
        *,
        agent_id: UUID,
        idem_key: str,
        amount_minor: int,
        currency: str,
        reason: str,
        payload: dict[str, Any] | None = None,
    ) -> HoldRecord:
        """Place or update a payment hold idempotently.

        WHY idempotent re-place:
        The same logical payment re-quarantined (e.g. agent retry with same idempotency key)
        maps to the exact same hold row (ON CONFLICT DO UPDATE).
        This guarantees the Task 11 reservation pairing remains strictly 1:1.
        """
        if amount_minor <= 0:
            raise ValueError(f"amount_minor must be > 0, got {amount_minor}")
        if not re.match(CURRENCY_PATTERN, currency):
            raise ValueError(f"Invalid currency '{currency}'; must match {CURRENCY_PATTERN}")
        if reason not in VALID_HOLD_REASONS:
            raise ValueError(
                f"Invalid hold reason '{reason}'; must be one of {sorted(VALID_HOLD_REASONS)}"
            )
        if not idem_key:
            raise ValueError("idem_key must be non-empty")

        raw_payload = orjson.dumps(payload or {}).decode("utf-8")

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO payment_holds (
                    agent_id, idem_key, amount_minor, currency, reason,
                    status, payload, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, 'pending', $6::jsonb, now(), now())
                ON CONFLICT (agent_id, idem_key) DO UPDATE SET
                    updated_at = now(),
                    payload = payment_holds.payload || EXCLUDED.payload
                RETURNING
                    hold_id, agent_id, idem_key, amount_minor, currency,
                    reason, status, payload, created_at, updated_at;
                """,
                agent_id,
                idem_key,
                amount_minor,
                currency,
                reason,
                raw_payload,
            )

        if row is None:
            raise RuntimeError("Failed to insert or update payment_holds row")

        loaded_payload: dict[str, Any] = (
            json.loads(row["payload"]) if isinstance(row["payload"], str) else dict(row["payload"])
        )

        return HoldRecord(
            hold_id=row["hold_id"],
            agent_id=row["agent_id"],
            idem_key=row["idem_key"],
            amount_minor=row["amount_minor"],
            currency=row["currency"],
            reason=row["reason"],
            status=row["status"],
            created_at=row["created_at"],
            payload=loaded_payload,
            updated_at=row["updated_at"],
        )

    async def decide(
        self,
        hold_id: UUID,
        *,
        approved: bool,
    ) -> HoldRecord | None:
        """Atomically decide a pending hold (approve or reject).

        Returns the updated HoldRecord on success, or None if the hold was
        already decided or not found (double-decide guard).
        """
        target_status = "approved" if approved else "rejected"
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE payment_holds
                SET status = $2,
                    updated_at = now()
                WHERE hold_id = $1 AND status = 'pending'
                RETURNING
                    hold_id, agent_id, idem_key, amount_minor, currency,
                    reason, status, payload, created_at, updated_at;
                """,
                hold_id,
                target_status,
            )

        if row is None:
            return None

        loaded_payload: dict[str, Any] = (
            json.loads(row["payload"]) if isinstance(row["payload"], str) else dict(row["payload"])
        )

        return HoldRecord(
            hold_id=row["hold_id"],
            agent_id=row["agent_id"],
            idem_key=row["idem_key"],
            amount_minor=row["amount_minor"],
            currency=row["currency"],
            reason=row["reason"],
            status=row["status"],
            created_at=row["created_at"],
            payload=loaded_payload,
            updated_at=row["updated_at"],
        )

    async def list_pending(self, *, limit: int = 50) -> tuple[HoldRecord, ...]:
        """Query pending holds queue ordered by created_at ascending (oldest first)."""
        if not (1 <= limit <= 200):
            raise ValueError(f"limit must be between 1 and 200, got {limit}")

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                    hold_id, agent_id, idem_key, amount_minor, currency,
                    reason, status, payload, created_at, updated_at
                FROM payment_holds
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT $1;
                """,
                limit,
            )

        records: list[HoldRecord] = []
        for row in rows:
            loaded_payload: dict[str, Any] = (
                json.loads(row["payload"])
                if isinstance(row["payload"], str)
                else dict(row["payload"])
            )
            records.append(
                HoldRecord(
                    hold_id=row["hold_id"],
                    agent_id=row["agent_id"],
                    idem_key=row["idem_key"],
                    amount_minor=row["amount_minor"],
                    currency=row["currency"],
                    reason=row["reason"],
                    status=row["status"],
                    created_at=row["created_at"],
                    payload=loaded_payload,
                    updated_at=row["updated_at"],
                )
            )
        return tuple(records)

    # --- Task 34 append
    async def count_open(self, agent_id: UUID) -> int:
        """Count pending holds for an agent (saturation signal)."""
        async with self._pool.acquire() as conn:
            val = await conn.fetchval(
                "SELECT COUNT(*) FROM payment_holds WHERE status = 'pending' AND agent_id = $1;",
                agent_id,
            )
            return int(val or 0)
