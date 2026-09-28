"""=============================================================================
FluxPay Test Harness: In-Memory Payment Stack Fakes
=============================================================================
Provides unit-speed in-memory fakes for:
1. FakeLedgerStore (Task 17 re-export/mirror).
2. FakeAccountDirectory (in-memory account resolver).
3. FakeEventBus (records EventEnvelope instances).
4. FakeLimitRepo (in-memory agent limits store).
5. FakeQuarantineService (in-memory payment_holds queue).
6. FakeValkey (in-memory async Redis simulation).
7. FakeIdempotencyStore (in-memory Task 11 state machine mirror).
8. FakeUow / FakeUowFactory (zero-I/O context manager).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from _fakes.ledger import FakeLedgerStore
from fluxpay.risk.limits import DEFAULT_LIMITS, AgentLimits
from fluxpay.risk.quarantine import HoldRecord
from fluxpay.shared.errors import (
    IdempotencyConflict,
    IdempotencyStateError,
)
from fluxpay.shared.events import EventEnvelope, EventType
from fluxpay.shared.idempotency import (
    ClassificationAction,
    ExistingRecord,
    IdempotencyState,
    Reservation,
    ReservationOutcome,
    classify,
)
from fluxpay.wallet.accounts import (
    FEES_OWNER_ID,
    LedgerAccountRef,
)

__all__ = [
    "FakeAccountDirectory",
    "FakeEventBus",
    "FakeIdempotencyStore",
    "FakeLedgerStore",
    "FakeLimitRepo",
    "FakeQuarantineService",
    "FakeUow",
    "FakeValkey",
]


class FakeAccountDirectory:
    """In-memory account directory implementing AccountDirectory contract."""

    def __init__(self) -> None:
        self.agent_accounts: dict[tuple[UUID, str], LedgerAccountRef] = {}
        self.merchant_accounts: dict[tuple[str, str], LedgerAccountRef] = {}
        self.fees_accounts: dict[str, LedgerAccountRef] = {}
        self.system_accounts: dict[str, LedgerAccountRef] = {}
        self.treasury_accounts: dict[str, LedgerAccountRef] = {}

    def register_agent(self, agent_id: UUID, account_id: UUID, currency: str = "USDC") -> None:
        self.agent_accounts[(agent_id, currency)] = LedgerAccountRef(
            account_id=account_id,
            owner_type="agent",
            owner_id=agent_id,
            currency=currency,
        )

    def register_merchant(
        self,
        external_id: str,
        account_id: UUID,
        currency: str = "USDC",
        owner_id: UUID | None = None,
    ) -> None:
        self.merchant_accounts[(external_id, currency)] = LedgerAccountRef(
            account_id=account_id,
            owner_type="merchant",
            owner_id=owner_id or uuid.uuid4(),
            currency=currency,
        )

    def set_fees_account(self, account_id: UUID, currency: str = "USDC") -> None:
        self.fees_accounts[currency] = LedgerAccountRef(
            account_id=account_id,
            owner_type="fees",
            owner_id=FEES_OWNER_ID,
            currency=currency,
        )

    async def get_agent_account(self, agent_id: UUID, currency: str = "USDC") -> LedgerAccountRef:
        key = (agent_id, currency)
        if key not in self.agent_accounts:
            raise LookupError(f"Agent ledger account not found for agent_id='{agent_id}'")
        return self.agent_accounts[key]

    async def get_merchant_account(
        self, external_id: str, currency: str = "USDC"
    ) -> LedgerAccountRef:
        key = (external_id, currency)
        if key not in self.merchant_accounts:
            raise LookupError(f"Merchant ledger account not found for external_id='{external_id}'")
        return self.merchant_accounts[key]

    async def get_fees_account(self, currency: str = "USDC") -> LedgerAccountRef:
        if currency not in self.fees_accounts:
            raise LookupError(f"Fees ledger account not found for currency='{currency}'")
        return self.fees_accounts[currency]

    async def get_system_account(self, currency: str = "USDC") -> LedgerAccountRef:
        if currency not in self.system_accounts:
            raise LookupError(f"System account not found for currency='{currency}'")
        return self.system_accounts[currency]

    async def get_treasury_account(self, currency: str = "USDC") -> LedgerAccountRef:
        if currency not in self.treasury_accounts:
            raise LookupError(f"Treasury account not found for currency='{currency}'")
        return self.treasury_accounts[currency]


class FakeEventBus:
    """In-memory event bus capturing published EventEnvelope instances."""

    def __init__(self) -> None:
        self.published_events: list[EventEnvelope] = []

    async def publish(self, event: EventEnvelope) -> None:
        self.published_events.append(event)

    async def ensure_group(self, event_type: EventType, group: str) -> None:
        pass

    async def read_batch(
        self,
        event_type: EventType,
        group: str,
        consumer: str,
        *,
        count: int,
        block_ms: int,
    ) -> list[Any]:
        return []

    async def ack(self, event_type: EventType, group: str, delivery_id: str) -> None:
        pass

    async def claim_stale(
        self,
        event_type: EventType,
        group: str,
        consumer: str,
        *,
        min_idle_ms: int,
        count: int,
    ) -> list[Any]:
        return []


class FakeLimitRepo:
    """In-memory limit repository implementing LimitRepo contract."""

    def __init__(self) -> None:
        self.limits: dict[UUID, AgentLimits] = {}

    async def get(self, agent_id: UUID) -> AgentLimits:
        return self.limits.get(agent_id, DEFAULT_LIMITS)

    async def upsert(self, agent_id: UUID, limits: AgentLimits) -> None:
        self.limits[agent_id] = limits

    async def ensure_row(self, agent_id: UUID) -> None:
        if agent_id not in self.limits:
            self.limits[agent_id] = DEFAULT_LIMITS


class FakeQuarantineService:
    """In-memory quarantine service implementing QuarantineService contract."""

    def __init__(self) -> None:
        self.holds: list[HoldRecord] = []
        self._by_key: dict[tuple[UUID, str], HoldRecord] = {}

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
        key = (agent_id, idem_key)
        existing = self._by_key.get(key)
        now = datetime.now(UTC)
        if existing is not None:
            updated = HoldRecord(
                hold_id=existing.hold_id,
                agent_id=agent_id,
                idem_key=idem_key,
                amount_minor=amount_minor,
                currency=currency,
                reason=reason,
                status="pending",
                created_at=existing.created_at,
                payload=payload or {},
                updated_at=now,
            )
            self._by_key[key] = updated
            # Replace in list
            self.holds = [h if h.hold_id != existing.hold_id else updated for h in self.holds]
            return updated

        hold_id = uuid.uuid4()
        record = HoldRecord(
            hold_id=hold_id,
            agent_id=agent_id,
            idem_key=idem_key,
            amount_minor=amount_minor,
            currency=currency,
            reason=reason,
            status="pending",
            created_at=now,
            payload=payload or {},
            updated_at=now,
        )
        self._by_key[key] = record
        self.holds.append(record)
        return record

    async def decide(
        self,
        *,
        hold_id: UUID,
        decision: str,
        decided_by: str,
        notes: str | None = None,
    ) -> HoldRecord | None:
        for idx, h in enumerate(self.holds):
            if h.hold_id == hold_id:
                if h.status != "pending":
                    return None
                updated = HoldRecord(
                    hold_id=h.hold_id,
                    agent_id=h.agent_id,
                    idem_key=h.idem_key,
                    amount_minor=h.amount_minor,
                    currency=h.currency,
                    reason=h.reason,
                    status=decision,
                    created_at=h.created_at,
                    payload=h.payload,
                    updated_at=datetime.now(UTC),
                )
                self.holds[idx] = updated
                self._by_key[(h.agent_id, h.idem_key)] = updated
                return updated
        return None


class FakeValkey:
    """In-memory async Redis / Valkey simulator for counters and TTLs."""

    def __init__(self) -> None:
        self._data: dict[str, str | int] = {}
        self._ttls: dict[str, float] = {}

    async def incr(self, key: str) -> int:
        val = int(self._data.get(key, 0)) + 1
        self._data[key] = val
        return val

    async def incrby(self, key: str, amount: int) -> int:
        val = int(self._data.get(key, 0)) + amount
        self._data[key] = val
        return val

    async def get(self, key: str) -> str | None:
        val = self._data.get(key)
        return str(val) if val is not None else None

    async def set(self, key: str, value: Any, **kwargs: Any) -> bool:
        self._data[key] = str(value)
        return True

    async def pexpire(self, key: str, ms: int) -> bool:
        self._ttls[key] = ms / 1000.0
        return True

    async def expire(self, key: str, s: int) -> bool:
        self._ttls[key] = float(s)
        return True


class FakeIdempotencyStore:
    """In-memory mirror of Task 11 PostgreSQL idempotency state machine."""

    def __init__(self, time_fn: Callable[[], datetime] | None = None) -> None:
        self._records: dict[tuple[UUID, str], dict[str, Any]] = {}
        self._time_fn = time_fn if time_fn is not None else lambda: datetime.now(UTC)

    async def reserve(
        self,
        conn: Any,
        agent_id: UUID,
        idem_key: str,
        body_hash: str,
        *,
        reservation_ttl_s: float = 30.0,
    ) -> Reservation:
        key = (agent_id, idem_key)
        now = self._time_fn()
        rec = self._records.get(key)

        if rec is None:
            # Step 1: Initial atomic reservation
            self._records[key] = {
                "body_hash": body_hash,
                "state": IdempotencyState.PENDING,
                "reserved_at": now,
                "tx_id": None,
                "response_status": None,
                "response_body": None,
                "attempts": 1,
            }
            return Reservation(
                outcome=ReservationOutcome.OWNED,
                tx_id=None,
                response_status=None,
                response_body=None,
                attempts=1,
            )

        existing = ExistingRecord(
            body_hash=rec["body_hash"],
            state=rec["state"],
            reserved_at=rec["reserved_at"],
            tx_id=rec["tx_id"],
            response_status=rec["response_status"],
            response_body=rec["response_body"],
            attempts=rec["attempts"],
        )

        outcome = classify(
            existing,
            body_hash=body_hash,
            now=now,
            reservation_ttl_s=reservation_ttl_s,
        )

        if outcome.action == ClassificationAction.REPLAY:
            return Reservation(
                outcome=ReservationOutcome.REPLAY,
                tx_id=outcome.tx_id,
                response_status=outcome.response_status,
                response_body=outcome.response_body,
                attempts=rec["attempts"],
            )

        if outcome.action == ClassificationAction.IN_PROGRESS:
            return Reservation(
                outcome=ReservationOutcome.IN_PROGRESS,
                tx_id=None,
                response_status=None,
                response_body=None,
                attempts=rec["attempts"],
            )

        if outcome.action == ClassificationAction.CONFLICT:
            raise IdempotencyConflict(details={"agent_id": str(agent_id), "idem_key": idem_key})

        if outcome.action == "RECLAIMABLE":
            rec["state"] = IdempotencyState.PENDING
            rec["body_hash"] = body_hash
            rec["reserved_at"] = now
            rec["attempts"] += 1
            return Reservation(
                outcome=ReservationOutcome.OWNED,
                tx_id=None,
                response_status=None,
                response_body=None,
                attempts=rec["attempts"],
            )

        raise IdempotencyStateError(details={"reason": "unhandled_outcome"})

    async def claim_tx(
        self,
        conn: Any,
        agent_id: UUID,
        idem_key: str,
        tx_id: UUID,
    ) -> bool:
        key = (agent_id, idem_key)
        rec = self._records.get(key)
        if rec is None or rec["state"] != IdempotencyState.PENDING:
            return False
        if rec["tx_id"] is None or rec["tx_id"] == tx_id:
            rec["tx_id"] = tx_id
            return True
        return False

    async def complete(
        self,
        conn: Any,
        agent_id: UUID,
        idem_key: str,
        *,
        tx_id: UUID,
        response_status: int,
        response_body: str,
    ) -> None:
        key = (agent_id, idem_key)
        rec = self._records.get(key)
        if rec is None or rec["state"] != IdempotencyState.PENDING:
            raise IdempotencyStateError(
                details={
                    "agent_id": str(agent_id),
                    "idem_key": idem_key,
                    "reason": "reservation moved or not in PENDING state",
                }
            )
        rec["state"] = IdempotencyState.COMPLETED
        rec["tx_id"] = tx_id
        rec["response_status"] = response_status
        rec["response_body"] = response_body

    async def fail(
        self,
        conn: Any,
        agent_id: UUID,
        idem_key: str,
    ) -> None:
        key = (agent_id, idem_key)
        rec = self._records.get(key)
        if rec is None or rec["state"] != IdempotencyState.PENDING:
            raise IdempotencyStateError(
                details={
                    "agent_id": str(agent_id),
                    "idem_key": idem_key,
                    "reason": "reservation moved or not in PENDING state",
                }
            )
        rec["state"] = IdempotencyState.FAILED


class FakeUow:
    """In-memory fake UnitOfWork context manager."""

    def __init__(self, conn: Any = None) -> None:
        self.connection = conn or object()

    async def __aenter__(self) -> FakeUow:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, tb: Any) -> None:
        pass
