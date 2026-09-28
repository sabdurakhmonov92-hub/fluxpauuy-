"""=============================================================================
FluxPay Payment Service: The Full Money Flow (Block F, Part 2 — The Heart)
=============================================================================

ARCHITECTURE ESSAY: EXACTLY-ONCE EFFECT ACROSS THE CRASH WINDOW
----------------------------------------------------------------
The fundamental challenge of payment orchestration is the non-atomic composition
of distributed storage boundaries:
1. Database Idempotency (Task 11): Tracks caller requests, prevents replay, and
   enforces double-debit prevention in PostgreSQL via UnitOfWork transactions.
2. Ledger Store (Task 16): Owns its own independent transaction to enforce the
   hash-chain tip lock boundary (SELECT ... FOR UPDATE on ledger_chain_tip)
   and strict solvency invariants.
3. Redis Ingress / Risk Gate (Task 20/28): Evaluates velocity and outflow counters.
4. Event Bus (Task 9/10): Broadcasts reliable financial events to RabbitMQ/Redis.

Because Task 16's LedgerStore OWNS its own transaction (the tip lock boundary rule,
Task 8/15/16 frozen), the ledger post CANNOT be enclosed inside the caller's UoW.
The execution must proceed across distinct phases:
    Phase 1: UoW#1 — reserve idempotency (state='PENDING') + claim deterministic tx_id.
    Phase 2: Risk policy check (velocity attempt count + single/daily ceilings).
    Phase 3: Ledger post (under LedgerStore's own internal tip-locked transaction).
    Phase 4: Valkey daily outflow counter increment (money committed).
    Phase 5: UoW#2 — complete idempotency (state='COMPLETED', wire response bytes).
    Phase 6: Event publication (payment.settled via RabbitMQ).

THE CRASH GAP & DOUBLE-DEBIT HAZARD:
If a worker crashes immediately after Phase 3 (ledger post commits) but before
Phase 5 (UoW#2 completes), the reservation in PostgreSQL remains 'PENDING'.
When the client agent retries the request with the same idempotency key:
- Task 11's stale takeover reclaims the expired PENDING reservation.
- If the service blindly re-posted the transaction legs to the ledger, a
  CATASTROPHIC DOUBLE DEBIT would occur.

THE SENIOR RESOLUTION: DETERMINISTIC IDENTITY & CRASH PROBE:
We close the crash gap without altering frozen storage tables by unifying payment
identity with cryptographic determinism:
1. Deterministic tx_id:
   tx_id = uuid5(FLXPAY_TX_NAMESPACE, f"payment:{agent_id}:{idem_key}")
   Given an agent and idempotency key, the transaction ID is immutable and pure.
2. Claim-Before-Post Invariant:
   Inside UoW#1, `claim_tx(conn, agent_id, idem_key, tx_id)` binds the deterministic
   tx_id to the PENDING row BEFORE any ledger interaction.
3. Crash-Recovery Probe:
   Upon acquiring/reclaiming the reservation, the service queries:
   `await ledger.get_transaction(tx_id)`
   - If the transaction ALREADY EXISTS in the ledger (crash occurred between post and complete):
     The service SKIPS `post_transaction()`, logs a recovery event, and proceeds
     directly to Phase 4/5 (outflow + complete).
   - If the transaction DOES NOT EXIST:
     The service posts the transaction drafts carrying `tx_id=tx_id` (the sanctioned
     additive evolution of EntryDraft).

INVARIANT GUARANTEE:
Deterministic tx_id + claim-before-post + get-before-post =
EXACTLY-ONCE EFFECT on at-least-once transport execution.
The Protocol's foresight in providing `get_transaction(tx_id) -> LedgerTransaction | None`
pays off completely without requiring protocol mutations.

IDENTITY UNIFICATION:
payment_id == ledger tx_id == webhook event tx_id == PaymentResponse.id.
A single, consistent UUID identifies the payment across the database, double-entry
journal, audit logs, and external client wire responses.

HELD-PATH CORRECTION (THE TASK 42 HITL DOORWAY):
Earlier design drafts considered completing the idempotency reservation with status="held".
SENIOR CORRECTION: Completing a held reservation would permanently freeze the row in
state='COMPLETED'. When human reviewers or a multi-party quorum approve the hold in Task 42,
re-entering the flow with the original idempotency key would hit the REPLAY branch,
returning the cached "held" response without ever moving money!
CORRECT DESIGN:
- `pay()`: When quarantined, places a hold in `payment_holds`, publishes `payment.held`,
  and returns HTTP 201 wire bytes with `status="held"`. Crucially, it LEAVES the
  reservation in state='PENDING' with a 7-day TTL (`HOLD_RESERVATION_TTL_S = 604800`).
- `settle_approved()`: Task 42's dedicated settlement entry point. Re-enters using
  the original `idem_key`, verifies the PENDING reservation, skips policy checks
  (already approved by human quorum), posts to the ledger using the deterministic tx_id,
  completes the reservation with `status="settled"`, and publishes `payment.settled`.
- `reject_held()`: Task 42's rejection entry point. Fails the reservation (releasing
  the key) and emits terminal `payment.failed`.

SINGLE SOURCE OF WIRE BYTES:
The service renders `wire_body` directly using `PaymentResponse.model_dump_json().encode()`.
The HTTP route (Task 33) is a 5-line pass-through. Caching and wire replay operate on the
exact byte stream generated here, guaranteeing byte-exact reproducibility for AI agents.

=============================================================================
FAILURE LADDER
=============================================================================
Exception               | Acquired State                   | Recovery Action
------------------------|----------------------------------|------------------------------------
ValueError (quote/rail) | None                             | Bubbles immediately (HTTP 422/400).
NotFoundError (merchant)| None                             | Bubbles immediately (HTTP 404).
IdempotencyConflict     | Twin in-flight / hash mismatch   | Bubbles immediately (HTTP 409).
PaymentPolicyError      | UoW#1 PENDING reservation        | UoW#2: fail(), emit payment.failed.
InsufficientFunds       | UoW#1 PENDING reservation        | UoW#2: fail(), emit payment.failed.
OCCConflict             | UoW#1 PENDING reservation        | Bubbles (503 retryable); stale
                        |                                  | takeover heals on retry.
Worker Crash (pre-post) | UoW#1 PENDING reservation        | Stale takeover reclaims key; probe
                        |                                  | finds no tx -> posts ledger.
Worker Crash (post-post)| UoW#1 PENDING + Ledger tx posted | Stale takeover reclaims key; probe
                        |                                  | finds tx -> skips post, completes.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal
from uuid import UUID, uuid5

import asyncpg  # type: ignore[import-untyped]
import orjson
import redis.asyncio as redis_async

from fluxpay.contracts.schemas import PaymentResponse
from fluxpay.gateway.gate import compose_day
from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.store import EntryDraft, LedgerStore
from fluxpay.payments import fees, routing

# --- Task 32 refactor (extraction, no behavior change)
from fluxpay.payments.render import render_payment
from fluxpay.risk.limits import LimitRepo, check_payment
from fluxpay.risk.quarantine import QuarantineService
from fluxpay.shared import idempotency
from fluxpay.shared.errors import (
    IdempotencyConflict,
    IdempotencyStateError,
    InsufficientFunds,
    NotFoundError,
    OCCConflict,
    PaymentPolicyError,
)
from fluxpay.shared.events import EventBus, EventType, make_event
from fluxpay.shared.idempotency import ReservationOutcome
from fluxpay.shared.logging import get_logger
from fluxpay.shared.metrics import FLX_PAYMENTS_TOTAL
from fluxpay.shared.uow import UnitOfWork
from fluxpay.wallet.accounts import AccountDirectory

logger = get_logger("fluxpay.payments.service")

__all__ = [
    "FLXPAY_TX_NAMESPACE",
    "HOLD_RESERVATION_TTL_S",
    "PayOutcome",
    "PaymentService",
    "deterministic_tx_id",
]

# Fixed UUID namespace anchor for deterministic payment transaction derivation.
# Generated once; the determinism anchor for payment transaction IDs across the platform.
FLXPAY_TX_NAMESPACE: Final[UUID] = UUID("9c4b7264-77a8-4448-9366-eb15c6d04212")

# Extended reservation TTL for quarantined/held payments awaiting human approval (7 days).
# Bound to the operational human review SLA; stale takeover after 7d triggers escalation.
HOLD_RESERVATION_TTL_S: Final[float] = 604_800.0


def deterministic_tx_id(agent_id: UUID, idem_key: str) -> UUID:
    """Derive deterministic transaction ID from agent UUID and idempotency key.

    Pure mathematical function. Guarantees that any retry of the same logical payment
    attempt produces the exact same UUID for ledger entries and idempotency records.
    """
    return uuid5(FLXPAY_TX_NAMESPACE, f"payment:{agent_id}:{idem_key}")


@dataclass(frozen=True, slots=True)
class PayOutcome:
    """Immutable domain outcome of a payment execution."""

    status: Literal["settled", "held"]
    tx_id: UUID
    response_status: int
    wire_body: bytes
    replayed: bool = False


class PaymentService:
    """Core payment orchestration service managing the complete money path."""

    def __init__(
        self,
        *,
        ledger: LedgerStore,
        directory: AccountDirectory | Any,
        limits_repo: LimitRepo | Any,
        quarantine: QuarantineService | Any,
        bus: EventBus,
        valkey: redis_async.Redis | Any,
        pool: asyncpg.Pool | None = None,
        uow_factory: Callable[[], AbstractAsyncContextManager[Any]] | None = None,
        time_fn: Callable[[], datetime] | None = None,
        idempotency_module: Any = None,
        reservation_ttl_s: float = 30.0,
    ) -> None:
        """Initialize PaymentService with all financial dependencies."""
        self._ledger = ledger
        self._directory = directory
        self._limits_repo = limits_repo
        self._quarantine = quarantine
        self._bus = bus
        self._valkey = valkey
        self._pool = pool
        self._reservation_ttl_s = reservation_ttl_s
        self._time_fn = time_fn if time_fn is not None else lambda: datetime.now(UTC)
        self._idempotency = idempotency_module if idempotency_module is not None else idempotency

        if uow_factory is not None:
            self._uow_factory = uow_factory
        elif pool is not None:
            self._uow_factory = lambda: UnitOfWork(pool)
        else:
            raise ValueError("Either pool or uow_factory must be provided to PaymentService")

    def _get_uow(self) -> AbstractAsyncContextManager[Any]:
        """Produce a fresh UnitOfWork context manager instance."""
        return self._uow_factory()

    async def _publish_settled(
        self,
        *,
        tx_id: UUID,
        agent_id: UUID,
        to_merchant: str,
        amount_minor: int,
        fee_minor: int,
        total_minor: int,
        currency: str,
    ) -> None:
        """Emit payment.settled event with flat scalar payload (Task 9 law)."""
        event = make_event(
            type=EventType.PAYMENT_SETTLED,
            payload={
                "tx_id": str(tx_id),
                "payment_id": str(tx_id),
                "agent_id": str(agent_id),
                "merchant": to_merchant,
                "amount": amount_minor,
                "fee": fee_minor,
                "total": total_minor,
                "currency": currency,
            },
            producer="fluxpay.payments",
        )
        await self._bus.publish(event)
        # --- Task 69 append ---
        FLX_PAYMENTS_TOTAL.labels(result="settled").inc()

    async def _publish_held(
        self,
        *,
        tx_id: UUID,
        agent_id: UUID,
        to_merchant: str,
        amount_minor: int,
        fee_minor: int,
        total_minor: int,
        currency: str,
        reason: str,
    ) -> None:
        """Emit payment.held event with flat scalar payload."""
        event = make_event(
            type=EventType.PAYMENT_HELD,
            payload={
                "tx_id": str(tx_id),
                "payment_id": str(tx_id),
                "agent_id": str(agent_id),
                "merchant": to_merchant,
                "amount": amount_minor,
                "fee": fee_minor,
                "total": total_minor,
                "currency": currency,
                "reason": reason,
            },
            producer="fluxpay.payments",
        )
        await self._bus.publish(event)
        # --- Task 69 append ---
        FLX_PAYMENTS_TOTAL.labels(result="held").inc()

    async def _publish_failed(
        self,
        *,
        tx_id: UUID,
        agent_id: UUID,
        to_merchant: str,
        amount_minor: int,
        fee_minor: int,
        total_minor: int,
        currency: str,
        reason: str,
    ) -> None:
        """Emit payment.failed event with flat scalar payload."""
        event = make_event(
            type=EventType.PAYMENT_FAILED,
            payload={
                "tx_id": str(tx_id),
                "payment_id": str(tx_id),
                "agent_id": str(agent_id),
                "merchant": to_merchant,
                "amount": amount_minor,
                "fee": fee_minor,
                "total": total_minor,
                "currency": currency,
                "reason": reason,
            },
            producer="fluxpay.payments",
        )
        await self._bus.publish(event)
        # --- Task 69 append ---
        FLX_PAYMENTS_TOTAL.labels(result="rejected" if "rejected" in reason else "failed").inc()

    async def _increment_outflow(self, agent_id: UUID, total_minor: int, now: datetime) -> None:
        """Increment daily cumulative outflow counter in Valkey with 25h expiry."""
        now_ms = int(now.timestamp() * 1000)
        yyyymmdd = compose_day(now_ms)
        outflow_key = f"flx:outflow:{{{agent_id}}}:{yyyymmdd}"
        await self._valkey.incrby(outflow_key, total_minor)
        await self._valkey.expire(outflow_key, 25 * 3600)

    async def pay(
        self,
        *,
        agent_id: UUID,
        idem_key: str,
        body_hash: str,
        to_merchant: str,
        amount_minor: int,
        currency: str = "USDC",
    ) -> PayOutcome:
        """Execute or replay a payment transaction across the six-phase pipeline.

        Args:
            agent_id: Debited agent identity.
            idem_key: Client-provided idempotency key from HTTP transport header.
            body_hash: SHA-256 hex digest of the canonical request body.
            to_merchant: External identifier handle of target merchant.
            amount_minor: Principal payment amount in minor units.
            currency: Currency code (default 'USDC').

        Returns:
            PayOutcome with terminal status ('settled' or 'held') and exact wire bytes.
        """
        # =========================================================================
        # 1. PURE QUOTE & RAIL VALIDATION
        # =========================================================================
        # Computes exact floor fee (1% = 100 bps) and asserts operational limits.
        # ValueError bubbles to route handler for mapping to HTTP 422.
        quote = fees.quote(amount_minor, currency)

        # Assert internal settlement rail (Phase 1 frozen seam).
        rail_decision = routing.route(amount_minor=amount_minor, currency=currency)
        if rail_decision.rail != routing.Rail.INTERNAL:
            raise ValueError(f"Unsupported settlement rail: {rail_decision.rail}")

        # =========================================================================
        # 2. ACCOUNT RESOLUTION
        # =========================================================================
        # Resolves fee collection account and destination merchant account.
        fee_acct = await self._directory.get_fees_account(currency)
        try:
            merchant_acct = await self._directory.get_merchant_account(to_merchant, currency)
        except LookupError as exc:
            # Unknown merchant maps to NotFoundError (HTTP 404) with structured details.
            raise NotFoundError(
                details={"merchant": to_merchant, "currency": currency},
                message=f"Merchant '{to_merchant}' not found for currency '{currency}'",
            ) from exc

        # Debited agent ledger account must exist by provisioning invariant.
        agent_acct = await self._directory.get_agent_account(agent_id, currency)

        # Compute deterministic transaction identity once.
        tx_id = deterministic_tx_id(agent_id, idem_key)

        # =========================================================================
        # 3. UoW#1: IDEMPOTENCY RESERVATION & DETERMINISTIC TX_ID CLAIM
        # =========================================================================
        async with self._get_uow() as uow:
            reservation = await self._idempotency.reserve(
                uow.connection,
                agent_id,
                idem_key,
                body_hash,
                reservation_ttl_s=self._reservation_ttl_s,
            )

            # 3.a. REPLAY: Fast-path evicted but PostgreSQL holds completed execution
            if reservation.outcome == ReservationOutcome.REPLAY:
                body_str = reservation.response_body or ""
                wire_bytes = body_str.encode("utf-8")
                status: Literal["settled", "held"] = "settled"
                with contextlib.suppress(Exception):
                    parsed = orjson.loads(wire_bytes)
                    if parsed.get("status") in ("settled", "held"):
                        status = parsed["status"]
                resp_status = reservation.response_status or 201
                resp_tx_id = reservation.tx_id or tx_id
                logger.info(
                    "payment_replayed_from_db",
                    agent_id=str(agent_id),
                    idem_key_hash=body_hash[:16],
                    tx_id=str(resp_tx_id),
                )
                return PayOutcome(
                    status=status,
                    tx_id=resp_tx_id,
                    response_status=resp_status,
                    wire_body=wire_bytes,
                    replayed=True,
                )

            # 3.b. IN_PROGRESS: Concurrent live twin request in flight
            if reservation.outcome == ReservationOutcome.IN_PROGRESS:
                raise IdempotencyConflict(
                    details={"agent_id": str(agent_id), "idem_key": idem_key},
                    message="A payment with this idempotency key is already in progress.",
                )

            # 3.c. OWNED: First execution or stale takeover -> claim deterministic tx_id
            claimed = await self._idempotency.claim_tx(uow.connection, agent_id, idem_key, tx_id)
            if not claimed:
                # Impossible under deterministic derivation unless hijacked concurrently
                raise IdempotencyStateError(
                    details={
                        "agent_id": str(agent_id),
                        "idem_key": idem_key,
                        "tx_id": str(tx_id),
                    },
                    message="Failed to claim deterministic tx_id on PENDING reservation.",
                )

        # UoW#1 committed: reservation state='PENDING' and tx_id are durable in PostgreSQL.

        # =========================================================================
        # 4. RISK POLICY EVALUATION
        # =========================================================================
        now = self._time_fn()
        limits = await self._limits_repo.get(agent_id)
        decision = await check_payment(
            pool=self._pool,
            valkey=self._valkey,
            agent_id=agent_id,
            limits=limits,
            amount_minor=quote.total_minor,
            currency=currency,
            now=now,
        )

        # 4.a. QUARANTINED (ceiling breached): place hold, emit event, leave PENDING
        if decision.quarantined:
            await self._quarantine.place_hold(
                agent_id=agent_id,
                idem_key=idem_key,
                amount_minor=quote.total_minor,
                currency=currency,
                reason=decision.reason or "quarantined",
                payload={
                    "to_merchant": to_merchant,
                    "amount_minor": amount_minor,
                    "fee_minor": quote.fee_minor,
                    "total_minor": quote.total_minor,
                    "currency": currency,
                    "tx_id": str(tx_id),
                },
            )
            await self._publish_held(
                tx_id=tx_id,
                agent_id=agent_id,
                to_merchant=to_merchant,
                amount_minor=quote.amount_minor,
                fee_minor=quote.fee_minor,
                total_minor=quote.total_minor,
                currency=currency,
                reason=decision.reason or "quarantined",
            )
            held_response = PaymentResponse(id=tx_id, status="held")
            held_wire_bytes = held_response.model_dump_json().encode("utf-8")
            # Note: We do NOT call complete(). Row stays PENDING for Task 42 settlement.
            return PayOutcome(
                status="held",
                tx_id=tx_id,
                response_status=201,
                wire_body=held_wire_bytes,
                replayed=False,
            )

        # 4.b. REJECTED (velocity limit): fail reservation, emit payment.failed, raise
        if not decision.allowed:
            async with self._get_uow() as uow:
                await self._idempotency.fail(uow.connection, agent_id, idem_key)
            await self._publish_failed(
                tx_id=tx_id,
                agent_id=agent_id,
                to_merchant=to_merchant,
                amount_minor=quote.amount_minor,
                fee_minor=quote.fee_minor,
                total_minor=quote.total_minor,
                currency=currency,
                reason=decision.reason or "velocity_rejected",
            )
            raise PaymentPolicyError(
                details={"agent_id": str(agent_id), "reason": decision.reason or "velocity"},
                message="Payment rejected by risk policy (velocity limit exceeded).",
            )

        # =========================================================================
        # 5. CRASH-RECOVERY PROBE (THE EXACTLY-ONCE GUARANTEE)
        # =========================================================================
        # Probe whether ledger transaction already exists from a prior post before crash.
        existing_tx = await self._ledger.get_transaction(tx_id)
        if existing_tx is not None:
            logger.info(
                "payment_crash_recovery_skipping_post",
                agent_id=str(agent_id),
                tx_id=str(tx_id),
            )
        else:
            # =====================================================================
            # 6. ATOMIC LEDGER TRANSACTION POST
            # =====================================================================
            entries = (
                EntryDraft(
                    account_id=agent_acct.account_id,
                    direction=Direction.DEBIT,
                    amount=quote.total_minor,
                    currency=currency,
                    tx_id=tx_id,
                ),
                EntryDraft(
                    account_id=merchant_acct.account_id,
                    direction=Direction.CREDIT,
                    amount=quote.amount_minor,
                    currency=currency,
                    tx_id=tx_id,
                ),
                EntryDraft(
                    account_id=fee_acct.account_id,
                    direction=Direction.CREDIT,
                    amount=quote.fee_minor,
                    currency=currency,
                    tx_id=tx_id,
                ),
            )

            try:
                await self._ledger.post_transaction(entries)
            except InsufficientFunds:
                # Terminal solvency reject: fail reservation + publish payment.failed + raise
                async with self._get_uow() as uow:
                    await self._idempotency.fail(uow.connection, agent_id, idem_key)
                await self._publish_failed(
                    tx_id=tx_id,
                    agent_id=agent_id,
                    to_merchant=to_merchant,
                    amount_minor=quote.amount_minor,
                    fee_minor=quote.fee_minor,
                    total_minor=quote.total_minor,
                    currency=currency,
                    reason="insufficient_funds",
                )
                raise
            except OCCConflict:
                # Store retried internally up to limit; bubble to client for backoff retry.
                # Reservation stays PENDING; stale takeover heals upon subsequent attempt.
                raise

        # =========================================================================
        # 7. REDIS OUTFLOW COUNTER INCREMENT
        # =========================================================================
        # Only increment outflow counter on successfully committed money.
        await self._increment_outflow(agent_id, quote.total_minor, now)

        # =========================================================================
        # 8. UoW#2: COMPLETE IDEMPOTENCY RESERVATION
        # =========================================================================
        # Single source of truth for wire bytes: serialize model once.
        # --- Task 32 refactor (extraction, no behavior change)
        settled_wire_bytes = render_payment(tx_id=tx_id, status="settled")

        async with self._get_uow() as uow:
            await self._idempotency.complete(
                uow.connection,
                agent_id,
                idem_key,
                tx_id=tx_id,
                response_status=201,
                response_body=settled_wire_bytes.decode("utf-8"),
            )

        # =========================================================================
        # 9. PUBLISH EVENT BUS NOTIFICATION
        # =========================================================================
        await self._publish_settled(
            tx_id=tx_id,
            agent_id=agent_id,
            to_merchant=to_merchant,
            amount_minor=quote.amount_minor,
            fee_minor=quote.fee_minor,
            total_minor=quote.total_minor,
            currency=currency,
        )

        # =========================================================================
        # 10. RETURN OUTCOME
        # =========================================================================
        return PayOutcome(
            status="settled",
            tx_id=tx_id,
            response_status=201,
            wire_body=settled_wire_bytes,
            replayed=False,
        )

    async def settle_approved(
        self,
        *,
        agent_id: UUID,
        idem_key: str,
        to_merchant: str,
        amount_minor: int,
        currency: str = "USDC",
    ) -> PayOutcome:
        """Settle a previously quarantined and approved payment (Task 42 handoff).

        Skips risk evaluation (human review completed). Asserts PENDING reservation,
        posts to the double-entry ledger using the deterministic tx_id, advances
        the outflow counter, completes the reservation with status="settled",
        and emits payment.settled.
        """
        quote = fees.quote(amount_minor, currency)
        fee_acct = await self._directory.get_fees_account(currency)
        merchant_acct = await self._directory.get_merchant_account(to_merchant, currency)
        agent_acct = await self._directory.get_agent_account(agent_id, currency)
        tx_id = deterministic_tx_id(agent_id, idem_key)

        # Verify reservation is in PENDING state and ensure deterministic tx_id is claimed
        async with self._get_uow() as uow:
            claimed = await self._idempotency.claim_tx(uow.connection, agent_id, idem_key, tx_id)
            if not claimed:
                raise IdempotencyStateError(
                    details={
                        "agent_id": str(agent_id),
                        "idem_key": idem_key,
                        "tx_id": str(tx_id),
                    },
                    message="Cannot settle approved payment: reservation is not PENDING.",
                )

        # Crash recovery probe before ledger post
        existing_tx = await self._ledger.get_transaction(tx_id)
        if existing_tx is None:
            entries = (
                EntryDraft(
                    account_id=agent_acct.account_id,
                    direction=Direction.DEBIT,
                    amount=quote.total_minor,
                    currency=currency,
                    tx_id=tx_id,
                ),
                EntryDraft(
                    account_id=merchant_acct.account_id,
                    direction=Direction.CREDIT,
                    amount=quote.amount_minor,
                    currency=currency,
                    tx_id=tx_id,
                ),
                EntryDraft(
                    account_id=fee_acct.account_id,
                    direction=Direction.CREDIT,
                    amount=quote.fee_minor,
                    currency=currency,
                    tx_id=tx_id,
                ),
            )
            try:
                await self._ledger.post_transaction(entries)
            except InsufficientFunds:
                async with self._get_uow() as uow:
                    await self._idempotency.fail(uow.connection, agent_id, idem_key)
                await self._publish_failed(
                    tx_id=tx_id,
                    agent_id=agent_id,
                    to_merchant=to_merchant,
                    amount_minor=quote.amount_minor,
                    fee_minor=quote.fee_minor,
                    total_minor=quote.total_minor,
                    currency=currency,
                    reason="insufficient_funds",
                )
                raise

        now = self._time_fn()
        await self._increment_outflow(agent_id, quote.total_minor, now)

        settled_response = PaymentResponse(id=tx_id, status="settled")
        settled_wire_bytes = settled_response.model_dump_json().encode("utf-8")

        async with self._get_uow() as uow:
            await self._idempotency.complete(
                uow.connection,
                agent_id,
                idem_key,
                tx_id=tx_id,
                response_status=201,
                response_body=settled_wire_bytes.decode("utf-8"),
            )

        await self._publish_settled(
            tx_id=tx_id,
            agent_id=agent_id,
            to_merchant=to_merchant,
            amount_minor=quote.amount_minor,
            fee_minor=quote.fee_minor,
            total_minor=quote.total_minor,
            currency=currency,
        )

        return PayOutcome(
            status="settled",
            tx_id=tx_id,
            response_status=201,
            wire_body=settled_wire_bytes,
            replayed=False,
        )

    async def reject_held(
        self,
        *,
        agent_id: UUID,
        idem_key: str,
        to_merchant: str,
        amount_minor: int,
        currency: str = "USDC",
        reason: str = "rejected_by_approver",
    ) -> None:
        """Reject a previously quarantined payment (Task 42 handoff).

        Transitions the PENDING reservation to FAILED (freeing the key for retry)
        and broadcasts payment.failed to the event bus.
        """
        quote = fees.quote(amount_minor, currency)
        tx_id = deterministic_tx_id(agent_id, idem_key)

        async with self._get_uow() as uow:
            await self._idempotency.fail(uow.connection, agent_id, idem_key)

        await self._publish_failed(
            tx_id=tx_id,
            agent_id=agent_id,
            to_merchant=to_merchant,
            amount_minor=quote.amount_minor,
            fee_minor=quote.fee_minor,
            total_minor=quote.total_minor,
            currency=currency,
            reason=reason,
        )
