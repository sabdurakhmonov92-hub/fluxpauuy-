"""Cold Payout Pipeline: 2-Man Queue, Execution Recording, and Custody Bridge.

FluxPay v3 | Block I (Consolidates Tasks 46-48 — Block I Closure)
Blueprint §8 institutional cold vault and manual transfer queue.

ARCHITECTURAL PRINCIPLES & DESIGN INVARIANTS:
1. THE RECEIPT-IS-BLOCKCHAIN LAW:
   The server OBSERVES and PROPOSES; humans EXECUTE behind a Gnosis Safe 2-of-3
   multisig outside our walls. The server holds zero keys and signs nothing.
   Execution is recorded strictly by `tx_hash` — the blockchain IS the receipt.
   The server's role is scribe, never signer. Confirmation is a READ against
   `OnChainReader`, never trust.

2. VOTE-THEN-TRANSITION TWO-PHASE (TASK 42 COPY DISCIPLINE):
   Votes commit to `payout_approvals` FIRST; state transitions on `cold_payouts`
   occur ONLY after recount against `decide_from_votes`. The code mirrors Task 42's
   pattern rather than sharing modules to prevent coupled evolution across different
   domain entities and audit tables.

3. REJECT-TERMINATES ASYMMETRY:
   A single reject vote terminates the payout immediately into 'rejected'.
   Two approval votes are required to advance to 'approved'.

4. SEPARATION OF DUTIES & ACCESS GATE:
   Voter role must be 'admin' (enforced via ForbiddenError). Support roles may
   observe open queues via `list_open()` or CLI, but never sign or vote.

5. CUSTODY RECONCILIATION BRIDGE:
   In-flight accounting bridges the gap between approval and on-chain finality.
   Provides `custody_snapshot()` exposing cached balances, on-chain truth, drift,
   and in-flight payout totals for daily truth audits (Task 41 Phase 2 seed).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal
from urllib.parse import urlsplit
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import httpx

from fluxpay.audit import audit
from fluxpay.config import get_settings
from fluxpay.contracts.schemas import CURRENCY_PATTERN
from fluxpay.notifications.channels import TelegramChannel
from fluxpay.notifications.records import record_failure_pool
from fluxpay.shared.errors import (
    ForbiddenError,
    NotFoundError,
    PayoutNotOpenError,
    ValidationError,
)
from fluxpay.shared.logging import get_logger
from fluxpay.shared.uow import UnitOfWork
from fluxpay.treasury.reader import OnChainReader, TxStatus

logger = get_logger("fluxpay.treasury.payouts")

__all__ = [
    "EXIT_OK",
    "EXIT_OPS_FAILURE",
    "REJECTS_TERMINAL",
    "STUCK_PAYOUT_HOURS",
    "VOTES_REQUIRED",
    "CustodySnapshot",
    "PayoutRecord",
    "PayoutService",
    "PayoutSweepReport",
    "PayoutSweeper",
    "VoteOutcome",
    "build_report_line",
    "classify_stuck",
    "custody_snapshot",
    "decide_from_votes",
    "main",
    "map_exit_code",
]

# ==============================================================================
# POLICY CONSTANTS (MODULE-LEVEL, FROZEN)
# ==============================================================================
VOTES_REQUIRED: Final[int] = 2
REJECTS_TERMINAL: Final[bool] = True
STUCK_PAYOUT_HOURS: Final[int] = 24

EXIT_OK: Final[int] = 0
EXIT_OPS_FAILURE: Final[int] = 2

VALID_REASONS: Final[frozenset[str]] = frozenset({"surplus_sweep", "operational", "rebalance"})
_ETH_ADDRESS_RE: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TX_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-fA-F]{64}$")
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(CURRENCY_PATTERN)


# ==============================================================================
# PURE DECISION POLICY FUNCTIONS
# ==============================================================================
def decide_from_votes(
    for_count: int, against_count: int
) -> Literal["pending", "approved", "rejected"]:
    """Evaluate vote counts against the 2-man rule quorum policy.

    Copied pattern from Task 42 (the copy discipline):
    - Rejection is asymmetrical and terminal: a single reject terminates the payout.
    - Two approvals advance the payout to 'approved'.
    - Otherwise, remains 'pending'.

    Documented why not imported: different tables, audits, and lifecycles.
    Shared code would couple independent domain evolutions.
    """
    if REJECTS_TERMINAL and against_count >= 1:
        return "rejected"
    if for_count >= VOTES_REQUIRED:
        return "approved"
    return "pending"


def classify_stuck(payout: PayoutRecord, now: datetime) -> bool:
    """Classify whether a payout is stuck awaiting human signature or on-chain confirmation.

    A payout is classified as stuck when:
    - Status is 'approved' (awaiting Safe execution) and (now - updated_at) >= 24h.
    - Status is 'executed' (awaiting RPC confirmation) and (now - updated_at) >= 24h.
    - Other statuses return False.

    Boundary rule: exactly 24h is stuck (>=); 23:59 is not stuck.
    """
    if payout.status not in ("approved", "executed"):
        return False

    now_dt = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
    updated_dt = (
        payout.updated_at
        if payout.updated_at.tzinfo is not None
        else payout.updated_at.replace(tzinfo=UTC)
    )
    delta = now_dt - updated_dt
    return delta >= timedelta(hours=STUCK_PAYOUT_HOURS)


def map_exit_code(report: PayoutSweepReport | None, error: Exception | None = None) -> int:
    """Map execution outcome to standard treasury process exit code (0 or 2)."""
    if error is not None or report is None:
        return EXIT_OPS_FAILURE
    return EXIT_OK


# ==============================================================================
# DATA CLASSES / VALUE OBJECTS
# ==============================================================================
@dataclass(frozen=True, slots=True)
class PayoutRecord:
    """Immutable representation of a cold payout queue record."""

    payout_id: UUID
    rail: str
    to_address: str
    amount_minor: int
    currency: str
    reason: str
    status: str
    requested_by_sub: str
    created_at: datetime
    updated_at: datetime
    tx_hash: str | None = None
    executed_at: datetime | None = None
    confirmed_at: datetime | None = None
    votes_for: int = 0
    votes_against: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize payout record to dictionary with ISO-formatted timestamps."""
        return {
            "payout_id": str(self.payout_id),
            "rail": self.rail,
            "to_address": self.to_address,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "reason": self.reason,
            "status": self.status,
            "requested_by_sub": self.requested_by_sub,
            "tx_hash": self.tx_hash,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "votes_for": self.votes_for,
            "votes_against": self.votes_against,
        }


VoteStatus = Literal["pending", "approved", "rejected", "already_voted"]


@dataclass(frozen=True, slots=True)
class VoteOutcome:
    """Immutable outcome of casting an approval vote on a cold payout."""

    status: VoteStatus
    votes_for: int
    votes_against: int

    def to_dict(self) -> dict[str, Any]:
        """Produce JSON-serializable dictionary."""
        return {
            "status": self.status,
            "votes_for": self.votes_for,
            "votes_against": self.votes_against,
        }


@dataclass(frozen=True, slots=True)
class PayoutSweepReport:
    """Execution telemetry report from PayoutSweeper."""

    mode: str
    confirmed: int
    stuck: int
    open: int
    checked_at: str
    elapsed_ms: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to dictionary."""
        return {
            "mode": self.mode,
            "confirmed": self.confirmed,
            "stuck": self.stuck,
            "open": self.open,
            "checked_at": self.checked_at,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True, slots=True)
class CustodySnapshot:
    """Custody reconciliation bridge snapshot between on-chain truth and database caches."""

    rail: str
    hot_cache: int
    cold_cache: int
    hot_truth: int
    cold_truth: int
    hot_drift: int
    cold_drift: int
    in_flight_total: int
    oldest_in_flight: tuple[PayoutRecord, ...]
    captured_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot to dictionary."""
        return {
            "rail": self.rail,
            "hot_cache": self.hot_cache,
            "cold_cache": self.cold_cache,
            "hot_truth": self.hot_truth,
            "cold_truth": self.cold_truth,
            "hot_drift": self.hot_drift,
            "cold_drift": self.cold_drift,
            "in_flight_total": self.in_flight_total,
            "oldest_in_flight": [p.to_dict() for p in self.oldest_in_flight],
            "captured_at": self.captured_at.isoformat(),
        }


def build_report_line(report: PayoutSweepReport, elapsed_ms: int) -> str:
    """Produce single-line machine-parseable JSON report for systemd journal logging."""
    payload = {
        "mode": report.mode,
        "confirmed": report.confirmed,
        "stuck": report.stuck,
        "open": report.open,
        "checked_at": report.checked_at,
        "elapsed_ms": elapsed_ms,
    }
    return json.dumps(payload, separators=(",", ":"))


def _row_to_payout_record(row: asyncpg.Record | dict[str, Any]) -> PayoutRecord:
    """Convert an asyncpg database record to a typed PayoutRecord."""
    return PayoutRecord(
        payout_id=UUID(str(row["payout_id"])),
        rail=row["rail"],
        to_address=row["to_address"],
        amount_minor=int(row["amount_minor"]),
        currency=row["currency"],
        reason=row["reason"],
        status=row["status"],
        requested_by_sub=row["requested_by_sub"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        tx_hash=row.get("tx_hash"),
        executed_at=row.get("executed_at"),
        confirmed_at=row.get("confirmed_at"),
        votes_for=int(row.get("votes_for") or 0),
        votes_against=int(row.get("votes_against") or 0),
    )


# ==============================================================================
# PAYOUT SERVICE
# ==============================================================================
class PayoutService:
    """Core domain service managing the cold payout lifecycle.

    Lifecycle:
    requested -> approved (via 2 admin votes) | rejected (via 1 admin reject)
    approved  -> executed (tx_hash recorded by operator)
    executed  -> confirmed (via OnChainReader confirmation)
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        reader: OnChainReader,
        alert: Callable[[str], Awaitable[None]],
        now: Callable[[], float] = time.time,
    ) -> None:
        self._pool = pool
        self._reader = reader
        self._alert = alert
        self._now = now

    async def _send_alert(self, msg: str, rail: str = "base_usdc") -> None:
        """Deliver alert via transport; record failure on error (Task 43 discipline)."""
        try:
            res = self._alert(msg)
            if inspect.isawaitable(res):
                await res
        except Exception as exc:
            logger.error("payout_alert_dispatch_failed", error=str(exc), message=msg)
            try:
                await record_failure_pool(
                    self._pool,
                    channel="telegram",
                    subject="treasury_admin",
                    purpose="treasury.alert",
                    payload={"message": msg, "rail": rail},
                    error=exc.__class__.__name__,
                )
            except Exception as rec_err:
                logger.error("payout_failure_record_failed", error=str(rec_err))

    async def request(
        self,
        *,
        rail: str = "base_usdc",
        to_address: str,
        amount_minor: int,
        currency: str = "USDC",
        reason: str = "operational",
        requested_by_sub: str = "system",
    ) -> PayoutRecord:
        """Propose a new cold payout request into the approval queue.

        Validates grammar and amounts at the door. No UnitOfWork is required for
        a single atomic INSERT. Alert fires post-commit (Task 27 post-commit law).
        """
        if amount_minor <= 0:
            raise ValidationError(
                message="Payout amount must be positive",
                details={"amount_minor": str(amount_minor)},
            )

        if not _ETH_ADDRESS_RE.match(to_address):
            raise ValidationError(
                message=f"Invalid to_address: '{to_address}'. Must match EVM 0x format.",
                details={"to_address": to_address},
            )

        if not _CURRENCY_RE.match(currency):
            raise ValidationError(
                message=f"Invalid currency: '{currency}'",
                details={"currency": currency},
            )

        if reason not in VALID_REASONS:
            raise ValidationError(
                message=f"Invalid reason: '{reason}'. Allowed: {VALID_REASONS}",
                details={"reason": reason},
            )

        if not requested_by_sub.strip():
            raise ValidationError(
                message="requested_by_sub must not be empty",
                details={"requested_by_sub": requested_by_sub},
            )

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO cold_payouts (
                    rail,
                    to_address,
                    amount_minor,
                    currency,
                    reason,
                    status,
                    requested_by_sub
                ) VALUES ($1, $2, $3, $4, $5, 'requested', $6)
                RETURNING *;
                """,
                rail,
                to_address,
                amount_minor,
                currency,
                reason,
                requested_by_sub,
            )

        if not row:
            raise RuntimeError("Failed to insert cold payout record")

        payout = _row_to_payout_record(row)

        alert_msg = (
            f"payout REQUESTED (2 approvals needed): id={payout.payout_id} "
            f"rail={rail} amount={amount_minor} {currency} to={to_address}"
        )
        await self._send_alert(alert_msg, rail=rail)
        return payout

    async def vote(
        self,
        *,
        payout_id: UUID | str,
        voter_sub: str,
        voter_role: str,
        vote: Literal["approve", "reject"] | str,
        note: str = "",
    ) -> VoteOutcome:
        """Cast an administrative approval or rejection vote on a requested payout.

        Separation of duties: voter_role MUST be 'admin' (Task 29 ForbiddenError).
        Two-phase commit:
        1. Lock payout row FOR UPDATE. Must be in 'requested' status (else PayoutNotOpenError).
        2. Insert vote into payout_approvals (UNIQUE constraint prevents double voting).
        3. Recount votes and evaluate via pure `decide_from_votes`.
        4. Apply transition and commit audit row in the exact same UnitOfWork.
        5. Emit alert post-commit.
        """
        if voter_role != "admin":
            raise ForbiddenError(message="insufficient permissions: admin role required to vote")

        if vote not in ("approve", "reject"):
            raise ValidationError(
                message="Invalid vote: must be 'approve' or 'reject'",
                details={"vote": vote},
            )

        payout_uuid = UUID(str(payout_id))
        truncated_note = note[:200]
        alert_msg: str | None = None
        decision_status: VoteStatus = "pending"
        final_for = 0
        final_against = 0

        async with UnitOfWork(self._pool) as uow:
            payout_row = await uow.connection.fetchrow(
                "SELECT * FROM cold_payouts WHERE payout_id = $1 FOR UPDATE;",
                payout_uuid,
            )
            if payout_row is None:
                raise NotFoundError(message=f"payout {payout_uuid} not found")

            if payout_row["status"] != "requested":
                raise PayoutNotOpenError(
                    message=f"payout {payout_uuid} is not in requested status",
                    details={"payout_id": str(payout_uuid), "status": payout_row["status"]},
                )

            existing_votes = await uow.connection.fetch(
                "SELECT voter_sub, vote FROM payout_approvals WHERE payout_id = $1;",
                payout_uuid,
            )
            voters = {r["voter_sub"] for r in existing_votes}
            cur_for = sum(1 for r in existing_votes if r["vote"] == "approve")
            cur_against = sum(1 for r in existing_votes if r["vote"] == "reject")

            if voter_sub in voters:
                return VoteOutcome(
                    status="already_voted",
                    votes_for=cur_for,
                    votes_against=cur_against,
                )

            try:
                await uow.connection.execute(
                    """
                    INSERT INTO payout_approvals (payout_id, voter_sub, vote, note, voted_at)
                    VALUES ($1, $2, $3, $4, now());
                    """,
                    payout_uuid,
                    voter_sub,
                    vote,
                    truncated_note,
                )
            except asyncpg.UniqueViolationError:
                return VoteOutcome(
                    status="already_voted",
                    votes_for=cur_for,
                    votes_against=cur_against,
                )

            final_for = cur_for + (1 if vote == "approve" else 0)
            final_against = cur_against + (1 if vote == "reject" else 0)

            pure_decision = decide_from_votes(final_for, final_against)
            decision_status = pure_decision

            if pure_decision == "rejected":
                await uow.connection.execute(
                    """
                    UPDATE cold_payouts
                    SET status = 'rejected', updated_at = now()
                    WHERE payout_id = $1 AND status = 'requested';
                    """,
                    payout_uuid,
                )
                await audit.record(
                    uow.connection,
                    actor_sub=voter_sub,
                    actor_role=voter_role,
                    action="payout.reject",
                    target_type="user",
                    target_id=str(payout_uuid),
                    details={
                        "payout_id": str(payout_uuid),
                        "reason": "rejected_by_approver",
                        "note": truncated_note,
                    },
                )
                alert_msg = f"payout REJECTED: id={payout_uuid} by {voter_sub}"

            elif pure_decision == "approved":
                await uow.connection.execute(
                    """
                    UPDATE cold_payouts
                    SET status = 'approved', updated_at = now()
                    WHERE payout_id = $1 AND status = 'requested';
                    """,
                    payout_uuid,
                )
                await audit.record(
                    uow.connection,
                    actor_sub=voter_sub,
                    actor_role=voter_role,
                    action="payout.approved",
                    target_type="user",
                    target_id=str(payout_uuid),
                    details={
                        "payout_id": str(payout_uuid),
                        "votes_for": final_for,
                        "note": truncated_note,
                    },
                )
                # THE HUMAN MOMENT: THIS alert is the execution instruction for human Safe signers.
                # Safe multisig UI is outside our server walls.
                alert_msg = f"payout APPROVED: id={payout_uuid} READY FOR EXECUTION (Safe — 2-of-3)"

        if alert_msg is not None:
            await self._send_alert(alert_msg)

        return VoteOutcome(
            status=decision_status,
            votes_for=final_for,
            votes_against=final_against,
        )

    async def record_execution(
        self,
        *,
        payout_id: UUID | str,
        tx_hash: str,
        recorded_by_sub: str,
    ) -> PayoutRecord:
        """Record manual multisig broadcast execution receipt.

        THE RECEIPT MOMENT:
        The server acts strictly as a scribe, never a signer.
        Validates tx_hash format (0x + 64 hex chars).
        Guards against double-execution: status must be 'approved' (else PayoutNotOpenError).
        Writes audit record atomically with UPDATE status='executed'.
        Fires post-commit alert.
        """
        if not _TX_HASH_RE.match(tx_hash):
            raise ValueError(
                f"Invalid tx_hash format: '{tx_hash}'. Must match ^0x[0-9a-fA-F]{{64}}$."
            )

        payout_uuid = UUID(str(payout_id))

        async with UnitOfWork(self._pool) as uow:
            row = await uow.connection.fetchrow(
                "SELECT * FROM cold_payouts WHERE payout_id = $1 FOR UPDATE;",
                payout_uuid,
            )
            if row is None:
                raise NotFoundError(message=f"payout {payout_uuid} not found")

            if row["status"] != "approved":
                raise PayoutNotOpenError(
                    message=f"payout {payout_uuid} is not in approved status for execution",
                    details={"payout_id": str(payout_uuid), "status": row["status"]},
                )

            updated_row = await uow.connection.fetchrow(
                """
                UPDATE cold_payouts
                SET status = 'executed',
                    tx_hash = $2,
                    executed_at = now(),
                    updated_at = now()
                WHERE payout_id = $1 AND status = 'approved'
                RETURNING *;
                """,
                payout_uuid,
                tx_hash,
            )
            if updated_row is None:
                raise PayoutNotOpenError(
                    message=f"payout {payout_uuid} could not be updated to executed",
                    details={"payout_id": str(payout_uuid)},
                )

            await audit.record(
                uow.connection,
                actor_sub=recorded_by_sub,
                actor_role="admin",
                action="payout.executed",
                target_type="user",
                target_id=str(payout_uuid),
                details={
                    "payout_id": str(payout_uuid),
                    "tx_hash": tx_hash,
                    "recorded_by": recorded_by_sub,
                },
            )

        executed_payout = _row_to_payout_record(updated_row)
        alert_msg = f"payout EXECUTED — awaiting confirmations: id={payout_uuid} tx_hash={tx_hash}"
        await self._send_alert(alert_msg, rail=executed_payout.rail)
        return executed_payout

    async def confirm_if_ready(self, *, payout_id: UUID | str) -> PayoutRecord | None:
        """Poll OnChainReader and advance executed payout to confirmed if threshold met.

        OBSERVATION FAIL-OPEN (Task 44 law):
        Underlying RPC errors log a warning and return None without crashing the caller.
        If tx is confirmed on-chain, status advances to 'confirmed' atomically with
        audit row 'payout.confirmed', closing the custody reconciliation loop.
        """
        payout_uuid = UUID(str(payout_id))

        async with UnitOfWork(self._pool) as uow:
            row = await uow.connection.fetchrow(
                "SELECT * FROM cold_payouts WHERE payout_id = $1 FOR UPDATE;",
                payout_uuid,
            )
            if row is None or row["status"] != "executed":
                return None

            rail = row["rail"]
            tx_hash = row["tx_hash"]
            if not tx_hash:
                return None

            try:
                tx_status: TxStatus = await self._reader.get_tx_status(rail, tx_hash)
            except Exception as exc:
                logger.warning(
                    "payout_confirmation_reader_failed",
                    payout_id=str(payout_uuid),
                    rail=rail,
                    error=str(exc),
                )
                return None

            if not tx_status.confirmed:
                return None

            confirmed_row = await uow.connection.fetchrow(
                """
                UPDATE cold_payouts
                SET status = 'confirmed',
                    confirmed_at = now(),
                    updated_at = now()
                WHERE payout_id = $1 AND status = 'executed'
                RETURNING *;
                """,
                payout_uuid,
            )
            if confirmed_row is None:
                return None

            await audit.record(
                uow.connection,
                actor_sub="system",
                actor_role="admin",
                action="payout.confirmed",
                target_type="user",
                target_id=str(payout_uuid),
                details={
                    "payout_id": str(payout_uuid),
                    "tx_hash": tx_hash,
                    "confirmations": tx_status.confirmations,
                },
            )

        confirmed_payout = _row_to_payout_record(confirmed_row)
        alert_msg = (
            f"payout CONFIRMED: id={payout_uuid} tx_hash={tx_hash} "
            f"confirmations={tx_status.confirmations}"
        )
        await self._send_alert(alert_msg, rail=confirmed_payout.rail)
        return confirmed_payout

    async def list_open(self, *, limit: int = 50) -> tuple[PayoutRecord, ...]:
        """Fetch active ops work queue items (requested + approved) ordered by creation time."""
        if limit < 1 or limit > 200:
            raise ValueError("limit must be between 1 and 200")

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT cp.*,
                       COALESCE(
                           SUM(CASE WHEN pa.vote = 'approve' THEN 1 ELSE 0 END), 0
                       ) AS votes_for,
                       COALESCE(
                           SUM(CASE WHEN pa.vote = 'reject' THEN 1 ELSE 0 END), 0
                       ) AS votes_against
                FROM cold_payouts cp
                LEFT JOIN payout_approvals pa ON cp.payout_id = pa.payout_id
                WHERE cp.status IN ('requested', 'approved')
                GROUP BY cp.payout_id
                ORDER BY cp.created_at ASC
                LIMIT $1;
                """,
                limit,
            )

        return tuple(_row_to_payout_record(r) for r in rows)


# ==============================================================================
# PAYOUT SWEEPER
# ==============================================================================
class PayoutSweeper:
    """One-shot batch sweeper for cold payouts (runs on a 15-minute systemd timer).

    Responsibilities:
    1. Confirm executed payouts: checks up to 20 executed payouts against OnChainReader.
    2. Stuck payout scan: alerts on payouts approved or executed > 24h ago with age context.
    3. Emits JSON telemetry line matching standard treasury logging taxonomy.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        reader: OnChainReader,
        alert: Callable[[str], Awaitable[None]],
        now: Callable[[], float] = time.time,
    ) -> None:
        self._pool = pool
        self._reader = reader
        self._alert = alert
        self._now = now
        self._service = PayoutService(pool=pool, reader=reader, alert=alert, now=now)

    async def _send_alert(self, msg: str) -> None:
        """Deliver alert via transport; record failure on error (Task 43 discipline)."""
        try:
            res = self._alert(msg)
            if inspect.isawaitable(res):
                await res
        except Exception as exc:
            logger.error("treasury_sweeper_alert_failed", error=str(exc), message=msg)
            try:
                await record_failure_pool(
                    self._pool,
                    channel="telegram",
                    subject="treasury_admin",
                    purpose="treasury.alert",
                    payload={"message": msg, "rail": "base_usdc"},
                    error=exc.__class__.__name__,
                )
            except Exception as rec_err:
                logger.error("treasury_failure_record_failed", error=str(rec_err))

    async def run_once(self) -> PayoutSweepReport:
        """Execute one complete payout sweeping cycle."""
        current_ts = self._now()
        current_dt = datetime.fromtimestamp(current_ts, tz=UTC)

        # 1. Confirm executed payouts (bounded batch 20)
        async with self._pool.acquire() as conn:
            executed_rows = await conn.fetch(
                """
                SELECT payout_id
                FROM cold_payouts
                WHERE status = 'executed'
                ORDER BY updated_at ASC
                LIMIT 20;
                """
            )

        confirmed_count = 0
        for row in executed_rows:
            confirmed = await self._service.confirm_if_ready(payout_id=row["payout_id"])
            if confirmed is not None:
                confirmed_count += 1

        # 2. STUCK scan: classify_stuck over open + executed
        async with self._pool.acquire() as conn:
            active_rows = await conn.fetch(
                """
                SELECT cp.*,
                       COALESCE(
                           SUM(CASE WHEN pa.vote = 'approve' THEN 1 ELSE 0 END), 0
                       ) AS votes_for,
                       COALESCE(
                           SUM(CASE WHEN pa.vote = 'reject' THEN 1 ELSE 0 END), 0
                       ) AS votes_against
                FROM cold_payouts cp
                LEFT JOIN payout_approvals pa ON cp.payout_id = pa.payout_id
                WHERE cp.status IN ('requested', 'approved', 'executed')
                GROUP BY cp.payout_id
                ORDER BY cp.updated_at ASC;
                """
            )

        stuck_count = 0
        open_count = 0
        for row in active_rows:
            payout = _row_to_payout_record(row)
            if payout.status in ("requested", "approved"):
                open_count += 1

            if classify_stuck(payout, current_dt):
                stuck_count += 1
                age_s = (current_dt - payout.updated_at.astimezone(UTC)).total_seconds()
                age_hours = age_s / 3600.0
                alert_msg = (
                    f"payout STUCK: id={payout.payout_id} status={payout.status} "
                    f"age={age_hours:.1f}h rail={payout.rail} amount={payout.amount_minor}"
                )
                await self._send_alert(alert_msg)

        return PayoutSweepReport(
            mode="treasury_payout_sweep",
            confirmed=confirmed_count,
            stuck=stuck_count,
            open=open_count,
            checked_at=current_dt.isoformat(),
            elapsed_ms=0,
        )


# ==============================================================================
# CUSTODY RECONCILIATION BRIDGE (CLOSING GIFT FOR TASK 41 / PHASE 2)
# ==============================================================================
async def custody_snapshot(
    pool: asyncpg.Pool,
    reader: OnChainReader,
    rail: str = "base_usdc",
    now: Callable[[], float] = time.time,
) -> CustodySnapshot:
    """Capture fresh custody state, on-chain truth, drift, and in-flight payouts.

    Architectural Seam:
    Task 41's daily reconciliation worker is currently frozen to single-currency
    ledger-vs-gateway audits. Full institutional custody reconciliation (comparing
    total customer ledger liabilities against hot wallet + cold vault reserves minus
    in-flight payouts) is the Phase 2 evolution seeded here.
    """
    captured_at = datetime.fromtimestamp(now(), tz=UTC)

    async with pool.acquire() as conn:
        state_row = await conn.fetchrow(
            """
            SELECT hot_balance_minor, cold_balance_minor
            FROM wallet_state
            WHERE rail = $1;
            """,
            rail,
        )
        if state_row is None:
            raise NotFoundError(message=f"wallet_state for rail '{rail}' not found")

        hot_cache = int(state_row["hot_balance_minor"])
        cold_cache = int(state_row["cold_balance_minor"])

        in_flight_sum = await conn.fetchval(
            """
            SELECT COALESCE(SUM(amount_minor), 0)
            FROM cold_payouts
            WHERE rail = $1 AND status IN ('requested', 'approved', 'executed');
            """,
            rail,
        )
        in_flight_total = int(in_flight_sum)

        oldest_rows = await conn.fetch(
            """
            SELECT cp.*,
                   COALESCE(SUM(CASE WHEN pa.vote = 'approve' THEN 1 ELSE 0 END), 0) AS votes_for,
                   COALESCE(SUM(CASE WHEN pa.vote = 'reject' THEN 1 ELSE 0 END), 0) AS votes_against
            FROM cold_payouts cp
            LEFT JOIN payout_approvals pa ON cp.payout_id = pa.payout_id
            WHERE cp.rail = $1 AND cp.status IN ('requested', 'approved', 'executed')
            GROUP BY cp.payout_id
            ORDER BY cp.created_at ASC
            LIMIT 5;
            """,
            rail,
        )
        oldest_in_flight = tuple(_row_to_payout_record(r) for r in oldest_rows)

    # Fresh on-chain truth from reader
    hot_truth = await reader.read_hot_balance(rail)
    cold_truth = await reader.read_cold_balance(rail)

    hot_drift = hot_truth - hot_cache
    cold_drift = cold_truth - cold_cache

    return CustodySnapshot(
        rail=rail,
        hot_cache=hot_cache,
        cold_cache=cold_cache,
        hot_truth=hot_truth,
        cold_truth=cold_truth,
        hot_drift=hot_drift,
        cold_drift=cold_drift,
        in_flight_total=in_flight_total,
        oldest_in_flight=oldest_in_flight,
        captured_at=captured_at,
    )


# ==============================================================================
# CLI / ENTRYPOINT HARNESS
# ==============================================================================
class _DefaultOnChainReader:
    """Default production OnChainReader stub for Phase 1 before Task 50 RPC integration."""

    async def read_hot_balance(self, rail: str) -> int:
        return 0

    async def read_cold_balance(self, rail: str) -> int:
        return 0

    async def get_tx_status(self, rail: str, tx_hash: str) -> TxStatus:
        return TxStatus(confirmed=False, confirmations=0)


async def main(
    pool: asyncpg.Pool | None = None,
    reader: OnChainReader | None = None,
    alert: Callable[[str], Awaitable[None]] | None = None,
    now: Callable[[], float] = time.time,
) -> int:
    """Entrypoint for the 15-minute treasury payout sweeper one-shot process."""
    start_time = time.perf_counter()
    pool_created_here = False

    if pool is None:
        try:
            settings = get_settings()
            parsed_dsn = urlsplit(settings.pg_dsn)
            db_host = parsed_dsn.hostname or "unknown"
            db_name = parsed_dsn.path.lstrip("/") or "unknown"
        except Exception as exc:
            sys.stderr.write(f"Configuration failure: {exc.__class__.__name__}: {exc}\n")
            sys.stderr.flush()
            return EXIT_OPS_FAILURE

        try:
            pool = await asyncpg.create_pool(
                settings.pg_dsn,
                min_size=1,
                max_size=2,
                server_settings={"TimeZone": "UTC"},
                command_timeout=30.0,
            )
            pool_created_here = True

            async with pool.acquire() as conn:
                tz = await conn.fetchval("SHOW timezone")
                if tz not in ("UTC", "Etc/UTC"):
                    raise RuntimeError(f"PostgreSQL connection timezone must be UTC, got '{tz}'")
        except Exception as exc:
            err_msg = (
                f"Operational failure in treasury payout sweeper "
                f"(host='{db_host}', db='{db_name}'): {exc.__class__.__name__}: {exc}\n"
            )
            sys.stderr.write(err_msg)
            sys.stderr.flush()
            return EXIT_OPS_FAILURE

    http_client: httpx.AsyncClient | None = None
    try:
        active_alert: Callable[[str], Awaitable[None]]
        if alert is not None:
            active_alert = alert
        else:
            settings = get_settings()
            if settings.telegram_bot_token and settings.telegram_admin_chat_id:
                http_client = httpx.AsyncClient()
                channel = TelegramChannel(
                    http_client,
                    bot_token=settings.telegram_bot_token,
                    chat_id=settings.telegram_admin_chat_id,
                    retry_max=settings.notification_retry_max,
                    backoff_base_s=settings.notification_backoff_base_s,
                )
                active_alert = channel.send
            else:

                async def _log_alert(msg: str) -> None:
                    logger.info("treasury_payout_alert_emitted", alert_message=msg)

                active_alert = _log_alert

        active_reader: OnChainReader = reader if reader is not None else _DefaultOnChainReader()

        sweeper = PayoutSweeper(
            pool=pool,
            reader=active_reader,
            alert=active_alert,
            now=now,
        )
        report = await sweeper.run_once()
        elapsed_s = time.perf_counter() - start_time
        elapsed_ms = max(0, round(elapsed_s * 1000))

        report_line = build_report_line(report, elapsed_ms)
        sys.stdout.write(report_line + "\n")
        sys.stdout.flush()

        code = map_exit_code(report)
        # --- Task 69 append ---
        from fluxpay.alerts.router import send_heartbeat

        send_heartbeat("treasury_sweeper", ok=(code == 0))
        return code
    except Exception as exc:
        # --- Task 69 append ---
        from fluxpay.alerts.router import send_heartbeat

        send_heartbeat("treasury_sweeper", ok=False, reason=str(exc))
        sys.stderr.write(f"Operational failure in treasury sweeper run: {exc}\n")
        sys.stderr.flush()
        return EXIT_OPS_FAILURE
    finally:
        if http_client is not None:
            await http_client.aclose()
        if pool_created_here and pool is not None:
            await pool.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
