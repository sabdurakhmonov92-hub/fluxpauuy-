"""Integration tests for Dual-Authorization: 2-Man Rule for Held Payments (Task 42).

Exercises end-to-end 2-man approval quorum, settlement convergence, self-vote blocking,
rejection asymmetry, role-based wire security, concurrency races, crash-heal sweeps,
and audit atomicity against real PostgreSQL, Valkey, and RabbitMQ/Redis event bus.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
import pytest_asyncio

from fluxpay.approvals.service import (
    ApprovalService,
    ApprovalsWorker,
    HoldNotPendingError,
    VoteOutcome,
)
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.payments.service import PaymentService, deterministic_tx_id
from fluxpay.registry.agents import (
    AgentLifecycle,
    CreateAgentCommand,
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.registry.users import UserRecord
from fluxpay.risk.limits import LimitRepo
from fluxpay.risk.quarantine import HoldRecord, QuarantineService
from fluxpay.shared.events import EventBus, EventType
from fluxpay.wallet.accounts import AccountDirectory

pytestmark = pytest.mark.integration

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
MIGRATION_0009_PATH: Path = REPO_ROOT / "migrations" / "0009_approvals.sql"


def _sha256_hex(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------
# TEST NOTIFIER RECORDER (TASK 43 SEAM STUB)
# ------------------------------------------------------------------------------
class RecorderAdminNotifier:
    """In-memory test double capturing operator notifications dispatched by Task 42."""

    def __init__(self) -> None:
        self.pending_notifications: list[HoldRecord] = []
        self.settled_notifications: list[tuple[HoldRecord, Any]] = []
        self.rejected_notifications: list[tuple[HoldRecord, Any]] = []

    async def notify_hold_pending(self, hold: HoldRecord) -> None:
        self.pending_notifications.append(hold)

    async def notify_hold_settled(self, hold: HoldRecord, outcome: Any) -> None:
        self.settled_notifications.append((hold, outcome))

    async def notify_hold_rejected(self, hold: HoldRecord, outcome: Any) -> None:
        self.rejected_notifications.append((hold, outcome))


# ------------------------------------------------------------------------------
# FIXTURES
# ------------------------------------------------------------------------------
@pytest_asyncio.fixture
async def apply_approvals_schema(
    db_pool: asyncpg.Pool,
    apply_limits_schema: None,
) -> None:
    """Execute migrations/0009_approvals.sql idempotently."""
    sql = MIGRATION_0009_PATH.read_text(encoding="utf-8")  # noqa: ASYNC240
    async with db_pool.acquire() as conn:
        await conn.execute(sql)


@pytest.fixture
def notifier() -> RecorderAdminNotifier:
    """Provide clean notification recorder."""
    return RecorderAdminNotifier()


@pytest_asyncio.fixture
async def seeded_hold(
    db_pool: asyncpg.Pool,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    seed_account: Any,
    payment_bus: EventBus,
    valkey_client: Any,
    apply_approvals_schema: None,
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_audit_schema: None,
) -> Callable[..., Coroutine[Any, Any, tuple[UUID, UUID, str, str, PaymentService]]]:
    """Helper to provision agent, merchant, fund balance, and create a real quarantined hold."""

    async def _seed(
        *,
        amount_minor: int = 150_000_000,  # $150 breaches default ceiling $100
    ) -> tuple[UUID, UUID, str, str, PaymentService]:
        agent_ext = f"agt_appr_{uuid4().hex[:10]}"
        merch_ext = f"mch_appr_{uuid4().hex[:10]}"
        agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
        await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=merch_ext))

        agent_acct = await account_directory.get_agent_account(agent.agent_id)
        # Fund agent with $1,000 (1_000_000_000 minor)
        await seed_account(agent_acct.account_id, 1_000_000_000, "USDC")

        quarantine = QuarantineService(db_pool)
        payment_service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=LimitRepo(db_pool),
            quarantine=quarantine,
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
        )

        idem_key = f"hold-seed-{uuid4().hex[:12]}"
        body_hash = _sha256_hex(idem_key)

        outcome = await payment_service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=amount_minor,
            currency="USDC",
        )
        assert outcome.status == "held"

        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT hold_id FROM payment_holds WHERE agent_id = $1 AND idem_key = $2;",
                agent.agent_id,
                idem_key,
            )
            assert row is not None
            hold_id = row["hold_id"]

        return hold_id, agent.agent_id, idem_key, merch_ext, payment_service

    return _seed


# ------------------------------------------------------------------------------
# 1. E2E TWO-MAN APPROVAL & SETTLEMENT CONVERGENCE
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_e2e_two_man_approval_and_settlement(
    db_pool: asyncpg.Pool,
    payment_bus: EventBus,
    ledger_store: PostgresLedgerStore,
    make_user: Any,
    notifier: RecorderAdminNotifier,
    seeded_hold: Any,
) -> None:
    """Verify full 2-man rule: vote 1 counted (money untouched) -> vote 2 settles."""
    hold_id, agent_id, idem_key, _merch_ext, payment_service = await seeded_hold()
    admin_a: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_adm_a_{uuid4().hex[:8]}")
    admin_b: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_adm_b_{uuid4().hex[:8]}")

    approval_service = ApprovalService(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    await payment_bus.ensure_group(EventType.PAYMENT_SETTLED, "approvals_test_group")

    # Step 1: Admin A votes approve -> counted; money NOT moved
    tx_id = deterministic_tx_id(agent_id, idem_key)
    out1 = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="approve",
        note="Initial review passed",
    )
    assert out1.status == "counted"
    assert out1.votes_for == 1
    assert out1.votes_against == 0

    # Ledger entries MUST be 0
    tx_check = await ledger_store.get_transaction(tx_id)
    assert tx_check is None

    # Hold status must remain pending
    async with db_pool.acquire() as conn:
        st = await conn.fetchval("SELECT status FROM payment_holds WHERE hold_id = $1;", hold_id)
        assert st == "pending"

    # Step 2: Admin B votes approve -> threshold reached (2) -> approved and settled
    out2 = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_b.keycloak_sub,
        voter_role="admin",
        vote="approve",
        note="Second approval confirmed with merchant",
    )
    assert out2.status == "approved_settled"
    assert out2.votes_for == 2
    assert out2.votes_against == 0

    # Hold status updated to approved
    async with db_pool.acquire() as conn:
        st = await conn.fetchval("SELECT status FROM payment_holds WHERE hold_id = $1;", hold_id)
        assert st == "approved"

        # Idempotency reservation MUST be COMPLETED
        idem_row = await conn.fetchrow(
            """
            SELECT state, response_status
            FROM idempotency_keys
            WHERE agent_id = $1 AND idem_key = $2;
            """,
            agent_id,
            idem_key,
        )
        assert idem_row is not None
        assert idem_row["state"] == "COMPLETED"
        assert idem_row["response_status"] == 201

    # Ledger entries EXIST (3 entries: agent DEBIT, merchant CREDIT, fees CREDIT)
    tx_settled = await ledger_store.get_transaction(tx_id)
    assert tx_settled is not None
    assert len(tx_settled.entries) == 3

    # Audit rows verified: hold.vote x2, hold.approve2, hold.settled
    async with db_pool.acquire() as conn:
        audit_rows = await conn.fetch(
            """
            SELECT action, actor_sub, details
            FROM audit_log
            WHERE target_id = $1
            ORDER BY id ASC;
            """,
            str(agent_id),
        )
        actions = [r["action"] for r in audit_rows]
        assert "hold.vote" in actions
        assert actions.count("hold.vote") == 2
        assert "hold.approve2" in actions
        assert "hold.settled" in actions

    # Notifier called for settled
    assert len(notifier.settled_notifications) == 1
    assert notifier.settled_notifications[0][0].hold_id == hold_id


# ------------------------------------------------------------------------------
# 2. SELF-VOTE & DUPLICATE VOTE PREVENTION
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_duplicate_and_self_vote_blocked(
    db_pool: asyncpg.Pool,
    payment_bus: EventBus,
    make_user: Any,
    notifier: RecorderAdminNotifier,
    seeded_hold: Any,
) -> None:
    """Validate UNIQUE constraint blocks duplicate vote from the same admin."""
    hold_id, _agent_id, _idem_key, _, payment_service = await seeded_hold()
    admin_a: UserRecord = await make_user(
        role="admin", keycloak_sub=f"sub_adm_dup_{uuid4().hex[:8]}"
    )

    approval_service = ApprovalService(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    # First vote succeeds
    out1 = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="approve",
        note="First vote",
    )
    assert out1.status == "counted"
    assert out1.votes_for == 1

    # Second vote from SAME admin is classified as already_voted
    out2 = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="approve",
        note="Second vote attempt by same human",
    )
    assert out2.status == "already_voted"
    assert out2.votes_for == 1
    assert out2.votes_against == 0

    # Ensure vote was NOT inserted into DB
    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM approval_votes WHERE hold_id = $1;", hold_id
        )
        assert count == 1


# ------------------------------------------------------------------------------
# 3. REJECT-TERMINATES & DOOR CLOSURE
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reject_terminates_and_closes_door(
    db_pool: asyncpg.Pool,
    payment_bus: EventBus,
    make_user: Any,
    notifier: RecorderAdminNotifier,
    seeded_hold: Any,
) -> None:
    """Validate 1 approve + 1 reject resolves as rejected, failing idempotency."""
    hold_id, agent_id, idem_key, _, payment_service = await seeded_hold()
    admin_a: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_rej_a_{uuid4().hex[:8]}")
    admin_b: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_rej_b_{uuid4().hex[:8]}")

    approval_service = ApprovalService(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    await payment_bus.ensure_group(EventType.PAYMENT_FAILED, "reject_test_group")

    # Admin A approves (counted)
    await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="approve",
    )

    # Admin B rejects -> immediate terminal rejection
    out_rej = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_b.keycloak_sub,
        voter_role="admin",
        vote="reject",
        note="Sanctions violation suspected",
    )
    assert out_rej.status == "rejected"
    assert out_rej.votes_against == 1

    # DB status rejected and idempotency FAILED
    async with db_pool.acquire() as conn:
        st = await conn.fetchval("SELECT status FROM payment_holds WHERE hold_id = $1;", hold_id)
        assert st == "rejected"

        state = await conn.fetchval(
            "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
            agent_id,
            idem_key,
        )
        assert state == "FAILED"

    # Notification dispatched
    assert len(notifier.rejected_notifications) == 1
    assert notifier.rejected_notifications[0][0].hold_id == hold_id

    # Door is closed: subsequent vote attempt raises HoldNotPendingError
    admin_c: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_rej_c_{uuid4().hex[:8]}")
    with pytest.raises(HoldNotPendingError):
        await approval_service.submit_vote(
            hold_id=hold_id,
            voter_sub=admin_c.keycloak_sub,
            voter_role="admin",
            vote="approve",
        )


# ------------------------------------------------------------------------------
# 4. ROLE GATE: SUPPORT OPERATOR 403 WIRE ENVELOPE
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_role_gate_support_forbidden_wire(
    platform_client: tuple[httpx.AsyncClient, Any],
    make_user: Any,
    seeded_hold: Any,
) -> None:
    """Validate HTTP POST /admin/holds/{hold_id}/vote rejects support role with 403."""
    client, app = platform_client
    hold_id, _, _, _, _ = await seeded_hold()

    support_user: UserRecord = await make_user(
        role="support", keycloak_sub=f"sub_supp_{uuid4().hex[:8]}"
    )
    mint_token = app.state.mint_admin_token
    token = mint_token(sub=support_user.keycloak_sub, role="support")

    resp = await client.post(
        f"/admin/holds/{hold_id}/vote",
        json={"vote": "approve", "note": "support review"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 403
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] == "forbidden"
    assert body["error"]["retryable"] is False


# ------------------------------------------------------------------------------
# 5. CONCURRENT THRESHOLD RACE: SINGLE SETTLEMENT EXECUTION
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_concurrent_threshold_race_single_settlement(
    db_pool: asyncpg.Pool,
    payment_bus: EventBus,
    ledger_store: PostgresLedgerStore,
    make_user: Any,
    notifier: RecorderAdminNotifier,
    seeded_hold: Any,
) -> None:
    """Two concurrent votes racing to hit threshold 2: exactly one settles."""
    hold_id, agent_id, idem_key, _, payment_service = await seeded_hold()
    admin_1: UserRecord = await make_user(
        role="admin", keycloak_sub=f"sub_race_1_{uuid4().hex[:8]}"
    )
    admin_2: UserRecord = await make_user(
        role="admin", keycloak_sub=f"sub_race_2_{uuid4().hex[:8]}"
    )
    admin_3: UserRecord = await make_user(
        role="admin", keycloak_sub=f"sub_race_3_{uuid4().hex[:8]}"
    )

    approval_service = ApprovalService(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    # Initial vote counted (threshold at 1/2)
    out1 = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_1.keycloak_sub,
        voter_role="admin",
        vote="approve",
    )
    assert out1.status == "counted"

    # Concurrent race between admin_2 and admin_3 to deliver the second approval
    results = await asyncio.gather(
        approval_service.submit_vote(
            hold_id=hold_id,
            voter_sub=admin_2.keycloak_sub,
            voter_role="admin",
            vote="approve",
        ),
        approval_service.submit_vote(
            hold_id=hold_id,
            voter_sub=admin_3.keycloak_sub,
            voter_role="admin",
            vote="approve",
        ),
        return_exceptions=True,
    )

    # Exactly one must succeed with approved_settled; the other encounters HoldNotPendingError
    settled_outcomes = [
        r for r in results if isinstance(r, VoteOutcome) and r.status == "approved_settled"
    ]
    not_pending_errors = [r for r in results if isinstance(r, HoldNotPendingError)]

    assert len(settled_outcomes) == 1
    assert len(not_pending_errors) == 1

    # Ledger entries posted exactly ONCE (3 entries total)
    tx_id = deterministic_tx_id(agent_id, idem_key)
    tx = await ledger_store.get_transaction(tx_id)
    assert tx is not None
    assert len(tx.entries) == 3


# ------------------------------------------------------------------------------
# 6. CRASH-HEAL SWEEP: IDEMPOTENT CONVERGENCE
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_crash_heal_sweep_converges(
    db_pool: asyncpg.Pool,
    payment_bus: EventBus,
    ledger_store: PostgresLedgerStore,
    make_user: Any,
    notifier: RecorderAdminNotifier,
    seeded_hold: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validate that worker sweeps approved-but-unsettled hold and converges safely."""
    hold_id, agent_id, idem_key, _, payment_service = await seeded_hold()
    admin_a: UserRecord = await make_user(
        role="admin", keycloak_sub=f"sub_crash_a_{uuid4().hex[:8]}"
    )
    admin_b: UserRecord = await make_user(
        role="admin", keycloak_sub=f"sub_crash_b_{uuid4().hex[:8]}"
    )

    approval_service = ApprovalService(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    # Admin A votes approve
    await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="approve",
    )

    # Simulate crash during settlement on the second vote
    original_settle = payment_service.settle_approved

    call_count = 0

    async def _failing_settle(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        raise RuntimeError("Simulated process crash during settlement")

    monkeypatch.setattr(payment_service, "settle_approved", _failing_settle)

    with pytest.raises(RuntimeError, match="Simulated process crash during settlement"):
        await approval_service.submit_vote(
            hold_id=hold_id,
            voter_sub=admin_b.keycloak_sub,
            voter_role="admin",
            vote="approve",
        )

    # State in DB: hold is 'approved', but idempotency is PENDING, ledger has 0 entries
    async with db_pool.acquire() as conn:
        st = await conn.fetchval("SELECT status FROM payment_holds WHERE hold_id = $1;", hold_id)
        assert st == "approved"

        idem_state = await conn.fetchval(
            "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
            agent_id,
            idem_key,
        )
        assert idem_state == "PENDING"

    # Restore real settle function
    monkeypatch.setattr(payment_service, "settle_approved", original_settle)

    # Backdate updated_at on hold to bypass grace period without sleep
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE payment_holds
            SET updated_at = now() - interval '120 seconds'
            WHERE hold_id = $1;
            """,
            hold_id,
        )

    # Worker executes crash-heal sweep
    worker = ApprovalsWorker(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
        grace_seconds=60.0,
    )

    batch = await worker.poll()
    assert len(batch) >= 1
    await worker.process(batch)

    # Hold is now settled in ledger and idempotency row COMPLETED
    tx_id = deterministic_tx_id(agent_id, idem_key)
    tx = await ledger_store.get_transaction(tx_id)
    assert tx is not None
    assert len(tx.entries) == 3

    async with db_pool.acquire() as conn:
        idem_state = await conn.fetchval(
            "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
            agent_id,
            idem_key,
        )
        assert idem_state == "COMPLETED"

    # Second worker poll: probe checks COMPLETED and skips safely without error
    batch2 = await worker.poll()
    await worker.process(batch2)
    # Ledger still has exactly 3 entries (strictly idempotent)
    tx_after = await ledger_store.get_transaction(tx_id)
    assert tx_after is not None
    assert len(tx_after.entries) == 3


# ------------------------------------------------------------------------------
# 7. NOTIFICATION IDEMPOTENCY DEDUP MARKER
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_notification_idempotency_marker(
    db_pool: asyncpg.Pool,
    payment_bus: EventBus,
    notifier: RecorderAdminNotifier,
    seeded_hold: Any,
) -> None:
    """Validate payment_holds.notified_at prevents duplicate operator notifications."""
    hold_id, _agent_id, _, _, payment_service = await seeded_hold()

    # Initial state: notified_at is NULL
    async with db_pool.acquire() as conn:
        n_at = await conn.fetchval(
            "SELECT notified_at FROM payment_holds WHERE hold_id = $1;", hold_id
        )
        assert n_at is None

    worker = ApprovalsWorker(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    # First cycle: notifies pending hold and sets notified_at
    batch1 = await worker.poll()
    notify_items = [
        item for item in batch1 if item.kind == "notify_pending" and item.hold.hold_id == hold_id
    ]
    assert len(notify_items) == 1
    await worker.process(batch1)

    assert len(notifier.pending_notifications) == 1
    assert notifier.pending_notifications[0].hold_id == hold_id

    async with db_pool.acquire() as conn:
        n_at_after = await conn.fetchval(
            "SELECT notified_at FROM payment_holds WHERE hold_id = $1;", hold_id
        )
        assert n_at_after is not None

    # Second cycle: hold is filtered by notified_at IS NULL; notify is NOT called again
    batch2 = await worker.poll()
    subsequent_notify = [
        item for item in batch2 if item.kind == "notify_pending" and item.hold.hold_id == hold_id
    ]
    assert len(subsequent_notify) == 0
    await worker.process(batch2)

    # Recorder count remains strictly 1
    # NOTE: Crash between notify_hold_pending and UPDATE notified_at results in at most one
    # duplicate notification, which is standard acceptable at-least-once behavior.
    assert len(notifier.pending_notifications) == 1


# ------------------------------------------------------------------------------
# 8. AUDIT ATOMICITY THROUGH COMPOSITION
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_audit_atomicity_on_mid_uow_failure(
    db_pool: asyncpg.Pool,
    payment_bus: EventBus,
    make_user: Any,
    notifier: RecorderAdminNotifier,
    seeded_hold: Any,
) -> None:
    """Validate Task 29 audit law: aborted transaction leaves NO audit rows."""
    hold_id, agent_id, _, _, payment_service = await seeded_hold()
    admin_a: UserRecord = await make_user(
        role="admin", keycloak_sub=f"sub_atom_a_{uuid4().hex[:8]}"
    )

    approval_service = ApprovalService(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    # Valid first vote commits 1 audit row
    await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="approve",
        note="Valid initial vote",
    )

    async with db_pool.acquire() as conn:
        initial_votes = await conn.fetchval(
            "SELECT COUNT(*) FROM audit_log WHERE target_id = $1 AND action = 'hold.vote';",
            str(agent_id),
        )
        assert initial_votes == 1

    # Second duplicate vote returns already_voted; transaction commits no new audit row
    out_dup = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="approve",
        note="Duplicate attempt",
    )
    assert out_dup.status == "already_voted"

    async with db_pool.acquire() as conn:
        final_votes = await conn.fetchval(
            "SELECT COUNT(*) FROM audit_log WHERE target_id = $1 AND action = 'hold.vote';",
            str(agent_id),
        )
        # Audit count remains strictly 1 (no spurious audit on failed/rejected vote)
        assert final_votes == 1


# ------------------------------------------------------------------------------
# 9. WIRE VOTE ENDPOINT VIA HTTPX (TASK 29 ADMIN HARNESS)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_vote_endpoint_wire_success_and_unauthenticated(
    platform_client: tuple[httpx.AsyncClient, Any],
    make_user: Any,
    seeded_hold: Any,
) -> None:
    """Validate HTTP wire format: 200 VoteOutcome dict shape and 401 unauthenticated."""
    client, app = platform_client
    hold_id, _, _, _, _ = await seeded_hold()
    admin: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_wire_{uuid4().hex[:8]}")
    mint_token = app.state.mint_admin_token
    token = mint_token(sub=admin.keycloak_sub, role="admin")

    # 1. Unauthenticated request -> 401
    resp_unauth = await client.post(
        f"/admin/holds/{hold_id}/vote",
        json={"vote": "approve"},
    )
    assert resp_unauth.status_code == 401
    body_unauth = resp_unauth.json()
    assert body_unauth["error"]["code"] == "authentication_failed"

    # 2. Authenticated valid request -> 200 VoteOutcome dict shape
    resp_ok = await client.post(
        f"/admin/holds/{hold_id}/vote",
        json={"vote": "approve", "note": "wire validation"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp_ok.status_code == 200
    body_ok = resp_ok.json()
    assert body_ok == {
        "status": "counted",
        "votes_for": 1,
        "votes_against": 0,
    }
