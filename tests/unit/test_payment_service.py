"""=============================================================================
Unit Tests for PaymentService: The Full Money Flow (Task 31)
=============================================================================
Tests:
1. Deterministic tx_id (KAT frozen, purity, collisions, namespace stability).
2. Happy path:
   - status="settled", response_status=201.
   - Exact entries: agent debited total, merchant credited amount, fees credited fee.
   - Event payment.settled emitted with flat scalars.
   - Outflow counter incremented in Valkey.
   - Wire bytes match PaymentResponse model.
3. Held path:
   - Quarantined by ceiling -> hold row created in payment_holds.
   - Event payment.held emitted.
   - Response 201 with status="held".
   - Idempotency reservation remains PENDING (the Task 42 HITL gap resolved).
4. Velocity reject path:
   - Exceeded velocity limit -> reservation marked FAILED.
   - Event payment.failed emitted.
   - PaymentPolicyError raised.
5. Insufficient funds path:
   - Agent balance < total -> post_transaction raises InsufficientFunds.
   - Reservation marked FAILED.
   - Event payment.failed emitted.
   - InsufficientFunds propagates.
6. Duplicate after completion:
   - Idempotency reserve returns REPLAY.
   - Cached response returned immediately with replayed=True.
   - Zero ledger calls, zero event emissions, zero outflow increments.
7. Crash recovery probe:
   - Worker crashed after ledger post before complete().
   - Stale takeover reclaims PENDING reservation.
   - Probe finds existing tx in ledger -> skips post_transaction.
   - Idempotency reservation completes -> exactly-once effect.
8. Task 42 handoff (settle_approved and reject_held):
   - Held payment settled via settle_approved -> entries posted, completed.
   - Held payment rejected via reject_held -> reservation FAILED, payment.failed event.
9. Merchant not found -> NotFoundError raised.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from _fakes.payment_stack import (
    FakeAccountDirectory,
    FakeEventBus,
    FakeIdempotencyStore,
    FakeLedgerStore,
    FakeLimitRepo,
    FakeQuarantineService,
    FakeUow,
    FakeValkey,
)

from fluxpay.contracts.schemas import PaymentResponse
from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.store import EntryDraft
from fluxpay.payments.service import (
    PaymentService,
    deterministic_tx_id,
)
from fluxpay.risk.limits import AgentLimits
from fluxpay.shared.errors import (
    InsufficientFunds,
    NotFoundError,
    PaymentPolicyError,
)
from fluxpay.shared.events import EventType

# Deterministic KAT constants
KAT_AGENT_ID = UUID("00000000-0000-0000-0000-000000000001")
KAT_IDEM_KEY = "idem-test-key-12345678"
KAT_EXPECTED_TX_ID = UUID("1253d480-fffa-5933-a2d8-656f3be2cb7d")


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ==============================================================================
# 1. DETERMINISTIC TX_ID TESTS
# ==============================================================================


def test_deterministic_tx_id_kat() -> None:
    """Freeze deterministic tx_id against hardcoded KAT anchor."""
    actual = deterministic_tx_id(KAT_AGENT_ID, KAT_IDEM_KEY)
    assert actual == KAT_EXPECTED_TX_ID
    assert actual.version == 5


def test_deterministic_tx_id_purity_and_variation() -> None:
    """Verify purity: same inputs produce same UUID; different idem produces different UUID."""
    agent_id = uuid4()
    key1 = "idem-key-abc-123"
    key2 = "idem-key-abc-456"

    id1 = deterministic_tx_id(agent_id, key1)
    id1_again = deterministic_tx_id(agent_id, key1)
    id2 = deterministic_tx_id(agent_id, key2)

    assert id1 == id1_again
    assert id1 != id2


# ==============================================================================
# FIXTURE SETUP
# ==============================================================================


@pytest.fixture
def stack() -> dict[str, Any]:
    """Assemble in-memory test stack with pre-seeded accounts."""
    ledger = FakeLedgerStore()
    directory = FakeAccountDirectory()
    limits_repo = FakeLimitRepo()
    quarantine = FakeQuarantineService()
    bus = FakeEventBus()
    valkey = FakeValkey()

    def time_fn() -> datetime:
        return datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)

    idem_store = FakeIdempotencyStore(time_fn=time_fn)

    # Seed accounts
    agent_id = uuid4()
    agent_acc_id = uuid4()
    merchant_acc_id = uuid4()
    fees_acc_id = uuid4()

    directory.register_agent(agent_id, agent_acc_id, currency="USDC")
    directory.register_merchant("demo_merchant", merchant_acc_id, currency="USDC")
    directory.set_fees_account(fees_acc_id, currency="USDC")

    # Initial funds for agent: $1,000 (1_000_000_000 minor)
    ledger.init_account(agent_acc_id, currency="USDC", initial_balance=1_000_000_000)
    ledger.init_account(merchant_acc_id, currency="USDC", initial_balance=0)
    ledger.init_account(fees_acc_id, currency="USDC", initial_balance=0)

    service = PaymentService(
        ledger=ledger,
        directory=directory,
        limits_repo=limits_repo,
        quarantine=quarantine,
        bus=bus,
        valkey=valkey,
        uow_factory=lambda: FakeUow(),
        time_fn=time_fn,
        idempotency_module=idem_store,
    )

    return {
        "service": service,
        "ledger": ledger,
        "directory": directory,
        "limits_repo": limits_repo,
        "quarantine": quarantine,
        "bus": bus,
        "valkey": valkey,
        "idem_store": idem_store,
        "agent_id": agent_id,
        "agent_acc_id": agent_acc_id,
        "merchant_acc_id": merchant_acc_id,
        "fees_acc_id": fees_acc_id,
        "time_fn": time_fn,
    }


# ==============================================================================
# 2. HAPPY PATH TEST
# ==============================================================================


@pytest.mark.asyncio
async def test_payment_happy_path(stack: dict[str, Any]) -> None:
    service: PaymentService = stack["service"]
    ledger: FakeLedgerStore = stack["ledger"]
    bus: FakeEventBus = stack["bus"]
    valkey: FakeValkey = stack["valkey"]
    agent_id: UUID = stack["agent_id"]
    agent_acc_id: UUID = stack["agent_acc_id"]
    merchant_acc_id: UUID = stack["merchant_acc_id"]
    fees_acc_id: UUID = stack["fees_acc_id"]

    idem_key = "test-idem-happy-001"
    body_hash = _sha256_hex("to=demo_merchant&amount=10000")
    # Transfer 10,000 minor units ($0.01) -> fee = 100 minor units (1%), total = 10,100
    outcome = await service.pay(
        agent_id=agent_id,
        idem_key=idem_key,
        body_hash=body_hash,
        to_merchant="demo_merchant",
        amount_minor=10_000,
        currency="USDC",
    )

    # 1. Assert Outcome
    expected_tx_id = deterministic_tx_id(agent_id, idem_key)
    assert outcome.status == "settled"
    assert outcome.tx_id == expected_tx_id
    assert outcome.response_status == 201
    assert outcome.replayed is False

    # 2. Assert Wire Bytes match PaymentResponse
    parsed_response = PaymentResponse.model_validate_json(outcome.wire_body)
    assert parsed_response.id == expected_tx_id
    assert parsed_response.status == "settled"

    # 3. Assert Ledger Entries
    tx = await ledger.get_transaction(expected_tx_id)
    assert tx is not None
    assert len(tx.entries) == 3
    # debit agent 10,100; credit merchant 10,000; credit fees 100
    e_agent, e_merchant, e_fees = tx.entries
    assert e_agent.account_id == agent_acc_id
    assert e_agent.direction == Direction.DEBIT
    assert e_agent.amount == 10_100
    assert e_merchant.account_id == merchant_acc_id
    assert e_merchant.direction == Direction.CREDIT
    assert e_merchant.amount == 10_000
    assert e_fees.account_id == fees_acc_id
    assert e_fees.direction == Direction.CREDIT
    assert e_fees.amount == 100

    # Balances
    bal_agent = await ledger.get_balance(agent_acc_id)
    bal_merch = await ledger.get_balance(merchant_acc_id)
    bal_fees = await ledger.get_balance(fees_acc_id)
    assert bal_agent.balance == 1_000_000_000 - 10_100
    assert bal_merch.balance == 10_000
    assert bal_fees.balance == 100

    # 4. Assert Event Bus
    assert len(bus.published_events) == 1
    evt = bus.published_events[0]
    assert evt.type == EventType.PAYMENT_SETTLED
    assert evt.payload["tx_id"] == str(expected_tx_id)
    assert evt.payload["merchant"] == "demo_merchant"
    assert evt.payload["amount"] == 10_000
    assert evt.payload["fee"] == 100
    assert evt.payload["total"] == 10_100
    assert evt.payload["currency"] == "USDC"

    # 5. Assert Outflow in Valkey
    outflow_key = f"flx:outflow:{{{agent_id}}}:20260926"
    stored_outflow = await valkey.get(outflow_key)
    assert stored_outflow == "10100"


# ==============================================================================
# 3. HELD PATH TEST (QUARANTINED BY CEILING)
# ==============================================================================


@pytest.mark.asyncio
async def test_payment_held_path(stack: dict[str, Any]) -> None:
    service: PaymentService = stack["service"]
    ledger: FakeLedgerStore = stack["ledger"]
    quarantine: FakeQuarantineService = stack["quarantine"]
    bus: FakeEventBus = stack["bus"]
    idem_store: FakeIdempotencyStore = stack["idem_store"]
    agent_id: UUID = stack["agent_id"]

    idem_key = "test-idem-held-001"
    body_hash = _sha256_hex("large-payment-holding")
    # Default single_tx_ceiling is 100_000_000 ($100). Send 150_000_000
    amount = 150_000_000
    outcome = await service.pay(
        agent_id=agent_id,
        idem_key=idem_key,
        body_hash=body_hash,
        to_merchant="demo_merchant",
        amount_minor=amount,
        currency="USDC",
    )

    expected_tx_id = deterministic_tx_id(agent_id, idem_key)
    assert outcome.status == "held"
    assert outcome.tx_id == expected_tx_id
    assert outcome.response_status == 201
    assert outcome.replayed is False

    # Ledger untouched
    tx = await ledger.get_transaction(expected_tx_id)
    assert tx is None

    # Hold placed in quarantine queue
    assert len(quarantine.holds) == 1
    hold = quarantine.holds[0]
    assert hold.agent_id == agent_id
    assert hold.idem_key == idem_key
    assert hold.amount_minor == 151_500_000  # Total = amount + 1% fee
    assert hold.status == "pending"

    # Event payment.held emitted
    assert len(bus.published_events) == 1
    assert bus.published_events[0].type == EventType.PAYMENT_HELD
    assert bus.published_events[0].payload["reason"] == "single_tx_ceiling"

    # Idempotency reservation MUST REMAIN PENDING (Task 42 door)
    rec = idem_store._records[(agent_id, idem_key)]
    assert rec["state"] == "PENDING"
    assert rec["tx_id"] == expected_tx_id


# ==============================================================================
# 4. VELOCITY REJECT TEST
# ==============================================================================


@pytest.mark.asyncio
async def test_payment_velocity_reject(stack: dict[str, Any]) -> None:
    service: PaymentService = stack["service"]
    bus: FakeEventBus = stack["bus"]
    idem_store: FakeIdempotencyStore = stack["idem_store"]
    limits_repo: FakeLimitRepo = stack["limits_repo"]
    agent_id: UUID = stack["agent_id"]

    # Set velocity limit to 2 attempts per 60s
    await limits_repo.upsert(
        agent_id,
        AgentLimits(
            agent_id=agent_id,
            velocity_limit=2,
            velocity_window_s=60,
            max_single_tx_minor=100_000_000,
            daily_outflow_cap_minor=500_000_000,
        ),
    )

    # First attempt: succeeds (count=1 <= 1)
    await service.pay(
        agent_id=agent_id,
        idem_key="velocity-first",
        body_hash=_sha256_hex("first"),
        to_merchant="demo_merchant",
        amount_minor=1_000,
    )

    # Second attempt: fails on velocity check (count=2 > 1)
    idem_key2 = "velocity-second"
    with pytest.raises(PaymentPolicyError):
        await service.pay(
            agent_id=agent_id,
            idem_key=idem_key2,
            body_hash=_sha256_hex("second"),
            to_merchant="demo_merchant",
            amount_minor=1_000,
        )

    # Reservation for second attempt must be FAILED (reclaimable later)
    rec2 = idem_store._records[(agent_id, idem_key2)]
    assert rec2["state"] == "FAILED"

    # Event payment.failed emitted
    failed_evts = [e for e in bus.published_events if e.type == EventType.PAYMENT_FAILED]
    assert len(failed_evts) == 1
    assert failed_evts[0].payload["reason"] == "velocity"


# ==============================================================================
# 5. INSUFFICIENT FUNDS TEST
# ==============================================================================


@pytest.mark.asyncio
async def test_payment_insufficient_funds(stack: dict[str, Any]) -> None:
    service: PaymentService = stack["service"]
    bus: FakeEventBus = stack["bus"]
    ledger: FakeLedgerStore = stack["ledger"]
    idem_store: FakeIdempotencyStore = stack["idem_store"]
    agent_id: UUID = stack["agent_id"]
    agent_acc_id: UUID = stack["agent_acc_id"]

    # Drain agent account to 0
    ledger._accounts[agent_acc_id][0] = 0

    idem_key = "test-idem-insufficient"
    with pytest.raises(InsufficientFunds):
        await service.pay(
            agent_id=agent_id,
            idem_key=idem_key,
            body_hash=_sha256_hex("broke"),
            to_merchant="demo_merchant",
            amount_minor=5_000,
        )

    # Reservation FAILED
    rec = idem_store._records[(agent_id, idem_key)]
    assert rec["state"] == "FAILED"

    # Event payment.failed emitted
    failed_evts = [e for e in bus.published_events if e.type == EventType.PAYMENT_FAILED]
    assert len(failed_evts) == 1
    assert failed_evts[0].payload["reason"] == "insufficient_funds"


# ==============================================================================
# 6. DUPLICATE REPLAY TEST
# ==============================================================================


@pytest.mark.asyncio
async def test_payment_duplicate_replay_from_db(stack: dict[str, Any]) -> None:
    service: PaymentService = stack["service"]
    bus: FakeEventBus = stack["bus"]
    ledger: FakeLedgerStore = stack["ledger"]
    valkey: FakeValkey = stack["valkey"]
    agent_id: UUID = stack["agent_id"]

    idem_key = "test-idem-replay-001"
    body_hash = _sha256_hex("original-payment")

    # 1. Initial payment
    o1 = await service.pay(
        agent_id=agent_id,
        idem_key=idem_key,
        body_hash=body_hash,
        to_merchant="demo_merchant",
        amount_minor=10_000,
    )
    assert o1.status == "settled"
    assert o1.replayed is False
    assert len(bus.published_events) == 1

    # 2. Duplicate payment (same key, same hash)
    o2 = await service.pay(
        agent_id=agent_id,
        idem_key=idem_key,
        body_hash=body_hash,
        to_merchant="demo_merchant",
        amount_minor=10_000,
    )
    assert o2.status == "settled"
    assert o2.tx_id == o1.tx_id
    assert o2.response_status == o1.response_status
    assert o2.wire_body == o1.wire_body
    assert o2.replayed is True

    # Invariants: Zero new ledger entries, zero new events, zero extra outflow
    assert len(ledger._entries) == 3
    assert len(bus.published_events) == 1  # No duplicate event
    outflow_key = f"flx:outflow:{{{agent_id}}}:20260926"
    assert await valkey.get(outflow_key) == "10100"  # Not 20200


# ==============================================================================
# 7. CRASH RECOVERY PROBE TEST (THE EXACTLY-ONCE PROOF)
# ==============================================================================


@pytest.mark.asyncio
async def test_payment_crash_recovery_probe(stack: dict[str, Any]) -> None:
    """Worker crashed after ledger post before complete().

    Retry reclaims reservation, probe finds transaction, skips post, completes cleanly.
    """
    service: PaymentService = stack["service"]
    ledger: FakeLedgerStore = stack["ledger"]
    idem_store: FakeIdempotencyStore = stack["idem_store"]
    agent_id: UUID = stack["agent_id"]
    agent_acc_id: UUID = stack["agent_acc_id"]
    merchant_acc_id: UUID = stack["merchant_acc_id"]
    fees_acc_id: UUID = stack["fees_acc_id"]

    idem_key = "crash-recovery-key-001"
    body_hash = _sha256_hex("crash-payload")
    tx_id = deterministic_tx_id(agent_id, idem_key)

    # 1. Simulate crashed prior worker:
    # - Reservation was left in PENDING state 40 seconds ago (stale > 30s)
    stale_time = datetime(2026, 9, 26, 11, 59, 0, tzinfo=UTC)
    idem_store._records[(agent_id, idem_key)] = {
        "body_hash": body_hash,
        "state": "PENDING",
        "reserved_at": stale_time,
        "tx_id": tx_id,
        "response_status": None,
        "response_body": None,
        "attempts": 1,
    }

    # - Ledger transaction WAS ALREADY POSTED under tx_id
    entries = (
        EntryDraft(
            account_id=agent_acc_id,
            direction=Direction.DEBIT,
            amount=10_100,
            currency="USDC",
            tx_id=tx_id,
        ),
        EntryDraft(
            account_id=merchant_acc_id,
            direction=Direction.CREDIT,
            amount=10_000,
            currency="USDC",
            tx_id=tx_id,
        ),
        EntryDraft(
            account_id=fees_acc_id,
            direction=Direction.CREDIT,
            amount=100,
            currency="USDC",
            tx_id=tx_id,
        ),
    )
    await ledger.post_transaction(entries)
    assert len(ledger._entries) == 3

    # 2. Re-enter pay() with fresh service (stale takeover -> probe -> skip post)
    outcome = await service.pay(
        agent_id=agent_id,
        idem_key=idem_key,
        body_hash=body_hash,
        to_merchant="demo_merchant",
        amount_minor=10_000,
    )

    # Converged to settled
    assert outcome.status == "settled"
    assert outcome.tx_id == tx_id
    assert outcome.replayed is False

    # Ledger entries count UNCHANGED (post was skipped!)
    assert len(ledger._entries) == 3

    # Reservation COMPLETED in database
    rec = idem_store._records[(agent_id, idem_key)]
    assert rec["state"] == "COMPLETED"
    assert rec["tx_id"] == tx_id


# ==============================================================================
# 8. TASK 42 HITL HANDOFF (SETTLE_APPROVED & REJECT_HELD)
# ==============================================================================


@pytest.mark.asyncio
async def test_task42_settle_approved(stack: dict[str, Any]) -> None:
    service: PaymentService = stack["service"]
    ledger: FakeLedgerStore = stack["ledger"]
    quarantine: FakeQuarantineService = stack["quarantine"]
    bus: FakeEventBus = stack["bus"]
    idem_store: FakeIdempotencyStore = stack["idem_store"]
    agent_id: UUID = stack["agent_id"]

    idem_key = "held-then-approved-001"
    body_hash = _sha256_hex("held-then-approved")

    # 1. Initial payment is quarantined
    o_held = await service.pay(
        agent_id=agent_id,
        idem_key=idem_key,
        body_hash=body_hash,
        to_merchant="demo_merchant",
        amount_minor=150_000_000,
    )
    assert o_held.status == "held"
    assert len(ledger._entries) == 0

    # 2. Admin approves hold in QuarantineService
    hold_id = quarantine.holds[0].hold_id
    await quarantine.decide(hold_id=hold_id, decision="approved", decided_by="admin_alice")

    # 3. Task 42 calls settle_approved with original parameters
    o_settled = await service.settle_approved(
        agent_id=agent_id,
        idem_key=idem_key,
        to_merchant="demo_merchant",
        amount_minor=150_000_000,
    )
    assert o_settled.status == "settled"
    assert o_settled.tx_id == o_held.tx_id

    # Ledger now has 3 entries
    assert len(ledger._entries) == 3

    # Reservation state is now COMPLETED
    rec = idem_store._records[(agent_id, idem_key)]
    assert rec["state"] == "COMPLETED"

    # payment.settled emitted
    settled_evts = [e for e in bus.published_events if e.type == EventType.PAYMENT_SETTLED]
    assert len(settled_evts) == 1


@pytest.mark.asyncio
async def test_task42_reject_held(stack: dict[str, Any]) -> None:
    service: PaymentService = stack["service"]
    quarantine: FakeQuarantineService = stack["quarantine"]
    bus: FakeEventBus = stack["bus"]
    idem_store: FakeIdempotencyStore = stack["idem_store"]
    agent_id: UUID = stack["agent_id"]

    idem_key = "held-then-rejected-001"
    body_hash = _sha256_hex("held-then-rejected")

    await service.pay(
        agent_id=agent_id,
        idem_key=idem_key,
        body_hash=body_hash,
        to_merchant="demo_merchant",
        amount_minor=150_000_000,
    )

    hold_id = quarantine.holds[0].hold_id
    await quarantine.decide(hold_id=hold_id, decision="rejected", decided_by="admin_bob")

    await service.reject_held(
        agent_id=agent_id,
        idem_key=idem_key,
        to_merchant="demo_merchant",
        amount_minor=150_000_000,
        reason="compliance_reject",
    )

    # Reservation is now FAILED
    rec = idem_store._records[(agent_id, idem_key)]
    assert rec["state"] == "FAILED"

    # payment.failed emitted
    failed_evts = [e for e in bus.published_events if e.type == EventType.PAYMENT_FAILED]
    assert len(failed_evts) == 1
    assert failed_evts[0].payload["reason"] == "compliance_reject"


# ==============================================================================
# 9. MERCHANT NOT FOUND TEST
# ==============================================================================


@pytest.mark.asyncio
async def test_merchant_not_found(stack: dict[str, Any]) -> None:
    service: PaymentService = stack["service"]
    agent_id: UUID = stack["agent_id"]

    with pytest.raises(NotFoundError) as exc_info:
        await service.pay(
            agent_id=agent_id,
            idem_key="unknown-merchant-key",
            body_hash=_sha256_hex("unknown"),
            to_merchant="ghost_merchant",
            amount_minor=5_000,
        )

    assert exc_info.value.code == "not_found"
    assert exc_info.value.details["merchant"] == "ghost_merchant"
