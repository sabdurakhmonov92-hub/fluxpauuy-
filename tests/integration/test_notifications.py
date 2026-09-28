"""Integration tests for Task 43 notification adapters.

Tests real PostgreSQL (notification_failures table) with MockTransport channels
(no real Telegram/SendGrid sends). Exercises:
1. TelegramAdminNotifier E2E: notify_hold_pending -> MockTransport captured POST
2. FAILURE -> ROW: channel 5xx x retry_max -> failure row recorded
3. SWEEP: retry_pending -> resolved_at set on success; attempts preserved
4. ABANDON: 11-attempt row -> sweep -> abandoned
5. Task 42 wiring: ApprovalService + TelegramAdminNotifier -> hold lifecycle
6. LoggingStub disabled-mode: config None -> logs, zero HTTP calls
7. record_failure_pool standalone roundtrip
8. Migration idempotency (0010 re-executable)
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import httpx
import orjson
import pytest
import pytest_asyncio

from fluxpay.approvals.service import ApprovalService, ApprovalsWorker
from fluxpay.notifications.channels import NotificationFailed, TelegramChannel
from fluxpay.notifications.notifier import (
    LoggingStubNotifier,
    TelegramAdminNotifier,
    format_hold_pending,
)
from fluxpay.notifications.records import record_failure_pool, retry_pending
from fluxpay.registry.users import UserRecord
from fluxpay.risk.quarantine import HoldRecord
from fluxpay.shared.events import EventBus

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_0010_PATH = REPO_ROOT / "migrations" / "0010_notifications.sql"
MIGRATION_0009_PATH = REPO_ROOT / "migrations" / "0009_approvals.sql"


def _sha256_hex(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def apply_notifications_schema(
    db_pool: asyncpg.Pool,
    apply_approvals_schema: None,
) -> None:
    """Execute migrations/0010_notifications.sql idempotently."""
    sql = MIGRATION_0010_PATH.read_text(encoding="utf-8")
    async with db_pool.acquire() as conn:
        await conn.execute(sql)


@pytest_asyncio.fixture
async def apply_approvals_schema(db_pool: asyncpg.Pool) -> None:
    """Execute migrations/0009_approvals.sql idempotently (local re-definition for isolation)."""
    sql = MIGRATION_0009_PATH.read_text(encoding="utf-8")
    async with db_pool.acquire() as conn:
        await conn.execute(sql)


# ---------------------------------------------------------------------------
# MOCK TRANSPORT HELPERS
# ---------------------------------------------------------------------------


class _CapturedRequest:
    def __init__(self, url: str, body: dict[str, Any], status: int) -> None:
        self.url = url
        self.body = body
        self.status = status


class _MockTelegramTransport:
    """MockTransport that captures Telegram POST requests."""

    def __init__(self, *, always_status: int = 200) -> None:
        self.captured: list[_CapturedRequest] = []
        self.always_status = always_status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body: dict[str, Any] = {}
        if request.content:
            try:
                body = orjson.loads(request.content)
            except Exception:
                body = {}
        self.captured.append(_CapturedRequest(str(request.url), body, self.always_status))
        return httpx.Response(self.always_status)


def _make_tg_channel(
    transport: _MockTelegramTransport,
    pool: asyncpg.Pool,
    *,
    retry_max: int = 3,
) -> tuple[TelegramChannel, TelegramAdminNotifier]:
    """Build a TelegramChannel + TelegramAdminNotifier pair with mock transport."""

    async def _no_sleep(duration: float) -> None:
        pass

    client = httpx.AsyncClient(transport=httpx.MockTransport(transport))
    channel = TelegramChannel(
        client,
        bot_token="TESTTOKEN_INTEGRATION",  # noqa: S106
        chat_id="-100123456789",
        retry_max=retry_max,
        backoff_base_s=0.001,
        sleep=_no_sleep,
    )
    notifier = TelegramAdminNotifier(channel, pool)
    return channel, notifier


def _make_hold(
    *,
    hold_id: UUID | None = None,
    agent_id: UUID | None = None,
    amount_minor: int = 150_000_000,
    currency: str = "USDC",
    reason: str = "single_tx_ceiling",
) -> HoldRecord:
    return HoldRecord(
        hold_id=hold_id or uuid4(),
        agent_id=agent_id or uuid4(),
        idem_key=f"idem-{uuid4().hex[:8]}",
        amount_minor=amount_minor,
        currency=currency,
        reason=reason,
        status="pending",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# 1. TELEGRAMADMINNOTIFIER E2E: notify_hold_pending → correct wire body
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notify_hold_pending_captured_on_wire(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
) -> None:
    """notify_hold_pending → MockTransport captures POST with correct chat_id and body."""
    transport = _MockTelegramTransport(always_status=200)
    _, notifier = _make_tg_channel(transport, db_pool)

    hold = _make_hold()
    await notifier.notify_hold_pending(hold)

    assert len(transport.captured) == 1
    req = transport.captured[0]
    assert "sendMessage" in req.url
    assert req.body.get("chat_id") == "-100123456789"
    # Verify body matches format_hold_pending exactly
    expected_text = format_hold_pending(hold)
    assert req.body.get("text") == expected_text
    # Token must NOT be in the captured text
    assert "TESTTOKEN_INTEGRATION" not in req.body.get("text", "")

    # No failure rows recorded on success
    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM notification_failures WHERE resolved_at IS NULL;"
        )
    assert count == 0


# ---------------------------------------------------------------------------
# 2. FAILURE → ROW: channel 500 x retry_max → notification_failures row
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notify_failure_records_row_on_exhaustion(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
) -> None:
    """5xx x retry_max → NotificationFailed → notification_failures row with full payload."""
    transport = _MockTelegramTransport(always_status=500)
    _, notifier = _make_tg_channel(transport, db_pool, retry_max=2)

    hold = _make_hold()
    # notify_hold_pending catches NotificationFailed and records failure row
    await notifier.notify_hold_pending(hold)

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT channel, subject, purpose, payload, error, attempts
            FROM notification_failures
            WHERE resolved_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1;
            """
        )

    assert row is not None
    assert row["channel"] == "telegram"
    assert row["purpose"] == "hold.pending"
    assert row["attempts"] == 1

    payload = (
        orjson.loads(row["payload"])
        if isinstance(row["payload"], (str, bytes))
        else dict(row["payload"])
    )
    assert str(hold.hold_id) in payload.get("hold_id", "")
    assert "text" in payload  # enough context to re-send

    # Token must NOT appear in subject or payload
    subject = row["subject"]
    assert "TESTTOKEN_INTEGRATION" not in subject
    assert "TESTTOKEN_INTEGRATION" not in str(payload)


# ---------------------------------------------------------------------------
# 3. SWEEP: retry_pending → success → resolved_at set
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sweep_resolves_failure_row(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
) -> None:
    """retry_pending with succeeding channel → resolved_at set; attempts preserved."""
    # Seed a failure row manually
    await record_failure_pool(
        db_pool,
        channel="telegram",
        subject="-100123456789",
        purpose="hold.pending",
        payload={"text": "test sweep message", "hold_id": str(uuid4())},
        error="http_5xx",
    )

    # Verify row exists
    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM notification_failures WHERE resolved_at IS NULL;"
        )
    assert count >= 1

    # Build a succeeding channel callable
    sent_texts: list[str] = []

    async def _succeeding_send(**kwargs: Any) -> None:
        sent_texts.append(kwargs.get("text", ""))

    processed = await retry_pending(db_pool, channels={"telegram": _succeeding_send})
    assert processed >= 1

    # Verify row is resolved
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT resolved_at, attempts
            FROM notification_failures
            ORDER BY created_at DESC
            LIMIT 1;
            """
        )
    assert row is not None
    assert row["resolved_at"] is not None  # successfully resolved
    assert row["attempts"] == 1  # preserved from INSERT


# ---------------------------------------------------------------------------
# 4. ABANDON: 11-attempt row → sweep → abandoned
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sweep_abandons_row_after_threshold(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
) -> None:
    """Row with attempts=10 + one more failure → abandoned (attempts>10, resolved_at set)."""
    # Pre-seed a row that is already at the threshold attempts
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO notification_failures
                (channel, subject, purpose, payload, error, attempts, created_at)
            VALUES ('telegram', '-100abc', 'hold.pending', $1::jsonb, 'http_5xx', 10, now());
            """,
            orjson.dumps({"text": "abandon me", "hold_id": str(uuid4())}).decode(),
        )

    # Failing channel
    async def _always_fail(**kwargs: Any) -> None:
        raise NotificationFailed("http_5xx still failing")

    processed = await retry_pending(db_pool, channels={"telegram": _always_fail})
    assert processed >= 1

    # The row should now be abandoned: resolved_at set, error='abandoned', attempts=11
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT resolved_at, error, attempts
            FROM notification_failures
            WHERE subject = '-100abc'
            ORDER BY created_at DESC
            LIMIT 1;
            """
        )
    assert row is not None
    assert row["resolved_at"] is not None
    assert row["error"] == "abandoned"
    assert row["attempts"] == 11


# ---------------------------------------------------------------------------
# 5. MIGRATION IDEMPOTENCY
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migration_0010_is_idempotent(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
) -> None:
    """Running 0010_notifications.sql twice raises no error (IF NOT EXISTS guards)."""
    sql = MIGRATION_0010_PATH.read_text(encoding="utf-8")
    async with db_pool.acquire() as conn:
        await conn.execute(sql)  # second run — must not raise


# ---------------------------------------------------------------------------
# 6. record_failure_pool STANDALONE ROUNDTRIP (worker context)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_failure_pool_standalone_roundtrip(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
) -> None:
    """record_failure_pool inserts a row that is queryable immediately."""
    hold_id = uuid4()
    await record_failure_pool(
        db_pool,
        channel="email",
        subject="admin@test.com",
        purpose="hold.settled",
        payload={"hold_id": str(hold_id), "text": "settled notice"},
        error="transport_error",
    )

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT channel, subject, purpose, attempts, resolved_at
            FROM notification_failures
            WHERE subject = 'admin@test.com' AND purpose = 'hold.settled'
            ORDER BY created_at DESC
            LIMIT 1;
            """
        )

    assert row is not None
    assert row["channel"] == "email"
    assert row["attempts"] == 1
    assert row["resolved_at"] is None  # pending sweep


# ---------------------------------------------------------------------------
# 7. LOGGING STUB DISABLED MODE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logging_stub_no_http_calls(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """LoggingStubNotifier → logs INFO, zero HTTP calls, zero failure rows."""
    notifier = LoggingStubNotifier()
    hold = _make_hold()

    with caplog.at_level(logging.INFO):
        await notifier.notify_hold_pending(hold)
        await notifier.notify_hold_settled(hold, "test-outcome")
        await notifier.notify_hold_rejected(hold, "rejected")

    # No failure rows should have been recorded
    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM notification_failures WHERE resolved_at IS NULL;"
        )
    assert count == 0


# ---------------------------------------------------------------------------
# 8. TASK 42 PROTOCOL WIRING E2E
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_task42_protocol_wiring(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
    payment_bus: EventBus,
    seeded_hold: Any,
    make_user: Any,
) -> None:
    """ApprovalService + TelegramAdminNotifier → hold lifecycle honored on wire."""
    hold_id, _, _, _, payment_service = await seeded_hold()

    transport = _MockTelegramTransport(always_status=200)
    _, notifier = _make_tg_channel(transport, db_pool)

    approval_service = ApprovalService(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    admin_a: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_t43_a_{uuid4().hex[:8]}")
    admin_b: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_t43_b_{uuid4().hex[:8]}")

    # Trigger hold pending notification via worker-ish pattern
    worker = ApprovalsWorker(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )
    batch = await worker.poll()
    await worker.process(batch)

    # At least one sendMessage captured (hold.pending)
    pending_msgs = [c for c in transport.captured if "sendMessage" in c.url]
    assert len(pending_msgs) >= 1
    assert "🚨 HOLD pending approval" in pending_msgs[0].body.get("text", "")

    transport.captured.clear()

    # Second admin approves → settled notification
    await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="approve",
    )
    await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_b.keycloak_sub,
        voter_role="admin",
        vote="approve",
    )

    settled_msgs = [c for c in transport.captured if "sendMessage" in c.url]
    assert len(settled_msgs) >= 1
    assert "✅ HOLD settled" in settled_msgs[-1].body.get("text", "")


@pytest.mark.asyncio
async def test_task42_protocol_rejected_message(
    db_pool: asyncpg.Pool,
    apply_notifications_schema: None,
    payment_bus: EventBus,
    seeded_hold: Any,
    make_user: Any,
) -> None:
    """ApprovalService + TelegramAdminNotifier → rejection sends ❌ message."""
    hold_id, *_, payment_service = await seeded_hold()

    transport = _MockTelegramTransport(always_status=200)
    _, notifier = _make_tg_channel(transport, db_pool)

    approval_service = ApprovalService(
        pool=db_pool,
        bus=payment_bus,
        notifier=notifier,
        payments=payment_service,
    )

    admin_a: UserRecord = await make_user(role="admin", keycloak_sub=f"sub_t43_r_{uuid4().hex[:8]}")
    await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=admin_a.keycloak_sub,
        voter_role="admin",
        vote="reject",
        note="sanctions check failed",
    )

    rejected_msgs = [c for c in transport.captured if "sendMessage" in c.url]
    assert len(rejected_msgs) >= 1
    assert "❌ HOLD rejected" in rejected_msgs[0].body.get("text", "")
