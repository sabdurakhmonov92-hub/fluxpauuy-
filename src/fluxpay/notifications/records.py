"""Notification failure ledger: record and sweep for missed alerts (Task 43).

==============================================================================
FAIL-CLOSED-TO-RECORD DOCTRINE
==============================================================================
The single most important operational invariant of the notification subsystem:
A missed notification is NEVER silent — it becomes a database row.

When TelegramChannel or EmailChannel raises NotificationFailed, the caller
(TelegramAdminNotifier) writes a notification_failures row with the full
message context (payload) and a defect class string (error). The row is then
eligible for re-dispatch by retry_pending().

WHY a database row instead of just logging?
  - A log entry is mutable (log rotation, disk full, pipeline failure).
  - A database row is durable, queryable, and alertable.
  - Operations can SELECT * FROM notification_failures WHERE resolved_at IS
    NULL to see exactly which alerts are pending re-dispatch without reading
    through log files.

WHY not a message queue (Redis, RabbitMQ)?
  - Task 42's AdminNotifier Protocol explicitly chose to avoid a bus layer
    for hold notifications: admin notices are FEW, LOUD, and human-targeted.
    A bus introduces broker availability as a dependency for operational
    safety. A database table owned by the same PostgreSQL instance as the
    holds table is simpler, auditable, and available wherever the DB is.
  - SMS/Twilio (Phase 2) will introduce per-channel queue semantics when
    volume justifies it.

==============================================================================
SWEEP & ABANDON POLICY
==============================================================================
retry_pending() runs every 15 minutes (systemd timer OnCalendar=*:0/15).
It selects unresolved rows (SKIP LOCKED for parallel-safe sweep), calls the
appropriate channel callable (telegram/email), and on success sets
resolved_at=now(). On continued failure it increments attempts.

Abandon threshold: attempts > 10 (11th failure) → resolved_at=now(),
error='abandoned'. Abandoned rows are NOT deleted — they remain as permanent
audit evidence that a notification could not be delivered. Operations can
query abandoned rows; they are NOT included in Task 41's reconciliation report
(that report covers financial ledger health; notification health is an ops
concern surfaced here and via Grafana/Loki alerting).

==============================================================================
WHO RUNS THE SWEEP
==============================================================================
run_notify_sweep() is the one-shot entry point invoked by systemd
fluxpay-notify-sweep.service every 15 minutes via fluxpay-notify-sweep.timer.
The unit pair is delivered in deploy/systemd/.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import orjson

from fluxpay.shared.logging import get_logger

__all__ = [
    "record_failure",
    "record_failure_pool",
    "retry_pending",
    "run_notify_sweep",
]

logger = get_logger("fluxpay.notifications.records")

# Abandon threshold: attempts beyond this value on sweep mark the row abandoned.
_ABANDON_AFTER_ATTEMPTS: int = 10


async def record_failure(
    conn: asyncpg.Connection,
    *,
    channel: str,
    subject: str,
    purpose: str,
    payload: dict[str, Any],
    error: str,
) -> None:
    """Insert a notification failure row using an existing connection.

    Used within a UnitOfWork transaction context where the caller controls
    commit boundaries. The failure row commits atomically with the caller's UoW.

    Args:
        conn: Active asyncpg connection (caller owns the transaction).
        channel: 'telegram' or 'email'.
        subject: Recipient identity (chat_id or email address) — NOT secrets.
        purpose: Notification category (e.g. 'hold.pending', 'sev.escalation').
        payload: Full message context for re-send; all fields the formatter needs.
        error: Defect class string only (e.g. 'transport_error', 'http_5xx').
    """
    payload_json = orjson.dumps(payload).decode("utf-8")
    await conn.execute(
        """
        INSERT INTO notification_failures
            (channel, subject, purpose, payload, error, attempts, created_at)
        VALUES ($1, $2, $3, $4::jsonb, $5, 1, now());
        """,
        channel,
        subject,
        purpose,
        payload_json,
        error,
    )


async def record_failure_pool(
    pool: asyncpg.Pool,
    *,
    channel: str,
    subject: str,
    purpose: str,
    payload: dict[str, Any],
    error: str,
) -> None:
    """Insert a notification failure row using the connection pool directly.

    Used in worker contexts where there is no ambient UnitOfWork. Each call
    acquires and releases a connection independently (auto-commit semantics).

    Args:
        pool: asyncpg connection pool.
        channel: 'telegram' or 'email'.
        subject: Recipient identity (chat_id or email address) — NOT secrets.
        purpose: Notification category.
        payload: Full message context for re-send.
        error: Defect class string only.
    """
    async with pool.acquire() as conn:
        await record_failure(
            conn,
            channel=channel,
            subject=subject,
            purpose=purpose,
            payload=payload,
            error=error,
        )


async def retry_pending(
    pool: asyncpg.Pool,
    channels: dict[str, Callable[..., Coroutine[Any, Any, None]]],
) -> int:
    """Sweep unresolved notification_failures and re-dispatch via channel callables.

    Uses SKIP LOCKED for parallel-safe sweep: multiple sweep instances (e.g.
    overlapping timer firings) will not double-process the same row.

    Args:
        pool: asyncpg connection pool.
        channels: Map of channel name ('telegram', 'email') to async send callable.
            The callable signature is channel-specific; the payload dict is
            passed as **kwargs. Callers must wire matching callables.

    Returns:
        Number of rows processed (attempted, whether successful or not).

    Abandon policy:
        Rows with attempts > _ABANDON_AFTER_ATTEMPTS (10) on a sweep failure
        are marked resolved_at=now() with error='abandoned'.
        Abandoned rows are permanent audit evidence.
    """
    processed = 0

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, channel, subject, purpose, payload, error, attempts
            FROM notification_failures
            WHERE resolved_at IS NULL
            ORDER BY created_at ASC
            LIMIT 100
            FOR UPDATE SKIP LOCKED;
            """
        )

    for row in rows:
        row_id = row["id"]
        channel_name: str = row["channel"]
        payload_raw = row["payload"]
        attempts: int = row["attempts"]

        payload: dict[str, Any] = (
            orjson.loads(payload_raw)
            if isinstance(payload_raw, (str, bytes))
            else dict(payload_raw)
        )

        channel_fn = channels.get(channel_name)
        if channel_fn is None:
            logger.warning(
                "notify_sweep_no_channel",
                row_id=str(row_id),
                channel=channel_name,
            )
            processed += 1
            continue

        try:
            await channel_fn(**payload)
            # Success: mark resolved
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE notification_failures
                    SET resolved_at = now()
                    WHERE id = $1;
                    """,
                    row_id,
                )
            logger.info(
                "notify_sweep_resolved",
                row_id=str(row_id),
                channel=channel_name,
                attempts=attempts,
            )
        except Exception as exc:
            new_attempts = attempts + 1
            if new_attempts > _ABANDON_AFTER_ATTEMPTS:
                # Abandon: mark resolved with error='abandoned'
                async with pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE notification_failures
                        SET attempts = $2,
                            resolved_at = now(),
                            error = 'abandoned'
                        WHERE id = $1;
                        """,
                        row_id,
                        new_attempts,
                    )
                logger.error(
                    "notify_sweep_abandoned",
                    row_id=str(row_id),
                    channel=channel_name,
                    attempts=new_attempts,
                )
            else:
                async with pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE notification_failures
                        SET attempts = $2
                        WHERE id = $1;
                        """,
                        row_id,
                        new_attempts,
                    )
                logger.warning(
                    "notify_sweep_retry_failed",
                    row_id=str(row_id),
                    channel=channel_name,
                    attempts=new_attempts,
                    exc_type=type(exc).__name__,
                )

        processed += 1

    return processed


async def run_notify_sweep(pool: asyncpg.Pool, channels: dict[str, Any]) -> int:
    """One-shot entry point for the systemd fluxpay-notify-sweep.service.

    Calls retry_pending once and returns the count of processed rows.
    The systemd timer runs this every 15 minutes (OnCalendar=*:0/15).
    """
    logger.info("notify_sweep_start", utc=datetime.now(UTC).isoformat())
    count = await retry_pending(pool, channels)
    logger.info("notify_sweep_done", processed=count)
    return count
