"""Notification Sweep Worker — one-shot entry point for systemd timer (Task 43).

Invoked every 15 minutes via fluxpay-notify-sweep.service/.timer.
Calls retry_pending() against the notification_failures table,
re-dispatching unresolved rows via the configured channels.

Exit codes:
    0 = completed (even if some rows failed; failure is expected and counted)
    2 = operational failure (DB unreachable, config error)
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable, Coroutine
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import httpx

from fluxpay.config import get_settings
from fluxpay.notifications.channels import TelegramChannel
from fluxpay.notifications.records import run_notify_sweep
from fluxpay.shared.logging import configure_logging, get_logger

logger = get_logger("fluxpay.workers.notify_sweep")


async def _main() -> int:
    """Run the notification sweep once and return an exit code."""
    configure_logging()
    settings = get_settings()

    try:
        pool = await asyncpg.create_pool(
            settings.pg_dsn,
            min_size=1,
            max_size=3,
            server_settings={"TimeZone": "UTC", "synchronous_commit": "on"},
            command_timeout=30.0,
        )
    except Exception as exc:
        logger.error("notify_sweep_db_connect_failed", exc_type=type(exc).__name__)
        return 2

    channels: dict[str, Callable[..., Coroutine[Any, Any, None]]] = {}

    # Wire Telegram channel if configured
    notify_http_client: httpx.AsyncClient | None = None
    if settings.telegram_bot_token and settings.telegram_admin_chat_id:
        notify_http_client = httpx.AsyncClient(timeout=10.0)
        tg_channel = TelegramChannel(
            notify_http_client,
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_admin_chat_id,
            retry_max=settings.notification_retry_max,
            backoff_base_s=settings.notification_backoff_base_s,
        )

        async def _telegram_send(**kwargs: Any) -> None:
            await tg_channel.send(kwargs.get("text", ""))

        channels["telegram"] = _telegram_send

    try:
        await run_notify_sweep(pool, channels)
    except Exception as exc:
        logger.error("notify_sweep_failed", exc_type=type(exc).__name__)
        return 2
    finally:
        if notify_http_client is not None:
            await notify_http_client.aclose()
        await pool.close()

    return 0


def main() -> None:
    """Entry point for systemd ExecStart."""
    exit_code = asyncio.run(_main())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
