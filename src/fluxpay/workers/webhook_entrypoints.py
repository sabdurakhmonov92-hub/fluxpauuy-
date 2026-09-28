"""Webhook worker entrypoints for systemd service units (Task 65).

Provides subcommands 'fanout' and 'delivery' for fluxpay-worker@.service.
Supports bare process execution under systemd with graceful shutdown handling.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import aio_pika
import asyncpg  # type: ignore[import-untyped]
import httpx
from redis import asyncio as redis_async

from fluxpay.config import get_settings
from fluxpay.notifications.dispatcher import DeliveryWorker, EventFanoutWorker
from fluxpay.shared.logging import configure_logging, get_logger
from fluxpay.shared.rabbitmq_bus import RabbitMQBus
from fluxpay.workers.base import run_worker

logger = get_logger("fluxpay.workers.webhook_entrypoints")

__all__ = [
    "main",
    "main_delivery",
    "main_fanout",
    "run_delivery",
    "run_fanout",
]


# --- TASK 38/65 APPEND: WEBHOOK WORKER DAEMON RUNNERS ---
async def run_fanout() -> None:
    """Run the EventFanoutWorker daemon until stopped."""
    settings = get_settings()
    pool = await asyncpg.create_pool(
        settings.pg_dsn,
        min_size=2,
        max_size=5,
        server_settings={"TimeZone": "UTC", "synchronous_commit": "on"},
        command_timeout=30.0,
    )
    valkey: Any = redis_async.from_url(settings.valkey_url)  # type: ignore[no-untyped-call]
    conn = await aio_pika.connect_robust(settings.rabbitmq_url)
    bus = RabbitMQBus(connection=conn)
    worker = EventFanoutWorker(pool=pool, valkey=valkey, bus=bus)
    await worker.setup()
    try:
        await run_worker(worker)
    finally:
        await bus.close()
        await conn.close()
        await valkey.aclose()
        await pool.close()


async def run_delivery() -> None:
    """Run the DeliveryWorker daemon until stopped."""
    settings = get_settings()
    pool = await asyncpg.create_pool(
        settings.pg_dsn,
        min_size=2,
        max_size=5,
        server_settings={"TimeZone": "UTC", "synchronous_commit": "on"},
        command_timeout=30.0,
    )
    valkey: Any = redis_async.from_url(settings.valkey_url)  # type: ignore[no-untyped-call]
    async with httpx.AsyncClient(timeout=10.0) as http_client:
        worker = DeliveryWorker(pool=pool, valkey=valkey, http_client=http_client)
        try:
            await run_worker(worker)
        finally:
            await valkey.aclose()
            await pool.close()


def main_fanout() -> None:
    """Systemd ExecStart entrypoint for fanout instance."""
    configure_logging()
    asyncio.run(run_fanout())


def main_delivery() -> None:
    """Systemd ExecStart entrypoint for delivery instance."""
    configure_logging()
    asyncio.run(run_delivery())


def main(argv: list[str] | None = None) -> None:
    """Subcommand dispatcher for webhook worker entrypoints."""
    args = argv if argv is not None else sys.argv[1:]
    if not args or args[0] not in ("fanout", "delivery"):
        sys.stderr.write("Usage: python -m fluxpay.workers.webhook_entrypoints <fanout|delivery>\n")
        sys.exit(1)
    if args[0] == "fanout":
        main_fanout()
    else:
        main_delivery()


if __name__ == "__main__":
    main()
