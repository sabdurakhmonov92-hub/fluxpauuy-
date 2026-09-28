"""Base worker abstraction and graceful shutdown lifecycle for FluxPay background workers.

==============================================================================
PULL-FORWARD RATIONALE (WHY WORKER BASE IS DELIVERED IN TASK 34)
==============================================================================
Workers are formally owned by Tasks 38-43 (event dispatcher, outbox relay,
reconciliation, approvals). However, establishing production-true operational
resilience requires proving the asynchronous execution and graceful shutdown
contract EARLY.

Delivering the abstract Worker base shell here guarantees:
1. Unified Lifecycle Contract: All subsequent workers (Task 38 dispatcher, Task 41
   reconciliation, Task 42 approvals, Task 43 notifications) inherit an identical,
   field-tested shutdown discipline.
2. Signal-Safe Shutdown Discipline: Bare worker processes managed under systemd
   (Task 65 ExecStart) receive SIGTERM/SIGINT and execute an orderly resource drain
   without abrupt connection termination or orphaned transactions.
3. Testability Standard (No Sleeps): Injected clocks and custom sleepers eliminate
   flaky time.sleep() and asyncio.sleep() calls across all worker integration suites.
"""

from __future__ import annotations

import abc
import asyncio
import inspect
import signal
from collections.abc import Callable, Coroutine, Sequence
from typing import Any, TypeVar

from fluxpay.shared.logging import get_logger
from fluxpay.shared.metrics import (
    FLX_WORKER_BATCHES_TOTAL,
    FLX_WORKER_ERRORS_TOTAL,
    FLX_WORKER_LAST_SUCCESS_TIMESTAMP,
)

logger = get_logger("fluxpay.workers.base")

T = TypeVar("T")


class Worker(abc.ABC):
    """Abstract base worker managing batch polling, processing, and lifecycle."""

    def __init__(
        self,
        name: str,
        pool: Any,
        valkey: Any,
        bus: Any,
        *,
        poll_interval_s: float = 1.0,
        batch_size: int = 10,
        stop: asyncio.Event | None = None,
        sleeper: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep,
    ) -> None:
        self.name = name
        self.pool: Any = pool
        self.valkey: Any = valkey
        self.bus: Any = bus
        self.poll_interval_s = poll_interval_s
        self.batch_size = batch_size
        self.stop = stop if stop is not None else asyncio.Event()
        self._sleep = sleeper

    @abc.abstractmethod
    async def poll(self) -> Sequence[Any]:
        """Poll upstream source (broker, database, or queue) for a batch of items."""

    @abc.abstractmethod
    async def process(self, batch: Sequence[Any]) -> None:
        """Process a polled batch of items transactionally."""

    async def run_forever(self) -> None:
        """Execute the worker polling and processing loop until stop is signalled."""
        logger.info("worker_started", worker=self.name, batch_size=self.batch_size)
        while not self.stop.is_set():
            try:
                batch = await self.poll()
                if batch:
                    await self.process(batch)
                    # --- Task 69 append ---
                    FLX_WORKER_BATCHES_TOTAL.labels(worker=self.name).inc()
                FLX_WORKER_LAST_SUCCESS_TIMESTAMP.labels(worker=self.name).set_to_current_time()
            except Exception:
                FLX_WORKER_ERRORS_TOTAL.labels(worker=self.name).inc()
                raise
            if not batch:
                if self.stop.is_set():
                    break
                await self._sleep(self.poll_interval_s)
        logger.info("worker_stopped", worker=self.name)

    async def close(self) -> None:
        """Close worker resources in strict order: bus -> valkey -> pool.

        Drain order rationale:
        1. bus: Stop accepting/consuming incoming transport deliveries.
        2. valkey: Close ephemeral locks and cache connections.
        3. pool: Close persistent database connections after all transactions commit.
        """
        logger.info("worker_closing_resources", worker=self.name)
        # 1. Bus close
        if self.bus is not None and hasattr(self.bus, "close"):
            res = self.bus.close()
            if inspect.isawaitable(res):
                await res

        # 2. Valkey close
        if self.valkey is not None:
            if hasattr(self.valkey, "aclose"):
                await self.valkey.aclose()
            elif hasattr(self.valkey, "close"):
                res = self.valkey.close()
                if inspect.isawaitable(res):
                    await res

        # 3. DB Pool close
        if self.pool is not None and hasattr(self.pool, "close"):
            res = self.pool.close()
            if inspect.isawaitable(res):
                await res


def install_signal_handlers(stop: asyncio.Event) -> None:
    """Install SIGTERM and SIGINT handlers to set the stop event.

    Uses asyncio loop signal handlers on POSIX (uvloop/asyncio) and falls back
    to standard signal.signal on platforms/loops where add_signal_handler is not implemented.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    def _trigger_stop(*args: Any) -> None:
        logger.info("shutdown_signal_received")
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        installed = False
        if loop is not None:
            try:
                loop.add_signal_handler(sig, _trigger_stop)
                installed = True
            except (NotImplementedError, RuntimeError):
                pass
        if not installed:
            try:
                signal.signal(sig, _trigger_stop)
            except (ValueError, OSError):
                pass


async def run_worker(worker: Worker) -> None:
    """Run a worker with signal handling and resource cleanup on exit."""
    install_signal_handlers(worker.stop)
    try:
        await worker.run_forever()
    finally:
        await worker.close()


def main(worker: Worker) -> None:
    """Entry point for bare worker processes (e.g. systemd ExecStart)."""
    asyncio.run(run_worker(worker))
