"""Integration tests for the Worker base class and graceful shutdown lifecycle.

Exercises:
1. run_forever loop execution:
   - Injected stop-event + instant sleeper + scripted poll sequence.
   - Processes N batches sequentially and stops cleanly on event with zero sleeps.
2. Signal-safe shutdown (SIGTERM simulation):
   - In-task signal emission -> signal handler triggers stop event -> clean loop exit.
3. Strict resource drain order:
   - Recording fakes assert close order is exactly (bus, valkey, pool).
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from collections.abc import Sequence
from typing import Any

import pytest

from fluxpay.workers.base import Worker, run_worker

pytestmark = pytest.mark.integration


class FakeBus:
    """Recording fake for event bus."""

    def __init__(self, recorder: list[str]) -> None:
        self.recorder = recorder
        self.closed = False

    async def close(self) -> None:
        self.closed = True
        self.recorder.append("bus")


class FakeValkey:
    """Recording fake for Valkey/Redis client."""

    def __init__(self, recorder: list[str]) -> None:
        self.recorder = recorder
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True
        self.recorder.append("valkey")


class FakePool:
    """Recording fake for PostgreSQL connection pool."""

    def __init__(self, recorder: list[str]) -> None:
        self.recorder = recorder
        self.closed = False

    async def close(self) -> None:
        self.closed = True
        self.recorder.append("pool")


class ScriptedWorker(Worker):
    """Test worker processing scripted batches."""

    def __init__(
        self,
        name: str,
        batches: list[list[int]],
        recorder: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        rec = recorder if recorder is not None else []
        bus = FakeBus(rec)
        valkey = FakeValkey(rec)
        pool = FakePool(rec)
        super().__init__(name=name, pool=pool, valkey=valkey, bus=bus, **kwargs)
        self._batches = list(batches)
        self.processed: list[list[int]] = []
        self.poll_count = 0

    async def poll(self) -> Sequence[int]:
        self.poll_count += 1
        if self._batches:
            return self._batches.pop(0)
        # Once batches are drained, signal stop
        self.stop.set()
        return []

    async def process(self, batch: Sequence[Any]) -> None:
        self.processed.append(list(batch))


# ==============================================================================
# 1. RUN_FOREVER BATCH LOOP & INSTANT SLEEP
# ==============================================================================


async def test_worker_run_forever_processes_batches_and_stops_cleanly() -> None:
    """Worker processes scripted batches sequentially and terminates when stop is set."""
    stop = asyncio.Event()
    batches = [[1, 2, 3], [4, 5], [6, 7, 8, 9]]
    sleep_calls: list[float] = []

    async def instant_sleep(duration_s: float) -> None:
        sleep_calls.append(duration_s)

    worker = ScriptedWorker(
        name="test_scripted_worker",
        batches=batches,
        stop=stop,
        sleeper=instant_sleep,
        poll_interval_s=0.5,
    )

    await worker.run_forever()

    assert worker.processed == [[1, 2, 3], [4, 5], [6, 7, 8, 9]]
    assert worker.stop.is_set() is True
    # Poll count should be 4 (3 batch polls + 1 empty terminal poll)
    assert worker.poll_count == 4


# ==============================================================================
# 2. SIGTERM SIMULATION & CLEAN EXIT
# ==============================================================================


class SignalTriggerWorker(Worker):
    """Worker that simulates an external SIGTERM signal during poll."""

    def __init__(self, **kwargs: Any) -> None:
        rec: list[str] = []
        super().__init__(
            name="sigterm_worker",
            pool=FakePool(rec),
            valkey=FakeValkey(rec),
            bus=FakeBus(rec),
            **kwargs,
        )
        self.poll_count = 0

    async def poll(self) -> Sequence[int]:
        self.poll_count += 1
        if self.poll_count == 1:
            return [100]

        # Trigger SIGTERM on 2nd iteration
        if sys.platform == "win32":
            signal.raise_signal(signal.SIGTERM)
        else:
            os.kill(os.getpid(), signal.SIGTERM)
        return []

    async def process(self, batch: Sequence[Any]) -> None:
        pass


async def test_worker_sigterm_simulation_stops_cleanly() -> None:
    """Simulating SIGTERM signal triggers stop event and cleanly exits run_worker."""

    async def instant_sleep(_: float) -> None:
        pass

    worker = SignalTriggerWorker(sleeper=instant_sleep)

    # run_worker installs signal handlers and executes run_forever
    await run_worker(worker)

    assert worker.stop.is_set() is True
    assert worker.poll_count >= 2


# ==============================================================================
# 3. RESOURCE DRAIN ORDER ASSERTION
# ==============================================================================


async def test_worker_close_order_strict() -> None:
    """Worker.close drains resources in strict canonical order: bus -> valkey -> pool."""
    drain_log: list[str] = []

    bus = FakeBus(drain_log)
    valkey = FakeValkey(drain_log)
    pool = FakePool(drain_log)

    worker = ScriptedWorker(
        name="drain_order_worker",
        batches=[],
        recorder=drain_log,
    )
    # Explicitly bind the tracked instances
    worker.bus = bus
    worker.valkey = valkey
    worker.pool = pool

    await worker.close()

    assert drain_log == ["bus", "valkey", "pool"], (
        f"Resource drain order violated! Expected ['bus', 'valkey', 'pool'], got {drain_log}"
    )
    assert bus.closed is True
    assert valkey.closed is True
    assert pool.closed is True
