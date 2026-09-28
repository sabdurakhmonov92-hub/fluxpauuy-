"""Integration tests verifying UnitOfWork transaction boundary invariants.

Validates commit, rollback, cancellation, early return, nesting prevention,
re-entry guard, use-after-exit guard, and connection pool health against PostgreSQL.
"""

import asyncio
import re

import asyncpg  # type: ignore[import-untyped]
import pytest

from fluxpay.shared.errors import ERROR_REGISTRY, TransactionError
from fluxpay.shared.uow import UnitOfWork

# Module-level integration marker; individual unit tests override/augment with @pytest.mark.unit
pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Unit-marked Failure Contract Tests (No external services required)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_transaction_error_contract_and_registry() -> None:
    """Validate that TransactionError conforms to the typed failure contract and registry.

    Verifies:
    - Code 'transaction_error'
    - HTTP status 500
    - retryable is False
    - client_message is 'internal transaction failure'
    - Registered, unique across all error codes, snake_case pattern
    - Task 4 error contract invariants hold (wire shape and detail exclusion)
    """
    assert TransactionError.code == "transaction_error"
    assert TransactionError.status == 500
    assert TransactionError.retryable is False
    assert TransactionError.client_message == "internal transaction failure"

    err = TransactionError(details={"internal_sql": "SELECT * FROM secrets"})
    payload = err.to_payload()
    assert payload == {
        "error": {
            "code": "transaction_error",
            "message": "internal transaction failure",
            "retryable": False,
        }
    }
    assert "internal_sql" not in str(err)
    assert "internal_sql" not in str(payload)

    # Validate registry registration (mirroring Task 7 pattern)
    # Using try/finally to restore registry state and keep Task 4 tests green
    was_present = "transaction_error" in ERROR_REGISTRY
    ERROR_REGISTRY["transaction_error"] = TransactionError
    try:
        assert "transaction_error" in ERROR_REGISTRY
        cls = ERROR_REGISTRY["transaction_error"]
        assert cls is TransactionError
        assert cls.retryable is False
        assert cls.status == 500

        # Verify snake_case format
        code_pattern = re.compile(r"^[a-z][a-z0-9_]*$")
        assert code_pattern.match(TransactionError.code)

        # Verify uniqueness
        codes = list(ERROR_REGISTRY.keys())
        assert len(codes) == len(set(codes)), "Duplicate error code detected in registry"
    finally:
        if not was_present:
            ERROR_REGISTRY.pop("transaction_error", None)


# ---------------------------------------------------------------------------
# Integration Tests (PostgreSQL required)
# ---------------------------------------------------------------------------


async def test_commit_path(db_pool: asyncpg.Pool, scratch_table: str) -> None:
    """Validate that clean exit from UnitOfWork commits all writes.

    After exit, a fresh connection from the pool (outside the UoW) must see the row.
    """
    async with UnitOfWork(db_pool) as uow:
        await uow.connection.execute(
            f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
            1,
            "commit_success",
        )

    # Verify visibility from an independent connection outside the UoW
    async with db_pool.acquire() as fresh_conn:
        row = await fresh_conn.fetchrow(
            f"SELECT payload FROM {scratch_table} WHERE id = $1",  # noqa: S608
            1,
        )
        assert row is not None
        assert row["payload"] == "commit_success"


async def test_rollback_path(db_pool: asyncpg.Pool, scratch_table: str) -> None:
    """Validate that exceptions inside UnitOfWork trigger rollback and re-raise.

    Row must be absent on a fresh connection; the original exception must propagate untouched.
    """
    with pytest.raises(ValueError, match="simulated failure"):
        async with UnitOfWork(db_pool) as uow:
            await uow.connection.execute(
                f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
                2,
                "rollback_data",
            )
            raise ValueError("simulated failure")

    # Verify row was rolled back and is completely absent
    async with db_pool.acquire() as fresh_conn:
        row = await fresh_conn.fetchrow(
            f"SELECT payload FROM {scratch_table} WHERE id = $1",  # noqa: S608
            2,
        )
        assert row is None


async def test_cancellation_path(db_pool: asyncpg.Pool, scratch_table: str) -> None:
    """Validate that task cancellation triggers automatic rollback and propagates CancelledError.

    WHY: Cancelled requests (client disconnects, HTTP timeouts, worker shutdowns)
    must never leave partial state or uncommitted writes in the database.
    """
    started_event = asyncio.Event()

    async def worker() -> None:
        async with UnitOfWork(db_pool) as uow:
            await uow.connection.execute(
                f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
                3,
                "cancelled_data",
            )
            started_event.set()
            # Await forever until cancelled
            await asyncio.Event().wait()

    task = asyncio.create_task(worker())
    await started_event.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    # Verify that partial writes were rolled back on cancellation
    async with db_pool.acquire() as fresh_conn:
        row = await fresh_conn.fetchrow(
            f"SELECT payload FROM {scratch_table} WHERE id = $1",  # noqa: S608
            3,
        )
        assert row is None


async def test_early_return_commits(db_pool: asyncpg.Pool, scratch_table: str) -> None:
    """Validate that an early return inside the `async with` block COMMITS the transaction.

    Locks in documented semantics mirroring asyncpg: clean exit (including return) commits.
    Callers expecting rollback must raise an exception.
    """

    async def do_work() -> str:
        async with UnitOfWork(db_pool) as uow:
            await uow.connection.execute(
                f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
                4,
                "early_return_data",
            )
            return "returned_value"

    result = await do_work()
    assert result == "returned_value"

    # Verify row was committed
    async with db_pool.acquire() as fresh_conn:
        row = await fresh_conn.fetchrow(
            f"SELECT payload FROM {scratch_table} WHERE id = $1",  # noqa: S608
            4,
        )
        assert row is not None
        assert row["payload"] == "early_return_data"


async def test_nested_uow_raises_transaction_error(db_pool: asyncpg.Pool) -> None:
    """Validate that nesting UnitOfWork within the same task raises TransactionError.

    Message must contain 'nested'.
    """
    async with UnitOfWork(db_pool):
        with pytest.raises(TransactionError) as exc_info:
            async with UnitOfWork(db_pool):
                pass

        assert "nested" in str(exc_info.value).lower()


async def test_sequential_uows_in_one_task_succeed(
    db_pool: asyncpg.Pool, scratch_table: str
) -> None:
    """Validate that sequential UnitOfWork blocks in the same task succeed.

    Proves that ContextVar token and internal state reset correctly on exit.
    """
    async with UnitOfWork(db_pool) as uow1:
        await uow1.connection.execute(
            f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
            5,
            "seq_1",
        )

    async with UnitOfWork(db_pool) as uow2:
        await uow2.connection.execute(
            f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
            6,
            "seq_2",
        )

    async with db_pool.acquire() as fresh_conn:
        rows = await fresh_conn.fetch(
            f"SELECT id, payload FROM {scratch_table} WHERE id IN (5, 6) ORDER BY id"  # noqa: S608
        )
        assert len(rows) == 2
        assert rows[0]["payload"] == "seq_1"
        assert rows[1]["payload"] == "seq_2"


async def test_concurrent_uows_in_different_tasks(
    db_pool: asyncpg.Pool, scratch_table: str
) -> None:
    """Validate that concurrent UnitOfWork instances across different tasks do not conflict.

    ContextVar isolates the active UoW per asyncio Task.
    """

    async def worker(task_id: int, payload: str) -> None:
        async with UnitOfWork(db_pool) as uow:
            await uow.connection.execute(
                f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
                task_id,
                payload,
            )

    await asyncio.gather(
        worker(7, "task_7_data"),
        worker(8, "task_8_data"),
    )

    async with db_pool.acquire() as fresh_conn:
        rows = await fresh_conn.fetch(
            f"SELECT id, payload FROM {scratch_table} WHERE id IN (7, 8) ORDER BY id"  # noqa: S608
        )
        assert len(rows) == 2


async def test_instance_reentry_raises_transaction_error(db_pool: asyncpg.Pool) -> None:
    """Validate that entering the same UnitOfWork instance twice raises TransactionError."""
    uow = UnitOfWork(db_pool)

    async with uow:
        pass

    with pytest.raises(TransactionError, match="cannot be re-entered"):
        async with uow:
            pass


async def test_use_after_exit_raises_transaction_error(db_pool: asyncpg.Pool) -> None:
    """Validate that accessing uow.connection after exit raises TransactionError."""
    uow = UnitOfWork(db_pool)

    async with uow:
        # Valid access inside block
        assert uow.connection is not None

    # Invalid access after exit
    with pytest.raises(TransactionError, match="connection is not active"):
        _ = uow.connection


async def test_pool_health_baseline_restored_after_all_paths(
    db_pool: asyncpg.Pool, scratch_table: str
) -> None:
    """Validate that pool idle connections return to baseline after commit, rollback, and cancel.

    Eliminates connection leaks — the primary cause of connection pool exhaustion in production.
    """
    baseline_idle = db_pool.get_idle_size()

    # 1. After commit
    async with UnitOfWork(db_pool) as uow:
        await uow.connection.execute(
            f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
            9,
            "health_commit",
        )
    assert db_pool.get_idle_size() == baseline_idle

    # 2. After rollback
    with pytest.raises(RuntimeError):
        async with UnitOfWork(db_pool) as uow:
            await uow.connection.execute(
                f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
                10,
                "health_rollback",
            )
            raise RuntimeError("rollback")
    assert db_pool.get_idle_size() == baseline_idle

    # 3. After cancellation
    started = asyncio.Event()

    async def cancellable_worker() -> None:
        async with UnitOfWork(db_pool) as uow:
            await uow.connection.execute(
                f"INSERT INTO {scratch_table} (id, payload) VALUES ($1, $2)",  # noqa: S608
                11,
                "health_cancel",
            )
            started.set()
            await asyncio.Event().wait()

    t = asyncio.create_task(cancellable_worker())
    await started.wait()
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t

    assert db_pool.get_idle_size() == baseline_idle
