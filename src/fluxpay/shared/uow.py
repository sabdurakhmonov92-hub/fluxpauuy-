"""Unit of Work (UoW) transaction boundary foundation for FluxPay.

Owns exactly one pooled PostgreSQL connection and one asyncpg transaction per context
block. Designed for high-integrity financial operations where unhandled commits,
swallowed rollbacks, connection leaks, and use-after-release access are made
impossible by construction.
"""

from contextvars import ContextVar, Token
from types import TracebackType
from typing import Final, Self

import asyncpg  # type: ignore[import-untyped]

from fluxpay.shared.errors import TransactionError

__all__ = ["UnitOfWork"]

# Module-level ContextVar tracking the active UnitOfWork per asyncio Task.
# WHY: Tracks the active transaction boundary per asyncio Task to prevent forbidden
# nested UnitOfWork invocations. Using ContextVar ensures strict isolation across
# concurrent tasks without shared global state, while detecting nested usage within
# the same task context.
_active_uow: Final[ContextVar["UnitOfWork | None"]] = ContextVar("_active_uow", default=None)


class UnitOfWork:
    """Async context manager managing a single pooled connection and atomic transaction.

    Design Invariants & Architectural Boundaries:
    - NO public commit()/rollback() methods:
      The `async with` block boundary defines the transaction lifecycle.
      Clean exit (including early return and loop break) COMMITS the transaction.
      Any exception (including asyncio.CancelledError) ROLLS BACK the transaction
      and re-raises the exception.
      NOTE ON EARLY RETURN: An early return inside the `async with` block COMMITS
      the transaction. This mirrors asyncpg's predictable semantics. If an operation
      needs to abort and roll back, it must raise an exception.
    - NESTING GUARD:
      Entering a second UnitOfWork within the same asyncio Task raises TransactionError.
      WHY: Nested UoWs acquire a second connection from the pool, creating immediate
      deadlock risk under connection pool pressure (e.g. pool max_size=2) and breaking
      the single atomic transaction mental model.
    - RE-ENTRY GUARD:
      Entering the same UnitOfWork instance more than once raises TransactionError.
      WHY: Instance reuse after exit causes stale connection bugs and race conditions.
      Each transaction boundary must instantiate a fresh UnitOfWork.
    - USE-AFTER-EXIT GUARD:
      Accessing the `connection` property outside or after the context manager block
      raises TransactionError.
      WHY: Use-after-release is a classic connection pool corruption bug where stale
      references execute queries on connections already returned to the pool.
    - ACQUISITION-FAILURE SAFETY:
      If transaction start fails after acquiring a connection from the pool, the
      connection is released immediately back to the pool before re-raising.
      WHY: Eliminates connection leaks on partial initialization during pool exhaustion
      or transient database connectivity drops.
    - EXCEPTION-SAFE __aexit__:
      Connection release, ContextVar token reset, and instance state clearance are
      guaranteed to execute in `finally`. If rollback fails (e.g. broken socket),
      the original caller exception propagates unmasked without replacement.
    - NO RETRIES, NO TIMEOUTS, NO SAVEPOINTS:
      WHY: OCC retries belong exclusively to LedgerStore (Task 16), which manages
      its own internal transaction for the hash-chain tip lock spanning only entry writes.
      UoW composes repositories for ordinary business operations. Statement timeouts
      and idle-in-transaction timeouts belong to infrastructure configuration
      (Task 65 systemd/pg config). Savepoints introduce nested transaction complexity
      and partial failure ambiguities, deferred to Phase 2 if a proven need arises.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialize UnitOfWork with a connection pool owned by the application shell.

        Pool lifetime is owned by the app shell (Task 33), never by the UnitOfWork.
        """
        self._pool: asyncpg.Pool = pool
        self._connection: asyncpg.Connection | None = None
        self._transaction: asyncpg.transaction.Transaction | None = None
        self._token: Token[UnitOfWork | None] | None = None
        self._entered: bool = False
        self._exited: bool = False

    @property
    def connection(self) -> asyncpg.Connection:
        """Return the active asyncpg connection for repository operations.

        Raises TransactionError if accessed outside the active context manager block.
        """
        if self._connection is None:
            # WHY: Use-after-release is the classic pooled-connection corruption bug;
            # make it loud at the call site, not mysterious at the pool level.
            raise TransactionError(
                message="UnitOfWork connection is not active or has already been released"
            )
        return self._connection

    async def __aenter__(self) -> Self:
        """Acquire connection and start transaction with nesting and re-entry guards."""
        # RE-ENTRY GUARD
        # WHY: Instance reuse after exit causes stale connection bugs and race conditions.
        if self._entered or self._exited:
            raise TransactionError(message="UnitOfWork instance cannot be re-entered or reused")

        # NESTING GUARD
        # WHY: Nested UoWs acquire a second connection -> deadlock risk under pool pressure
        # and a broken mental model of the transaction boundary.
        if _active_uow.get() is not None:
            raise TransactionError(
                message=(
                    "nested UnitOfWork forbidden within the same task: "
                    "deadlock risk and broken transaction boundary"
                )
            )

        self._entered = True
        self._token = _active_uow.set(self)

        # ACQUISITION-FAILURE SAFETY
        # WHY: If transaction start fails after acquire, release the connection and re-raise.
        # Eliminates leaked pooled connections on partial initialization.
        conn: asyncpg.Connection | None = None
        try:
            conn = await self._pool.acquire()
            tx = conn.transaction()
            await tx.start()
            self._connection = conn
            self._transaction = tx
        except BaseException:
            if conn is not None:
                await self._pool.release(conn)
            if self._token is not None:
                _active_uow.reset(self._token)
                self._token = None
            raise

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Commit on clean exit, rollback on exception, and guarantee resource release."""
        try:
            if exc_type is None:
                # Clean exit (including early return / break): COMMIT
                # WHY: Explicit commit() methods enable forgotten commits (silent data loss)
                # and double commits. Block boundary defines transaction completion.
                if self._transaction is not None:
                    await self._transaction.commit()
            else:
                # Any exception (including asyncio.CancelledError): ROLLBACK
                # WHY: Atomic failure semantics require rolling back partial writes
                # on any error or cancellation.
                if self._transaction is not None:
                    try:
                        await self._transaction.rollback()
                    except BaseException:  # noqa: S110
                        # Documented choice: If rollback raises while handling a caller exception
                        # (e.g. broken network socket or closed connection), the rollback exception
                        # is suppressed so that the original caller exception (exc_val) propagates
                        # cleanly without being masked or replaced by secondary cleanup noise.
                        pass
        finally:
            # FINALLY: reset ContextVar token + release connection + clear instance state.
            # WHY: Connection release and token reset must ALWAYS execute even if commit/rollback
            # raises, preventing pooled connection leaks and cross-task context pollution.
            conn = self._connection
            self._connection = None
            self._transaction = None
            self._exited = True

            try:
                if conn is not None:
                    await self._pool.release(conn)
            finally:
                if self._token is not None:
                    _active_uow.reset(self._token)
                    self._token = None
