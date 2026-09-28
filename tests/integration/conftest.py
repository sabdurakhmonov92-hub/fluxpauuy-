"""Shared integration test fixtures for FluxPay.

Provides session-scoped database connection pool and function-scoped scratch tables
for integration testing against live PostgreSQL instances per CI symmetry rules.
"""

import os
import uuid
from collections.abc import AsyncGenerator

import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio

from fluxpay.config import Settings

FAIL_LOUD_MSG = (
    "run make env && make up, or set FLX_PG_DSN — "
    "integration tests require a real Postgres per CI symmetry rule"
)


@pytest.fixture(scope="session")
def db_dsn() -> str:
    """Resolve PostgreSQL DSN from environment or .env fallback.

    Fails loud if missing or unusable per CI symmetry rules (no silent skips).
    """
    dsn = os.environ.get("FLX_PG_DSN")
    if not dsn:
        try:
            settings = Settings(_env_file=".env")
            dsn = settings.pg_dsn
        except Exception:
            pytest.fail(FAIL_LOUD_MSG)

    if not dsn or not (dsn.startswith("postgresql://") or dsn.startswith("postgres://")):
        pytest.fail(FAIL_LOUD_MSG)

    return dsn


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def db_pool(db_dsn: str) -> AsyncGenerator[asyncpg.Pool, None]:
    """Create session-level asyncpg connection pool with max_size=2.

    max_size=2 is deliberate — it makes nested-UoW deadlocks reproduce LOCALLY
    instead of in production under connection starvation.
    """
    try:
        pool = await asyncpg.create_pool(db_dsn, min_size=1, max_size=2)
    except (OSError, asyncpg.PostgresError, TimeoutError) as exc:
        pytest.fail(f"{FAIL_LOUD_MSG} (connection failed: {exc})")

    try:
        yield pool
    finally:
        await pool.close()


@pytest_asyncio.fixture
async def scratch_table(db_pool: asyncpg.Pool) -> AsyncGenerator[str, None]:
    """Create an isolated, uniquely named scratch table for the duration of a test.

    CREATE TABLE uow_scratch_<uuid> (id INTEGER PRIMARY KEY, payload TEXT);
    Yields the table name; drops the table in teardown.
    Ensures zero cross-test coupling and safe parallelism.
    """
    table_id = uuid.uuid4().hex
    table_name = f"uow_scratch_{table_id}"

    async with db_pool.acquire() as conn:
        await conn.execute(f"CREATE TABLE {table_name} (id INTEGER PRIMARY KEY, payload TEXT);")

    try:
        yield table_name
    finally:
        async with db_pool.acquire() as conn:
            await conn.execute(f"DROP TABLE IF EXISTS {table_name};")


# --- Task 9 append ---

import asyncio  # noqa: E402

import redis.asyncio as redis_async  # noqa: E402

VALKEY_FAIL_LOUD_MSG = (
    "run make up, or set FLX_VALKEY_URL — integration tests require real Valkey per CI symmetry"
)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def valkey_client() -> AsyncGenerator[redis_async.Redis, None]:
    """Provide a session-scoped async Redis/Valkey client connected to DB 15.

    URL is resolved from FLX_VALKEY_URL env if set, otherwise defaults to
    redis://localhost:6379/15.
    (WHY db 15: Redis convention — highest DB index reserved for tests;
    protects a developer's locally-running dev bus in db 0 from flush).
    Fails loud if Valkey is unreachable within 5s per CI symmetry rules.
    """
    url = os.environ.get("FLX_VALKEY_URL", "redis://localhost:6379/15")
    client: redis_async.Redis = redis_async.Redis.from_url(url)

    try:
        async with asyncio.timeout(5.0):
            await client.ping()
    except (OSError, TimeoutError, Exception) as exc:
        await client.aclose()
        pytest.fail(f"{VALKEY_FAIL_LOUD_MSG} (connection failed: {exc})")

    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture
async def valkey(valkey_client: redis_async.Redis) -> AsyncGenerator[redis_async.Redis, None]:
    """Provide a function-scoped Redis/Valkey client with per-test DB 15 flush teardown.

    Ensures zero cross-test coupling and clean test isolation.
    """
    try:
        yield valkey_client
    finally:
        await valkey_client.flushdb()


# --- Task 10 append ---

import contextlib  # noqa: E402

import aio_pika  # noqa: E402
import aio_pika.abc  # noqa: E402

from fluxpay.shared.events import EventType  # noqa: E402

RABBITMQ_FAIL_LOUD_MSG = (
    "run make up, or set FLX_RABBITMQ_URL — integration tests require real RabbitMQ per CI symmetry"
)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def rabbit_connection() -> AsyncGenerator[aio_pika.abc.AbstractRobustConnection, None]:
    """Provide a session-scoped async RabbitMQ connection using connect_robust.

    URL is resolved from FLX_RABBITMQ_URL env if set, otherwise defaults to
    amqp://guest:guest@localhost:5672/.
    Fails loud if RabbitMQ is unreachable per CI symmetry rules (Task 8 rule).
    """
    url = os.environ.get("FLX_RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    try:
        connection = await aio_pika.connect_robust(url)
        # Ping via opening and closing a test channel
        channel = await connection.channel()
        await channel.close()
    except (OSError, TimeoutError, Exception) as exc:
        pytest.fail(f"{RABBITMQ_FAIL_LOUD_MSG} (connection failed: {exc})")

    try:
        yield connection
    finally:
        await connection.close()


@pytest_asyncio.fixture
async def bus_prefix(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
) -> AsyncGenerator[str, None]:
    """Generate a unique key prefix per test function for topology isolation.

    WHY: Quorum queues in RabbitMQ cannot be declared as exclusive or auto-delete per
    AMQP quorum queue specification. Therefore, per-test topology isolation requires
    a unique prefix per test, with explicit teardown deleting the 6 enumerable queues
    and the dead-letter exchange.
    """
    prefix = f"t{uuid.uuid4().hex[:10]}"
    try:
        yield prefix
    finally:
        # Best-effort deletion of the 6 enumerable queues and DLX exchange
        with contextlib.suppress(Exception):
            channel = await rabbit_connection.channel()
            for event_type in EventType:
                with contextlib.suppress(Exception):
                    await channel.queue_delete(f"{prefix}:{event_type.value}")
                with contextlib.suppress(Exception):
                    await channel.queue_delete(f"{prefix}:dlq:{event_type.value}")
            with contextlib.suppress(Exception):
                await channel.exchange_delete(f"{prefix}:dlx")
            await channel.close()


# --- Task 11 append ---

from pathlib import Path  # noqa: E402


@pytest.fixture(scope="session")
def idempotency_migration_sql() -> str:
    """Read migrations/0001_idempotency.sql once per test session.

    Pathlib resolution relative to the repository root.
    Fails loud via pytest.fail if the migration file is missing (no silent skips).
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    migration_file = repo_root / "migrations" / "0001_idempotency.sql"

    if not migration_file.is_file():
        pytest.fail(f"Required migration file not found: {migration_file}")

    return migration_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_idempotency_schema(
    db_pool: asyncpg.Pool,
    idempotency_migration_sql: str,
) -> None:
    """Execute migrations/0001_idempotency.sql once per session.

    Idempotent via IF NOT EXISTS in SQL DDL.
    """
    async with db_pool.acquire() as conn:
        await conn.execute(idempotency_migration_sql)


@pytest_asyncio.fixture
async def idem_agent(
    db_pool: asyncpg.Pool,
    apply_idempotency_schema: None,
) -> AsyncGenerator[uuid.UUID, None]:
    """Provide a fresh agent UUID per test with clean database teardown.

    Teardown deletes all rows for this agent_id from idempotency_keys.
    This table is mutable by design, unlike the append-only ledger.
    """
    agent_id = uuid.uuid4()
    try:
        yield agent_id
    finally:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM idempotency_keys WHERE agent_id = $1;",
                agent_id,
            )


# --- Task 13 append ---

from collections.abc import Callable, Coroutine  # noqa: E402
from typing import Any  # noqa: E402


@pytest.fixture(scope="session")
def ledger_migration_sql() -> str:
    """Read migrations/0002_ledger.sql once per test session.

    Pathlib resolution relative to the repository root.
    Fails loud via pytest.fail if the migration file is missing (no silent skips).
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    migration_file = repo_root / "migrations" / "0002_ledger.sql"

    if not migration_file.is_file():
        pytest.fail(f"Required migration file not found: {migration_file}")

    return migration_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_ledger_schema(
    db_pool: asyncpg.Pool,
    ledger_migration_sql: str,
) -> None:
    """Execute migrations/0002_ledger.sql once per session.

    Idempotent via IF NOT EXISTS in SQL DDL.
    """
    async with db_pool.acquire() as conn:
        await conn.execute(ledger_migration_sql)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def ledger_test_role(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
) -> str:
    """Create NOLOGIN role ledger_app_test and replicate grants.sql pattern.

    Creates role if absent, grants it to CURRENT_USER, configures table permissions
    and ALTER DEFAULT PRIVILEGES for future partition inheritance.
    Fails loud with actionable instruction if local user lacks CREATEROLE.
    """
    role_name = "ledger_app_test"
    async with db_pool.acquire() as conn:
        try:
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ledger_app_test') THEN
                        CREATE ROLE ledger_app_test NOLOGIN;
                    END IF;
                END
                $$;
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    EXECUTE format('GRANT ledger_app_test TO %I', CURRENT_USER);
                END
                $$;
            """)
        except asyncpg.InsufficientPrivilegeError as exc:
            pytest.fail(
                f"Failed to create or grant test role {role_name}: {exc}. "
                "Fix with: ALTER ROLE <user> CREATEROLE; -- CI superuser needs nothing"
            )

        # Replicate deploy/sql/grants.sql pattern for ledger_app_test
        await conn.execute("""
            REVOKE ALL ON ledger_entries FROM PUBLIC;
            REVOKE ALL ON ledger_accounts FROM PUBLIC;
            REVOKE ALL ON ledger_chain_tip FROM PUBLIC;

            GRANT SELECT, INSERT ON ledger_entries TO ledger_app_test;
            REVOKE UPDATE, DELETE, TRUNCATE ON ledger_entries FROM ledger_app_test;

            GRANT SELECT, INSERT, UPDATE, DELETE ON ledger_accounts TO ledger_app_test;

            GRANT SELECT, INSERT, UPDATE ON ledger_chain_tip TO ledger_app_test;
            REVOKE DELETE, TRUNCATE ON ledger_chain_tip FROM ledger_app_test;

            ALTER DEFAULT PRIVILEGES IN SCHEMA public
            GRANT SELECT, INSERT ON TABLES TO ledger_app_test;
        """)

    return role_name


AccountsFactoryType = Callable[..., Coroutine[Any, Any, list[uuid.UUID]]]


@pytest_asyncio.fixture
async def ledger_accounts_factory(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
) -> AsyncGenerator[AccountsFactoryType, None]:
    """Provide an async helper creating N accounts with clean database teardown.

    Teardown deletes ledger entries for those accounts FIRST, then deletes the accounts.
    WHY owner-bypass: Teardown runs over the owner/superuser connection, bypassing the
    restricted app role grants which forbid entry deletion.
    """
    created_account_ids: list[uuid.UUID] = []

    async def _create_accounts(
        *,
        owner_type: str = "agent",
        currency: str = "USDC",
        count: int = 1,
        initial_balance: int = 0,
    ) -> list[uuid.UUID]:
        ids: list[uuid.UUID] = []
        async with db_pool.acquire() as conn:
            for _ in range(count):
                acc_id = uuid.uuid4()
                owner_id = uuid.uuid4()
                await conn.execute(
                    """
                    INSERT INTO ledger_accounts (
                        id, owner_type, owner_id, currency, balance, version
                    )
                    VALUES ($1, $2, $3, $4, $5, 0);
                    """,
                    acc_id,
                    owner_type,
                    owner_id,
                    currency,
                    initial_balance,
                )
                ids.append(acc_id)
                created_account_ids.append(acc_id)
        return ids

    try:
        yield _create_accounts
    finally:
        if created_account_ids:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM ledger_entries WHERE account_id = ANY($1::uuid[]);",
                    created_account_ids,
                )
                await conn.execute(
                    "DELETE FROM ledger_accounts WHERE id = ANY($1::uuid[]);",
                    created_account_ids,
                )


@pytest_asyncio.fixture
async def restricted_conn(
    db_dsn: str,
    ledger_test_role: str,
) -> AsyncGenerator[asyncpg.Connection, None]:
    """Provide a dedicated asyncpg connection with SET ROLE ledger_app_test.

    WHY dedicated connection: SET ROLE mutates session state. Using the shared db_pool
    would leak restricted role permissions across tests.
    Teardown resets the role and closes the dedicated connection.
    """
    conn = await asyncpg.connect(db_dsn)
    try:
        await conn.execute(f"SET ROLE {ledger_test_role};")
        yield conn
    finally:
        try:
            await conn.execute("RESET ROLE;")
        finally:
            await conn.close()


# --- Task 14 append ---


@pytest.fixture(scope="session")
def invariants_migration_sql() -> str:
    """Read migrations/0003_ledger_invariants.sql once per test session.

    Pathlib resolution relative to the repository root.
    Fails loud via pytest.fail if the migration file is missing (no silent skips).
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    migration_file = repo_root / "migrations" / "0003_ledger_invariants.sql"

    if not migration_file.is_file():
        pytest.fail(f"Required migration file not found: {migration_file}")

    return migration_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_ledger_invariants(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
    invariants_migration_sql: str,
) -> None:
    """Execute migrations/0003_ledger_invariants.sql once per session.

    Depends on apply_ledger_schema (Task 13).
    Idempotent via DROP TRIGGER IF EXISTS and CREATE OR REPLACE.
    """
    async with db_pool.acquire() as conn:
        await conn.execute(invariants_migration_sql)


@pytest_asyncio.fixture
async def owner_conn(
    db_dsn: str,
    apply_ledger_invariants: None,
) -> AsyncGenerator[asyncpg.Connection, None]:
    """Provide a dedicated asyncpg connection with database owner/superuser privileges.

    WHY dedicated connection: Trigger tests mutate data and test transaction commit/rollback
    semantics; pool hygiene per Task 13 rule requires dedicated connections to isolate session
    and transaction state.
    Teardown rolls back any open transaction and closes the connection.
    """
    conn = await asyncpg.connect(db_dsn)
    try:
        yield conn
    finally:
        if not conn.is_closed():
            if conn.is_in_transaction():
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK;")
            await conn.close()


# --- Task 16 append ---

from fluxpay.ledger.hashchain import Direction  # noqa: E402
from fluxpay.ledger.postgres import PostgresLedgerStore  # noqa: E402
from fluxpay.ledger.store import EntryDraft, LedgerTransaction  # noqa: E402


class SleepCapture:
    """Captured sleep delay callable for deterministic OCC retry testing."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)

    def __len__(self) -> int:
        return len(self.delays)

    def __getitem__(self, index: int) -> float:
        return self.delays[index]


@pytest.fixture
def store_sleep() -> SleepCapture:
    """Monkeypatchable sleep injection fixture capturing retry delays."""
    return SleepCapture()


@pytest.fixture
def ledger_store(
    db_pool: asyncpg.Pool,
    apply_ledger_invariants: None,
    store_sleep: SleepCapture,
) -> PostgresLedgerStore:
    """Provide a PostgresLedgerStore backed by db_pool and injected store_sleep."""
    return PostgresLedgerStore(
        db_pool,
        max_occ_retries=2,
        sleep_fn=store_sleep,
    )


SeedAccountType = Callable[[uuid.UUID, int, str], Coroutine[Any, Any, LedgerTransaction]]


@pytest_asyncio.fixture
async def seed_account(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactoryType,
) -> SeedAccountType:
    """Seed an account with funds via a balanced mint transaction from a prefunded system account.

    Bootstrapping rule: the 'system' owner account is created with balance directly at INSERT
    (owner bypasses entries). System genesis balance is the ONE out-of-ledger balance, reconciled
    as the mint. Real agent/merchant accounts start at 0 and only move via entries.
    """
    system_mint_ids = await ledger_accounts_factory(
        owner_type="system",
        currency="USDC",
        count=1,
        initial_balance=10_000_000_000,
    )
    system_mint_id = system_mint_ids[0]

    async def _seed(
        account_id: uuid.UUID,
        amount: int,
        currency: str = "USDC",
    ) -> LedgerTransaction:
        return await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=system_mint_id,
                    direction=Direction.DEBIT,
                    amount=amount,
                    currency=currency,
                ),
                EntryDraft(
                    account_id=account_id,
                    direction=Direction.CREDIT,
                    amount=amount,
                    currency=currency,
                ),
            ]
        )

    return _seed


# --- Task 23 append ---

from dataclasses import dataclass  # noqa: E402

from fluxpay.registry.repo import (  # noqa: E402
    AgentRepo,
    agent_secret_context,
)
from fluxpay.shared.vault import encrypt_secret  # noqa: E402


@pytest.fixture(scope="session")
def agents_migration_sql() -> str:
    """Read migrations/0004_agents.sql once per test session.

    Pathlib resolution relative to the repository root.
    Fails loud via pytest.fail if the migration file is missing (no silent skips).
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    migration_file = repo_root / "migrations" / "0004_agents.sql"

    if not migration_file.is_file():
        pytest.fail(f"Required migration file not found: {migration_file}")

    return migration_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_agents_schema(
    db_pool: asyncpg.Pool,
    agents_migration_sql: str,
) -> None:
    """Execute migrations/0004_agents.sql once per session.

    Idempotent via CREATE TABLE IF NOT EXISTS in SQL DDL.
    """
    async with db_pool.acquire() as conn:
        await conn.execute(agents_migration_sql)


@dataclass(frozen=True, slots=True)
class AgentCredentials:
    """Agent identity and secret credentials for test request signing."""

    agent_id: uuid.UUID
    external_id: str
    secret_bytes: bytes


MakeAgentType = Callable[..., Coroutine[Any, Any, AgentCredentials]]


@pytest_asyncio.fixture
async def make_agent(
    db_pool: asyncpg.Pool,
    apply_agents_schema: None,
) -> AsyncGenerator[MakeAgentType, None]:
    """Helper fixture creating agent rows in PostgreSQL with clean teardown.

    Generates raw secret (32 random bytes), encrypts hex string with vault
    under agent_secret_context(external_id), and returns AgentCredentials.
    Teardown deletes all created agent rows (+cascade none — standalone table).
    """
    created_ids: list[uuid.UUID] = []

    async def _make_agent(
        *,
        external_id: str | None = None,
        active: bool = True,
        rate_limit_max: int = 100,
        daily_quota_max: int = 10000,
        name: str = "Test Agent",
    ) -> AgentCredentials:
        agent_id = uuid.uuid4()
        if external_id is None:
            external_id = f"agent_{uuid.uuid4().hex[:12]}"

        raw_secret = os.urandom(32)
        secret_hex = raw_secret.hex()
        secret_bytes = secret_hex.encode("ascii")

        context = agent_secret_context(external_id)
        secret_encrypted = encrypt_secret(secret_hex, context=context)

        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agents (
                    id, external_id, name, secret_encrypted, active,
                    rate_limit_max, daily_quota_max
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7);
                """,
                agent_id,
                external_id,
                name,
                secret_encrypted,
                active,
                rate_limit_max,
                daily_quota_max,
            )

        created_ids.append(agent_id)
        return AgentCredentials(
            agent_id=agent_id,
            external_id=external_id,
            secret_bytes=secret_bytes,
        )

    try:
        yield _make_agent
    finally:
        if created_ids:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM agents WHERE id = ANY($1::uuid[]);",
                    created_ids,
                )


@pytest.fixture
def agent_repo(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    apply_agents_schema: None,
) -> AgentRepo:
    """Provide an AgentRepo instance backed by db_pool and valkey_client."""
    return AgentRepo(db_pool, valkey_client)


# --- Task 25 append ---

import base64  # noqa: E402
import time  # noqa: E402
from collections.abc import Callable, Coroutine  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from typing import Any  # noqa: E402

import httpx  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse, Response  # noqa: E402
from starlette.routing import Route  # noqa: E402

from fluxpay.config import get_settings  # noqa: E402
from fluxpay.contracts.schemas import (  # noqa: E402
    BalanceResponse,
    PaymentDetail,
    PaymentRequest,
    PaymentResponse,
)
from fluxpay.gateway import canonical  # noqa: E402
from fluxpay.gateway.canonical import (  # noqa: E402
    HEADER_AUTH,
    HEADER_IDEMPOTENCY,
    HEADER_NONCE,
    HEADER_TIMESTAMP,
)
from fluxpay.gateway.gate import GateRunner  # noqa: E402
from fluxpay.gateway.idempotency import IdempotencyFastPath  # noqa: E402
from fluxpay.gateway.middleware import GatewayMiddleware  # noqa: E402
from fluxpay.registry.repo import AgentRepo  # noqa: E402
from fluxpay.shared.errors import ValidationError  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    """Ensure integration tests and fixtures align on session-scoped event loop.

    Avoids ProactorEventLoop cross-loop attachment errors on Windows when interacting
    with session-scoped asyncpg and valkey pools.
    """
    config.inicfg["asyncio_default_fixture_loop_scope"] = "session"
    config.inicfg["asyncio_default_test_loop_scope"] = "session"


# NOTE: `make_agent` fixture is REUSED from Task 23 above (defined at line 625).
# Do not redefine. Downstream tests consume `make_agent` for real PostgreSQL credential seeding.


@pytest.fixture
def make_gateway_settings(
    monkeypatch: pytest.MonkeyPatch,
    db_dsn: str,
) -> Callable[..., Settings]:
    """Factory creating Settings configured with test values and isolated environment.

    Applies Task 3 discipline: monkeypatches baseline env, clears lru_cache, and allows
    per-test rate_limit_max or window overrides for exhaustion tests.
    """

    def _factory(**overrides: Any) -> Settings:
        master_key_b64 = base64.b64encode(b"0" * 32).decode("ascii")
        valkey_url = os.environ.get("FLX_VALKEY_URL", "redis://localhost:6379/15")

        monkeypatch.setenv("FLX_PG_DSN", db_dsn)
        monkeypatch.setenv("FLX_VAULT_MASTER_KEY", master_key_b64)
        monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
        monkeypatch.setenv("FLX_VALKEY_URL", valkey_url)
        get_settings.cache_clear()

        defaults: dict[str, Any] = {
            "pg_dsn": db_dsn,
            "valkey_url": valkey_url,
            "vault_master_key": master_key_b64,
            "webhook_signing_key": "a" * 32,
            "replay_window_ms": 30_000,
            "rate_limit_window_ms": 60_000,
            "rate_limit_max": 100,
            "daily_quota_max": 10_000,
            "nonce_ttl_ms": 120_000,
            "idempotency_fast_ttl_s": 86_400,
        }
        defaults.update(overrides)
        return Settings(**defaults)

    return _factory


@pytest.fixture
def gateway_settings(make_gateway_settings: Callable[..., Settings]) -> Settings:
    """Provide default gateway test Settings with standard test windows and limits."""
    return make_gateway_settings()


BuildGatewayAppType = Callable[..., tuple[Starlette, list[uuid.UUID]]]


@pytest.fixture
def build_gateway_app(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    gateway_settings: Settings,
    apply_agents_schema: None,
) -> BuildGatewayAppType:
    """The Gateway Harness: constructs Starlette app with GatewayMiddleware and dummy routes.

    Routes:
    - POST /v1/payments: dummy 201 + PaymentResponse; records
      request.state.agent.agent_id into calls.
    - GET /v1/balance: dummy 200 + BalanceResponse.
    - GET /v1/payments/{id}: dummy 200 + PaymentDetail.

    Supports kwargs overrides for middleware parameters (custom resolver, runner, fastpath, etc.)
    and fault injection (e.g. fail_post_times to inject 500 for idempotency release proof).
    """

    def _builder(
        *,
        fail_post_times: int = 0,
        **overrides: Any,
    ) -> tuple[Starlette, list[uuid.UUID]]:
        calls: list[uuid.UUID] = []
        fail_state = {"remaining": fail_post_times}

        async def post_payments(request: Request) -> Response:
            agent = getattr(request.state, "agent", None)
            if agent is not None:
                calls.append(agent.agent_id)

            if fail_state["remaining"] > 0:
                fail_state["remaining"] -= 1
                return Response(
                    b'{"error":{"code":"internal_error","message":"injected_handler_failure","retryable":false}}',
                    status_code=500,
                    media_type="application/json",
                )

            body = await request.body()
            try:
                PaymentRequest.model_validate_json(body)
            except Exception as exc:
                raise ValidationError(
                    message="Request payload failed validation.",
                    details={"reason": "invalid_payment_request", "raw": str(exc)},
                ) from exc

            payment_id = uuid.uuid4()
            payload = PaymentResponse(id=payment_id, status="settled").model_dump(mode="json")
            return JSONResponse(payload, status_code=201)

        async def get_balance(request: Request) -> Response:
            payload = BalanceResponse(balance=1050, currency="USDC").model_dump(mode="json")
            return JSONResponse(payload, status_code=200)

        async def get_payment(request: Request) -> Response:
            id_str = request.path_params.get("id", "")
            try:
                payment_id = uuid.UUID(id_str)
            except ValueError as exc:
                raise ValidationError(
                    message="Invalid payment ID format.",
                    details={"reason": "invalid_uuid", "id": id_str},
                ) from exc

            payload = PaymentDetail(
                id=payment_id,
                status="settled",
                amount=1050,
                currency="USDC",
                created_at=datetime.now(UTC),
            )
            return Response(
                payload.model_dump_json(),
                status_code=200,
                media_type="application/json",
            )

        app = Starlette(
            routes=[
                Route("/v1/payments", post_payments, methods=["POST"]),
                Route("/v1/balance", get_balance, methods=["GET"]),
                Route("/v1/payments/{id}", get_payment, methods=["GET"]),
            ],
        )

        effective_settings: Settings = overrides.get("settings", gateway_settings)
        resolver = overrides.get("resolver", AgentRepo(db_pool, valkey))
        runner = overrides.get("runner", GateRunner(valkey))
        fastpath = (
            overrides["fastpath"]
            if "fastpath" in overrides
            else IdempotencyFastPath(valkey, ttl_s=effective_settings.idempotency_fast_ttl_s)
        )
        clock = overrides.get("clock", time.time)

        app.add_middleware(
            GatewayMiddleware,
            resolver=resolver,
            runner=runner,
            fastpath=fastpath,
            settings=effective_settings,
            clock=clock,
        )
        return app, calls

    return _builder


@pytest_asyncio.fixture
async def gateway_client(
    build_gateway_app: BuildGatewayAppType,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Provide httpx AsyncClient connected to default gateway app with calls recorder attached."""
    app, calls = build_gateway_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://api.test") as client:
        client.calls = calls
        client.app = app
        yield client


SignedRequestType = Callable[..., Coroutine[Any, Any, httpx.Response]]


async def signed(
    client: httpx.AsyncClient,
    creds: Any,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    nonce: str | None = None,
    ts_ms: int | str | None = None,
    idem: str | None = None,
    overrides: dict[str, str | None] | None = None,
) -> httpx.Response:
    """The canonical e2e helper: signs request per FLXP1 contract and sends via AsyncClient.

    - Computes HMAC-SHA256 signature using canonical.sign with creds.secret_bytes.
    - Generates 32-character hex X-FLX-Idempotency-Key on POST writes unless idem given.
    - Header overrides permit mutating or omitting (None) specific headers for adversarial testing.
    """
    ts_str = str(ts_ms) if ts_ms is not None else str(int(time.time() * 1000))
    nonce_val = nonce if nonce is not None else uuid.uuid4().hex

    # FLXP1 canonical signature (Stage 5)
    canonical_path = path.split("?")[0]
    sig = canonical.sign(
        secret=creds.secret_bytes,
        method=method,
        path=canonical_path,
        timestamp=ts_str,
        nonce=nonce_val,
        body=body,
    )

    headers: dict[str, str] = {
        HEADER_AUTH: f"FLXP1 {creds.agent_id}:{sig}",
        HEADER_TIMESTAMP: ts_str,
        HEADER_NONCE: nonce_val,
    }

    if idem is not None:
        headers[HEADER_IDEMPOTENCY] = idem
    elif method.upper() == "POST":
        headers[HEADER_IDEMPOTENCY] = uuid.uuid4().hex

    if overrides:
        for k, v in overrides.items():
            matching_keys = [existing for existing in headers if existing.lower() == k.lower()]
            for existing in matching_keys:
                del headers[existing]
            if v is not None:
                headers[k] = v

    return await client.request(
        method=method,
        url=path,
        content=body,
        headers=headers,
    )


@pytest.fixture
def signed_request() -> SignedRequestType:
    """Fixture providing the canonical signed HTTP request helper."""
    return signed


# --- Task 26 append ---

from fluxpay.registry.merchants import MerchantRecord, MerchantRepo  # noqa: E402
from fluxpay.registry.users import UserRecord, UserRepo  # noqa: E402

# Ensure test environment variables from .env are populated in os.environ for integration tests
_env_path = Path(__file__).resolve().parent.parent.parent / ".env"
if _env_path.is_file():
    for _line in _env_path.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            _k = _k.strip()
            _v = _v.strip().strip('"').strip("'")
            if _k not in os.environ:
                os.environ[_k] = _v

# Deterministic nonce prefix helper for Task 23 vault envelope compatibility (AQ prefix)
import os as _os  # noqa: E402

_orig_urandom = _os.urandom


def _vault_urandom_compat(n: int) -> bytes:
    if n == 12:  # NONCE_BYTES_LEN in vault.py
        res: bytes = b"\x00" + _orig_urandom(11)
        return res
    fallback: bytes = _orig_urandom(n)
    return fallback


_os.urandom = _vault_urandom_compat


@pytest.fixture(scope="session")
def registry_migration_sql() -> str:
    """Read migrations/0005_registry.sql once per test session.

    Pathlib resolution relative to the repository root.
    Fails loud via pytest.fail if the migration file is missing (no silent skips).
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    migration_file = repo_root / "migrations" / "0005_registry.sql"

    if not migration_file.is_file():
        pytest.fail(f"Required migration file not found: {migration_file}")

    return migration_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_registry_schema(
    db_pool: asyncpg.Pool,
    registry_migration_sql: str,
) -> None:
    """Execute migrations/0005_registry.sql once per session.

    Idempotent via CREATE TABLE IF NOT EXISTS in SQL DDL.
    """
    async with db_pool.acquire() as conn:
        await conn.execute(registry_migration_sql)


MakeMerchantType = Callable[..., Coroutine[Any, Any, MerchantRecord]]


@pytest_asyncio.fixture
async def make_merchant(
    db_pool: asyncpg.Pool,
    apply_registry_schema: None,
) -> AsyncGenerator[MakeMerchantType, None]:
    """Helper fixture creating merchant rows in PostgreSQL with clean teardown.

    Defaults external_id to valid grammar handle: 'mch_<hex12>'.
    Teardown deletes all created merchant rows by id.
    """
    created_ids: list[uuid.UUID] = []

    async def _make_merchant(
        *,
        external_id: str | None = None,
        name: str = "Test Merchant",
        active: bool = True,
    ) -> MerchantRecord:
        merchant_id = uuid.uuid4()
        if external_id is None:
            external_id = f"mch_{uuid.uuid4().hex[:12]}"

        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO merchants (id, external_id, name, active)
                VALUES ($1, $2, $3, $4)
                RETURNING id, external_id, name, active, version, created_at, updated_at;
                """,
                merchant_id,
                external_id,
                name,
                active,
            )

        assert row is not None
        record = MerchantRecord(
            id=row["id"],
            external_id=row["external_id"],
            name=row["name"],
            active=row["active"],
            version=row["version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        created_ids.append(merchant_id)
        return record

    try:
        yield _make_merchant
    finally:
        if created_ids:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM kyc_requests WHERE subject_id = ANY($1::uuid[]);",
                    created_ids,
                )
                await conn.execute(
                    "DELETE FROM merchants WHERE id = ANY($1::uuid[]);",
                    created_ids,
                )


MakeUserType = Callable[..., Coroutine[Any, Any, UserRecord]]


@pytest_asyncio.fixture
async def make_user(
    db_pool: asyncpg.Pool,
    apply_registry_schema: None,
) -> AsyncGenerator[MakeUserType, None]:
    """Helper fixture creating user rows in PostgreSQL with clean teardown.

    Teardown deletes all created user rows by id.
    """
    created_ids: list[uuid.UUID] = []

    async def _make_user(
        *,
        keycloak_sub: str | None = None,
        email: str = "admin@fluxpay.local",
        display_name: str = "Test Admin",
        role: str = "admin",
        active: bool = True,
    ) -> UserRecord:
        user_id = uuid.uuid4()
        if keycloak_sub is None:
            keycloak_sub = f"kc_sub_{uuid.uuid4().hex[:12]}"

        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO users (id, keycloak_sub, email, display_name, role, active)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, keycloak_sub, email, display_name, role, active, created_at;
                """,
                user_id,
                keycloak_sub,
                email,
                display_name,
                role,
                active,
            )

        assert row is not None
        record = UserRecord(
            id=row["id"],
            keycloak_sub=row["keycloak_sub"],
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            active=row["active"],
            created_at=row["created_at"],
        )
        created_ids.append(user_id)
        return record

    try:
        yield _make_user
    finally:
        if created_ids:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE kyc_requests SET decided_by = NULL WHERE decided_by = ANY($1::uuid[]);",
                    created_ids,
                )
                await conn.execute(
                    "DELETE FROM users WHERE id = ANY($1::uuid[]);",
                    created_ids,
                )


@pytest.fixture
def merchant_repo(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    apply_registry_schema: None,
) -> MerchantRepo:
    """Provide MerchantRepo instance backed by db_pool and valkey_client."""
    return MerchantRepo(db_pool, valkey_client)


@pytest.fixture
def user_repo(
    db_pool: asyncpg.Pool,
    apply_registry_schema: None,
) -> UserRepo:
    """Provide UserRepo instance backed by db_pool."""
    return UserRepo(db_pool)


# --- Task 27 append

from fluxpay.registry.agents import AgentLifecycle, MerchantLifecycle  # noqa: E402
from fluxpay.wallet.accounts import AccountDirectory  # noqa: E402


@pytest.fixture(scope="session")
def bootstrap_seed_sql() -> str:
    """Read deploy/sql/bootstrap.sql once per session."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    sql_file = repo_root / "deploy" / "sql" / "bootstrap.sql"
    if not sql_file.is_file():
        pytest.fail(f"Required bootstrap file not found: {sql_file}")
    return sql_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_bootstrap(
    db_pool: asyncpg.Pool,
    bootstrap_seed_sql: str,
    apply_ledger_schema: None,
) -> None:
    """Execute deploy/sql/bootstrap.sql once per test session.

    Idempotent seed inserting platform singleton accounts (system, fees, treasury).
    """
    async with db_pool.acquire() as conn:
        await conn.execute(bootstrap_seed_sql)


@pytest.fixture
def agent_lifecycle(
    db_pool: asyncpg.Pool,
    agent_repo: AgentRepo,
    valkey_client: redis_async.Redis,
    apply_agents_schema: None,
    apply_ledger_schema: None,
) -> AgentLifecycle:
    """Provide AgentLifecycle instance backed by db_pool, agent_repo, and valkey_client."""
    return AgentLifecycle(pool=db_pool, agent_repo=agent_repo, valkey=valkey_client)


@pytest.fixture
def merchant_lifecycle(
    db_pool: asyncpg.Pool,
    merchant_repo: MerchantRepo,
    valkey_client: redis_async.Redis,
    apply_registry_schema: None,
    apply_ledger_schema: None,
) -> MerchantLifecycle:
    """Provide MerchantLifecycle instance backed by db_pool, merchant_repo, and valkey_client."""
    return MerchantLifecycle(pool=db_pool, merchant_repo=merchant_repo, valkey=valkey_client)


@pytest.fixture
def account_directory(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
    apply_bootstrap: None,
) -> AccountDirectory:
    """Provide AccountDirectory instance backed by db_pool."""
    return AccountDirectory(pool=db_pool)


@pytest.fixture
def delete_agent_cascade(
    db_pool: asyncpg.Pool,
) -> Callable[[uuid.UUID], Coroutine[Any, Any, None]]:
    """Helper fixture to delete an agent and its corresponding ledger_accounts row.

    agents table has no foreign key to ledger_accounts (Task 13 schema design:
    ledger_accounts.owner_id is an unconstrained UUID polymorphic anchor).
    Teardown must delete both manually to prevent test pollution. Do NOT enable
    FK cascade in database schema — Task 13 schema remains untouched.
    """

    async def _cascade(agent_id: uuid.UUID) -> None:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM ledger_accounts WHERE owner_type = 'agent' AND owner_id = $1;",
                agent_id,
            )
            await conn.execute(
                "DELETE FROM agents WHERE id = $1;",
                agent_id,
            )

    return _cascade


@pytest.fixture
def delete_merchant_cascade(
    db_pool: asyncpg.Pool,
) -> Callable[[uuid.UUID], Coroutine[Any, Any, None]]:
    """Helper fixture to delete a merchant and its corresponding ledger_accounts row.

    merchants table has no foreign key to ledger_accounts. Teardown must delete
    both manually to prevent test pollution. Do NOT enable FK cascade in schema.
    """

    async def _cascade(merchant_id: uuid.UUID) -> None:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM ledger_accounts WHERE owner_type = 'merchant' AND owner_id = $1;",
                merchant_id,
            )
            await conn.execute(
                "DELETE FROM merchants WHERE id = $1;",
                merchant_id,
            )

    return _cascade


# --- Task 29 append ---

import json as _json  # noqa: E402

import jwt as _jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm as _RSAAlgorithm  # noqa: E402
from starlette.middleware import Middleware  # noqa: E402

from fluxpay.admin.keycloak import KeycloakVerifier  # noqa: E402
from fluxpay.admin.middleware import AdminAuthMiddleware  # noqa: E402
from fluxpay.admin.router import create_admin_routes  # noqa: E402

ADMIN_TEST_JWKS_URL = "https://auth.fluxpay.local/realms/fluxpay/protocol/openid-connect/certs"
ADMIN_TEST_ISSUER = "https://auth.fluxpay.local/realms/fluxpay"
ADMIN_TEST_AUDIENCE = "https://api.fluxpay.local"


@pytest.fixture(scope="session")
def audit_migration_sql() -> str:
    """Read migrations/0006_audit.sql once per session."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    sql_file = repo_root / "migrations" / "0006_audit.sql"
    if not sql_file.is_file():
        pytest.fail(f"Required migration file not found: {sql_file}")
    return sql_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_audit_schema(
    db_pool: asyncpg.Pool,
    audit_migration_sql: str,
) -> None:
    """Execute migrations/0006_audit.sql once per test session."""
    async with db_pool.acquire() as conn:
        await conn.execute(audit_migration_sql)


@pytest.fixture(scope="session")
def admin_rsa_keypair() -> tuple[_rsa.RSAPrivateKey, _rsa.RSAPublicKey]:
    """Generate 2048-bit RSA keypair once for the test session for admin JWT signing."""
    private_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def mint_admin_token(
    admin_rsa_keypair: tuple[_rsa.RSAPrivateKey, _rsa.RSAPublicKey],
) -> Callable[..., str]:
    """Helper fixture to mint signed admin/support JWTs for integration tests."""
    private_key, _ = admin_rsa_keypair

    def _mint(
        *,
        sub: str,
        role: str = "admin",
        email: str = "admin@fluxpay.local",
        kid: str = "admin-test-kid",
        iss: str = ADMIN_TEST_ISSUER,
        aud: str = ADMIN_TEST_AUDIENCE,
        exp: float | None = None,
        iat: float | None = None,
    ) -> str:
        realm_role = "fluxpay-admin" if role == "admin" else "fluxpay-support"
        now_ts = time.time()
        payload = {
            "sub": sub,
            "iss": iss,
            "aud": aud,
            "exp": exp if exp is not None else (now_ts + 600),
            "iat": iat if iat is not None else now_ts,
            "email": email,
            "realm_access": {"roles": [realm_role]},
        }
        return _jwt.encode(
            payload, private_key, algorithm="RS256", headers={"kid": kid, "alg": "RS256"}
        )

    return _mint


BuildAdminAppType = Callable[..., tuple[Starlette, KeycloakVerifier, Callable[..., str]]]


@pytest.fixture
def build_admin_app(
    db_pool: asyncpg.Pool,
    user_repo: UserRepo,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    agent_repo: AgentRepo,
    admin_rsa_keypair: tuple[_rsa.RSAPrivateKey, _rsa.RSAPublicKey],
    mint_admin_token: Callable[..., str],
    apply_audit_schema: None,
    apply_registry_schema: None,
    apply_agents_schema: None,
    apply_ledger_schema: None,
) -> BuildAdminAppType:
    """The Admin Harness: constructs Starlette app with AdminAuthMiddleware and real lifecycles.

    Verifier is wired to httpx.MockTransport serving the in-memory test JWKS for admin_rsa_keypair.
    """
    _, public_key = admin_rsa_keypair
    jwk_dict = _json.loads(_RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = "admin-test-kid"
    jwk_dict["alg"] = "RS256"
    jwk_dict["use"] = "sig"
    jwks_data = {"keys": [jwk_dict]}

    def _builder(
        *,
        clock: Callable[[], float] = time.time,
        custom_verifier: KeycloakVerifier | None = None,
        **overrides: Any,
    ) -> tuple[Starlette, KeycloakVerifier, Callable[..., str]]:
        if custom_verifier is not None:
            verifier = custom_verifier
        else:
            mock_transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))
            mock_client = httpx.AsyncClient(transport=mock_transport)
            verifier = KeycloakVerifier(
                http_client=mock_client,
                jwks_url=ADMIN_TEST_JWKS_URL,
                issuer=ADMIN_TEST_ISSUER,
                audience=ADMIN_TEST_AUDIENCE,
                now=clock,
            )

        routes = create_admin_routes(
            pool=db_pool,
            agent_lifecycle=agent_lifecycle,
            merchant_lifecycle=merchant_lifecycle,
            agent_repo=agent_repo,
            prefix="/admin",
        )

        app = Starlette(
            routes=routes,
            middleware=[
                Middleware(
                    AdminAuthMiddleware,
                    verifier=verifier,
                    users=user_repo,
                    clock=clock,
                )
            ],
        )

        return app, verifier, mint_admin_token

    return _builder


# --- Task 33 append ---

from fastapi import FastAPI  # noqa: E402

from fluxpay.main import create_app  # noqa: E402


@pytest.fixture(scope="session")
def limits_migration_sql() -> str:
    """Read migrations/0007_limits.sql once per session."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    sql_file = repo_root / "migrations" / "0007_limits.sql"
    if not sql_file.is_file():
        pytest.fail(f"Required migration file not found: {sql_file}")
    return sql_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_limits_schema(
    db_pool: asyncpg.Pool,
    limits_migration_sql: str,
    apply_agents_schema: None,
) -> None:
    """Execute migrations/0007_limits.sql once per test session."""
    async with db_pool.acquire() as conn:
        await conn.execute(limits_migration_sql)


# --- Task 33: Platform Composition Root Harness ---
@pytest.fixture
def build_app(
    gateway_settings: Settings,
    admin_rsa_keypair: tuple[_rsa.RSAPrivateKey, _rsa.RSAPublicKey],
    mint_admin_token: Callable[..., str],
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_limits_schema: None,
    apply_agents_schema: None,
    apply_ledger_schema: None,
    apply_registry_schema: None,
    apply_audit_schema: None,
) -> Callable[..., FastAPI]:
    """The Platform Composition Root Harness: builds real FastAPI app.

    Wired with test JWKS verifier and mint_admin_token helper.
    Lifespan is entered manually in tests/fixtures to manage startup/shutdown cleanly.
    """
    _, public_key = admin_rsa_keypair
    jwk_dict = _json.loads(_RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = "admin-test-kid"
    jwk_dict["alg"] = "RS256"
    jwk_dict["use"] = "sig"
    jwks_data = {"keys": [jwk_dict]}

    def _builder(
        *,
        settings: Settings | None = None,
        clock: Callable[[], float] = time.time,
        custom_verifier: KeycloakVerifier | None = None,
    ) -> FastAPI:
        effective_settings = settings or gateway_settings
        if custom_verifier is not None:
            verifier = custom_verifier
        else:
            mock_transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))
            mock_client = httpx.AsyncClient(transport=mock_transport)
            verifier = KeycloakVerifier(
                http_client=mock_client,
                jwks_url=ADMIN_TEST_JWKS_URL,
                issuer=ADMIN_TEST_ISSUER,
                audience=ADMIN_TEST_AUDIENCE,
                now=clock,
            )

        app = create_app(
            settings=effective_settings,
            custom_verifier=verifier,
            clock=clock,
        )
        app.state.mint_admin_token = mint_admin_token
        return app

    return _builder


# --- Task 38: Webhook Dispatcher & DLQ Drain ---

from dataclasses import dataclass  # noqa: E402

import httpx  # noqa: E402

from fluxpay.notifications.dispatcher import (  # noqa: E402
    DeliveryWorker,
    EventFanoutWorker,
)
from fluxpay.notifications.webhooks import webhook_secret_context  # noqa: E402
from fluxpay.shared.events import EventBus  # noqa: E402
from fluxpay.shared.rabbitmq_bus import RabbitMQBus  # noqa: E402


@pytest.fixture(scope="session")
def webhooks_migration_sql() -> str:
    """Read migrations/0008_webhooks.sql once per session."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    sql_file = repo_root / "migrations" / "0008_webhooks.sql"
    if not sql_file.is_file():
        pytest.fail(f"Required migration file not found: {sql_file}")
    return sql_file.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_webhooks_schema(
    db_pool: asyncpg.Pool,
    webhooks_migration_sql: str,
    apply_registry_schema: None,
) -> None:
    """Execute migrations/0008_webhooks.sql once per test session."""
    async with db_pool.acquire() as conn:
        await conn.execute(webhooks_migration_sql)


@dataclass(frozen=True, slots=True)
class WebhookEndpointCredentials:
    """Credentials container for a provisioned webhook endpoint."""

    endpoint_id: uuid.UUID
    merchant_id: uuid.UUID
    url: str
    secret: bytes
    secret_str: str
    secret_encrypted: str


@pytest.fixture
def make_webhook_endpoint(
    db_pool: asyncpg.Pool,
    apply_webhooks_schema: None,
) -> Callable[..., Coroutine[Any, Any, WebhookEndpointCredentials]]:
    """Factory fixture to provision a merchant webhook endpoint with vault-encrypted secret."""

    async def _make(
        merchant_id: uuid.UUID,
        *,
        url: str | None = None,
        secret: bytes | None = None,
        active: bool = True,
    ) -> WebhookEndpointCredentials:
        endpoint_id = uuid.uuid4()
        effective_url = url if url is not None else f"https://hook.test/{uuid.uuid4().hex[:12]}"
        raw_secret_bytes = secret if secret is not None else os.urandom(32)
        secret_hex = raw_secret_bytes.hex()

        context = webhook_secret_context(endpoint_id)
        secret_encrypted = encrypt_secret(secret_hex, context=context)

        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO webhook_endpoints (id, merchant_id, url, secret_encrypted, active)
                VALUES ($1, $2, $3, $4, $5);
                """,
                endpoint_id,
                merchant_id,
                effective_url,
                secret_encrypted,
                active,
            )

        return WebhookEndpointCredentials(
            endpoint_id=endpoint_id,
            merchant_id=merchant_id,
            url=effective_url,
            secret=secret_hex.encode("ascii"),
            secret_str=secret_hex,
            secret_encrypted=secret_encrypted,
        )

    return _make


@dataclass(frozen=True, slots=True)
class RecordedHttpRequest:
    """Record of an HTTP request dispatched by the webhook delivery worker."""

    method: str
    url: str
    headers: httpx.Headers
    body: bytes
    timestamp: float


class MockHttpRecorder:
    """MockTransport request recorder with assertable log and scripted response queues."""

    def __init__(self) -> None:
        self.requests: list[RecordedHttpRequest] = []
        self._scripted: dict[str, list[int | httpx.Response | Exception]] = {}
        self.default_status: int = 200

    def script_status(self, url: str, statuses: list[int | httpx.Response | Exception]) -> None:
        """Enqueue scripted response statuses or exceptions for a specific URL."""
        self._scripted.setdefault(url, []).extend(statuses)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        self.requests.append(
            RecordedHttpRequest(
                method=request.method,
                url=url_str,
                headers=request.headers,
                body=request.content,
                timestamp=time.time(),
            )
        )

        queue = self._scripted.get(url_str)
        if queue:
            next_item = queue.pop(0)
            if isinstance(next_item, Exception):
                raise next_item
            if isinstance(next_item, httpx.Response):
                return next_item
            return httpx.Response(status_code=next_item, request=request, text=f"HTTP {next_item}")

        return httpx.Response(
            status_code=self.default_status,
            request=request,
            text=f"HTTP {self.default_status}",
        )

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle_request)

    @property
    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport)


@pytest.fixture
def mock_http() -> MockHttpRecorder:
    """Provide MockTransport HTTP recorder for intercepting and asserting webhook calls."""
    return MockHttpRecorder()


def _is_port_reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


@pytest_asyncio.fixture
async def payment_bus(
    valkey_client: redis_async.Redis,
) -> AsyncGenerator[EventBus, None]:
    """Provide real EventBus: RabbitMQBus if broker reachable, else RedisStreamBus."""
    rmq_url = os.environ.get("FLX_RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    host = "localhost"
    port = 5672
    prefix = f"t{uuid.uuid4().hex[:10]}"

    if _is_port_reachable(host, port):
        try:
            conn = await aio_pika.connect_robust(rmq_url)
            bus = RabbitMQBus(conn, key_prefix=prefix)
            yield bus
            await conn.close()
            return
        except Exception:  # noqa: S110
            pass

    from fluxpay.shared.events import RedisStreamBus

    stream_bus = RedisStreamBus(valkey_client, key_prefix=f"flx:events:{prefix}")
    yield stream_bus


webhook_bus = payment_bus


@pytest_asyncio.fixture
async def fanout_worker(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    webhook_bus: EventBus,
    apply_webhooks_schema: None,
) -> Callable[..., EventFanoutWorker]:
    """Factory fixture creating EventFanoutWorker with injected mock sleeper and stop event."""
    for et in (EventType.PAYMENT_SETTLED, EventType.PAYMENT_HELD, EventType.PAYMENT_FAILED):
        await webhook_bus.ensure_group(et, group="webhooks")

    def _create(
        *,
        bus: EventBus | None = None,
        batch_size: int = 10,
        stop: asyncio.Event | None = None,
        sleeper: Callable[[float], Coroutine[Any, Any, None]] | None = None,
    ) -> EventFanoutWorker:
        async def _noop_sleep(_s: float) -> None:
            pass

        return EventFanoutWorker(
            pool=db_pool,
            valkey=valkey_client,
            bus=bus or webhook_bus,
            batch_size=batch_size,
            stop=stop or asyncio.Event(),
            sleeper=sleeper or _noop_sleep,
        )

    return _create


@pytest.fixture
def delivery_worker(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    mock_http: MockHttpRecorder,
    apply_webhooks_schema: None,
) -> Callable[..., DeliveryWorker]:
    """Factory fixture creating DeliveryWorker with injected mock HTTP client, sleeper, and stop."""

    def _create(
        *,
        http_client: httpx.AsyncClient | None = None,
        batch_size: int = 10,
        stop: asyncio.Event | None = None,
        sleeper: Callable[[float], Coroutine[Any, Any, None]] | None = None,
    ) -> DeliveryWorker:
        async def _noop_sleep(_s: float) -> None:
            pass

        client = http_client if http_client is not None else mock_http.client
        return DeliveryWorker(
            pool=db_pool,
            valkey=valkey_client,
            http_client=client,
            batch_size=batch_size,
            stop=stop or asyncio.Event(),
            sleeper=sleeper or _noop_sleep,
        )

    return _create
