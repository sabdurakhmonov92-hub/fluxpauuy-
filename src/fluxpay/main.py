"""Composition root and application entry point for FluxPay (Task 33).

=============================================================================
ARCHITECTURAL BLUEPRINT & COMPOSITION MANIFESTO
=============================================================================
The entire dependency graph of the platform is wired here in under 100 lines
of business-logic-free assembly.

Startup Sequencing Law:
1. Logging: Configures structlog and bridges stdlib loggers (Task 5).
2. Database Pool: Connection pool with strict UTC timezone and synchronous_commit=on.
   Task 13 durability: applies platform-wide to ledger, idempotency, and audit.
3. TZ Probe: Fail-fast structural invariant checking database connection timezone.
4. Valkey (Redis): Raw bytes connection mode for cryptographic cache fidelity.
5. RabbitMQ Event Bus: High-durability financial event bus for payment notifications.
6. Repositories & Services: Clean unidirectional dependency DAG.
7. Gateway Security Gate & Fast-Path: Ingress rate-limit gate and idempotency fast-path.
8. Graceful Teardown: Deterministic reverse-order shutdown draining bus, valkey, and database.

Middleware Registration Order Law:
FastAPI / Starlette middleware execution order is REVERSE registration order
(last added = outermost wrapper = executed first on ingress).
- AdminAuthMiddleware is added FIRST -> inner lane, wraps core routing.
- GatewayMiddleware is added LAST -> outermost lane, executes FIRST on ingress.
"""

from __future__ import annotations

import contextlib
import socket
import time
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from typing import Any, Final
from urllib.parse import urlparse
from uuid import UUID

import aio_pika
import aio_pika.abc
import asyncpg  # type: ignore[import-untyped]
import httpx
import sentry_sdk
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, ORJSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest, make_asgi_app, start_http_server
from redis import asyncio as redis_async
from starlette.routing import Router

from fluxpay import __version__
from fluxpay.admin.keycloak import KeycloakVerifier
from fluxpay.admin.middleware import AdminAuthMiddleware
from fluxpay.admin.router import create_admin_routes
from fluxpay.config import Settings, get_settings
from fluxpay.contracts.schemas import (
    BalanceResponse,
    PaymentDetail,
    PaymentRequest,
    PaymentResponse,
)
from fluxpay.gateway.canonical import HEADER_IDEMPOTENCY, sha256_hex
from fluxpay.gateway.gate import GateResult, GateRunner
from fluxpay.gateway.idempotency import FastPathOutcome, IdempotencyFastPath
from fluxpay.gateway.middleware import (
    HEADER_REQUEST_ID,
    AuthenticatedAgent,
    GatewayMiddleware,
    error_response,
)
from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.payments import PRIMARY_CURRENCY
from fluxpay.payments.render import render_error
from fluxpay.payments.service import PaymentService
from fluxpay.registry.agents import AgentLifecycle, MerchantLifecycle
from fluxpay.registry.merchants import MerchantRepo
from fluxpay.registry.repo import AgentRepo
from fluxpay.registry.users import UserRepo
from fluxpay.risk.limits import LimitRepo
from fluxpay.risk.quarantine import QuarantineService
from fluxpay.shared.errors import FluxPayError, NotFoundError, ValidationError
from fluxpay.shared.events import EventBus, RedisStreamBus
from fluxpay.shared.logging import configure_logging
from fluxpay.shared.rabbitmq_bus import RabbitMQBus
from fluxpay.wallet.accounts import AccountDirectory

# EventBus transport selection constant (Task 31 decision: RabbitMQ is the money rail).
# RedisStreamBus serves as the lightweight local/composition fallback.
DEFAULT_EVENT_BUS: Final[str] = "rabbitmq"


def _is_broker_listening(url: str, timeout: float = 0.5) -> bool:
    """Non-blocking socket check to verify broker reachability before attempting connect_robust."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 5672
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


# -----------------------------------------------------------------------------
# Middleware State Proxies (Zero-Downtime Lifespan Delegation)
# -----------------------------------------------------------------------------
# Starlette requires middleware instances at application build time, before the
# async lifespan context acquires runtime database and network connections.
# These lightweight proxies route middleware invocations directly to the live
# singletons stored in app.state after lifespan bootstrap completes.


class _StateAgentResolver:
    """Dynamic agent credential resolver delegating to app.state.agent_repo."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    async def resolve(self, agent_id: UUID) -> AuthenticatedAgent | None:
        repo: AgentRepo = self._app.state.agent_repo
        return await repo.resolve(agent_id)


class _StateGateRunner(GateRunner):
    """Dynamic atomic decision gate executor delegating to app.state.gate."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    async def run(
        self,
        *,
        agent_id: str,
        nonce: str,
        now_ms: int,
        window_ms: int,
        rate_max: int,
        nonce_ttl_ms: int,
        daily_max: int,
        day_ttl_s: int,
    ) -> GateResult:
        runner: GateRunner = self._app.state.gate
        return await runner.run(
            agent_id=agent_id,
            nonce=nonce,
            now_ms=now_ms,
            window_ms=window_ms,
            rate_max=rate_max,
            nonce_ttl_ms=nonce_ttl_ms,
            daily_max=daily_max,
            day_ttl_s=day_ttl_s,
        )

    async def execute(
        self,
        *,
        agent_id: str,
        nonce: str,
        now_ms: int,
        window_ms: int,
        rate_max: int,
        nonce_ttl_ms: int,
        daily_max: int,
        day_ttl_s: int,
    ) -> GateResult:
        return await self.run(
            agent_id=agent_id,
            nonce=nonce,
            now_ms=now_ms,
            window_ms=window_ms,
            rate_max=rate_max,
            nonce_ttl_ms=nonce_ttl_ms,
            daily_max=daily_max,
            day_ttl_s=day_ttl_s,
        )


class _StateFastPath(IdempotencyFastPath):
    """Dynamic idempotency fast-path delegating to app.state.fastpath."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    async def begin(
        self, agent_id: str, idem_key: str, body_hash: str
    ) -> tuple[FastPathOutcome, bytes | None]:
        fp: IdempotencyFastPath = self._app.state.fastpath
        return await fp.begin(agent_id, idem_key, body_hash)

    async def finish(self, agent_id: str, idem_key: str, *, status: int, body: bytes) -> None:
        fp: IdempotencyFastPath = self._app.state.fastpath
        await fp.finish(agent_id, idem_key, status=status, body=body)

    async def release(self, agent_id: str, idem_key: str) -> None:
        fp: IdempotencyFastPath = self._app.state.fastpath
        await fp.release(agent_id, idem_key)


class _StateUserRepo(UserRepo):
    """Dynamic user repo delegating to app.state.users."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    async def get_by_keycloak_sub(self, keycloak_sub: str) -> Any:
        repo: UserRepo = self._app.state.users
        return await repo.get_by_keycloak_sub(keycloak_sub)


class _StateKeycloakVerifier(KeycloakVerifier):
    """Dynamic Keycloak verifier delegating to app.state.verifier."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    async def verify(self, token: str) -> Any:
        verifier: KeycloakVerifier = self._app.state.verifier
        return await verifier.verify(token)


# -----------------------------------------------------------------------------
# Lifespan Management (Order of Assembly & Teardown)
# -----------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Execute asynchronous startup and shutdown lifecycle hooks."""
    settings = getattr(app.state, "settings", None) or get_settings()

    # Step 1: Configure structured logging pipeline (Task 5)
    configure_logging()

    # --- Task 69 append: Sentry initialization & Metrics Exporter ---
    if settings.sentry_dsn:
        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.env,
            traces_sample_rate=0.0,
        )
    if settings.metrics_enabled:
        with contextlib.suppress(OSError):
            start_http_server(settings.metrics_port_base)

    # Step 2: PostgreSQL connection pool with UTC timezone & synchronous_commit=on
    # WHY synchronous_commit=on: Task 13 ledger durability rule applies across all
    # connections including idempotency and audit. 500x headroom handles small latency cost.
    pool = await asyncpg.create_pool(
        settings.pg_dsn,
        min_size=settings.pg_pool_min,
        max_size=settings.pg_pool_max,
        server_settings={"TimeZone": "UTC", "synchronous_commit": "on"},
        command_timeout=30.0,
    )

    # Step 3: TZ PROBE — fail-fast timestamp drift prevention
    async with pool.acquire() as conn:
        tz = await conn.fetchval("SHOW timezone")
        if tz not in ("UTC", "Etc/UTC"):
            await pool.close()
            raise RuntimeError(
                f"PostgreSQL connection timezone must be 'UTC' or 'Etc/UTC', got '{tz}'. "
                "Ensure server_settings={'TimeZone': 'UTC'} is configured in asyncpg.create_pool."
            )

    # Step 4: Valkey (Redis) client in raw bytes mode
    # WHY decode_responses=False: Task 20/22 cache formats are raw binary bytes.
    # decode_responses=True would corrupt wire bodies and fast-path responses.
    valkey = redis_async.Redis.from_url(settings.valkey_url, decode_responses=False)

    # Step 5: Event bus wiring (Task 9/10/31)
    # RabbitMQ is the money rail per Task 31; RedisStreamBus is fallback/composition choice
    rabbit: aio_pika.abc.AbstractRobustConnection | None = None
    bus: EventBus
    if DEFAULT_EVENT_BUS == "rabbitmq" and _is_broker_listening(settings.rabbitmq_url):
        try:
            conn = await aio_pika.connect_robust(settings.rabbitmq_url)
            rabbit = conn
            bus = RabbitMQBus(connection=conn)
        except Exception:
            # Fallback to RedisStreamBus when RabbitMQ broker connection fails
            bus = RedisStreamBus(valkey, key_prefix="flx:events")
    else:
        bus = RedisStreamBus(valkey, key_prefix="flx:events")

    # Step 6: Domain stores, repositories, and orchestrators
    ledger = PostgresLedgerStore(pool)
    agent_repo = AgentRepo(pool, valkey)
    directory = AccountDirectory(pool)
    limits = LimitRepo(pool)
    quarantine = QuarantineService(pool)
    payments = PaymentService(
        ledger=ledger,
        directory=directory,
        limits_repo=limits,
        quarantine=quarantine,
        bus=bus,
        valkey=valkey,
        pool=pool,
    )

    # Step 7: Atomic decision gate runner and idempotency fast-path
    gate = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)

    # Admin plane identity and audit services (Task 29)
    users = UserRepo(pool)
    admin_http_client: httpx.AsyncClient | None = None
    custom_verifier = getattr(app.state, "custom_verifier", None)
    if custom_verifier is not None:
        verifier = custom_verifier
    else:
        admin_http_client = httpx.AsyncClient()
        verifier = KeycloakVerifier(
            http_client=admin_http_client,
            jwks_url=settings.keycloak_jwks_url,
            issuer=settings.keycloak_issuer,
            audience=settings.keycloak_audience,
        )

    # Mount admin routes under mounted Router
    merchant_repo = MerchantRepo(pool, valkey)
    agent_lifecycle = AgentLifecycle(pool, agent_repo, valkey=valkey)
    merchant_lifecycle = MerchantLifecycle(pool, merchant_repo, valkey=valkey)
    admin_routes = create_admin_routes(
        pool=pool,
        agent_lifecycle=agent_lifecycle,
        merchant_lifecycle=merchant_lifecycle,
        agent_repo=agent_repo,
        prefix="",
    )
    from fluxpay.admin.limits_router import create_limits_routes

    admin_limits_routes = create_limits_routes(
        pool=pool,
        limits_repo=limits,
        prefix="",
    )
    admin_router: Router = app.state.admin_router
    admin_router.routes.clear()
    admin_router.routes.extend(admin_routes)
    admin_router.routes.extend(admin_limits_routes)

    # Expose runtime singletons on app.state for middleware, handlers, and Task 69/70 telemetry
    app.state.pool = pool
    app.state.valkey = valkey
    app.state.rabbit = rabbit
    app.state.bus = bus
    app.state.ledger = ledger
    app.state.agent_repo = agent_repo
    app.state.directory = directory
    app.state.limits = limits
    app.state.quarantine = quarantine
    app.state.payments = payments
    app.state.gate = gate
    app.state.fastpath = fastpath
    app.state.users = users
    app.state.verifier = verifier

    # --- Task 43 append ---
    # Wire AdminNotifier: TelegramAdminNotifier if fully configured; else LoggingStubNotifier.
    # LoggingStubNotifier = dev/local: all events logged at INFO, zero HTTP calls.
    # WHY app.state.notifier: Task 65's app.state map entry seam was planned in Task 33's
    from fluxpay.approvals.service import AdminNotifier, ApprovalService
    from fluxpay.notifications.channels import TelegramChannel
    from fluxpay.notifications.notifier import (
        LoggingStubNotifier,
        TelegramAdminNotifier,
    )

    notifier: AdminNotifier
    if settings.telegram_bot_token and settings.telegram_admin_chat_id:
        _notify_http_client = httpx.AsyncClient(timeout=10.0)
        _tg_channel = TelegramChannel(
            _notify_http_client,
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_admin_chat_id,
            retry_max=settings.notification_retry_max,
            backoff_base_s=settings.notification_backoff_base_s,
        )
        notifier = TelegramAdminNotifier(_tg_channel, pool)
    else:
        _notify_http_client = None
        notifier = LoggingStubNotifier()

    app.state.notifier = notifier
    app.state.approval_service = ApprovalService(
        pool=pool,
        bus=bus,
        notifier=notifier,
        payments=payments,
    )
    # --- end Task 43 append ---

    try:
        yield
    finally:
        # Step 8: Graceful shutdown in strict reverse order
        # Close bus publisher channel first to finish outbound messages
        if rabbit is not None and not rabbit.is_closed:
            await rabbit.close()
        # Close valkey connections
        await valkey.aclose()
        # Close admin HTTP client if allocated
        if admin_http_client is not None:
            await admin_http_client.aclose()
        # Close notification HTTP client if allocated (Task 43 append)
        if _notify_http_client is not None:
            await _notify_http_client.aclose()
        # Close PostgreSQL pool last (Uvicorn drains requests before lifespan exit;
        # Task 65 systemd configuration provisions TimeoutStopSec=30).
        await pool.close()


# -----------------------------------------------------------------------------
# Application Assembly (Composition Root)
# -----------------------------------------------------------------------------


class _ContentTypeDefaultMiddleware:
    """Ensure HTTP POST/PUT/PATCH requests default to application/json if Content-Type omitted.

    Autonomous machine agents frequently omit standard Content-Type headers when signing
    custom transport headers. This ensures FastAPI parses JSON payloads rather than treating
    them as unparsed binary streams.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope["method"] in ("POST", "PUT", "PATCH"):
            raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
            has_ct = any(k.lower() == b"content-type" for k, _ in raw_headers)
            if not has_ct:
                raw_headers.append((b"content-type", b"application/json"))
                scope["headers"] = raw_headers
        await self.app(scope, receive, send)


def create_app(
    settings: Settings | None = None,
    *,
    custom_verifier: KeycloakVerifier | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    """Build and wire the complete FluxPay FastAPI application."""
    effective_settings = settings or get_settings()

    # Documentation policy: surface minimization in production.
    # In production, OpenAPI documentation and introspection routes are disabled.
    # The frozen tests/golden/openapi.golden.json contract is the source of truth.
    is_prod = effective_settings.env == "production"
    docs_url = None if is_prod else "/docs"
    redoc_url = None if is_prod else "/redoc"
    openapi_url = None if is_prod else "/openapi.json"

    app = FastAPI(
        title="FluxPay",
        version=__version__,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )

    app.state.settings = effective_settings
    app.state.custom_verifier = custom_verifier

    # Dynamic proxies routing middleware dependencies to app.state
    agent_resolver = _StateAgentResolver(app)
    gate_runner = _StateGateRunner(app)
    fastpath = _StateFastPath(app)
    users = _StateUserRepo(app)
    verifier = _StateKeycloakVerifier(app)

    # -------------------------------------------------------------------------
    # Middleware Registration (ORDER IS LAW)
    # -------------------------------------------------------------------------
    # Starlette executes middleware in REVERSE registration order (last added runs first).
    # 1. Content-Type default added FIRST -> innermost wrapper before route dispatch.
    app.add_middleware(_ContentTypeDefaultMiddleware)

    # 2. AdminAuthMiddleware added -> inner lane, wraps core endpoints.
    #    Restricted to ADMIN_PREFIX ("/admin").
    app.add_middleware(
        AdminAuthMiddleware,
        verifier=verifier,
        users=users,
        clock=clock,
    )

    # 3. GatewayMiddleware added LAST -> outermost lane, executes FIRST on ingress.
    #    Handles request correlation, FLXP1 HMAC verification, replay windows,
    #    atomic rate/quota gate, and idempotency fast-path caching.
    app.add_middleware(
        GatewayMiddleware,
        resolver=agent_resolver,
        runner=gate_runner,
        fastpath=fastpath,
        settings=effective_settings,
        clock=clock,
    )

    # Mount admin plane sub-router (include_in_schema=False via mount isolation)
    admin_router = Router()
    app.state.admin_router = admin_router
    app.mount("/admin", admin_router)

    # --- Task 42 append
    from fluxpay.admin.holds import router as holds_router

    app.include_router(holds_router)

    # --- Task 61 append
    from starlette.middleware import Middleware
    from starlette.staticfiles import StaticFiles

    from fluxpay.dashboard.middleware import DashboardAuthMiddleware
    from fluxpay.dashboard.views import router as dashboard_router

    app.include_router(dashboard_router)
    app.user_middleware.append(
        Middleware(
            DashboardAuthMiddleware,
            verifier=verifier,
            users=users,
            secret=effective_settings.dashboard_secret or "",
            cookie_name=effective_settings.dashboard_session_cookie_name,
            max_age_s=effective_settings.dashboard_cookie_max_age_s,
            origin=effective_settings.dashboard_origin,
            clock=clock,
        )
    )
    # Dev-mode static mount (Task 65 nginx serves static directly in production)
    app.mount("/static", StaticFiles(directory="static"), name="static")

    # -------------------------------------------------------------------------
    # Exception Handlers (Platform Wire Dialect Enforcement)
    # -------------------------------------------------------------------------

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Map FastAPI's RequestValidationError to the frozen Task 4 ErrorEnvelope."""
        request_id = getattr(request.state, "request_id", None)
        return error_response(
            ValidationError(
                message="Request payload failed validation.",
                details={"errors": str(exc.errors())},
            ),
            request_id=request_id,
        )

    @app.exception_handler(FluxPayError)
    async def fluxpay_error_handler(request: Request, exc: FluxPayError) -> Response:
        """Map domain FluxPayError to canonical error bytes with correlation header."""
        request_id = getattr(request.state, "request_id", None)
        headers = {HEADER_REQUEST_ID: request_id} if request_id else None
        return Response(
            content=render_error(exc),
            status_code=exc.status,
            media_type="application/json",
            headers=headers,
        )

    # -------------------------------------------------------------------------
    # Agent Payment Routes (The 3 Frozen Endpoints)
    # -------------------------------------------------------------------------

    @app.post("/v1/payments", status_code=201, response_model=PaymentResponse)
    async def post_payment(request: Request, body: PaymentRequest) -> Response:
        """Execute or replay a financial payment transaction.

        Three-tier idempotency dance:
        1. Redis fastpath replay: intercepted and returned by GatewayMiddleware.
        2. Database-tier replay: returned by service.pay using cached wire bytes.
        3. Fresh execution: posted to double-entry ledger with atomic event publish.
        """
        idem_key = request.headers.get(HEADER_IDEMPOTENCY, "")
        raw_body = await request.body()
        body_hash = sha256_hex(raw_body)
        agent: AuthenticatedAgent = request.state.agent

        try:
            outcome = await request.app.state.payments.pay(
                agent_id=agent.agent_id,
                idem_key=idem_key,
                body_hash=body_hash,
                to_merchant=body.to,
                amount_minor=body.amount,
                currency=body.currency,
            )
            return Response(
                content=outcome.wire_body,
                status_code=201,
                media_type="application/json",
            )
        except FluxPayError as e:
            return Response(
                content=render_error(e),
                status_code=e.status,
                media_type="application/json",
            )

    @app.get("/v1/payments/{tx_id}", response_model=PaymentDetail)
    async def get_payment(tx_id: UUID, request: Request) -> Response:
        """Query settled payment transaction by transaction ID.

        Product Decision (Ledger-Truth):
        GET by id reflects double-entry ledger truth. Held payments await human review
        in payment_holds and have no ledger transaction, returning 404 here.
        Held payments are notified via webhooks and future status endpoints (Phase 2).
        """
        ledger: PostgresLedgerStore = request.app.state.ledger
        directory: AccountDirectory = request.app.state.directory

        tx = await ledger.get_transaction(tx_id)
        if tx is None or not tx.entries:
            raise NotFoundError(
                details={"tx_id": str(tx_id)},
                message="The requested resource was not found.",
            )

        agent: AuthenticatedAgent = request.state.agent
        agent_ref = await directory.get_agent_account(agent.agent_id, PRIMARY_CURRENCY)

        debit_entry = next(
            (
                e
                for e in tx.entries
                if e.direction == Direction.DEBIT and e.account_id == agent_ref.account_id
            ),
            None,
        )
        if debit_entry is None:
            raise NotFoundError(
                details={"tx_id": str(tx_id)},
                message="The requested resource was not found.",
            )

        detail = PaymentDetail(
            id=tx.tx_id,
            status="settled",
            amount=debit_entry.amount,
            currency=debit_entry.currency,
            created_at=tx.entries[0].created_at,
        )
        return Response(
            content=detail.model_dump_json().encode("utf-8"),
            media_type="application/json",
        )

    @app.get("/v1/balance", response_model=BalanceResponse)
    async def get_balance(request: Request) -> Response:
        """Query available ledger balance for the authenticated agent."""
        agent: AuthenticatedAgent = request.state.agent
        directory: AccountDirectory = request.app.state.directory
        ledger: PostgresLedgerStore = request.app.state.ledger

        ref = await directory.get_agent_account(agent.agent_id, PRIMARY_CURRENCY)
        balance_record = await ledger.get_balance(ref.account_id)
        resp = BalanceResponse(balance=balance_record.balance, currency=PRIMARY_CURRENCY)
        return Response(
            content=resp.model_dump_json().encode("utf-8"),
            media_type="application/json",
        )

    # --- TASK 65 APPEND: HEALTH PROBE (PROCESS LIVENESS FOR SYSTEMD & NGINX) ---
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Process liveness probe for systemd/nginx load balancer health checks."""
        return {"status": "ok", "version": __version__}

    # --- Task 69 append: Prometheus /metrics exposition endpoint ---
    @app.get("/metrics", include_in_schema=False)
    def metrics_endpoint() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.mount("/metrics", make_asgi_app())

    return app


# Default singleton application instance for ASGI server runners (Uvicorn / Gunicorn)
app: FastAPI = create_app()
