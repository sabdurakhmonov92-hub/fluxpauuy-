"""Centralized Dependency Injection (DI) Container for FluxPay.

Provides request-scoped and application-scoped dependencies for FastAPI route handlers
via FastAPI's `Depends()` mechanism. Adheres strictly to the inversion-of-control principle:
no global singletons, zero import-time side effects, and strict typed access to services
initialized during application lifespan.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated, cast

import asyncpg  # type: ignore[import-untyped]
from fastapi import Depends, Request
from redis import asyncio as redis_async

from fluxpay.approvals.service import AdminNotifier, ApprovalService
from fluxpay.config import Settings, get_settings
from fluxpay.gateway.gate import GateRunner
from fluxpay.gateway.idempotency import IdempotencyFastPath
from fluxpay.gateway.middleware import AuthenticatedAgent
from fluxpay.integrations.base_indexer import BaseIndexer
from fluxpay.integrations.base_l2_writer import BaseL2Writer
from fluxpay.integrations.hd_wallet import HDWalletManager
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.payments.service import PaymentService
from fluxpay.registry.merchants import MerchantRepo
from fluxpay.registry.repo import AgentRepo
from fluxpay.registry.users import UserRepo
from fluxpay.risk.limits import LimitRepo
from fluxpay.risk.quarantine import QuarantineService
from fluxpay.shared.events import EventBus
from fluxpay.shared.kms import BaseSigner
from fluxpay.wallet.accounts import AccountDirectory


def get_settings_dep(request: Request) -> Settings:
    """Retrieve runtime Settings instance from app state or environment."""
    return getattr(request.app.state, "settings", None) or get_settings()


def get_db_pool(request: Request) -> asyncpg.Pool:
    """Retrieve PostgreSQL connection pool from application lifespan state."""
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise RuntimeError("Database pool is not initialized in application state.")
    return cast(asyncpg.Pool, pool)


async def get_db_connection(
    pool: Annotated[asyncpg.Pool, Depends(get_db_pool)],
) -> AsyncGenerator[asyncpg.Connection, None]:
    """Acquire a dedicated transactional database connection from the pool."""
    async with pool.acquire() as conn:
        yield conn


def get_redis_client(request: Request) -> redis_async.Redis:
    """Retrieve shared Redis/Valkey asynchronous client from application lifespan state."""
    valkey = getattr(request.app.state, "valkey", None)
    if valkey is None:
        raise RuntimeError("Redis/Valkey client is not initialized in application state.")
    return cast(redis_async.Redis, valkey)


def get_event_bus(request: Request) -> EventBus:
    """Retrieve durable event bus (RabbitMQ or Redis Streams fallback)."""
    bus = getattr(request.app.state, "bus", None)
    if bus is None:
        raise RuntimeError("EventBus is not initialized in application state.")
    return cast(EventBus, bus)


def get_ledger_store(request: Request) -> PostgresLedgerStore:
    """Retrieve immutable double-entry PostgreSQL ledger store."""
    ledger = getattr(request.app.state, "ledger", None)
    if ledger is None:
        raise RuntimeError("LedgerStore is not initialized in application state.")
    return cast(PostgresLedgerStore, ledger)


def get_agent_repo(request: Request) -> AgentRepo:
    """Retrieve autonomous agent repository."""
    repo = getattr(request.app.state, "agent_repo", None)
    if repo is None:
        raise RuntimeError("AgentRepo is not initialized in application state.")
    return cast(AgentRepo, repo)


def get_merchant_repo(request: Request) -> MerchantRepo:
    """Retrieve merchant registry repository."""
    repo = getattr(request.app.state, "merchant_repo", None)
    if repo is None:
        raise RuntimeError("MerchantRepo is not initialized in application state.")
    return cast(MerchantRepo, repo)


def get_account_directory(request: Request) -> AccountDirectory:
    """Retrieve double-entry account directory."""
    dir_svc = getattr(request.app.state, "directory", None)
    if dir_svc is None:
        raise RuntimeError("AccountDirectory is not initialized in application state.")
    return cast(AccountDirectory, dir_svc)


def get_limit_repo(request: Request) -> LimitRepo:
    """Retrieve risk limits repository."""
    limits = getattr(request.app.state, "limits", None)
    if limits is None:
        raise RuntimeError("LimitRepo is not initialized in application state.")
    return cast(LimitRepo, limits)


def get_quarantine_service(request: Request) -> QuarantineService:
    """Retrieve transaction quarantine and hold management service."""
    quar = getattr(request.app.state, "quarantine", None)
    if quar is None:
        raise RuntimeError("QuarantineService is not initialized in application state.")
    return cast(QuarantineService, quar)


def get_payment_service(request: Request) -> PaymentService:
    """Retrieve primary payment orchestrator service."""
    payments = getattr(request.app.state, "payments", None)
    if payments is None:
        raise RuntimeError("PaymentService is not initialized in application state.")
    return cast(PaymentService, payments)


def get_approval_service(request: Request) -> ApprovalService:
    """Retrieve payment approval workflow service."""
    approvals = getattr(request.app.state, "approval_service", None)
    if approvals is None:
        raise RuntimeError("ApprovalService is not initialized in application state.")
    return cast(ApprovalService, approvals)


def get_notifier(request: Request) -> AdminNotifier:
    """Retrieve admin notification channel."""
    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        raise RuntimeError("AdminNotifier is not initialized in application state.")
    return cast(AdminNotifier, notifier)


def get_gate_runner(request: Request) -> GateRunner:
    """Retrieve atomic rate/quota gate runner."""
    gate = getattr(request.app.state, "gate", None)
    if gate is None:
        raise RuntimeError("GateRunner is not initialized in application state.")
    return cast(GateRunner, gate)


def get_idempotency_fastpath(request: Request) -> IdempotencyFastPath:
    """Retrieve Redis-backed idempotency fast-path cache."""
    fastpath = getattr(request.app.state, "fastpath", None)
    if fastpath is None:
        raise RuntimeError("IdempotencyFastPath is not initialized in application state.")
    return cast(IdempotencyFastPath, fastpath)


def get_user_repo(request: Request) -> UserRepo:
    """Retrieve Keycloak user repository."""
    users = getattr(request.app.state, "users", None)
    if users is None:
        raise RuntimeError("UserRepo is not initialized in application state.")
    return cast(UserRepo, users)


def get_kms_signer(request: Request) -> BaseSigner | None:
    """Retrieve KMS or HSM transaction signer if configured."""
    return getattr(request.app.state, "kms_signer", None)


def get_base_l2_writer(request: Request) -> BaseL2Writer | None:
    """Retrieve Base L2 on-chain USDC writer client if configured."""
    return getattr(request.app.state, "base_l2_writer", None)


def get_base_indexer(request: Request) -> BaseIndexer | None:
    """Retrieve Base L2 deposit indexer worker if running."""
    return getattr(request.app.state, "base_indexer", None)


def get_hd_wallet_manager(request: Request) -> HDWalletManager | None:
    """Retrieve HD Wallet deposit address manager if configured."""
    return getattr(request.app.state, "hd_wallet", None)


def get_authenticated_agent(request: Request) -> AuthenticatedAgent:
    """Retrieve authenticated agent from GatewayMiddleware scope.

    Raises:
        RuntimeError: If request was not routed through GatewayMiddleware authentication.
    """
    agent = getattr(request.state, "agent", None)
    if agent is None:
        raise RuntimeError("Request has no authenticated agent in state.")
    return cast(AuthenticatedAgent, agent)
