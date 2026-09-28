"""Administrative plane limits and webhook endpoints router (Task 62 Append).

=============================================================================
THE TWO ENTRY SURFACES, ONE DOMAIN LAYER, ONE AUDIT TABLE ESSAY
=============================================================================
FluxPay enforces strict execution lane isolation (Task 61/62):
1. Machine-facing Admin Plane (/admin/*):
   - Authenticated via Keycloak Bearer JWTs (AdminAuthMiddleware).
   - Consumed by external machine automation, CI/CD runners, and operator CLI tools.
   - Wire representations are machine-readable JSON payloads.

2. Human-facing Operations Dashboard (/dashboard/*):
   - Authenticated via signed, encrypted HttpOnly SameSite=Strict session cookies
     (DashboardAuthMiddleware).
   - Protected against CSRF by the Three-Layer Defense (Origin verification, mandatory
     HX-Request header, and double-submit cryptographic CSRF tokens).
   - Wire representations are server-rendered Jinja2 HTML pages with htmx inline swaps.

THE HONEST FORK:
When browser operators perform mutations in the dashboard, the browser transmits
the HttpOnly session cookie, NOT a Keycloak Bearer token. Route handlers could theoretically
proxy HTTP requests into the /admin/* Bearer lane; however, that would require the dashboard
lane to mint synthetic Bearer tokens or bypass its own Bearer middleware, introducing
fragile loopback networking and credential leakage vectors.

Instead, the dashboard mutations call DASHBOARD endpoints (/dashboard/*), which directly
invoke the exact same DOMAIN services (LimitRepo, AgentLifecycle, MerchantLifecycle,
ApprovalService) as the admin API. Both surfaces write to the EXACT SAME immutable
audit log table (`audit_log` via `audit.record`), bound to the operator's verified
principal (`principal.sub` and `principal.role`).

Two entry surfaces (Machine Bearer JSON vs Human Cookie HTML);
One domain service layer;
One authoritative audit table.

This module provides the machine-facing Bearer admin endpoints for limits and webhooks,
fulfilling the contract promised in Task 28 and Task 38.
"""

from __future__ import annotations

import os
import uuid
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import orjson
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, Router

from fluxpay.admin.keycloak import AdminPrincipal
from fluxpay.audit import audit
from fluxpay.notifications.webhooks import webhook_secret_context
from fluxpay.risk.limits import AgentLimits, LimitRepo
from fluxpay.shared.errors import ForbiddenError, ValidationError
from fluxpay.shared.uow import UnitOfWork
from fluxpay.shared.vault import encrypt_secret

__all__ = [
    "create_limits_router",
    "create_limits_routes",
]


def _require_role(principal: AdminPrincipal | None, allowed_roles: set[str]) -> AdminPrincipal:
    """Enforce principal role membership or raise ForbiddenError (403)."""
    if principal is None or principal.role not in allowed_roles:
        raise ForbiddenError(message="insufficient permissions")
    return principal


def create_limits_routes(
    *,
    pool: asyncpg.Pool,
    limits_repo: LimitRepo,
    prefix: str = "/admin",
) -> list[Route]:
    """Build list of Starlette Routes for admin limits and webhook endpoints."""

    async def get_agent_limits(request: Request) -> Response:
        """Fetch effective financial policy limits for an agent."""
        _require_role(getattr(request.state, "principal", None), {"admin", "support"})

        id_str = request.path_params.get("id", "")
        try:
            agent_id = UUID(id_str)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "id", "reason": "invalid_uuid"},
            ) from exc

        limits = await limits_repo.get(agent_id)
        return JSONResponse(
            {
                "agent_id": str(agent_id),
                "velocity_limit": limits.velocity_limit,
                "velocity_window_s": limits.velocity_window_s,
                "max_single_tx_minor": limits.max_single_tx_minor,
                "daily_outflow_cap_minor": limits.daily_outflow_cap_minor,
            },
            status_code=200,
        )

    async def put_agent_limits(request: Request) -> Response:
        """Update or create financial policy limits for an agent.

        Requires admin role. Audited under action 'limits.update'.
        """
        principal = _require_role(getattr(request.state, "principal", None), {"admin"})

        id_str = request.path_params.get("id", "")
        try:
            agent_id = UUID(id_str)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "id", "reason": "invalid_uuid"},
            ) from exc

        try:
            body = await request.body()
            data = orjson.loads(body)
        except Exception as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"reason": "malformed_json", "error": str(exc)},
            ) from exc

        if not isinstance(data, dict):
            raise ValidationError(message="Request payload failed validation.")

        try:
            velocity_limit = int(data.get("velocity_limit", 5))
            velocity_window_s = int(data.get("velocity_window_s", 60))
            max_single_tx_minor = int(data.get("max_single_tx_minor", 100_000_000))
            daily_outflow_cap_minor = int(data.get("daily_outflow_cap_minor", 500_000_000))
        except (ValueError, TypeError) as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"reason": "integer_coercion_failed", "error": str(exc)},
            ) from exc

        new_limits = AgentLimits(
            agent_id=agent_id,
            velocity_limit=velocity_limit,
            velocity_window_s=velocity_window_s,
            max_single_tx_minor=max_single_tx_minor,
            daily_outflow_cap_minor=daily_outflow_cap_minor,
        )

        try:
            await limits_repo.upsert(agent_id, new_limits)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"reason": str(exc)},
            ) from exc

        async with UnitOfWork(pool) as uow:
            await audit.record(
                uow.connection,
                actor_sub=principal.sub,
                actor_role=principal.role,
                action="limits.update",
                target_type="agent",
                target_id=str(agent_id),
                details={
                    "velocity_limit": velocity_limit,
                    "velocity_window_s": velocity_window_s,
                    "max_single_tx_minor": max_single_tx_minor,
                    "daily_outflow_cap_minor": daily_outflow_cap_minor,
                },
            )

        return JSONResponse(
            {
                "agent_id": str(agent_id),
                "velocity_limit": velocity_limit,
                "velocity_window_s": velocity_window_s,
                "max_single_tx_minor": max_single_tx_minor,
                "daily_outflow_cap_minor": daily_outflow_cap_minor,
            },
            status_code=200,
        )

    async def post_merchant_webhook(request: Request) -> Response:
        """Create a new webhook endpoint for a merchant with one-time secret emission.

        Requires admin role. Audited under action 'webhook.create'.
        """
        principal = _require_role(getattr(request.state, "principal", None), {"admin"})

        id_str = request.path_params.get("merchant_id", "")
        try:
            merchant_id = UUID(id_str)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "merchant_id", "reason": "invalid_uuid"},
            ) from exc

        try:
            body = await request.body()
            data = orjson.loads(body)
        except Exception as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"reason": "malformed_json", "error": str(exc)},
            ) from exc

        if not isinstance(data, dict):
            raise ValidationError(message="Request payload failed validation.")

        url = data.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "url", "reason": "must_be_https_url"},
            )

        endpoint_id = uuid.uuid4()
        secret_hex = os.urandom(32).hex()
        context = webhook_secret_context(endpoint_id)
        secret_encrypted = encrypt_secret(secret_hex, context=context)

        # Direct SQL write deviation (Phase 2 refactors into NotificationRepo)
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO webhook_endpoints (id, merchant_id, url, secret_encrypted)
                    VALUES ($1, $2, $3, $4);
                    """,
                    endpoint_id,
                    merchant_id,
                    url,
                    secret_encrypted,
                )
        except asyncpg.IntegrityConstraintViolationError as exc:
            raise ValidationError(
                message="Endpoint registration failed.",
                details={"reason": "duplicate_or_invalid_url", "error": str(exc)},
            ) from exc

        async with UnitOfWork(pool) as uow:
            await audit.record(
                uow.connection,
                actor_sub=principal.sub,
                actor_role=principal.role,
                action="webhook.create",
                target_type="merchant",
                target_id=str(merchant_id),
                details={"endpoint_id": str(endpoint_id), "url": url},
            )

        return JSONResponse(
            {
                "id": str(endpoint_id),
                "merchant_id": str(merchant_id),
                "url": url,
                "secret": secret_hex,
            },
            status_code=201,
        )

    clean_prefix = prefix.rstrip("/")
    return [
        Route(f"{clean_prefix}/agents/{{id}}/limits", endpoint=get_agent_limits, methods=["GET"]),
        Route(
            f"{clean_prefix}/agents/{{id}}/limits",
            endpoint=put_agent_limits,
            methods=["PUT", "POST"],
        ),
        Route(
            f"{clean_prefix}/merchants/{{merchant_id}}/webhooks",
            endpoint=post_merchant_webhook,
            methods=["POST"],
        ),
    ]


def create_limits_router(
    *,
    pool: asyncpg.Pool,
    limits_repo: LimitRepo,
    prefix: str = "/admin",
) -> Router:
    """Instantiate Starlette Router configured with admin limits routes."""
    routes = create_limits_routes(pool=pool, limits_repo=limits_repo, prefix=prefix)
    return Router(routes=routes)
