"""Dashboard operational mutation handlers and screens (Task 62 - Block L Closure).

=============================================================================
ARCHITECTURAL DESIGN INVARIANTS & LAWS
=============================================================================

1. THE TWO ENTRY SURFACES, ONE AUDIT TABLE, ONE DOMAIN LAYER DOCTRINE:
   - Admin API (/admin/*) is the machine-facing surface: authenticated via Keycloak Bearer
     tokens, emitting and consuming JSON payloads for scripts and CLI tooling.
   - Operations Dashboard (/dashboard/*) is the human-facing surface: authenticated via
     HttpOnly SameSite=Strict cookies, guarded by the Three-Layer CSRF defense
     (Origin matching, HX-Request header, cryptographic CSRF token).
   - The dashboard calls DOMAIN services directly (LimitRepo, AgentLifecycle, MerchantLifecycle,
     ApprovalService) rather than loopback-HTTP proxying to Bearer endpoints.
   - Every administrative mutation writes to the EXACT SAME immutable `audit_log` table
     via `audit.record`, bound to the verified operator principal.

2. ONE-TIME SECRET CUSTODY LAW:
   - Plaintext secrets for agents (64-character hex) and webhook endpoints (64-character hex)
     are rendered EXACTLY ONCE upon creation on `created.html`.
   - The response is protected by strict cache-killer headers:
     `Cache-Control: no-store` and `Pragma: no-cache`.
   - The UI provides a client-side click-to-copy action without inline JavaScript.
   - NO plaintext secrets are ever stored in the database, retained in application memory,
     or written to audit logs.

3. THE PRG (POST-REDIRECT-GET) REFRESH-SAFETY HARDENING:
   - Form mutations that update state without one-time secret emission (such as limits updates,
     agent activations, merchant suspensions) return HTTP 303 See Other redirects.
   - 303 converts POST into GET, preventing accidental double-submissions when an operator
     refreshes the browser.

4. DIRECT SQL INSERT DEVIATION (WEBHOOK ENDPOINTS):
   - In Task 38, webhook endpoints were created without a standalone repository or
     lifecycle service.
   - The dashboard writes directly to `webhook_endpoints` with AES-256-GCM vault envelope
     encryption (bound to AAD "webhook_secret:<endpoint_id>").
   - This deviation is documented honestly; Phase 2 refactors it into a unified NotificationRepo.
   - The cross-block custody interlock test proves that delivery workers can successfully
     decrypt and sign webhooks using secrets generated here.

5. READ-ONLY TREASURY GOVERNANCE:
   - The treasury view is strictly read-only on the web dashboard.
   - Cold vault payouts require multi-signature governance via the CLI tool:
     `python -m fluxpay.treasury.cli vote --payout-id <id> --vote approve`
   - Zero `hx-post` mutation buttons are permitted on the treasury screen.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from fluxpay.admin.keycloak import AdminPrincipal
from fluxpay.audit import audit
from fluxpay.dashboard.auth import format_minor
from fluxpay.notifications.webhooks import webhook_secret_context
from fluxpay.registry.agents import (
    AgentLifecycle,
    CreateAgentCommand,
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.registry.merchants import MerchantRepo
from fluxpay.registry.repo import AgentRepo
from fluxpay.risk.limits import AgentLimits, LimitRepo
from fluxpay.risk.quarantine import QuarantineService
from fluxpay.shared.errors import ForbiddenError
from fluxpay.shared.uow import UnitOfWork
from fluxpay.shared.vault import encrypt_secret
from fluxpay.treasury.payouts import custody_snapshot
from fluxpay.treasury.reader import FakeReader

TEMPLATES_DIR: Path = Path(__file__).resolve().parents[3] / "templates"
templates: Jinja2Templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["format_minor"] = format_minor

router: APIRouter = APIRouter(tags=["dashboard_ops"])

__all__ = [
    "build_no_store_headers",
    "parse_int_field",
    "parse_limits_form",
    "router",
]

_HTTPS_URL_RE = re.compile(r"^https://[A-Za-z0-9]")


# =============================================================================
# 1. PURE FORM PARSERS & HEADER BUILDERS
# =============================================================================


def build_no_store_headers() -> dict[str, str]:
    """Build HTTP cache-killer headers preventing browser caching of one-time secrets."""
    return {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }


def parse_int_field(
    value: Any,
    field_name: str,
    *,
    min_val: int | None = None,
    max_val: int | None = None,
) -> int:
    """Coerce and validate integer form inputs defense-in-depth against malformed requests.

    Raises:
        ValueError: If value is missing, cannot be parsed as a base-10 int, or falls outside bounds.
    """
    if value is None:
        raise ValueError(f"Field '{field_name}' is required.")
    raw_str = str(value).strip()
    if not raw_str:
        raise ValueError(f"Field '{field_name}' cannot be empty.")

    # Strictly reject floats (e.g. "1.5")
    if "." in raw_str:
        raise ValueError(f"Field '{field_name}' must be an integer, got float string '{raw_str}'.")

    try:
        parsed = int(raw_str)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Field '{field_name}' must be a valid integer.") from exc

    if min_val is not None and parsed < min_val:
        raise ValueError(f"Field '{field_name}' must be >= {min_val}, got {parsed}.")
    if max_val is not None and parsed > max_val:
        raise ValueError(f"Field '{field_name}' must be <= {max_val}, got {parsed}.")

    return parsed


def parse_limits_form(data: Mapping[str, Any]) -> tuple[AgentLimits | None, str | None]:
    """Parse and validate financial policy limit fields from form submission.

    Validates Task 28 limits bounds:
    - velocity_limit: [1, 100]
    - velocity_window_s: [10, 3600]
    - max_single_tx_minor: > 0
    - daily_outflow_cap_minor: > 0

    Returns:
        (AgentLimits, None) on success, or (None, error_message) on validation failure.
    """
    try:
        velocity_limit = parse_int_field(
            data.get("velocity_limit"), "velocity_limit", min_val=1, max_val=100
        )
        velocity_window_s = parse_int_field(
            data.get("velocity_window_s"), "velocity_window_s", min_val=10, max_val=3600
        )
        max_single_tx_minor = parse_int_field(
            data.get("max_single_tx_minor"), "max_single_tx_minor", min_val=1
        )
        daily_outflow_cap_minor = parse_int_field(
            data.get("daily_outflow_cap_minor"), "daily_outflow_cap_minor", min_val=1
        )
    except ValueError as exc:
        return None, str(exc)

    return (
        AgentLimits(
            agent_id=None,
            velocity_limit=velocity_limit,
            velocity_window_s=velocity_window_s,
            max_single_tx_minor=max_single_tx_minor,
            daily_outflow_cap_minor=daily_outflow_cap_minor,
        ),
        None,
    )


def _get_principal(request: Request) -> AdminPrincipal:
    """Retrieve verified operator principal from request state."""
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, AdminPrincipal):
        raise HTTPException(status_code=401, detail="Authentication required.")
    return principal


def _require_admin(request: Request) -> AdminPrincipal:
    """Enforce admin role requirement or raise ForbiddenError (403)."""
    principal = _get_principal(request)
    if principal.role != "admin":
        raise ForbiddenError(message="insufficient permissions: admin role required")
    return principal


def _render_error_response(
    request: Request,
    *,
    status_code: int,
    title: str,
    message: str,
) -> HTMLResponse:
    """Render the standard error page preserving operator session context."""
    context = {
        "request": request,
        "status_code": status_code,
        "title": title,
        "message": message,
        "request_id": str(uuid.uuid4()),
        "principal": getattr(request.state, "principal", None),
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "error.html", context, status_code=status_code)


# =============================================================================
# 2. AGENT MUTATION & ONE-TIME SECRET EMISSION
# =============================================================================


@router.post("/agents", response_class=HTMLResponse)
async def post_dashboard_agent(request: Request) -> Response:
    """Provision a new autonomous agent and display its plaintext secret ONCE.

    Enforces:
    - Admin-only role check.
    - Input validation (external_id, name, currency, limits).
    - Cache-Control: no-store headers on the response.
    - Zero plaintext secret in database or audit logs.
    """
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    form = await request.form()
    external_id = str(form.get("external_id", "")).strip()
    name = str(form.get("name", "")).strip()
    currency = str(form.get("currency", "USDC")).strip().upper()

    pool: asyncpg.Pool = request.app.state.pool
    agent_repo: AgentRepo = request.app.state.agent_repo
    valkey = getattr(request.app.state, "valkey", None)
    agent_lifecycle: AgentLifecycle = getattr(
        request.app.state, "agent_lifecycle", None
    ) or AgentLifecycle(pool, agent_repo, valkey=valkey)

    # Input validation
    try:
        rate_limit_max = parse_int_field(
            form.get("rate_limit_max", 100), "rate_limit_max", min_val=1
        )
        daily_quota_max = parse_int_field(
            form.get("daily_quota_max", 10_000), "daily_quota_max", min_val=1
        )
        if not external_id or not name:
            raise ValueError("external_id and name are required fields.")

        cmd = CreateAgentCommand(
            external_id=external_id,
            name=name,
            currency=currency,
            rate_limit_max=rate_limit_max,
            daily_quota_max=daily_quota_max,
        )
        created = await agent_lifecycle.create_agent(cmd)
    except ValueError as exc:
        # Re-render agents list with form error banner (200 with error message)
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, external_id, name, active, created_at
                FROM agents
                ORDER BY created_at DESC;
                """
            )
        context = {
            "request": request,
            "agents": rows,
            "error_message": str(exc),
            "principal": principal,
            "csrf_token": getattr(request.state, "csrf_token", ""),
        }
        return templates.TemplateResponse(request, "agents.html", context, status_code=200)

    # Audit record: absence law strictly enforced (NO secret in audit)
    async with UnitOfWork(pool) as uow:
        await audit.record(
            uow.connection,
            actor_sub=principal.sub,
            actor_role=principal.role,
            action="agent.create",
            target_type="agent",
            target_id=str(created.agent_id),
            details={"external_id": created.external_id, "currency": cmd.currency},
        )

    context = {
        "request": request,
        "kind": "agent",
        "secret": created.secret,
        "agent_id": str(created.agent_id),
        "external_id": created.external_id,
        "name": name,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(
        request,
        "created.html",
        context,
        status_code=200,
        headers=build_no_store_headers(),
    )


# =============================================================================
# 3. AGENT LIMITS POLICY (PRG PATTERN)
# =============================================================================


@router.get("/agents/{agent_id}/limits", response_class=HTMLResponse)
async def get_agent_limits_page(agent_id: UUID, request: Request) -> HTMLResponse:
    """Screen: Edit and view agent financial policy limits."""
    principal = _get_principal(request)
    pool: asyncpg.Pool = request.app.state.pool
    limits_repo: LimitRepo = getattr(request.app.state, "limits", None) or LimitRepo(pool)

    async with pool.acquire() as conn:
        agent_row = await conn.fetchrow(
            "SELECT id, external_id, name, active, created_at FROM agents WHERE id = $1;",
            agent_id,
        )

    if agent_row is None:
        raise HTTPException(status_code=404, detail="Agent not found.")

    limits = await limits_repo.get(agent_id)

    context = {
        "request": request,
        "agent": agent_row,
        "limits": limits,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "limits.html", context)


@router.post("/agents/{agent_id}/limits", response_class=HTMLResponse)
async def post_agent_limits(agent_id: UUID, request: Request) -> Response:
    """Update agent policy limits with PRG pattern (303 Redirect) and audit recording."""
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    pool: asyncpg.Pool = request.app.state.pool
    limits_repo: LimitRepo = getattr(request.app.state, "limits", None) or LimitRepo(pool)

    async with pool.acquire() as conn:
        agent_row = await conn.fetchrow(
            "SELECT id, external_id, name, active, created_at FROM agents WHERE id = $1;",
            agent_id,
        )

    if agent_row is None:
        raise HTTPException(status_code=404, detail="Agent not found.")

    form = await request.form()
    parsed_limits, error_msg = parse_limits_form(form)

    if error_msg or parsed_limits is None:
        current_limits = await limits_repo.get(agent_id)
        context = {
            "request": request,
            "agent": agent_row,
            "limits": current_limits,
            "error_message": error_msg or "Invalid limits input.",
            "principal": principal,
            "csrf_token": getattr(request.state, "csrf_token", ""),
        }
        return templates.TemplateResponse(request, "limits.html", context, status_code=200)

    try:
        await limits_repo.upsert(agent_id, parsed_limits)
    except ValueError as exc:
        current_limits = await limits_repo.get(agent_id)
        context = {
            "request": request,
            "agent": agent_row,
            "limits": current_limits,
            "error_message": str(exc),
            "principal": principal,
            "csrf_token": getattr(request.state, "csrf_token", ""),
        }
        return templates.TemplateResponse(request, "limits.html", context, status_code=200)

    async with UnitOfWork(pool) as uow:
        await audit.record(
            uow.connection,
            actor_sub=principal.sub,
            actor_role=principal.role,
            action="limits.update",
            target_type="agent",
            target_id=str(agent_id),
            details={
                "velocity_limit": parsed_limits.velocity_limit,
                "velocity_window_s": parsed_limits.velocity_window_s,
                "max_single_tx_minor": parsed_limits.max_single_tx_minor,
                "daily_outflow_cap_minor": parsed_limits.daily_outflow_cap_minor,
            },
        )

    # WHY 303 Redirect (PRG Pattern):
    # Post-Redirect-Get is the web's oldest form hardening. It converts POST mutations
    # into idempotent GETs, preventing browser refresh re-submissions and ensuring
    # seamless compatibility with both standard browsers and htmx swaps.
    redirect_url = f"/dashboard/agents/{agent_id}/limits"
    return RedirectResponse(
        url=redirect_url,
        status_code=303,
        headers={"HX-Redirect": redirect_url},
    )


# =============================================================================
# 4. AGENT SUSPENSION & ACTIVATION
# =============================================================================


@router.post("/agents/{agent_id}/suspend", response_class=HTMLResponse)
async def post_suspend_agent(agent_id: UUID, request: Request) -> Response:
    """Suspend an active agent with cache invalidation and audit recording."""
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    pool: asyncpg.Pool = request.app.state.pool
    agent_repo: AgentRepo = request.app.state.agent_repo
    valkey = getattr(request.app.state, "valkey", None)
    agent_lifecycle: AgentLifecycle = getattr(
        request.app.state, "agent_lifecycle", None
    ) or AgentLifecycle(pool, agent_repo, valkey=valkey)

    suspended = await agent_lifecycle.suspend_agent(agent_id)

    audit_details: dict[str, str | int | bool | None] = (
        {"already_suspended": True} if not suspended else {}
    )
    async with UnitOfWork(pool) as uow:
        await audit.record(
            uow.connection,
            actor_sub=principal.sub,
            actor_role=principal.role,
            action="agent.suspend",
            target_type="agent",
            target_id=str(agent_id),
            details=audit_details,
        )

    redirect_url = "/dashboard/agents"
    return RedirectResponse(
        url=redirect_url,
        status_code=303,
        headers={"HX-Redirect": redirect_url},
    )


@router.post("/agents/{agent_id}/activate", response_class=HTMLResponse)
async def post_activate_agent(agent_id: UUID, request: Request) -> Response:
    """Activate a suspended agent with cache invalidation and audit recording."""
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    pool: asyncpg.Pool = request.app.state.pool
    agent_repo: AgentRepo = request.app.state.agent_repo
    valkey = getattr(request.app.state, "valkey", None)
    agent_lifecycle: AgentLifecycle = getattr(
        request.app.state, "agent_lifecycle", None
    ) or AgentLifecycle(pool, agent_repo, valkey=valkey)

    activated = await agent_lifecycle.activate_agent(agent_id)

    audit_details: dict[str, str | int | bool | None] = (
        {"already_active": True} if not activated else {}
    )
    async with UnitOfWork(pool) as uow:
        await audit.record(
            uow.connection,
            actor_sub=principal.sub,
            actor_role=principal.role,
            action="agent.activate",
            target_type="agent",
            target_id=str(agent_id),
            details=audit_details,
        )

    redirect_url = "/dashboard/agents"
    return RedirectResponse(
        url=redirect_url,
        status_code=303,
        headers={"HX-Redirect": redirect_url},
    )


# =============================================================================
# 5. MERCHANTS MANAGEMENT
# =============================================================================


@router.get("/merchants", response_class=HTMLResponse)
async def list_merchants(request: Request) -> HTMLResponse:
    """List registered merchants with status and link to webhook destinations."""
    principal = _get_principal(request)
    pool: asyncpg.Pool = request.app.state.pool

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, external_id, name, active, created_at
            FROM merchants
            ORDER BY created_at DESC;
            """
        )

    context = {
        "request": request,
        "merchants": rows,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "merchants.html", context)


@router.post("/merchants", response_class=HTMLResponse)
async def post_dashboard_merchant(request: Request) -> Response:
    """Provision a new merchant and settlement ledger account."""
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    form = await request.form()
    external_id = str(form.get("external_id", "")).strip()
    name = str(form.get("name", "")).strip()
    currency = str(form.get("currency", "USDC")).strip().upper()

    pool: asyncpg.Pool = request.app.state.pool
    merchant_lifecycle: MerchantLifecycle | None = getattr(
        request.app.state, "merchant_lifecycle", None
    )
    if merchant_lifecycle is None:
        valkey = getattr(request.app.state, "valkey", None)
        merchant_repo = MerchantRepo(pool, valkey)  # type: ignore[arg-type]
        merchant_lifecycle = MerchantLifecycle(pool, merchant_repo, valkey=valkey)

    try:
        if not external_id:
            raise ValueError("external_id is required.")
        cmd = CreateMerchantCommand(external_id=external_id, name=name, currency=currency)
        created = await merchant_lifecycle.create_merchant(cmd)
    except ValueError as exc:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, external_id, name, active, created_at
                FROM merchants
                ORDER BY created_at DESC;
                """
            )
        context = {
            "request": request,
            "merchants": rows,
            "error_message": str(exc),
            "principal": principal,
            "csrf_token": getattr(request.state, "csrf_token", ""),
        }
        return templates.TemplateResponse(request, "merchants.html", context, status_code=200)

    async with UnitOfWork(pool) as uow:
        await audit.record(
            uow.connection,
            actor_sub=principal.sub,
            actor_role=principal.role,
            action="merchant.create",
            target_type="merchant",
            target_id=str(created.merchant_id),
            details={"external_id": created.external_id},
        )

    redirect_url = "/dashboard/merchants"
    return RedirectResponse(
        url=redirect_url,
        status_code=303,
        headers={"HX-Redirect": redirect_url},
    )


@router.post("/merchants/{external_id}/suspend", response_class=HTMLResponse)
async def post_suspend_merchant(external_id: str, request: Request) -> Response:
    """Suspend a merchant by external_id handle."""
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    pool: asyncpg.Pool = request.app.state.pool
    merchant_lifecycle: MerchantLifecycle | None = getattr(
        request.app.state, "merchant_lifecycle", None
    )
    if merchant_lifecycle is None:
        valkey = getattr(request.app.state, "valkey", None)
        merchant_repo = MerchantRepo(pool, valkey)  # type: ignore[arg-type]
        merchant_lifecycle = MerchantLifecycle(pool, merchant_repo, valkey=valkey)

    suspended = await merchant_lifecycle.suspend_merchant(external_id)

    audit_details: dict[str, str | int | bool | None] = (
        {"already_suspended": True} if not suspended else {}
    )
    async with UnitOfWork(pool) as uow:
        await audit.record(
            uow.connection,
            actor_sub=principal.sub,
            actor_role=principal.role,
            action="merchant.suspend",
            target_type="merchant",
            target_id=external_id,
            details=audit_details,
        )

    redirect_url = "/dashboard/merchants"
    return RedirectResponse(
        url=redirect_url,
        status_code=303,
        headers={"HX-Redirect": redirect_url},
    )


# =============================================================================
# 6. WEBHOOK ENDPOINT MANAGEMENT
# =============================================================================


@router.get("/merchants/{merchant_id}/webhooks", response_class=HTMLResponse)
async def list_merchant_webhooks(merchant_id: UUID, request: Request) -> HTMLResponse:
    """List configured HTTPS notification endpoints for a merchant."""
    principal = _get_principal(request)
    pool: asyncpg.Pool = request.app.state.pool

    async with pool.acquire() as conn:
        merchant = await conn.fetchrow(
            "SELECT id, external_id, name FROM merchants WHERE id = $1;", merchant_id
        )
        if merchant is None:
            raise HTTPException(status_code=404, detail="Merchant not found.")
        endpoints = await conn.fetch(
            """
            SELECT id, merchant_id, url, active, created_at
            FROM webhook_endpoints
            WHERE merchant_id = $1
            ORDER BY created_at DESC;
            """,
            merchant_id,
        )

    context = {
        "request": request,
        "merchant": merchant,
        "endpoints": endpoints,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "webhooks.html", context)


@router.post("/merchants/{merchant_id}/webhooks", response_class=HTMLResponse)
async def post_dashboard_webhook(merchant_id: UUID, request: Request) -> Response:
    """Create a new webhook destination with one-time secret emission.

    Direct SQL Insertion Deviation:
    Task 38 defined webhook_endpoints schema without a domain repository.
    We write directly to SQL with AES-256-GCM vault envelope encryption bound
    to AAD "webhook_secret:<endpoint_id>". Phase 2 refactors to NotificationRepo.
    """
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    pool: asyncpg.Pool = request.app.state.pool

    async with pool.acquire() as conn:
        merchant = await conn.fetchrow(
            "SELECT id, external_id, name FROM merchants WHERE id = $1;", merchant_id
        )
    if merchant is None:
        raise HTTPException(status_code=404, detail="Merchant not found.")

    form = await request.form()
    url = str(form.get("url", "")).strip()

    # Task 38 HTTPS-only law matching DB check constraint ^https://[A-Za-z0-9]
    if not _HTTPS_URL_RE.match(url):
        async with pool.acquire() as conn:
            endpoints = await conn.fetch(
                """
                SELECT id, merchant_id, url, active, created_at
                FROM webhook_endpoints
                WHERE merchant_id = $1
                ORDER BY created_at DESC;
                """,
                merchant_id,
            )
        context = {
            "request": request,
            "merchant": merchant,
            "endpoints": endpoints,
            "error_message": (
                "Invalid webhook URL: Must be a valid HTTPS URL (e.g. https://example.com/webhook)."
            ),
            "principal": principal,
            "csrf_token": getattr(request.state, "csrf_token", ""),
        }
        return templates.TemplateResponse(request, "webhooks.html", context, status_code=200)

    endpoint_id = uuid.uuid4()
    secret_hex = os.urandom(32).hex()
    context_aad = webhook_secret_context(endpoint_id)
    secret_encrypted = encrypt_secret(secret_hex, context=context_aad)

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
        async with pool.acquire() as conn:
            endpoints = await conn.fetch(
                """
                SELECT id, merchant_id, url, active, created_at
                FROM webhook_endpoints
                WHERE merchant_id = $1
                ORDER BY created_at DESC;
                """,
                merchant_id,
            )
        context = {
            "request": request,
            "merchant": merchant,
            "endpoints": endpoints,
            "error_message": f"Webhook registration failed: {exc}",
            "principal": principal,
            "csrf_token": getattr(request.state, "csrf_token", ""),
        }
        return templates.TemplateResponse(request, "webhooks.html", context, status_code=200)

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

    created_context = {
        "request": request,
        "kind": "webhook",
        "secret": secret_hex,
        "endpoint_id": str(endpoint_id),
        "url": url,
        "merchant": merchant,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(
        request,
        "created.html",
        created_context,
        status_code=200,
        headers=build_no_store_headers(),
    )


# =============================================================================
# 7. HOLDS OPERATIONS PANEL & DUAL-AUTHORIZATION VOTING
# =============================================================================


@router.get("/holds", response_class=HTMLResponse)
async def list_holds_page(request: Request) -> HTMLResponse:
    """Operations panel: Review payments held in HITL quarantine queue."""
    principal = _get_principal(request)
    pool: asyncpg.Pool = request.app.state.pool
    quarantine: QuarantineService = getattr(
        request.app.state, "quarantine", None
    ) or QuarantineService(pool)

    holds = await quarantine.list_pending(limit=50)

    # Enrich holds with agent external_id if possible
    async with pool.acquire() as conn:
        agents = {
            row["id"]: row["external_id"]
            for row in await conn.fetch("SELECT id, external_id FROM agents;")
        }

    holds_data = [
        {
            "hold_id": h.hold_id,
            "agent_id": h.agent_id,
            "agent_external_id": agents.get(h.agent_id, str(h.agent_id)),
            "idem_key": h.idem_key,
            "amount_minor": h.amount_minor,
            "currency": h.currency,
            "reason": h.reason,
            "status": h.status,
            "created_at": h.created_at,
        }
        for h in holds
    ]

    context = {
        "request": request,
        "holds": holds_data,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "holds.html", context)


@router.post("/holds/{hold_id}/vote", response_class=HTMLResponse)
async def post_hold_vote(hold_id: UUID, request: Request) -> Response:
    """Submit approval or rejection vote on a held payment.

    Enforces:
    - Admin-only role check (support rejected with 403 page).
    - ApprovalService 2-man quorum rule.
    - HTMX row swap response or PRG redirect.
    """
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    form = await request.form()
    vote = str(form.get("vote", "")).strip().lower()
    note = str(form.get("note", "")).strip()

    if vote not in ("approve", "reject"):
        return _render_error_response(
            request,
            status_code=400,
            title="Bad Request",
            message="Vote must be 'approve' or 'reject'.",
        )

    approval_service = getattr(request.app.state, "approval_service", None)
    if approval_service is None:
        from fluxpay.approvals.service import ApprovalService

        pool = request.app.state.pool
        bus = request.app.state.bus
        payments = getattr(request.app.state, "payments", None)
        approval_service = ApprovalService(pool=pool, bus=bus, payments=payments)
        request.app.state.approval_service = approval_service

    outcome = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=principal.sub,
        voter_role=principal.role,
        vote=vote,
        note=note,
    )

    is_hx = request.headers.get("hx-request", "").lower() == "true"
    if is_hx:
        # Return table row fragment for seamless htmx inline swap
        row_html = f"""
        <tr id="hold-row-{hold_id}" class="voted-row">
            <td><code>{hold_id}</code></td>
            <td colspan="4">Vote recorded: <strong>{vote.upper()}</strong></td>
            <td>
                <span class="badge badge-credit">{outcome.status}</span>
                <span class="card-subtext">
                    (for: {outcome.votes_for}, against: {outcome.votes_against})
                </span>
            </td>
            <td>Decided</td>
        </tr>
        """
        return HTMLResponse(content=row_html, status_code=200)

    redirect_url = "/dashboard/holds"
    return RedirectResponse(
        url=redirect_url,
        status_code=303,
        headers={"HX-Redirect": redirect_url},
    )


# =============================================================================
# 8. KYC REVIEW & DECISION PANEL
# =============================================================================


@router.get("/kyc", response_class=HTMLResponse)
async def list_kyc_page(request: Request) -> HTMLResponse:
    """Operations panel: Review pending merchant KYC verification requests."""
    principal = _get_principal(request)
    pool: asyncpg.Pool = request.app.state.pool

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT k.id, k.subject_type, k.subject_id, k.status, k.provider,
                   k.provider_ref, k.notes, k.created_at,
                   m.external_id as merchant_handle, m.name as merchant_name
            FROM kyc_requests k
            JOIN merchants m ON k.subject_id = m.id
            WHERE k.status = 'pending'
            ORDER BY k.created_at ASC;
            """
        )

    context = {
        "request": request,
        "kyc_requests": rows,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "kyc.html", context)


@router.post("/kyc/{kyc_id}/decide", response_class=HTMLResponse)
async def post_kyc_decision(kyc_id: UUID, request: Request) -> Response:
    """Atomically decide a pending KYC request with double-decide guard and audit."""
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    form = await request.form()
    decision = str(form.get("decision", "")).strip().lower()
    raw_notes = form.get("notes", "")
    clean_notes = str(raw_notes).strip() if raw_notes is not None else ""

    if decision not in ("approved", "rejected"):
        return _render_error_response(
            request,
            status_code=400,
            title="Bad Request",
            message="Decision must be 'approved' or 'rejected'.",
        )

    pool: asyncpg.Pool = request.app.state.pool

    async with UnitOfWork(pool) as uow:
        row = await uow.connection.fetchrow(
            """
            UPDATE kyc_requests
            SET status = $1,
                decided_by = (SELECT id FROM users WHERE keycloak_sub = $2),
                decided_at = now(),
                notes = CASE WHEN $3 <> '' THEN $3 ELSE notes END,
                updated_at = now()
            WHERE id = $4 AND status = 'pending'
            RETURNING id, status, decided_by, decided_at;
            """,
            decision,
            principal.sub,
            clean_notes,
            kyc_id,
        )

        # Double-decide guard: 0 rows returned indicates already decided or missing
        if row is None:
            async with pool.acquire() as conn:
                pending_rows = await conn.fetch(
                    """
                    SELECT k.id, k.subject_type, k.subject_id, k.status, k.provider,
                           k.provider_ref, k.notes, k.created_at,
                           m.external_id as merchant_handle, m.name as merchant_name
                    FROM kyc_requests k
                    JOIN merchants m ON k.subject_id = m.id
                    WHERE k.status = 'pending'
                    ORDER BY k.created_at ASC;
                    """
                )
            context = {
                "request": request,
                "kyc_requests": pending_rows,
                "error_message": "KYC request not found or already decided.",
                "principal": principal,
                "csrf_token": getattr(request.state, "csrf_token", ""),
            }
            return templates.TemplateResponse(request, "kyc.html", context, status_code=200)

        # Audit recording with PII truncation
        audit_details: dict[str, str | int | bool | None] = {
            "decision": decision,
            "notes_len": len(clean_notes),
            "notes": clean_notes[:200],
        }
        await audit.record(
            uow.connection,
            actor_sub=principal.sub,
            actor_role=principal.role,
            action="kyc.decide",
            target_type="kyc",
            target_id=str(kyc_id),
            details=audit_details,
        )

    redirect_url = "/dashboard/kyc"
    return RedirectResponse(
        url=redirect_url,
        status_code=303,
        headers={"HX-Redirect": redirect_url},
    )


# =============================================================================
# 9. FORENSIC AUDIT TRAIL VIEW
# =============================================================================


@router.get("/audit", response_class=HTMLResponse)
async def get_audit_trail_page(request: Request) -> HTMLResponse:
    """Operations panel: View forensic audit log entries newest-first.

    Allowed roles: admin, support (Separation of Duties).
    """
    principal = _get_principal(request)
    pool: asyncpg.Pool = request.app.state.pool

    actions = await audit.read_recent(pool, limit=50)

    context = {
        "request": request,
        "actions": actions,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "audit.html", context)


# =============================================================================
# 10. TREASURY GOVERNANCE PANEL (STRICTLY READ-ONLY)
# =============================================================================


@router.get("/treasury", response_class=HTMLResponse)
async def get_treasury_page(request: Request) -> Response:
    """Institutional Treasury panel: hot/cold balances, drift, in-flight payouts.

    Architectural Law:
    STRICTLY READ-ONLY ON WEB. Treasury payouts require two-person cryptographic
    authorization executed exclusively through the operator CLI:
        python -m fluxpay.treasury.cli vote --payout-id <id> --vote approve
    """
    try:
        principal = _require_admin(request)
    except ForbiddenError as exc:
        return _render_error_response(
            request, status_code=403, title="Forbidden", message=exc.message
        )

    pool: asyncpg.Pool = request.app.state.pool

    # 1. Query wallet_state row
    async with pool.acquire() as conn:
        wallet_state_row = await conn.fetchrow(
            """
            SELECT rail, hot_balance_minor, cold_balance_minor, target_hot_minor,
                   min_hot_minor, max_hot_minor, last_synced_at, sync_status
            FROM wallet_state
            WHERE rail = 'base_usdc';
            """
        )

        # 2. Query open cold payouts
        open_payouts_rows = await conn.fetch(
            """
            SELECT cp.*,
                   COALESCE(SUM(CASE WHEN pa.vote = 'approve' THEN 1 ELSE 0 END), 0) AS votes_for,
                   COALESCE(SUM(CASE WHEN pa.vote = 'reject' THEN 1 ELSE 0 END), 0) AS votes_against
            FROM cold_payouts cp
            LEFT JOIN payout_approvals pa ON cp.payout_id = pa.payout_id
            WHERE cp.status IN ('requested', 'approved')
            GROUP BY cp.payout_id
            ORDER BY cp.created_at ASC;
            """
        )

    # 3. Capture custody snapshot if wallet_state is provisioned
    snapshot = None
    if wallet_state_row is not None:
        reader = getattr(request.app.state, "treasury_reader", None) or FakeReader(
            hot=int(wallet_state_row["hot_balance_minor"]),
            cold=int(wallet_state_row["cold_balance_minor"]),
        )
        try:
            snapshot = await custody_snapshot(pool=pool, reader=reader, rail="base_usdc")
        except Exception:
            snapshot = None

    context = {
        "request": request,
        "wallet_state": wallet_state_row,
        "payouts": open_payouts_rows,
        "snapshot": snapshot,
        "principal": principal,
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "treasury.html", context)
