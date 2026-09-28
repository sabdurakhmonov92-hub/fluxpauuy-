"""Administrative plane HTTP routing and mutation coordination.

Blueprint §4 Admin Plane & §5 System Audit Service.

=============================================================================
ADMIN PLANE CONTRACT & ARCHITECTURAL DECISIONS (WHY THE SYSTEM IS BUILT THIS WAY)
=============================================================================

1. WHY PLAIN DICTS WITH STABLE KEYS (NOT TASK 24 SCHEMAS):
----------------------------------------------------------
The Task 24 contract and Pydantic schemas (PaymentRequest, PaymentResponse, BalanceResponse)
are strictly frozen for machine agents on the public API wire. Admin responses are operator
and dashboard surfaces. Admin responses return plain dictionaries with stable, documented keys
rather than adding bloat to the public agent schema contract.

2. WHY OPENAPI EXCLUSION (include_in_schema=False in Task 33):
--------------------------------------------------------------
The merchant-facing OpenAPI documentation describes the autonomous agent payment platform.
Exposing internal administrative mutations (agent provisioning, suspension, KYC approvals)
in the public merchant schema would create cognitive noise and expose internal infrastructure
topography. In Task 33 composition, admin routes are mounted with include_in_schema=False.

3. WHY SEPARATION OF DUTIES (SUPPORT READ-ONLY VS ADMIN MUTATION):
------------------------------------------------------------------
Support operators require visibility into system state, agent metadata, and forensic audit
logs to assist merchants and debug reconciliation issues. However, support operators MUST NOT
possess the ability to mint credentials, suspend entities, or approve KYC requests. Mutators
are strictly admin-only; read routes permit both admin and support principals.

4. WHY AUDIT-IN-THE-SAME-TRANSACTION (ATOMICTY GUARANTEE):
-----------------------------------------------------------
Every mutation commits WITH an audit row. For direct operations like KYC decisions, the
UPDATE and audit.record execute on the exact same UnitOfWork connection. For lifecycle
services, domain validation failures or unique constraint collisions abort BEFORE audit
recording, guaranteeing an audit row is never committed for a failed mutation.

5. PII TRUNCATION POLICY:
-------------------------
Compliance review notes may contain unredacted personal information (SSNs, passport numbers).
Audit details truncate notes to 200 characters and record `notes_len` for SIEM indexing,
preventing unchecked PII accumulation in operational log sinks.

6. ONE-TIME SECRET CUSTODY WARNING:
-----------------------------------
Agent API secrets are returned in plaintext EXACTLY ONCE upon creation. FluxPay stores secrets
encrypted under AES-256-GCM vault envelopes and never retains plaintext. Downstream callers
must securely custody secrets immediately.
"""

from __future__ import annotations

import uuid

import asyncpg  # type: ignore[import-untyped]
import orjson
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, Router

from fluxpay.admin.keycloak import AdminPrincipal
from fluxpay.audit import audit
from fluxpay.registry.agents import (
    AgentLifecycle,
    CreateAgentCommand,
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.registry.repo import AgentRecord, AgentRepo
from fluxpay.shared.errors import ForbiddenError, NotFoundError, ValidationError
from fluxpay.shared.uow import UnitOfWork

__all__ = [
    "create_admin_router",
    "create_admin_routes",
]


def _require_role(principal: AdminPrincipal | None, allowed_roles: set[str]) -> AdminPrincipal:
    """Enforce principal role membership or raise ForbiddenError (403)."""
    if principal is None or principal.role not in allowed_roles:
        raise ForbiddenError(message="insufficient permissions")
    return principal


def create_admin_routes(
    *,
    pool: asyncpg.Pool,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    agent_repo: AgentRepo,
    prefix: str = "/admin",
) -> list[Route]:
    """Build list of Starlette Routes for the admin plane."""

    async def post_agents(request: Request) -> Response:
        """Provision a new agent identity and initial ledger account.

        Response: 201 Created {"id", "external_id", "secret"}
        WARNING: Plaintext secret is emitted once and never recoverable.
        """
        principal = _require_role(getattr(request.state, "principal", None), {"admin"})

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

        external_id = data.get("external_id")
        name = data.get("name")
        currency = data.get("currency", "USDC")
        rate_limit_max = data.get("rate_limit_max", 100)
        daily_quota_max = data.get("daily_quota_max", 10_000)

        if not external_id or not isinstance(external_id, str):
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "external_id", "reason": "missing_or_invalid"},
            )
        if not isinstance(name, str):
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "name", "reason": "missing_or_invalid"},
            )

        try:
            cmd = CreateAgentCommand(
                external_id=external_id,
                name=name,
                currency=currency,
                rate_limit_max=rate_limit_max,
                daily_quota_max=daily_quota_max,
            )
            created = await agent_lifecycle.create_agent(cmd)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"reason": str(exc)},
            ) from exc

        # Audit recording: absence law strictly enforced (NO secret in audit details)
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

        return JSONResponse(
            {
                "id": str(created.agent_id),
                "external_id": created.external_id,
                "secret": created.secret,
            },
            status_code=201,
        )

    async def post_merchants(request: Request) -> Response:
        """Provision a new merchant identity and settlement ledger account.

        Response: 201 Created {"id", "external_id"}
        """
        principal = _require_role(getattr(request.state, "principal", None), {"admin"})

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

        external_id = data.get("external_id")
        name = data.get("name", "")
        currency = data.get("currency", "USDC")

        if not external_id or not isinstance(external_id, str):
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "external_id", "reason": "missing_or_invalid"},
            )

        try:
            cmd = CreateMerchantCommand(
                external_id=external_id,
                name=name,
                currency=currency,
            )
            created = await merchant_lifecycle.create_merchant(cmd)
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
                action="merchant.create",
                target_type="merchant",
                target_id=str(created.merchant_id),
                details={"external_id": created.external_id},
            )

        return JSONResponse(
            {
                "id": str(created.merchant_id),
                "external_id": created.external_id,
            },
            status_code=201,
        )

    async def suspend_agent(request: Request) -> Response:
        """Suspend an agent by UUID.

        Idempotent: returns {"suspended": bool} and audits even if already suspended.
        """
        principal = _require_role(getattr(request.state, "principal", None), {"admin"})

        id_str = request.path_params.get("id", "")
        try:
            agent_id = uuid.UUID(id_str)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "id", "reason": "invalid_uuid"},
            ) from exc

        suspended = await agent_lifecycle.suspend_agent(agent_id)

        # WHY audit no-op: silence would hide repeated suspension retries or reconciliation sweeps
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

        return JSONResponse({"suspended": bool(suspended)}, status_code=200)

    async def activate_agent(request: Request) -> Response:
        """Activate a suspended agent by UUID.

        Idempotent: returns {"activated": bool} and audits action.
        """
        principal = _require_role(getattr(request.state, "principal", None), {"admin"})

        id_str = request.path_params.get("id", "")
        try:
            agent_id = uuid.UUID(id_str)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "id", "reason": "invalid_uuid"},
            ) from exc

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

        return JSONResponse({"activated": bool(activated)}, status_code=200)

    async def suspend_merchant(request: Request) -> Response:
        """Suspend a merchant by external_id handle.

        Idempotent: returns {"suspended": bool} and audits action.
        """
        principal = _require_role(getattr(request.state, "principal", None), {"admin"})

        external_id = request.path_params.get("external_id", "")
        if not external_id:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "external_id", "reason": "missing"},
            )

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

        return JSONResponse({"suspended": bool(suspended)}, status_code=200)

    async def decide_kyc(request: Request) -> Response:
        """Decide a pending KYC request (approve or reject) atomically.

        Enforces double-decide protection and records audit row with PII-truncated notes.
        """
        principal = _require_role(getattr(request.state, "principal", None), {"admin"})

        id_str = request.path_params.get("kyc_id", "")
        try:
            kyc_id = uuid.UUID(id_str)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "kyc_id", "reason": "invalid_uuid"},
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

        decision = data.get("decision")
        if decision not in ("approved", "rejected"):
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "decision", "reason": "must be 'approved' or 'rejected'"},
            )

        raw_notes = data.get("notes", "")
        clean_notes = raw_notes.strip() if isinstance(raw_notes, str) else ""

        # Atomic state transition + audit row in ONE transaction
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

            # Double-decide guard: 0 rows returned indicates request already decided or missing
            if row is None:
                raise NotFoundError(message="KYC request not found or already decided.")

            # PII Policy: compliance notes may contain unredacted personal identity data.
            # Store length and notes truncated to 200 characters for SIEM operational context.
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

        return JSONResponse({"id": str(kyc_id), "status": decision}, status_code=200)

    async def get_audit(request: Request) -> Response:
        """Query recent system audit logs with optional filtering and limits.

        Allowed roles: admin, support (separation of duties: support operators can audit).
        """
        principal: AdminPrincipal | None = getattr(request.state, "principal", None)
        _require_role(principal, {"admin", "support"})

        limit_raw = request.query_params.get("limit", "50")
        try:
            limit = int(limit_raw)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "limit", "reason": "integer_required"},
            ) from exc

        target_type = request.query_params.get("target_type")
        target_id = request.query_params.get("target_id")

        try:
            actions = await audit.read_recent(
                pool,
                limit=limit,
                target_type=target_type,
                target_id=target_id,
            )
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"reason": str(exc)},
            ) from exc

        payload = [
            {
                "action": a.action,
                "target_type": a.target_type,
                "target_id": a.target_id,
                "details": a.details,
                "occurred_at": a.occurred_at.isoformat(),
                "actor_sub": a.actor_sub,
                "actor_role": a.actor_role,
            }
            for a in actions
        ]
        return JSONResponse(payload, status_code=200)

    async def get_agent(request: Request) -> Response:
        """Fetch agent record by UUID without exposing encrypted secrets.

        Allowed roles: admin, support.
        """
        _require_role(getattr(request.state, "principal", None), {"admin", "support"})

        id_str = request.path_params.get("id", "")
        try:
            agent_id = uuid.UUID(id_str)
        except ValueError as exc:
            raise ValidationError(
                message="Request payload failed validation.",
                details={"field": "id", "reason": "invalid_uuid"},
            ) from exc

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, external_id, name, active, rate_limit_max,
                       daily_quota_max, version, created_at, updated_at
                FROM agents
                WHERE id = $1;
                """,
                agent_id,
            )

        if row is None:
            raise NotFoundError(message="The requested resource was not found.")

        record = AgentRecord(
            id=row["id"],
            external_id=row["external_id"],
            name=row["name"],
            active=row["active"],
            rate_limit_max=row["rate_limit_max"],
            daily_quota_max=row["daily_quota_max"],
            version=row["version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

        # AgentRecord custody holds: no secret is present in AgentRecord
        payload = {
            "id": str(record.id),
            "external_id": record.external_id,
            "name": record.name,
            "rate_limit_max": record.rate_limit_max,
            "daily_quota_max": record.daily_quota_max,
            "active": record.active,
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }
        return JSONResponse(payload, status_code=200)

    clean_prefix = prefix.rstrip("/")
    return [
        Route(f"{clean_prefix}/agents", endpoint=post_agents, methods=["POST"]),
        Route(f"{clean_prefix}/merchants", endpoint=post_merchants, methods=["POST"]),
        Route(f"{clean_prefix}/agents/{{id}}/suspend", endpoint=suspend_agent, methods=["POST"]),
        Route(f"{clean_prefix}/agents/{{id}}/activate", endpoint=activate_agent, methods=["POST"]),
        Route(
            f"{clean_prefix}/merchants/{{external_id}}/suspend",
            endpoint=suspend_merchant,
            methods=["POST"],
        ),
        Route(f"{clean_prefix}/kyc/{{kyc_id}}/decide", endpoint=decide_kyc, methods=["POST"]),
        Route(f"{clean_prefix}/audit", endpoint=get_audit, methods=["GET"]),
        Route(f"{clean_prefix}/agents/{{id}}", endpoint=get_agent, methods=["GET"]),
    ]


def create_admin_router(
    *,
    pool: asyncpg.Pool,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    agent_repo: AgentRepo,
    prefix: str = "/admin",
) -> Router:
    """Instantiate a Starlette Router configured with admin plane routes."""
    routes = create_admin_routes(
        pool=pool,
        agent_lifecycle=agent_lifecycle,
        merchant_lifecycle=merchant_lifecycle,
        agent_repo=agent_repo,
        prefix=prefix,
    )
    return Router(routes=routes)
