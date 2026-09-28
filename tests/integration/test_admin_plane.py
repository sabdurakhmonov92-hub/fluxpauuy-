"""Integration tests for FluxPay Admin Plane (Task 29 - Block E Closure).

Tests exercise live PostgreSQL database, real lifecycle services, Starlette routing,
AdminAuthMiddleware, Keycloak JWT verification, defense-in-depth DB checks, and the
append-only audit log.
"""

from __future__ import annotations

import uuid
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest

from fluxpay.audit import audit
from fluxpay.contracts.schemas import ErrorEnvelope
from fluxpay.registry.users import UserRecord

pytestmark = pytest.mark.integration


# ------------------------------------------------------------------------------
# 1. AGENT PROVISIONING & AUDIT ABSENCE LAW
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_agent_over_http_provisions_resources_and_audits(
    db_pool: asyncpg.Pool,
    make_user: Any,
    build_admin_app: Any,
    delete_agent_cascade: Any,
) -> None:
    """Validate POST /admin/agents provisions agent, ledger account, and audit row atomically.

    Absence Law Test: Plaintext secret is in HTTP 201 response, but NEVER in audit_log.details.
    """
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=admin_user.keycloak_sub, role="admin")

    ext_id = f"ag_test_{uuid.uuid4().hex[:12]}"
    payload = {
        "external_id": ext_id,
        "name": "Autonomous Market Maker",
        "currency": "USDC",
        "rate_limit_max": 250,
        "daily_quota_max": 50_000,
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/admin/agents",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 201
    body = resp.json()
    assert "id" in body
    assert body["external_id"] == ext_id
    assert "secret" in body
    secret = body["secret"]
    assert len(secret) == 64  # 32 bytes hex-encoded = 64 hex characters

    agent_id = uuid.UUID(body["id"])

    # Teardown registration
    try:
        # 1. Verify agents row exists in PostgreSQL
        async with db_pool.acquire() as conn:
            agent_row = await conn.fetchrow(
                "SELECT id, external_id, active, rate_limit_max FROM agents WHERE id = $1;",
                agent_id,
            )
            assert agent_row is not None
            assert agent_row["external_id"] == ext_id
            assert agent_row["active"] is True
            assert agent_row["rate_limit_max"] == 250

            # 2. Verify ledger_accounts row exists (created atomically by lifecycle)
            account_row = await conn.fetchrow(
                """
                SELECT owner_type, owner_id, currency, balance
                FROM ledger_accounts
                WHERE owner_id = $1;
                """,
                agent_id,
            )
            assert account_row is not None
            assert account_row["owner_type"] == "agent"
            assert account_row["currency"] == "USDC"
            assert account_row["balance"] == 0

            # 3. Verify audit_log row exists with strict absence of plaintext secret
            audit_row = await conn.fetchrow(
                """
                SELECT actor_sub, actor_role, action, target_type, target_id, details
                FROM audit_log
                WHERE target_type = 'agent' AND target_id = $1
                ORDER BY occurred_at DESC LIMIT 1;
                """,
                str(agent_id),
            )
            assert audit_row is not None
            assert audit_row["actor_sub"] == admin_user.keycloak_sub
            assert audit_row["actor_role"] == "admin"
            assert audit_row["action"] == "agent.create"

            # Parse details JSONB
            import orjson

            details = audit_row["details"]
            if isinstance(details, str):
                details = orjson.loads(details)
            assert details["external_id"] == ext_id
            assert details["currency"] == "USDC"

            # CRITICAL ABSENCE TEST: Plaintext secret must NEVER be persisted in audit details
            assert "secret" not in details
            assert secret not in str(details)

    finally:
        await delete_agent_cascade(agent_id)


@pytest.mark.asyncio
async def test_create_agent_duplicate_external_id_returns_422_validation_failed(
    make_user: Any,
    build_admin_app: Any,
    delete_agent_cascade: Any,
) -> None:
    """Validate duplicate external_id is mapped to 422 validation_failed (Task 4 taxonomy)."""
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=admin_user.keycloak_sub, role="admin")

    ext_id = f"ag_dup_{uuid.uuid4().hex[:12]}"
    payload = {"external_id": ext_id, "name": "First Agent", "currency": "USDC"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # First creation succeeds (201)
        resp1 = await client.post(
            "/admin/agents",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp1.status_code == 201
        agent_id = uuid.UUID(resp1.json()["id"])

        try:
            # Second creation with identical external_id fails (422)
            resp2 = await client.post(
                "/admin/agents",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp2.status_code == 422
            envelope = ErrorEnvelope.model_validate(resp2.json())
            assert envelope.error.code == "validation_failed"
            assert envelope.error.retryable is False
        finally:
            await delete_agent_cascade(agent_id)


# ------------------------------------------------------------------------------
# 2. SUSPENSION, ACTIVATION & RETRY VISIBILITY PROOF
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_suspend_and_activate_with_retry_visibility(
    db_pool: asyncpg.Pool,
    make_user: Any,
    build_admin_app: Any,
    delete_agent_cascade: Any,
) -> None:
    """Prove suspension, idempotency auditing (already_suspended), and re-activation."""
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=admin_user.keycloak_sub, role="admin")

    ext_id = f"ag_susp_{uuid.uuid4().hex[:12]}"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Create agent
        resp = await client.post(
            "/admin/agents",
            json={"external_id": ext_id, "name": "Suspension Subject"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201
        agent_id_str = resp.json()["id"]
        agent_id = uuid.UUID(agent_id_str)

        try:
            # 1. First suspend -> returns {"suspended": true}
            s1 = await client.post(
                f"/admin/agents/{agent_id_str}/suspend",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert s1.status_code == 200
            assert s1.json() == {"suspended": True}

            # 2. Re-suspend idempotent no-op -> returns {"suspended": false}
            # AND still creates an audit row with already_suspended=True (retry-visibility proof)
            s2 = await client.post(
                f"/admin/agents/{agent_id_str}/suspend",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert s2.status_code == 200
            assert s2.json() == {"suspended": False}

            # Check audit rows for suspension attempts
            actions = await audit.read_recent(
                db_pool, limit=10, target_type="agent", target_id=agent_id_str
            )
            suspend_actions = [a for a in actions if a.action == "agent.suspend"]
            assert len(suspend_actions) == 2
            # Newest action is the retry with already_suspended=True
            assert suspend_actions[0].details.get("already_suspended") is True

            # 3. Activate agent -> returns {"activated": true}
            act = await client.post(
                f"/admin/agents/{agent_id_str}/activate",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert act.status_code == 200
            assert act.json() == {"activated": True}

            # Re-activate idempotent no-op -> returns {"activated": false}
            act2 = await client.post(
                f"/admin/agents/{agent_id_str}/activate",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert act2.status_code == 200
            assert act2.json() == {"activated": False}

        finally:
            await delete_agent_cascade(agent_id)


@pytest.mark.asyncio
async def test_suspend_merchant_workflow(
    db_pool: asyncpg.Pool,
    make_user: Any,
    make_merchant: Any,
    build_admin_app: Any,
    delete_merchant_cascade: Any,
) -> None:
    """Validate merchant suspension and audit trail."""
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=admin_user.keycloak_sub, role="admin")

    merchant = await make_merchant()
    merchant_id = merchant.id
    ext_id = merchant.external_id

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                f"/admin/merchants/{ext_id}/suspend",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            assert resp.json() == {"suspended": True}

            # Verify merchant is marked inactive in database
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT active FROM merchants WHERE external_id = $1;", ext_id
                )
                assert row is not None
                assert row["active"] is False

            # Verify audit trail
            actions = await audit.read_recent(
                db_pool, limit=5, target_type="merchant", target_id=ext_id
            )
            assert len(actions) >= 1
            assert actions[0].action == "merchant.suspend"
    finally:
        await delete_merchant_cascade(merchant_id)


# ------------------------------------------------------------------------------
# 3. DEFENSE-IN-DEPTH STALE-TOKEN DEFENSE (IdP YES, DB NO)
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stale_token_defense_user_not_in_database(
    build_admin_app: Any,
) -> None:
    """IdP says YES (valid token), DB says NO (user not found in users table) -> 403 Forbidden."""
    app, _, mint_token = build_admin_app()
    # Mint a valid cryptographic JWT for an unknown subject ID
    unknown_sub = str(uuid.uuid4())
    token = mint_token(sub=unknown_sub, role="admin")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/admin/agents",
            json={"external_id": "ag_rogue_sub", "name": "Rogue"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 403
    envelope = ErrorEnvelope.model_validate(resp.json())
    assert envelope.error.code == "forbidden"
    assert envelope.error.retryable is False


@pytest.mark.asyncio
async def test_stale_token_defense_user_deactivated_in_database(
    make_user: Any,
    build_admin_app: Any,
) -> None:
    """IdP says YES (valid token), DB says NO (active=False in users table) -> 403 Forbidden."""
    # Seed user with active = False (locally deactivated operator)
    inactive_user: UserRecord = await make_user(
        role="admin", active=False, keycloak_sub=str(uuid.uuid4())
    )
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=inactive_user.keycloak_sub, role="admin")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/admin/agents",
            json={"external_id": "ag_inactive_admin", "name": "Inactive"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 403
    envelope = ErrorEnvelope.model_validate(resp.json())
    assert envelope.error.code == "forbidden"
    assert envelope.error.retryable is False


# ------------------------------------------------------------------------------
# 4. SEPARATION OF DUTIES (SUPPORT ROLE PRIVILEGE BOUNDARIES)
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_separation_of_duties_support_can_read_cannot_mutate(
    make_user: Any,
    build_admin_app: Any,
) -> None:
    """Prove support role: GET /admin/audit -> 200, but POST /admin/agents -> 403."""
    support_user: UserRecord = await make_user(role="support", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    support_token = mint_token(sub=support_user.keycloak_sub, role="support")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1. Read audit -> 200 OK
        audit_resp = await client.get(
            "/admin/audit?limit=10",
            headers={"Authorization": f"Bearer {support_token}"},
        )
        assert audit_resp.status_code == 200
        assert isinstance(audit_resp.json(), list)

        # 2. Mutate agent -> 403 ForbiddenError
        mutate_resp = await client.post(
            "/admin/agents",
            json={"external_id": "ag_support_forbidden", "name": "Illegal"},
            headers={"Authorization": f"Bearer {support_token}"},
        )
        assert mutate_resp.status_code == 403
        envelope = ErrorEnvelope.model_validate(mutate_resp.json())
        assert envelope.error.code == "forbidden"


# ------------------------------------------------------------------------------
# 5. KYC DECISION WORKFLOW & DOUBLE-DECIDE GUARD
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kyc_decide_workflow_and_double_decide_guard(
    db_pool: asyncpg.Pool,
    make_user: Any,
    make_merchant: Any,
    build_admin_app: Any,
    delete_merchant_cascade: Any,
) -> None:
    """Validate KYC approve, DB update, audit row with truncated notes, and 404 on double decide."""
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=admin_user.keycloak_sub, role="admin")

    merchant = await make_merchant()
    kyc_id = uuid.uuid4()

    # Seed pending KYC request row
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status, provider, notes)
            VALUES ($1, 'merchant', $2, 'pending', 'manual', 'initial submission');
            """,
            kyc_id,
            merchant.id,
        )

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            notes_content = "Certificate of incorporation and beneficial ownership verified."
            decide_resp = await client.post(
                f"/admin/kyc/{kyc_id}/decide",
                json={"decision": "approved", "notes": notes_content},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert decide_resp.status_code == 200
            assert decide_resp.json() == {"id": str(kyc_id), "status": "approved"}

            # Verify in PostgreSQL
            async with db_pool.acquire() as conn:
                kyc_row = await conn.fetchrow(
                    "SELECT status, decided_by, decided_at, notes FROM kyc_requests WHERE id = $1;",
                    kyc_id,
                )
                assert kyc_row is not None
                assert kyc_row["status"] == "approved"
                assert kyc_row["decided_by"] == admin_user.id
                assert kyc_row["decided_at"] is not None
                assert kyc_row["notes"] == notes_content

                # Verify audit row
                audit_row = await conn.fetchrow(
                    """
                    SELECT action, target_type, target_id, details
                    FROM audit_log
                    WHERE target_type = 'kyc' AND target_id = $1;
                    """,
                    str(kyc_id),
                )
                assert audit_row is not None
                assert audit_row["action"] == "kyc.decide"

                import orjson

                details = audit_row["details"]
                if isinstance(details, str):
                    details = orjson.loads(details)
                assert details["decision"] == "approved"
                assert details["notes_len"] == len(notes_content)
                assert details["notes"] == notes_content[:200]

            # 2. Second decide -> 404 NotFoundError (double-decide guard)
            second_resp = await client.post(
                f"/admin/kyc/{kyc_id}/decide",
                json={"decision": "rejected", "notes": "attempt to overwrite"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert second_resp.status_code == 404
            envelope = ErrorEnvelope.model_validate(second_resp.json())
            assert envelope.error.code == "not_found"

    finally:
        async with db_pool.acquire() as conn:
            await conn.execute("DELETE FROM kyc_requests WHERE id = $1;", kyc_id)
        await delete_merchant_cascade(merchant.id)


# ------------------------------------------------------------------------------
# 6. AUDIT ATOMICITY WITNESS TEST (ROLLBACK GUARANTEE)
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_atomicity_witness_no_audit_row_on_mutation_failure(
    db_pool: asyncpg.Pool,
    make_user: Any,
    build_admin_app: Any,
    delete_agent_cascade: Any,
) -> None:
    """Prove atomicity: when mutation fails, NO audit row is committed to audit_log."""
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=admin_user.keycloak_sub, role="admin")

    ext_id = f"ag_atomic_{uuid.uuid4().hex[:12]}"
    payload = {"external_id": ext_id, "name": "Atomic Agent", "currency": "USDC"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Pre-seed first agent
        r1 = await client.post(
            "/admin/agents",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r1.status_code == 201
        agent_id = uuid.UUID(r1.json()["id"])

        try:
            # Query count of audit rows before the failed attempt
            async with db_pool.acquire() as conn:
                count_before = await conn.fetchval(
                    "SELECT COUNT(*) FROM audit_log WHERE details->>'external_id' = $1;",
                    ext_id,
                )
                assert count_before == 1

            # Second call fails due to unique constraint collision
            r2 = await client.post(
                "/admin/agents",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r2.status_code == 422

            # Proves audit atomicity: count must NOT increase on failure
            async with db_pool.acquire() as conn:
                count_after = await conn.fetchval(
                    "SELECT COUNT(*) FROM audit_log WHERE details->>'external_id' = $1;",
                    ext_id,
                )
                assert count_after == count_before == 1

        finally:
            await delete_agent_cascade(agent_id)


# ------------------------------------------------------------------------------
# 7. DATABASE-LEVEL AUDIT_LOG IMMUTABILITY TRIGGER TEST
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_log_database_immutability_trigger(
    db_pool: asyncpg.Pool,
) -> None:
    """Validate direct UPDATE/DELETE on audit_log raises restrict_violation."""
    async with db_pool.acquire() as conn:
        # Insert test audit entry
        row = await conn.fetchrow(
            """
            INSERT INTO audit_log (
                actor_sub, actor_role, action, target_type, target_id, details
            )
            VALUES (
                $1, 'admin', 'agent.create', 'agent', 'test-immutability', '{"key":"val"}'::jsonb
            )
            RETURNING id;
            """,
            str(uuid.uuid4()),
        )
        assert row is not None
        audit_id = row["id"]

        # 1. Attempt UPDATE on audit_log -> MUST fail with restrict_violation
        with pytest.raises(asyncpg.RestrictViolationError) as exc_update:
            await conn.execute(
                "UPDATE audit_log SET action = 'agent.tampered' WHERE id = $1;",
                audit_id,
            )
        assert "audit_log is append-only: UPDATE forbidden" in str(exc_update.value)

        # 2. Attempt DELETE on audit_log -> MUST fail with restrict_violation
        with pytest.raises(asyncpg.RestrictViolationError) as exc_delete:
            await conn.execute(
                "DELETE FROM audit_log WHERE id = $1;",
                audit_id,
            )
        assert "audit_log is append-only: DELETE forbidden" in str(exc_delete.value)


# ------------------------------------------------------------------------------
# 8. AUDIT READ RECENT & PAGING TEST
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_read_recent_paging_and_filter(
    db_pool: asyncpg.Pool,
    make_user: Any,
    build_admin_app: Any,
) -> None:
    """Validate read_recent endpoint respects limits and filters by target entity."""
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=admin_user.keycloak_sub, role="admin")

    target_id_filter = f"filter_target_{uuid.uuid4().hex[:8]}"

    # Seed 3 rows for this target_id
    async with db_pool.acquire() as conn:
        for i in range(3):
            await audit.record(
                conn,
                actor_sub=admin_user.keycloak_sub,
                actor_role="admin",
                action="agent.suspend",
                target_type="agent",
                target_id=target_id_filter,
                details={"step": i},
            )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1. Paging limit=2
        resp_paged = await client.get(
            f"/admin/audit?limit=2&target_type=agent&target_id={target_id_filter}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp_paged.status_code == 200
        items = resp_paged.json()
        assert len(items) == 2

        # 2. Target filter matches all 3
        resp_all = await client.get(
            f"/admin/audit?limit=10&target_type=agent&target_id={target_id_filter}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp_all.status_code == 200
        assert len(resp_all.json()) == 3


# ------------------------------------------------------------------------------
# 9. GET AGENT BY ID (SUPPORT READ-ONLY ACCESS)
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_agent_by_id_endpoint(
    make_user: Any,
    build_admin_app: Any,
    delete_agent_cascade: Any,
) -> None:
    """Validate GET /admin/agents/{id} returns AgentRecord metadata with no secret."""
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    support_user: UserRecord = await make_user(role="support", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    admin_token = mint_token(sub=admin_user.keycloak_sub, role="admin")
    support_token = mint_token(sub=support_user.keycloak_sub, role="support")

    ext_id = f"ag_get_{uuid.uuid4().hex[:12]}"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Create agent
        c_resp = await client.post(
            "/admin/agents",
            json={"external_id": ext_id, "name": "Readable Agent"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert c_resp.status_code == 201
        agent_id_str = c_resp.json()["id"]
        agent_id = uuid.UUID(agent_id_str)

        try:
            # Support reads agent metadata
            g_resp = await client.get(
                f"/admin/agents/{agent_id_str}",
                headers={"Authorization": f"Bearer {support_token}"},
            )
            assert g_resp.status_code == 200
            body = g_resp.json()
            assert body["id"] == agent_id_str
            assert body["external_id"] == ext_id
            assert body["name"] == "Readable Agent"
            assert "secret" not in body  # Custody holds: secret never returned on GET
        finally:
            await delete_agent_cascade(agent_id)
