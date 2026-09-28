"""Integration tests for KYC Orchestrator and Provider Adapters (Block J, Task 55).

==============================================================================
TASK 55 INTEGRATION SUITE
==============================================================================
Verifies live PostgreSQL state transitions, UnitOfWork atomicity, audit logging,
provider-blind orchestration, and the fundamental Authority Law:
1. MANUAL FLOW E2E:
   Seed merchant + kyc_request -> orchestrator.start('manual') -> provider_ref set ->
   admin /admin/kyc/{id}/decide endpoint -> approved (full Phase 1 loop).
2. START GUARDS:
   - Starting a decided row raises NotFoundError.
   - Unknown provider name raises ValidationError.
   - Double-start on already-started pending row raises ValidationError (422 already started).
3. SUMSUB START & AUDIT:
   MockTransport applicant + token -> row updated with applicant ID ->
   audit row 'kyc.start' verified in audit_log table.
4. THE AUTHORITY LAW (PROVIDER OPINION NEVER OVERWRITES STATUS):
   sync_from_provider returns cleared KycState, but kyc_requests.status
   remains strictly 'pending' in PostgreSQL.
"""

from __future__ import annotations

import uuid
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest

from fluxpay.integrations.kyc.manual import ManualProvider
from fluxpay.integrations.kyc.protocol import KycState
from fluxpay.integrations.kyc.sumsub import SumsubProvider
from fluxpay.registry.kyc_service import KycOrchestrator
from fluxpay.registry.users import UserRecord
from fluxpay.shared.errors import NotFoundError, ValidationError

pytestmark = pytest.mark.integration


# -----------------------------------------------------------------------------
# 1. MANUAL FLOW E2E (PHASE 1 FULL LOOP)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_manual_kyc_flow_e2e(
    db_pool: asyncpg.Pool,
    make_merchant: Any,
    make_user: Any,
    build_admin_app: Any,
    apply_audit_schema: None,
) -> None:
    """Manual flow: start -> row updated -> admin decide -> approved."""
    merchant = await make_merchant()
    kyc_id = uuid.uuid4()

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status, provider, notes)
            VALUES ($1, 'merchant', $2, 'pending', 'manual', 'initial intake');
            """,
            kyc_id,
            merchant.id,
        )

    orchestrator = KycOrchestrator(
        pool=db_pool,
        providers={"manual": ManualProvider()},
        default_provider="manual",
    )

    # 1. Start verification via orchestrator
    start_res = await orchestrator.start(kyc_id, provider="manual")
    assert start_res.ref == str(kyc_id)
    assert start_res.redirect_url is None

    # Verify DB update
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT provider, provider_ref, status FROM kyc_requests WHERE id = $1;",
            kyc_id,
        )
        assert row is not None
        assert row["provider"] == "manual"
        assert row["provider_ref"] == str(kyc_id)
        assert row["status"] == "pending"

    # 2. Admin decides via Task 29 HTTP endpoint
    admin_user: UserRecord = await make_user(role="admin", keycloak_sub=str(uuid.uuid4()))
    app, _, mint_token = build_admin_app()
    token = mint_token(sub=admin_user.keycloak_sub, role="admin")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            f"/admin/kyc/{kyc_id}/decide",
            json={
                "decision": "approved",
                "notes": "Manual inspection verified valid incorporation certificate.",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"id": str(kyc_id), "status": "approved"}

    # Verify approved in PostgreSQL
    async with db_pool.acquire() as conn:
        final_row = await conn.fetchrow(
            "SELECT status, decided_by FROM kyc_requests WHERE id = $1;",
            kyc_id,
        )
        assert final_row is not None
        assert final_row["status"] == "approved"
        assert final_row["decided_by"] == admin_user.id


# -----------------------------------------------------------------------------
# 2. ORCHESTRATION GUARDS: DECIDED ROW & UNKNOWN PROVIDER
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_guards_decided_row_and_unknown_provider(
    db_pool: asyncpg.Pool,
    make_merchant: Any,
    make_user: Any,
    apply_audit_schema: None,
) -> None:
    """Starting an already-decided row raises NotFoundError.

    Unknown provider raises ValidationError.
    """
    merchant = await make_merchant()
    admin_user: UserRecord = await make_user(role="admin")
    decided_kyc_id = uuid.uuid4()

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO kyc_requests
                (id, subject_type, subject_id, status, provider, decided_by, decided_at)
            VALUES ($1, 'merchant', $2, 'approved', 'manual', $3, now());
            """,
            decided_kyc_id,
            merchant.id,
            admin_user.id,
        )

    orchestrator = KycOrchestrator(
        pool=db_pool,
        providers={"manual": ManualProvider()},
        default_provider="manual",
    )

    # 1. Guard against starting an already decided row
    with pytest.raises(NotFoundError) as exc_info:
        await orchestrator.start(decided_kyc_id, provider="manual")
    assert "already decided" in str(exc_info.value)

    # 2. Guard against unknown provider name
    pending_kyc_id = uuid.uuid4()
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status, provider)
            VALUES ($1, 'merchant', $2, 'pending', 'manual');
            """,
            pending_kyc_id,
            merchant.id,
        )

    with pytest.raises(ValidationError) as exc_info2:
        await orchestrator.start(pending_kyc_id, provider="non_existent_provider")
    assert "Unknown or unconfigured KYC provider" in str(exc_info2.value)


# -----------------------------------------------------------------------------
# 3. DOUBLE-START GUARD (422 ALREADY STARTED)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_double_start_guard_rejects(
    db_pool: asyncpg.Pool,
    make_merchant: Any,
    apply_audit_schema: None,
) -> None:
    """Calling start a second time on an already-started row raises ValidationError."""
    merchant = await make_merchant()
    kyc_id = uuid.uuid4()

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status, provider)
            VALUES ($1, 'merchant', $2, 'pending', 'manual');
            """,
            kyc_id,
            merchant.id,
        )

    orchestrator = KycOrchestrator(
        pool=db_pool,
        providers={"manual": ManualProvider()},
        default_provider="manual",
    )

    # First start succeeds
    res1 = await orchestrator.start(kyc_id)
    assert res1.ref == str(kyc_id)

    # Second start on same row must fail fast
    with pytest.raises(ValidationError) as exc_info:
        await orchestrator.start(kyc_id)

    assert "KYC verification already started" in str(exc_info.value)


# -----------------------------------------------------------------------------
# 4. SUMSUB START & AUDIT RECORDING
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sumsub_start_and_audit(
    db_pool: asyncpg.Pool,
    make_merchant: Any,
    apply_audit_schema: None,
) -> None:
    """Sumsub start persists provider_ref and records 'kyc.start' audit log row."""
    merchant = await make_merchant()
    kyc_id = uuid.uuid4()
    applicant_id = "app_sumsub_sandbox_777"
    hosted_url = "https://cockpit.sumsub.com/hosted/tok_sandbox_999"

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status, provider)
            VALUES ($1, 'merchant', $2, 'pending', 'manual');
            """,
            kyc_id,
            merchant.id,
        )

    def mock_transport(request: httpx.Request) -> httpx.Response:
        if "/resources/applicants?" in str(request.url):
            return httpx.Response(201, json={"id": applicant_id})
        if "/resources/accessTokens?" in str(request.url):
            return httpx.Response(200, json={"token": "tok_sandbox_999", "url": hosted_url})
        return httpx.Response(404)

    sumsub_prov = SumsubProvider(
        api_key="sbx_app_token",
        secret_key="sbx_secret",  # noqa: S106
        http=httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)),
    )

    orchestrator = KycOrchestrator(
        pool=db_pool,
        providers={"sumsub": sumsub_prov, "manual": ManualProvider()},
        default_provider="manual",
    )

    actor_sub = f"kc_admin_{uuid.uuid4().hex[:8]}"
    start_res = await orchestrator.start(
        kyc_id,
        provider="sumsub",
        actor_sub=actor_sub,
        actor_role="admin",
    )

    assert start_res.ref == applicant_id
    assert start_res.redirect_url == hosted_url

    # Check kyc_requests row carries provider_ref and status remains pending
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT provider, provider_ref, status FROM kyc_requests WHERE id = $1;",
            kyc_id,
        )
        assert row is not None
        assert row["provider"] == "sumsub"
        assert row["provider_ref"] == applicant_id
        assert row["status"] == "pending"

        # Check audit log entry exists
        audit_row = await conn.fetchrow(
            """
            SELECT action, target_type, target_id, actor_sub, details
            FROM audit_log
            WHERE target_type = 'kyc' AND target_id = $1 AND action = 'kyc.start';
            """,
            str(kyc_id),
        )
        assert audit_row is not None
        assert audit_row["actor_sub"] == actor_sub
        assert audit_row["details"]["provider"] == "sumsub"
        assert audit_row["details"]["provider_ref"] == applicant_id


# -----------------------------------------------------------------------------
# 5. THE AUTHORITY LAW: SYNC DOES NOT WRITE STATUS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_from_provider_authority_law(
    db_pool: asyncpg.Pool,
    make_merchant: Any,
    apply_audit_schema: None,
) -> None:
    """AUTHORITY LAW: sync_from_provider returns cleared KycState, but row is UNCHANGED.

    Providers recommend, platform decides. Automation never auto-writes approval.
    """
    merchant = await make_merchant()
    kyc_id = uuid.uuid4()
    applicant_id = "app_cleared_recommendation_123"

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status, provider, provider_ref)
            VALUES ($1, 'merchant', $2, 'pending', 'sumsub', $3);
            """,
            kyc_id,
            merchant.id,
            applicant_id,
        )

    # Provider returns completed review with GREEN answer
    def mock_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "reviewStatus": "completed",
                "reviewResult": {"reviewAnswer": "GREEN"},
            },
        )

    sumsub_prov = SumsubProvider(
        api_key="token",
        secret_key="secret",  # noqa: S106
        http=httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)),
    )

    orchestrator = KycOrchestrator(
        pool=db_pool,
        providers={"sumsub": sumsub_prov},
        default_provider="sumsub",
    )

    # Sync returns 'cleared' recommendation to the caller
    state = await orchestrator.sync_from_provider(kyc_id)
    assert isinstance(state, KycState)
    assert state.status == "cleared"

    # THE AUTHORITY LAW PROOF:
    # kyc_requests.status MUST STILL BE 'pending' in the database!
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT status, decided_by, decided_at FROM kyc_requests WHERE id = $1;",
            kyc_id,
        )
        assert row is not None
        assert row["status"] == "pending"
        assert row["decided_by"] is None
        assert row["decided_at"] is None
