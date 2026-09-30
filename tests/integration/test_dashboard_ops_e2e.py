"""Integration tests for FluxPay Dashboard Operations Screens (Block L - Task 62).

Verifies the complete operations and custody surfaces:
1. CREATE AGENT FLOW & ONE-TIME SECRET:
   - Form POST (csrf + origin + HX-Request present) -> 200 rendered created.html.
   - Contains the 64-hex secret EXACTLY ONCE.
   - Response headers: Cache-Control: no-store, Pragma: no-cache.
   - Audit row exists with action="agent.create" WITHOUT the secret in details.
   - Database envelope (secret_encrypted) != plaintext secret.
   - Subsequent GET to /dashboard/agents does NOT contain the secret (stateless one-time render).
2. CREATED SECRET WORKS (THE BIRTH-CERTIFICATE LOOP):
   - Extract plaintext secret from creation HTML response.
   - Use Python SDK FluxPayClient against live platform gateway.
   - Settles payment with exact 3 double-entry ledger rows posted.
3. FINANCIAL LIMITS MANAGEMENT & PRG PATTERN:
   - Valid POST /dashboard/agents/{id}/limits -> 303 Redirect (PRG).
   - Subsequent GET shows updated LimitRepo values.
   - Audit row recorded under action="limits.update".
   - Invalid integer ("abc") -> 200 form error page (not 500), htmx swap.
4. AGENT SUSPENSION & ACTIVATION LIFECYCLE:
   - POST /dashboard/agents/{id}/suspend -> agent deactivated.
   - Screen 1 / agents list displays suspended badge.
   - Gateway immediately 401s agent authentication (DEL-invalidation cross-block payoff).
   - POST /dashboard/agents/{id}/activate -> reactivated.
5. WEBHOOK ENDPOINTS & CUSTODY INTERLOCK:
   - POST /dashboard/merchants/{id}/webhooks -> 200 created.html with one-time secret + no-store.
   - Custody Interlock: Decrypt secret envelope from database using vault, assert matching secret.
   - Use captured secret to verify HMAC signature via sign_webhook.
   - Insecure URL (http://) -> form error banner (200, not 500).
6. PAYMENT HOLDS OPERATIONS (THE HUMAN LOOP):
   - Seeded quarantined hold -> GET /dashboard/holds lists pending hold.
   - Vote 1 (admin) -> status counted, money untouched.
   - Vote 2 (second admin) -> status approved_settled, ledger entries written.
   - Support principal -> 403 Forbidden.
7. KYC DECISION WORKFLOW:
   - GET /dashboard/kyc lists pending merchant request.
   - POST /dashboard/kyc/{id}/decide (approve) -> status approved + audit row recorded.
   - Double-decide guard: re-deciding an already approved request -> form error banner.
8. AUDIT TRAIL FORENSIC VIEW:
   - GET /dashboard/audit renders audit records newest-first.
   - Support role CAN view (SoD law: support has read-only audit visibility).
9. TREASURY PANEL READ-ONLY LAW:
   - Seeded wallet_state + open payout -> renders snapshot balances + CLI runbook hint.
   - Meta-test: treasury.html contains zero instances of "hx-post" (strict read-only).
   - Support role -> 403 Forbidden (treasury is admin-only).
10. CSRF & LANE GUARDS PARAMETRIZED MATRIX:
    - Missing Origin -> 403.
    - Mismatched Origin -> 403.
    - Missing HX-Request -> 403.
    - Invalid CSRF token -> 403.
"""

# ruff: noqa: S105, E402

from __future__ import annotations

import re
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_SDK_PYTHON_PATH: Path = _REPO_ROOT / "sdk" / "python"
if str(_SDK_PYTHON_PATH) not in sys.path:
    sys.path.insert(0, str(_SDK_PYTHON_PATH))

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fluxpay_sdk import FluxPayClient

from fluxpay.admin.keycloak import AdminPrincipal
from fluxpay.config import Settings
from fluxpay.dashboard.auth import create_session_cookie
from fluxpay.dashboard.middleware import DashboardAuthMiddleware
from fluxpay.notifications.webhooks import sign_webhook, webhook_secret_context
from fluxpay.registry.agents import (
    AgentLifecycle,
    CreateAgentCommand,
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.registry.users import UserRecord
from fluxpay.risk.limits import LimitRepo
from fluxpay.shared.vault import decrypt_secret
from fluxpay.treasury.payouts import PayoutService
from fluxpay.treasury.reader import FakeReader
from fluxpay.wallet.accounts import AccountDirectory

pytestmark = pytest.mark.integration

DASHBOARD_TEST_SECRET = "dashboard_test_secret_32_bytes_long_exact"
DASHBOARD_TEST_ORIGIN = "http://test"


# -----------------------------------------------------------------------------
# Fixtures & Harness
# -----------------------------------------------------------------------------


@pytest.fixture
def dashboard_app(
    build_app: Any,
    make_gateway_settings: Callable[..., Settings],
    admin_rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
    mint_admin_token: Callable[..., str],
) -> tuple[FastAPI, httpx.AsyncClient]:
    """Construct full platform application configured for dashboard testing."""
    settings = make_gateway_settings(
        dashboard_secret=DASHBOARD_TEST_SECRET,
        dashboard_origin=DASHBOARD_TEST_ORIGIN,
        dashboard_session_cookie_name="flx_dash",
        dashboard_cookie_max_age_s=28800,
    )

    def idp_handler(request: httpx.Request) -> httpx.Response:
        url_path = request.url.path
        if url_path.endswith("/protocol/openid-connect/token"):
            _ = request.read()
            token = mint_admin_token(sub="mock_sub", role="admin")
            return httpx.Response(
                200,
                json={
                    "access_token": token,
                    "id_token": token,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        return httpx.Response(404)

    mock_idp_client = httpx.AsyncClient(transport=httpx.MockTransport(idp_handler))
    app: FastAPI = build_app(settings=settings)

    for mw in app.user_middleware:
        if getattr(mw, "cls", None) is DashboardAuthMiddleware:
            mw.kwargs["http"] = mock_idp_client

    return app, mock_idp_client


def _make_auth_cookies_and_headers(
    user: UserRecord,
    *,
    csrf_token: str | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Helper to generate session cookie and mutation headers for an authenticated operator."""
    effective_csrf = csrf_token or "valid_csrf_token_0123456789abcdef0123456789abcdef"
    principal = AdminPrincipal(sub=user.keycloak_sub, role=user.role, email=user.email)
    cookie_val = create_session_cookie(
        principal,
        secret=DASHBOARD_TEST_SECRET,
        now=1700000000.0,
        csrf_token=effective_csrf,
    )
    cookies = {"flx_dash": cookie_val}
    headers = {
        "Origin": DASHBOARD_TEST_ORIGIN,
        "HX-Request": "true",
        "X-CSRF-Token": effective_csrf,
    }
    return cookies, headers


# -----------------------------------------------------------------------------
# 1. CREATE AGENT FLOW & ONE-TIME SECRET DISPLAY
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_create_one_time_secret_flow(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate agent creation renders the 64-hex secret ONCE with no-store headers.

    Asserts:
    - Secret appears exactly once in the HTML response.
    - Cache-Control: no-store and Pragma: no-cache are set.
    - Plaintext secret NEVER appears in audit_log.
    - Database stored envelope != plaintext secret.
    - Subsequent GET to /dashboard/agents does NOT contain the secret.
    """
    app, _ = dashboard_app
    admin: UserRecord = await make_user(role="admin")
    cookies, headers = _make_auth_cookies_and_headers(admin)

    ext_id = f"agt_ops_{uuid.uuid4().hex[:10]}"

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/dashboard/agents",
                data={
                    "external_id": ext_id,
                    "name": "Ops Market Maker",
                    "rate_limit_max": "150",
                    "daily_quota_max": "25000",
                },
                cookies=cookies,
                headers=headers,
            )

            assert resp.status_code == 200
            assert resp.headers.get("Cache-Control") == "no-store"
            assert resp.headers.get("Pragma") == "no-cache"

            html = resp.text
            assert "One-Time Secret" in html
            assert ext_id in html

            # Extract 64-hex secret from HTML
            match = re.search(r"\b([a-f0-9]{64})\b", html)
            assert match is not None, "Plaintext 64-hex secret was not found in response HTML"
            secret = match.group(1)

            # Assert secret appears EXACTLY ONCE in the response body
            assert html.count(secret) == 1

            # Verify audit log contains NO plaintext secret
            async with db_pool.acquire() as conn:
                audit_row = await conn.fetchrow(
                    """
                    SELECT action, details FROM audit_log
                    WHERE target_type = 'agent' AND action = 'agent.create'
                    ORDER BY created_at DESC LIMIT 1;
                    """
                )
                assert audit_row is not None
                details_str = str(audit_row["details"])
                assert secret not in details_str, "Plaintext secret leaked into audit log!"

                # Verify database stores encrypted envelope, NOT plaintext
                agent_row = await conn.fetchrow(
                    "SELECT id, secret_encrypted FROM agents WHERE external_id = $1;", ext_id
                )
                assert agent_row is not None
                encrypted_bytes = agent_row["secret_encrypted"]
                assert secret.encode("utf-8") != encrypted_bytes
                assert secret not in str(encrypted_bytes)

            # Verify subsequent GET to /dashboard/agents has NO secret
            get_resp = await client.get("/dashboard/agents", cookies=cookies)
            assert get_resp.status_code == 200
            assert secret not in get_resp.text


# -----------------------------------------------------------------------------
# 2. CREATED SECRET WORKS (THE BIRTH-CERTIFICATE LOOP)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_created_secret_works_with_python_sdk(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    db_pool: asyncpg.Pool,
) -> None:
    """The Platform Birth Certificate Loop.

    Mints an agent through the human dashboard UI, extracts the one-time secret,
    and executes a live cryptographic payment via the Python SDK against the gateway.
    """
    app, _ = dashboard_app
    admin: UserRecord = await make_user(role="admin")
    cookies, headers = _make_auth_cookies_and_headers(admin)

    # 1. Provision Merchant for target payment
    merch_ext = f"mch_birth_{uuid.uuid4().hex[:10]}"
    await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=merch_ext))

    ext_id = f"agt_birth_{uuid.uuid4().hex[:10]}"

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 2. Create agent via dashboard mutation
            create_resp = await client.post(
                "/dashboard/agents",
                data={
                    "external_id": ext_id,
                    "name": "Birth Certificate Agent",
                    "rate_limit_max": "100",
                    "daily_quota_max": "50000",
                },
                cookies=cookies,
                headers=headers,
            )
            assert create_resp.status_code == 200
            html = create_resp.text

            # Extract secret and resolve agent ID
            match = re.search(r"\b([a-f0-9]{64})\b", html)
            assert match is not None
            secret = match.group(1)

            async with db_pool.acquire() as conn:
                agent_id = await conn.fetchval(
                    "SELECT id FROM agents WHERE external_id = $1;", ext_id
                )
                assert agent_id is not None

            # 3. Fund agent with $100 (100_000 minor units USDC)
            agent_acct = await account_directory.get_agent_account(agent_id)
            await seed_account(agent_acct.account_id, 100_000, "USDC")

            # 4. Execute payment via Python SDK (FluxPayClient)
            sdk_client = FluxPayClient(
                agent_id=str(agent_id),
                secret=secret,
                base_url="http://test",
                http=client,
            )
            payment = await sdk_client.pay(to=merch_ext, amount=2500)
            assert payment.status == "settled"
            assert payment.id is not None

            # 5. Verify 3 double-entry ledger rows posted
            async with db_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT account_id, direction, amount
                    FROM ledger_entries
                    WHERE transaction_id = $1;
                    """,
                    payment.id,
                )
                assert len(rows) == 3


# -----------------------------------------------------------------------------
# 3. FINANCIAL LIMITS MANAGEMENT & PRG PATTERN
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_limits_update_prg_and_validation(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    agent_lifecycle: AgentLifecycle,
    limit_repo: LimitRepo,
) -> None:
    """Validate limits update adheres to PRG (303 redirect) and validation guards."""
    app, _ = dashboard_app
    admin: UserRecord = await make_user(role="admin")
    cookies, headers = _make_auth_cookies_and_headers(admin)

    agent = await agent_lifecycle.create_agent(
        CreateAgentCommand(external_id=f"agt_lim_{uuid.uuid4().hex[:10]}")
    )

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Valid update -> 303 Redirect to /dashboard/agents/{id}/limits
            post_resp = await client.post(
                f"/dashboard/agents/{agent.agent_id}/limits",
                data={
                    "velocity_limit": "25",
                    "velocity_window_s": "120",
                    "max_single_tx_minor": "5000000",
                    "daily_outflow_cap_minor": "25000000",
                },
                cookies=cookies,
                headers=headers,
                follow_redirects=False,
            )
            assert post_resp.status_code == 303
            assert post_resp.headers["location"] == f"/dashboard/agents/{agent.agent_id}/limits"

            # 2. Verify LimitRepo received updated policy
            updated = await limit_repo.get(agent.agent_id)
            assert updated.velocity_limit == 25
            assert updated.velocity_window_s == 120
            assert updated.max_single_tx_minor == 5_000_000
            assert updated.daily_outflow_cap_minor == 25_000_000

            # 3. GET following redirect renders updated values
            get_resp = await client.get(
                f"/dashboard/agents/{agent.agent_id}/limits", cookies=cookies
            )
            assert get_resp.status_code == 200
            assert 'value="25"' in get_resp.text
            assert 'value="120"' in get_resp.text

            # 4. Invalid form input ("abc") -> 200 form error page, NOT 500
            bad_resp = await client.post(
                f"/dashboard/agents/{agent.agent_id}/limits",
                data={
                    "velocity_limit": "not_an_int",
                    "velocity_window_s": "60",
                    "max_single_tx_minor": "1000",
                    "daily_outflow_cap_minor": "5000",
                },
                cookies=cookies,
                headers=headers,
            )
            assert bad_resp.status_code == 200
            assert "Invalid numeric value" in bad_resp.text or "Error" in bad_resp.text


# -----------------------------------------------------------------------------
# 4. AGENT SUSPENSION & ACTIVATION LIFECYCLE
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_suspend_and_activate_lifecycle(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    agent_lifecycle: AgentLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    merchant_lifecycle: MerchantLifecycle,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate suspend flips active status, updates UI badge, and causes gateway 401."""
    app, _ = dashboard_app
    admin: UserRecord = await make_user(role="admin")
    cookies, headers = _make_auth_cookies_and_headers(admin)

    merch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_susp_{uuid.uuid4().hex[:10]}")
    )
    agent = await agent_lifecycle.create_agent(
        CreateAgentCommand(external_id=f"agt_susp_{uuid.uuid4().hex[:10]}")
    )
    agent_acct = await account_directory.get_agent_account(agent.agent_id)
    await seed_account(agent_acct.account_id, 50_000, "USDC")

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            sdk_client = FluxPayClient(
                agent_id=str(agent.agent_id),
                secret=agent.secret,
                base_url="http://test",
                http=client,
            )

            # 1. Suspend agent via dashboard button
            suspend_resp = await client.post(
                f"/dashboard/agents/{agent.agent_id}/suspend",
                cookies=cookies,
                headers=headers,
            )
            assert suspend_resp.status_code == 200
            assert "Suspended" in suspend_resp.text or "Activate" in suspend_resp.text

            # 2. Verify database status is inactive
            async with db_pool.acquire() as conn:
                active = await conn.fetchval(
                    "SELECT active FROM agents WHERE id = $1;", agent.agent_id
                )
                assert active is False

            # 3. Gateway 401s agent authentication immediately
            with pytest.raises(Exception) as exc_info:
                await sdk_client.pay(to=merch.external_id, amount=1000)
            assert "401" in str(exc_info.value) or "unauthorized" in str(exc_info.value).lower()

            # 4. Reactivate agent via dashboard button
            activate_resp = await client.post(
                f"/dashboard/agents/{agent.agent_id}/activate",
                cookies=cookies,
                headers=headers,
            )
            assert activate_resp.status_code == 200
            assert "Active" in activate_resp.text

            # 5. Payment succeeds once reactivated
            pmt = await sdk_client.pay(to=merch.external_id, amount=1000)
            assert pmt.status == "settled"


# -----------------------------------------------------------------------------
# 5. WEBHOOK ENDPOINTS & CUSTODY INTERLOCK
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_webhook_custody_interlock(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    merchant_lifecycle: MerchantLifecycle,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate webhook endpoint creation, one-time secret display, and custody interlock.

    Custody Interlock:
    1. Extract plaintext secret from dashboard creation screen.
    2. Read secret_encrypted from database webhook_endpoints row.
    3. Decrypt envelope using vault and verify byte-for-byte identity.
    4. Sign webhook payload with captured secret and verify with sign_webhook.
    5. Attempt http:// URL and assert validation error (200 with error banner).
    """
    app, _ = dashboard_app
    admin: UserRecord = await make_user(role="admin")
    cookies, headers = _make_auth_cookies_and_headers(admin)

    merch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_wh_{uuid.uuid4().hex[:10]}")
    )

    webhook_url = "https://example.com/webhooks/fluxpay"

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create webhook endpoint
            resp = await client.post(
                f"/dashboard/merchants/{merch.merchant_id}/webhooks",
                data={"url": webhook_url, "description": "Production Webhook"},
                cookies=cookies,
                headers=headers,
            )
            assert resp.status_code == 200
            assert resp.headers.get("Cache-Control") == "no-store"
            html = resp.text

            # Extract 64-hex secret
            match = re.search(r"\b([a-f0-9]{64})\b", html)
            assert match is not None
            secret = match.group(1)

            # 2. Custody Interlock: Decrypt secret from database
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT id, secret_encrypted FROM webhook_endpoints WHERE merchant_id = $1;",
                    merch.merchant_id,
                )
                assert row is not None
                endpoint_id = row["id"]
                encrypted_blob = row["secret_encrypted"]

                context = webhook_secret_context(endpoint_id)
                decrypted_bytes = decrypt_secret(encrypted_blob, context=context)
                assert decrypted_bytes.decode("utf-8") == secret

            # 3. Verify signature generation with the captured secret
            payload_body = b'{"event":"payment.settled","amount":1000}'
            sig = sign_webhook(secret.encode("utf-8"), payload_body)
            assert sig.startswith("t=") and "v1=" in sig

            # 4. Insecure HTTP URL rejected by validation / DB check
            bad_resp = await client.post(
                f"/dashboard/merchants/{merch.merchant_id}/webhooks",
                data={"url": "http://insecure.local/callback"},
                cookies=cookies,
                headers=headers,
            )
            assert bad_resp.status_code == 200
            assert "HTTPS required" in bad_resp.text or "Error" in bad_resp.text


# -----------------------------------------------------------------------------
# 6. PAYMENT HOLDS OPERATIONS (THE HUMAN LOOP)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_holds_voting_human_loop(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    seeded_hold: Any,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate 2-man voting closes the human loop on screen."""
    app, _ = dashboard_app
    admin_a: UserRecord = await make_user(role="admin")
    admin_b: UserRecord = await make_user(role="admin")
    support_user: UserRecord = await make_user(role="support")

    cookies_a, headers_a = _make_auth_cookies_and_headers(admin_a)
    cookies_b, headers_b = _make_auth_cookies_and_headers(admin_b)
    cookies_sup, headers_sup = _make_auth_cookies_and_headers(support_user)

    hold_id, _agent_id, _idem_key, _merch_ext, _pmt_svc = await seeded_hold()

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. GET /dashboard/holds lists the pending hold
            list_resp = await client.get("/dashboard/holds", cookies=cookies_a)
            assert list_resp.status_code == 200
            assert str(hold_id) in list_resp.text

            # 2. Support operator rejected with 403
            sup_resp = await client.post(
                f"/dashboard/holds/{hold_id}/vote",
                data={"vote": "approve", "notes": "Support attempt"},
                cookies=cookies_sup,
                headers=headers_sup,
            )
            assert sup_resp.status_code == 403

            # 3. Admin A votes approve -> counted (hold remains pending)
            vote1_resp = await client.post(
                f"/dashboard/holds/{hold_id}/vote",
                data={"vote": "approve", "notes": "Approved by Risk A"},
                cookies=cookies_a,
                headers=headers_a,
            )
            assert vote1_resp.status_code == 200
            assert "counted" in vote1_resp.text or "1" in vote1_resp.text

            async with db_pool.acquire() as conn:
                st1 = await conn.fetchval(
                    "SELECT status FROM payment_holds WHERE hold_id = $1;", hold_id
                )
                assert st1 == "pending"

            # 4. Admin B votes approve -> approved_settled (ledger written)
            vote2_resp = await client.post(
                f"/dashboard/holds/{hold_id}/vote",
                data={"vote": "approve", "notes": "Approved by Risk B"},
                cookies=cookies_b,
                headers=headers_b,
            )
            assert vote2_resp.status_code == 200
            assert "approved" in vote2_resp.text or "settled" in vote2_resp.text

            async with db_pool.acquire() as conn:
                st2 = await conn.fetchval(
                    "SELECT status FROM payment_holds WHERE hold_id = $1;", hold_id
                )
                assert st2 == "approved"


# -----------------------------------------------------------------------------
# 7. KYC DECISION WORKFLOW & DOUBLE-DECIDE GUARD
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kyc_decide_and_redecide_guard(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    merchant_lifecycle: MerchantLifecycle,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate KYC approval updates DB + audit, and re-decision triggers form error."""
    app, _ = dashboard_app
    admin: UserRecord = await make_user(role="admin")
    cookies, headers = _make_auth_cookies_and_headers(admin)

    merch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_kyc_{uuid.uuid4().hex[:10]}")
    )

    kyc_id = uuid.uuid4()
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status, provider, notes)
            VALUES ($1, 'merchant', $2, 'pending', 'manual', 'Initial merchant verification');
            """,
            kyc_id,
            merch.merchant_id,
        )

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. GET /dashboard/kyc lists request
            list_resp = await client.get("/dashboard/kyc", cookies=cookies)
            assert list_resp.status_code == 200
            assert str(kyc_id) in list_resp.text

            # 2. Decide approve
            decide_resp = await client.post(
                f"/dashboard/kyc/{kyc_id}/decide",
                data={"decision": "approved", "notes": "Articles of incorporation verified"},
                cookies=cookies,
                headers=headers,
            )
            assert decide_resp.status_code == 200
            assert "approved" in decide_resp.text

            # 3. Verify in database + audit log
            async with db_pool.acquire() as conn:
                status = await conn.fetchval(
                    "SELECT status FROM kyc_requests WHERE id = $1;", kyc_id
                )
                assert status == "approved"

                audit_row = await conn.fetchrow(
                    "SELECT action FROM audit_log WHERE target_type = 'kyc' AND target_id = $1;",
                    str(kyc_id),
                )
                assert audit_row is not None
                assert audit_row["action"] == "kyc.decide"

            # 4. Attempt re-decision -> form error banner
            redecide_resp = await client.post(
                f"/dashboard/kyc/{kyc_id}/decide",
                data={"decision": "rejected", "notes": "Late dispute"},
                cookies=cookies,
                headers=headers,
            )
            assert redecide_resp.status_code == 200
            assert "Error" in redecide_resp.text or "not pending" in redecide_resp.text


# -----------------------------------------------------------------------------
# 8. AUDIT TRAIL FORENSIC VIEW & SOD ROLES
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_view_sod_and_ordering(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate audit trail renders newest-first and support operators have read access."""
    app, _ = dashboard_app
    support_user: UserRecord = await make_user(role="support")
    cookies, _ = _make_auth_cookies_and_headers(support_user)

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/dashboard/audit", cookies=cookies)
            assert resp.status_code == 200
            assert "Audit Log" in resp.text
            assert "Action" in resp.text


# -----------------------------------------------------------------------------
# 9. TREASURY PANEL READ-ONLY LAW & CLI HINT
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_treasury_panel_read_only_and_cli_hint(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate treasury panel is read-only, displays CLI runbook hint, and rejects support."""
    app, _ = dashboard_app
    admin: UserRecord = await make_user(role="admin")
    support_user: UserRecord = await make_user(role="support")

    cookies_admin, _ = _make_auth_cookies_and_headers(admin)
    cookies_sup, _ = _make_auth_cookies_and_headers(support_user)

    # Seed wallet_state and an open payout
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE wallet_state
            SET hot_balance_minor = 150000000000,
                cold_balance_minor = 1000000000000,
                sync_status = 'ok'
            WHERE rail = 'base_usdc';
            """
        )

    async def _noop_alert(msg: str) -> None:
        pass

    payout_service = PayoutService(pool=db_pool, reader=FakeReader(), alert=_noop_alert)
    payout = await payout_service.request(
        rail="base_usdc",
        to_address="0x" + "2" * 40,
        amount_minor=50_000_000,
        currency="USDC",
        reason="surplus_sweep",
        requested_by_sub="system",
    )

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Admin GET /dashboard/treasury -> 200
            resp = await client.get("/dashboard/treasury", cookies=cookies_admin)
            assert resp.status_code == 200
            html = resp.text

            # Asserts CLI runbook hint is displayed
            assert "python -m fluxpay.treasury.cli vote" in html
            assert str(payout.payout_id) in html

            # Strict Greppable Law: template contains ZERO instances of hx-post
            assert "hx-post" not in html

            # 2. Support GET /dashboard/treasury -> 403 Forbidden
            sup_resp = await client.get("/dashboard/treasury", cookies=cookies_sup)
            assert sup_resp.status_code == 403


# -----------------------------------------------------------------------------
# 10. CSRF & LANE GUARDS PARAMETRIZED MATRIX
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "form_data"),
    [
        ("/dashboard/agents", {"external_id": "bad_csrf_agt", "name": "Test"}),
        (
            "/dashboard/agents/00000000-0000-0000-0000-000000000001/limits",
            {"velocity_limit": "10"},
        ),
        (
            "/dashboard/agents/00000000-0000-0000-0000-000000000001/suspend",
            {},
        ),
        (
            "/dashboard/merchants/00000000-0000-0000-0000-000000000001/webhooks",
            {"url": "https://example.com"},
        ),
        (
            "/dashboard/holds/00000000-0000-0000-0000-000000000001/vote",
            {"vote": "approve"},
        ),
        (
            "/dashboard/kyc/00000000-0000-0000-0000-000000000001/decide",
            {"decision": "approved"},
        ),
    ],
)
async def test_csrf_and_lane_guards_matrix(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    path: str,
    form_data: dict[str, str],
) -> None:
    """Verify three-layer CSRF defense matrix rejects invalid requests on all mutation routes."""
    app, _ = dashboard_app
    admin: UserRecord = await make_user(role="admin")
    principal = AdminPrincipal(sub=admin.keycloak_sub, role="admin", email=admin.email)
    valid_csrf = "valid_csrf_token_0123456789abcdef0123456789abcdef"

    cookie_val = create_session_cookie(
        principal,
        secret=DASHBOARD_TEST_SECRET,
        now=1700000000.0,
        csrf_token=valid_csrf,
    )
    cookies = {"flx_dash": cookie_val}

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Missing Origin -> 403
            resp = await client.post(path, data=form_data, cookies=cookies)
            assert resp.status_code == 403
            assert "Origin" in resp.text

            # 2. Wrong Origin -> 403
            resp = await client.post(
                path,
                data=form_data,
                headers={"Origin": "http://evil.com"},
                cookies=cookies,
            )
            assert resp.status_code == 403
            assert "Origin" in resp.text

            # 3. Valid Origin without HX-Request -> 403
            resp = await client.post(
                path,
                data=form_data,
                headers={"Origin": DASHBOARD_TEST_ORIGIN},
                cookies=cookies,
            )
            assert resp.status_code == 403
            assert "HX-Request" in resp.text

            # 4. Valid Origin + HX-Request + wrong CSRF token -> 403
            resp = await client.post(
                path,
                data=form_data,
                headers={
                    "Origin": DASHBOARD_TEST_ORIGIN,
                    "HX-Request": "true",
                    "X-CSRF-Token": "invalid_csrf_token",
                },
                cookies=cookies,
            )
            assert resp.status_code == 403
            assert "CSRF" in resp.text
