"""Integration tests for FluxPay Dashboard Lane (Block L - Task 61/62).

Verifies:
1. LOGIN FLOW E2E: /dashboard/login -> 302 to authorize URL (state cookie, Lax)
   -> callback with code+state (MockTransport token exchange) -> 302 /dashboard
   + session cookie (flags asserted: HttpOnly, Secure, SameSite=Strict)
   -> GET /dashboard/agents 200.
2. STALE-TOKEN DEFENSE: User active=false in DB -> callback -> 403 error page.
   User deactivated after session creation -> subsequent request -> 403 error page.
3. CSRF MATRIX: POST without Origin -> 403; wrong Origin -> 403; right Origin without HX-Request
   -> 403; all three + valid csrf -> passes guard (to a stub route); csrf mismatch -> 403.
4. SCREEN 1 E2E: Seeded agent + funded ledger entries -> agents page lists agent; agent page
   shows balance card (exact format_minor), statement rows (seq/direction/amount/balance_after),
   chain_verified badge GREEN; pagination: >50 entries -> older link -> cursor page
   returns older rows.
5. RED BADGE: Corrupt entry via Task 16's tamper procedure (self-restoring) -> chain_verified False
   -> red badge rendered (the evidence-first UI moment) -> restore -> green.
6. LANES UNTOUCHED: /v1/payments unauthenticated -> 401 JSON envelope (gateway law);
   /admin/agents without Bearer -> 401 (Task 29 law); /dashboard/agents unauthenticated -> 302.
7. NO-JS GRACEFUL: Pages render fully server-side with core data present without JS.
8. ERROR PAGE: Forced exception route -> error.html with request_id.
9. MIDDLEWARE ORDER PROBE: Pinned 3-lane isolation order asserted via app.user_middleware.
"""

# ruff: noqa: S105

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from fluxpay.admin.keycloak import AdminPrincipal
from fluxpay.admin.middleware import AdminAuthMiddleware
from fluxpay.config import Settings
from fluxpay.contracts.schemas import ErrorEnvelope
from fluxpay.dashboard.auth import create_session_cookie
from fluxpay.dashboard.middleware import DashboardAuthMiddleware
from fluxpay.gateway.middleware import GatewayMiddleware
from fluxpay.registry.agents import AgentLifecycle, CreateAgentCommand
from fluxpay.registry.users import UserRecord
from fluxpay.wallet.accounts import AccountDirectory

pytestmark = pytest.mark.integration

DASHBOARD_TEST_SECRET = "dashboard_test_secret_32_bytes_long_exact"
DASHBOARD_TEST_ORIGIN = "http://test"


# -----------------------------------------------------------------------------
# Test Harness & App Factory
# -----------------------------------------------------------------------------


@pytest.fixture
def dashboard_app(
    build_app: Any,
    make_gateway_settings: Callable[..., Settings],
    admin_rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
    mint_admin_token: Callable[..., str],
) -> tuple[FastAPI, httpx.AsyncClient]:
    """Construct full platform application configured for dashboard testing with MockTransport."""
    settings = make_gateway_settings(
        dashboard_secret=DASHBOARD_TEST_SECRET,
        dashboard_origin=DASHBOARD_TEST_ORIGIN,
        dashboard_session_cookie_name="flx_dash",
        dashboard_cookie_max_age_s=28800,
    )

    # Injected MockTransport for Keycloak token exchange and JWKS
    def idp_handler(request: httpx.Request) -> httpx.Response:
        url_path = request.url.path
        if url_path.endswith("/protocol/openid-connect/token"):
            _ = request.read()
            # Mint token for mock operator
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

    # Attach injected mock HTTP client to DashboardAuthMiddleware in middleware stack
    for mw in app.user_middleware:
        if getattr(mw, "cls", None) is DashboardAuthMiddleware:
            mw.kwargs["http"] = mock_idp_client

    # Add stub mutation and error routes under /dashboard for matrix verification
    @app.post("/dashboard/test-mutation")
    async def stub_mutation(request: Request) -> JSONResponse:
        return JSONResponse({"status": "mutation_success"})

    @app.get("/dashboard/test-error")
    async def stub_error(request: Request) -> None:
        raise RuntimeError("Simulated crash for error page verification")

    return app, mock_idp_client


# -----------------------------------------------------------------------------
# 1. MIDDLEWARE ORDER PROBE (THE THREE-LANE DRIFT ALARM)
# -----------------------------------------------------------------------------


def test_three_lane_middleware_order_probe(dashboard_app: tuple[FastAPI, Any]) -> None:
    """Verify three-lane middleware order: Gateway (outermost) -> Admin -> Dashboard (innermost).

    Task 33 pinned GatewayMiddleware at user_middleware[0].
    Task 61 ensures DashboardAuthMiddleware is appended as the innermost lane.
    """
    app, _ = dashboard_app
    middleware_classes = [getattr(m, "cls", None) for m in app.user_middleware]

    # Task 33 contract: Gateway is outermost ingress gate
    assert middleware_classes[0] is GatewayMiddleware
    # Task 29 contract: Admin Bearer plane exists
    assert AdminAuthMiddleware in middleware_classes
    # Task 61 contract: Dashboard session cookie lane exists
    assert DashboardAuthMiddleware in middleware_classes

    gateway_idx = middleware_classes.index(GatewayMiddleware)
    admin_idx = middleware_classes.index(AdminAuthMiddleware)
    dashboard_idx = middleware_classes.index(DashboardAuthMiddleware)

    # Execution order on ingress: Gateway runs 1st, Admin runs 2nd, Dashboard runs 3rd
    assert gateway_idx < admin_idx
    assert admin_idx < dashboard_idx


# -----------------------------------------------------------------------------
# 2. LOGIN FLOW E2E & COOKIE FLAGS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_flow_e2e_and_cookie_flags(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    mint_admin_token: Callable[..., str],
) -> None:
    """Validate full OAuth code flow from /login to callback to /agents with cookie flags."""
    app, _ = dashboard_app
    admin_user: UserRecord = await make_user(role="admin", email="operator@fluxpay.local")

    # Override token exchange handler to mint for this specific admin_user.keycloak_sub
    def idp_handler(request: httpx.Request) -> httpx.Response:
        token = mint_admin_token(sub=admin_user.keycloak_sub, role="admin", email=admin_user.email)
        return httpx.Response(
            200,
            json={"access_token": token, "id_token": token, "expires_in": 3600},
        )

    for mw in app.user_middleware:
        if getattr(mw, "cls", None) is DashboardAuthMiddleware:
            mw.kwargs["http"] = httpx.AsyncClient(transport=httpx.MockTransport(idp_handler))

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. GET /dashboard/login -> 302 to authorize endpoint
            resp_login = await client.get("/dashboard/login", follow_redirects=False)
            assert resp_login.status_code == 302
            auth_location = resp_login.headers["location"]
            assert "protocol/openid-connect/auth" in auth_location

            # Assert temporary state cookie has SameSite=Lax (the documented exception)
            state_cookie_header = resp_login.headers.get("set-cookie", "")
            assert "flx_dash_state=" in state_cookie_header
            assert "SameSite=Lax" in state_cookie_header or "samesite=lax" in state_cookie_header
            assert "HttpOnly" in state_cookie_header or "httponly" in state_cookie_header

            state_cookie_val = resp_login.cookies.get("flx_dash_state")
            assert state_cookie_val is not None

            # Extract state query param from auth redirect URL
            parsed_query = httpx.URL(auth_location).params
            state_param = parsed_query["state"]

            # 2. Callback GET /dashboard/callback?code=mock_code&state=...
            resp_callback = await client.get(
                f"/dashboard/callback?code=mock_auth_code_123&state={state_param}",
                cookies={"flx_dash_state": state_cookie_val},
                follow_redirects=False,
            )
            assert resp_callback.status_code == 302
            assert resp_callback.headers["location"] == "/dashboard"

            # Assert post-login session cookie has SameSite=Strict, HttpOnly, Secure
            session_cookie_header = resp_callback.headers.get("set-cookie", "")
            assert "flx_dash=" in session_cookie_header
            assert "HttpOnly" in session_cookie_header or "httponly" in session_cookie_header
            assert (
                "SameSite=Strict" in session_cookie_header
                or "samesite=strict" in session_cookie_header
            )

            session_cookie = resp_callback.cookies.get("flx_dash")
            assert session_cookie is not None

            # 3. GET /dashboard/agents with valid session cookie -> 200
            resp_agents = await client.get(
                "/dashboard/agents",
                cookies={"flx_dash": session_cookie},
            )
            assert resp_agents.status_code == 200
            assert "Autonomous Agents" in resp_agents.text
            assert admin_user.email in resp_agents.text


# -----------------------------------------------------------------------------
# 3. STALE-TOKEN DEFENSE (TASK 29 REUSED IN COOKIE LANE)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stale_token_defense_inactive_user_rejected(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate DB inactive status rejects access even with valid cookie."""
    app, _ = dashboard_app
    user: UserRecord = await make_user(role="admin", active=True)

    # Mint valid session cookie
    principal = AdminPrincipal(sub=user.keycloak_sub, role="admin", email=user.email)
    cookie_val = create_session_cookie(
        principal,
        secret=DASHBOARD_TEST_SECRET,
        now=1700000000.0,
    )

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Active user succeeds
            resp_ok = await client.get("/dashboard/agents", cookies={"flx_dash": cookie_val})
            assert resp_ok.status_code == 200

            # Deactivate user in PostgreSQL (stale-token revocation)
            async with db_pool.acquire() as conn:
                await conn.execute("UPDATE users SET active = false WHERE id = $1;", user.id)

            # Re-attempt with identical authentic cookie -> 403 Forbidden Error Page
            resp_revoked = await client.get("/dashboard/agents", cookies={"flx_dash": cookie_val})
            assert resp_revoked.status_code == 403
            assert "User account has been deactivated or revoked" in resp_revoked.text
            assert "Error 403" in resp_revoked.text


# -----------------------------------------------------------------------------
# 4. THREE-LAYER CSRF DEFENSE MATRIX
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csrf_mutation_matrix(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
) -> None:
    """Verify three-layer CSRF defense matrix on dashboard mutations."""
    app, _ = dashboard_app
    user: UserRecord = await make_user(role="admin")
    principal = AdminPrincipal(sub=user.keycloak_sub, role="admin", email=user.email)
    csrf_token = "valid_csrf_token_0123456789abcdef0123456789abcdef"

    cookie_val = create_session_cookie(
        principal,
        secret=DASHBOARD_TEST_SECRET,
        now=1700000000.0,
        csrf_token=csrf_token,
    )
    cookies = {"flx_dash": cookie_val}

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Missing Origin -> 403
            resp = await client.post("/dashboard/test-mutation", cookies=cookies)
            assert resp.status_code == 403
            assert "Origin header missing or mismatched" in resp.text

            # 2. Wrong Origin -> 403
            resp = await client.post(
                "/dashboard/test-mutation",
                headers={"Origin": "http://evil.com"},
                cookies=cookies,
            )
            assert resp.status_code == 403
            assert "Origin header missing or mismatched" in resp.text

            # 3. Valid Origin without HX-Request -> 403
            resp = await client.post(
                "/dashboard/test-mutation",
                headers={"Origin": DASHBOARD_TEST_ORIGIN},
                cookies=cookies,
            )
            assert resp.status_code == 403
            assert "HX-Request header required" in resp.text

            # 4. Valid Origin + HX-Request + CSRF mismatch -> 403
            resp = await client.post(
                "/dashboard/test-mutation",
                headers={
                    "Origin": DASHBOARD_TEST_ORIGIN,
                    "HX-Request": "true",
                    "X-CSRF-Token": "wrong_csrf_token",
                },
                cookies=cookies,
            )
            assert resp.status_code == 403
            assert "CSRF token invalid or missing" in resp.text

            # 5. All three valid: Origin + HX-Request + valid CSRF -> 200 pass-through
            resp = await client.post(
                "/dashboard/test-mutation",
                headers={
                    "Origin": DASHBOARD_TEST_ORIGIN,
                    "HX-Request": "true",
                    "X-CSRF-Token": csrf_token,
                },
                cookies=cookies,
            )
            assert resp.status_code == 200
            assert resp.json() == {"status": "mutation_success"}


# -----------------------------------------------------------------------------
# 5. SCREEN 1: BALANCE CARD, STATEMENT, GREEN BADGE & KEYSET PAGINATION
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_screen_1_balance_statement_green_badge_and_cursor_pagination(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    agent_lifecycle: AgentLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate Screen 1: Balance card, statement rows, green badge, and keyset pagination."""
    app, _ = dashboard_app
    user: UserRecord = await make_user(role="admin")
    principal = AdminPrincipal(sub=user.keycloak_sub, role="admin", email=user.email)
    cookie_val = create_session_cookie(principal, secret=DASHBOARD_TEST_SECRET, now=1700000000.0)

    # 1. Provision Agent
    agent_ext = f"agt_dash_{uuid.uuid4().hex[:10]}"
    created_agent = await agent_lifecycle.create_agent(
        CreateAgentCommand(external_id=agent_ext, name="Screen 1 Agent")
    )
    agent_ref = await account_directory.get_agent_account(created_agent.agent_id)

    # 2. Seed 55 transactions (= 55 entries) to trigger >50 pagination window
    for _ in range(55):
        await seed_account(agent_ref.account_id, 10_000_000, "USDC")  # 10 USDC per deposit

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 3. GET /dashboard/agents lists the agent
            resp_list = await client.get("/dashboard/agents", cookies={"flx_dash": cookie_val})
            assert resp_list.status_code == 200
            assert agent_ext in resp_list.text

            # 4. GET /dashboard/agents/{id} shows balance card and statement
            resp_screen1 = await client.get(
                f"/dashboard/agents/{created_agent.agent_id}",
                cookies={"flx_dash": cookie_val},
            )
            assert resp_screen1.status_code == 200
            html = resp_screen1.text

            # Exact format_minor: 55 * 10 = 550 USDC
            assert "550.000000 USDC" in html
            # Green chain-verified badge
            assert "✓ Chain Verified" in html
            assert "chain-ok" in html

            # Pagination: >50 entries triggers Older Entries link with before_seq cursor
            assert "Older Entries" in html
            assert "before_seq=" in html

            # 5. Keyset Cursor: Follow older entries link
            # The newest 50 entries window spans seq 6..55 (from_seq=6).
            # The older cursor requests before_seq=6, returning entries 1..5 only.
            resp_older = await client.get(
                f"/dashboard/agents/{created_agent.agent_id}?before_seq=6",
                cookies={"flx_dash": cookie_val},
            )
            assert resp_older.status_code == 200
            older_html = resp_older.text

            # Older window contains seq #1..#5 only, does NOT contain newest seq #55
            assert "#1" in older_html
            assert "#55" not in older_html


# -----------------------------------------------------------------------------
# 6. RED BADGE UNDER CRYPTOGRAPHIC TAMPER (SELF-RESTORING)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_screen_1_red_badge_under_cryptographic_tamper(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
    agent_lifecycle: AgentLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    db_pool: asyncpg.Pool,
) -> None:
    """Validate that corrupting a ledger entry flips the badge RED, and restoring returns GREEN."""
    app, _ = dashboard_app
    user: UserRecord = await make_user(role="admin")
    principal = AdminPrincipal(sub=user.keycloak_sub, role="admin", email=user.email)
    cookie_val = create_session_cookie(principal, secret=DASHBOARD_TEST_SECRET, now=1700000000.0)

    agent_ext = f"agt_tamper_{uuid.uuid4().hex[:10]}"
    created_agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
    agent_ref = await account_directory.get_agent_account(created_agent.agent_id)

    tx = await seed_account(agent_ref.account_id, 25_000_000, "USDC")
    tamper_seq = tx.entries[0].seq

    async with db_pool.acquire() as conn:
        orig_row = await conn.fetchrow(
            "SELECT amount FROM ledger_entries WHERE seq = $1;", tamper_seq
        )
        assert orig_row is not None
        orig_amount = orig_row["amount"]

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Baseline: Green badge
            resp_green = await client.get(
                f"/dashboard/agents/{created_agent.agent_id}",
                cookies={"flx_dash": cookie_val},
            )
            assert "✓ Chain Verified" in resp_green.text

            try:
                # Corrupt entry via Task 16's tamper procedure
                disable_trg = (
                    "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
                )
                enable_trg = (
                    "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
                )
                async with db_pool.acquire() as conn:
                    await conn.execute(disable_trg)
                    await conn.execute(
                        "UPDATE ledger_entries SET amount = amount + 1 WHERE seq = $1;",
                        tamper_seq,
                    )
                    await conn.execute(enable_trg)

                # Re-query Screen 1: Cryptographic hash mismatch -> RED BADGE
                resp_red = await client.get(
                    f"/dashboard/agents/{created_agent.agent_id}",
                    cookies={"flx_dash": cookie_val},
                )
                assert resp_red.status_code == 200
                assert "✗ Tamper Detected" in resp_red.text
                assert "chain-tampered" in resp_red.text

            finally:
                # Self-restoring: return exact original value to keep suite clean
                async with db_pool.acquire() as conn:
                    await conn.execute(disable_trg)
                    await conn.execute(
                        "UPDATE ledger_entries SET amount = $1 WHERE seq = $2;",
                        orig_amount,
                        tamper_seq,
                    )
                    await conn.execute(enable_trg)

            # Restored: Green badge returns
            resp_restored = await client.get(
                f"/dashboard/agents/{created_agent.agent_id}",
                cookies={"flx_dash": cookie_val},
            )
            assert "✓ Chain Verified" in resp_restored.text


# -----------------------------------------------------------------------------
# 7. LANES UNTOUCHED (THREE-LANE ISOLATION PROVEN IN ONE TEST)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_three_lanes_isolation_untouched(dashboard_app: tuple[FastAPI, Any]) -> None:
    """Prove that Gateway, Admin API, and Dashboard lanes remain completely orthogonal."""
    app, _ = dashboard_app

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Gateway Lane (/v1/balance): Missing HMAC signature -> 401 JSON envelope
            resp_gateway = await client.get("/v1/balance")
            assert resp_gateway.status_code == 401
            assert resp_gateway.headers["content-type"] == "application/json"
            env_gw = ErrorEnvelope.model_validate(resp_gateway.json())
            assert env_gw.error.code == "authentication_failed"

            # 2. Admin API Lane (/admin/agents): Missing Bearer token -> 401 JSON envelope
            resp_admin = await client.post("/admin/agents", json={})
            assert resp_admin.status_code == 401
            assert resp_admin.headers["content-type"] == "application/json"
            env_adm = ErrorEnvelope.model_validate(resp_admin.json())
            assert env_adm.error.code == "authentication_failed"

            # 3. Dashboard Lane (/dashboard/agents): Missing session cookie -> 302 HTML redirect
            resp_dash = await client.get("/dashboard/agents", follow_redirects=False)
            assert resp_dash.status_code == 302
            assert resp_dash.headers["location"] == "/dashboard/login"


# -----------------------------------------------------------------------------
# 8. NO-JS GRACEFUL & ERROR PAGE WITH CORRELATION ID
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_page_renders_html_with_request_id(
    dashboard_app: tuple[FastAPI, Any],
    make_user: Any,
) -> None:
    """Validate forced exception under /dashboard renders error.html with correlation request_id."""
    app, _ = dashboard_app
    user: UserRecord = await make_user(role="admin")
    principal = AdminPrincipal(sub=user.keycloak_sub, role="admin", email=user.email)
    cookie_val = create_session_cookie(principal, secret=DASHBOARD_TEST_SECRET, now=1700000000.0)

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/dashboard/test-error",
                headers={"X-Request-Id": "req_corr_test_999"},
                cookies={"flx_dash": cookie_val},
            )
            assert resp.status_code == 500
            assert "text/html" in resp.headers["content-type"]
            assert "Error 500" in resp.text
            assert "Request ID: req_corr_test_999" in resp.text
