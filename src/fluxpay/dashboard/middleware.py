"""Dashboard Authentication and Security Middleware (Block L).

=============================================================================
ARCHITECTURAL DESIGN & SECURITY LAWS
=============================================================================

1. THE NEVER-MERGE DOCTRINE:
   This middleware is strictly isolated to the `/dashboard` lane. It never interacts
   with the `/v1/*` gateway lane (GatewayMiddleware) or `/admin/*` API lane
   (AdminAuthMiddleware). Non-dashboard paths immediately pass through without any
   evaluation or state mutation.

2. THE SAMESITE=LAX EXCEPTION ON THE STATE COOKIE:
   Standard session cookies use SameSite=Strict to defend against CSRF. However,
   when returning from Keycloak's authorization endpoint to `/dashboard/callback`,
   the browser performs a top-level cross-site GET redirect. If the temporary state
   cookie were SameSite=Strict, the browser would omit it on callback arrival, breaking
   the OAuth handshake. The temporary state cookie uses SameSite=Lax (the ONE documented
   exception in the platform). The post-login session cookie uses SameSite=Strict.

3. THE THREE-LAYER CSRF LAW FOR MUTATIONS:
   Every state-changing mutation (POST, PUT, DELETE, PATCH) under `/dashboard` must satisfy:
   - Layer 1: Valid Origin header matching settings.dashboard_origin exactly.
   - Layer 2: Valid `HX-Request: true` header indicating an interactive htmx client.
   - Layer 3: Double-submit CSRF token matching the authenticated session's CSRF token.
   State-changing GET requests are strictly forbidden by template design.

4. DEFENSE-IN-DEPTH STALE-TOKEN DEFENSE (TASK 29 REUSED):
   Even if an operator presents a valid, cryptographically authentic session cookie,
   every request queries `users.get_by_keycloak_sub()` to confirm `user.active is True`.
   If an administrator is deactivated in PostgreSQL, their dashboard access is terminated
   immediately, with zero latency and no need to wait for cookie expiration.
"""

from __future__ import annotations

import hmac
import time
import uuid
from collections.abc import Callable

import httpx
import structlog
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from fluxpay.admin.keycloak import KeycloakVerifier
from fluxpay.dashboard.auth import (
    build_authorize_url,
    create_oauth_state_cookie_value,
    create_session_cookie,
    exchange_code,
    generate_pkce,
    generate_signed_state,
    read_oauth_state_cookie_value,
    read_session_cookie,
)
from fluxpay.dashboard.views import templates as default_templates
from fluxpay.registry.users import UserRepo

logger = structlog.get_logger(__name__)

__all__ = [
    "DashboardAuthMiddleware",
]


class DashboardAuthMiddleware(BaseHTTPMiddleware):
    """Lane 3: Dashboard session authentication and CSRF protection middleware."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: KeycloakVerifier,
        users: UserRepo,
        secret: str,
        cookie_name: str = "flx_dash",
        max_age_s: int = 28800,
        origin: str = "http://localhost:8000",
        http: httpx.AsyncClient | None = None,
        now: Callable[[], float] = time.time,
        clock: Callable[[], float] | None = None,
        client_id: str = "fluxpay-dashboard",
        client_secret: str | None = None,
        issuer: str | None = None,
        templates: Jinja2Templates | None = None,
    ) -> None:
        super().__init__(app)
        self._verifier = verifier
        self._users = users
        self._secret = secret
        self._cookie_name = cookie_name
        self._max_age_s = max_age_s
        self._origin = origin.rstrip("/")
        self._http_client = http or httpx.AsyncClient()
        self._now = clock or now
        self._client_id = client_id
        self._client_secret = client_secret
        self._templates = templates or default_templates

        # Resolve issuer from verifier or explicit argument
        resolved_issuer = (
            issuer or getattr(verifier, "_issuer", None) or getattr(verifier, "issuer", None)
        )
        self._issuer = (
            str(resolved_issuer) if resolved_issuer else "https://auth.fluxpay.local/realms/fluxpay"
        )

    def _render_error(
        self,
        request: Request,
        *,
        status_code: int,
        title: str,
        message: str,
    ) -> HTMLResponse:
        """Render minimal error HTML page preserving request correlation ID."""
        request_id = (
            request.headers.get("x-request-id")
            or getattr(request.state, "request_id", None)
            or str(uuid.uuid4())
        )
        context = {
            "request": request,
            "status_code": status_code,
            "title": title,
            "message": message,
            "request_id": request_id,
            "principal": getattr(request.state, "principal", None),
            "csrf_token": getattr(request.state, "csrf_token", ""),
        }
        return self._templates.TemplateResponse(
            request, "error.html", context, status_code=status_code
        )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Enforce strict dashboard cookie authentication and CSRF boundary."""
        path = request.url.path

        # ---------------------------------------------------------------------
        # Non-dashboard paths immediately pass through (Never-Merge Doctrine)
        # ---------------------------------------------------------------------
        if not path.startswith("/dashboard"):
            return await call_next(request)

        # Fail loudly if dashboard secret is unconfigured (Task 49 disabled law)
        if not self._secret:
            return self._render_error(
                request,
                status_code=503,
                title="Service Unavailable",
                message="Admin dashboard is disabled: FLX_DASHBOARD_SECRET is not configured.",
            )

        # ---------------------------------------------------------------------
        # Unauthenticated OIDC Handshake Endpoints
        # ---------------------------------------------------------------------
        if path == "/dashboard/login" and request.method == "GET":
            verifier, challenge = generate_pkce()
            signed_state = generate_signed_state(secret=self._secret, now=self._now())
            nonce = str(uuid.uuid4())
            redirect_uri = f"{self._origin}/dashboard/callback"

            auth_url = build_authorize_url(
                issuer=self._issuer,
                client_id=self._client_id,
                redirect_uri=redirect_uri,
                state=signed_state,
                nonce=nonce,
                code_challenge=challenge,
            )

            state_cookie_val = create_oauth_state_cookie_value(
                state=signed_state,
                code_verifier=verifier,
                secret=self._secret,
                now=self._now(),
            )

            response = RedirectResponse(url=auth_url, status_code=302)
            # WHY SameSite=Lax: Required so the browser includes this state cookie when
            # Keycloak performs a top-level cross-site GET redirect back to /dashboard/callback.
            response.set_cookie(
                key=f"{self._cookie_name}_state",
                value=state_cookie_val,
                max_age=300,
                path="/dashboard/callback",
                httponly=True,
                secure=True,
                samesite="lax",
            )
            return response

        if path == "/dashboard/callback" and request.method == "GET":
            code = request.query_params.get("code")
            state = request.query_params.get("state")
            if not code or not state:
                return self._render_error(
                    request,
                    status_code=400,
                    title="Bad Request",
                    message="Missing code or state parameter in OAuth callback.",
                )

            raw_state_cookie = request.cookies.get(f"{self._cookie_name}_state")
            if not raw_state_cookie:
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="Missing or expired OAuth state cookie.",
                )

            verified_data = read_oauth_state_cookie_value(
                raw_state_cookie,
                secret=self._secret,
                now=self._now(),
            )
            if verified_data is None:
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="Invalid or expired OAuth state parameter.",
                )

            cookie_state, code_verifier = verified_data
            if not hmac.compare_digest(cookie_state, state):
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="OAuth state mismatch detected.",
                )

            token_url = f"{self._issuer.rstrip('/')}/protocol/openid-connect/token"
            redirect_uri = f"{self._origin}/dashboard/callback"
            try:
                tokens = await exchange_code(
                    http_client=self._http_client,
                    token_url=token_url,
                    code=code,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                    client_id=self._client_id,
                    client_secret=self._client_secret,
                )
            except Exception as exc:
                logger.warning("dashboard_token_exchange_failed", error=str(exc))
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="OIDC token exchange failed.",
                )

            try:
                principal = await self._verifier.verify(tokens["access_token"])
            except ValueError as exc:
                logger.warning("dashboard_token_verification_failed", error=str(exc))
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="OIDC token verification failed.",
                )

            # Stage 3: Defense-in-Depth Local User Row Verification (Stale-Token Defense)
            user_record = await self._users.get_by_keycloak_sub(principal.sub)
            if user_record is None or not user_record.active:
                logger.warning(
                    "dashboard_user_deactivated_or_absent",
                    sub=principal.sub,
                    found=user_record is not None,
                )
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="User account is inactive or not found.",
                )

            # Issue signed session cookie
            csrf_token = str(uuid.uuid4().hex)
            session_cookie = create_session_cookie(
                principal,
                secret=self._secret,
                now=self._now(),
                max_age_s=self._max_age_s,
                csrf_token=csrf_token,
            )

            response = RedirectResponse(url="/dashboard", status_code=302)
            response.set_cookie(
                key=self._cookie_name,
                value=session_cookie,
                max_age=self._max_age_s,
                path="/dashboard",
                httponly=True,
                secure=True,
                samesite="strict",
            )
            response.delete_cookie(
                key=f"{self._cookie_name}_state",
                path="/dashboard/callback",
            )
            return response

        if path == "/dashboard/logout":
            response = RedirectResponse(url="/dashboard/login", status_code=302)
            response.delete_cookie(key=self._cookie_name, path="/dashboard")
            return response

        # ---------------------------------------------------------------------
        # Authenticated Operator Paths (/dashboard/*)
        # ---------------------------------------------------------------------
        raw_cookie = request.cookies.get(self._cookie_name)
        session = (
            read_session_cookie(raw_cookie, secret=self._secret, now=self._now())
            if raw_cookie
            else None
        )

        if session is None:
            return RedirectResponse(url="/dashboard/login", status_code=302)

        # Defense-in-depth: Re-verify user active status in PostgreSQL on every request
        user_record = await self._users.get_by_keycloak_sub(session.principal.sub)
        if user_record is None or not user_record.active:
            logger.warning(
                "dashboard_active_session_revoked_by_db",
                sub=session.principal.sub,
            )
            return self._render_error(
                request,
                status_code=403,
                title="Forbidden",
                message="User account has been deactivated or revoked.",
            )

        request.state.principal = session.principal
        request.state.csrf_token = session.csrf_token

        # ---------------------------------------------------------------------
        # Mutation Guard: Three-Layer CSRF Defense
        # ---------------------------------------------------------------------
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # Layer 1: Origin Header Allowlist Check
            origin = request.headers.get("origin")
            if not origin or origin.rstrip("/") != self._origin:
                logger.warning("dashboard_csrf_origin_mismatch", origin=origin)
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="Mutation rejected: Origin header missing or mismatched.",
                )

            # Layer 2: Mandatory HX-Request Header (Interactive Client Proof)
            hx_req = request.headers.get("hx-request")
            if not hx_req or hx_req.lower() != "true":
                logger.warning("dashboard_csrf_missing_hx_request")
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="Mutation rejected: HX-Request header required.",
                )

            # Layer 3: Double-Submit CSRF Token Verification
            token = request.headers.get("x-csrf-token")
            if not token:
                try:
                    form = await request.form()
                    token = form.get("csrf_token")  # type: ignore[assignment]
                except Exception:
                    token = None

            if not token or not hmac.compare_digest(str(token), session.csrf_token):
                logger.warning("dashboard_csrf_token_mismatch")
                return self._render_error(
                    request,
                    status_code=403,
                    title="Forbidden",
                    message="Mutation rejected: CSRF token invalid or missing.",
                )

        try:
            return await call_next(request)
        except Exception as exc:
            logger.exception("dashboard_unhandled_route_error", error=str(exc))
            return self._render_error(
                request,
                status_code=500,
                title="Internal Server Error",
                message="An unexpected error occurred while rendering the dashboard.",
            )
