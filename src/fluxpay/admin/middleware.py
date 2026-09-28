"""Admin lane authentication and defense-in-depth authorization middleware.

Blueprint §4 Keycloak Identity Broker, RBAC & §5 System Audit.

=============================================================================
SECURITY & MIDDLEWARE DESIGN DECISIONS (WHY THE SYSTEM IS BUILT THIS WAY)
=============================================================================

1. WHY TWO MIDDLEWARE, NOT ONE (LANE SEPARATION DOCTRINE):
----------------------------------------------------------
FluxPay operates two distinct architectural lanes:
- The Agent Payment Gateway Lane (/v1/): High-throughput machine-to-machine financial
  traffic authenticated via custom FLXP1 HMAC-SHA256 signatures, millisecond freshness
  replay checks, and atomic Valkey rate/quota gates (Task 21).
- The Admin Plane Lane (/admin/): Low-frequency human and management traffic authenticated
  via standard OIDC Bearer JWTs, JWKS signature verification, and database-level role anchors.

Merging these two distinct auth models into a single "universal" middleware would create
a complex conditional state machine riddled with edge cases, branching hazards, and security
audit blind spots. Two separate middlewares ensure absolute lane separation: zero FLXP1 code
in the admin lane, zero Keycloak code in the payment lane, and independent, isolated testability.

2. WHY DEFENSE-IN-DEPTH STALE-REVOCATION DEFENSE (IdP TOKEN + DB CHECK):
------------------------------------------------------------------------
Stateless JWT verification has a well-known vulnerability: revocation lag. An identity
provider (Keycloak) mints cryptographically valid tokens with a standard lifetime (typically
5 to 15 minutes). If a compromised operator, disgruntled employee, or misconfigured account
is terminated or deactivated, their JWT remains technically valid until expiration.
Admin mutations (minting secrets, adjusting limits, suspending agents) are the most dangerous
surface of the platform. We cannot tolerate 5 minutes of rogue access.
By checking the authoritative PostgreSQL `users` table on EVERY administrative request:
- If the user row is missing from the database -> REJECT with ForbiddenError (403).
- If the user's `active` flag is False -> REJECT with ForbiddenError (403).
Revocation is instantaneous and engine-anchored, eliminating the IdP revocation window.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp
from structlog.contextvars import bind_contextvars

from fluxpay.admin.keycloak import KeycloakVerifier
from fluxpay.gateway.middleware import HEADER_REQUEST_ID, error_response
from fluxpay.registry.users import UserRepo
from fluxpay.shared.errors import AuthenticationError, ForbiddenError
from fluxpay.shared.logging import (
    bind_request_context,
    clear_request_context,
    get_logger,
    new_request_id,
)

__all__ = [
    "ADMIN_PREFIX",
    "AdminAuthMiddleware",
]

logger = get_logger("fluxpay.admin.middleware")

# Route prefix for administrative plane API endpoints
ADMIN_PREFIX: Final[str] = "/admin"


class AdminAuthMiddleware(BaseHTTPMiddleware):
    """Mandatory security boundary guard for all administrative plane requests."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: KeycloakVerifier,
        users: UserRepo,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Initialize AdminAuthMiddleware with verifier, user repo, and injected clock."""
        super().__init__(app)
        self._verifier: KeycloakVerifier = verifier
        self._users: UserRepo = users
        self._clock: Callable[[], float] = clock

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Execute admin authentication pipeline or pass through non-admin paths."""
        path = request.url.path

        # Non-admin requests (e.g. /v1/ payment traffic, health checks) pass through untouched
        if not path.startswith(ADMIN_PREFIX):
            return await call_next(request)

        # Stage 0: Context binding (Request correlation ID)
        request_id = new_request_id()
        bind_request_context(request_id)

        try:
            # Stage 1: Authorization Header Extraction & Strict Bearer Parsing
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return error_response(
                    AuthenticationError(message="Missing Authorization header"),
                    request_id=request_id,
                )

            parts = auth_header.split(" ", 1)
            if len(parts) != 2 or parts[0] != "Bearer" or not parts[1].strip():
                return error_response(
                    AuthenticationError(message="Invalid Authorization header format"),
                    request_id=request_id,
                )

            token = parts[1].strip()

            # Stage 2: Stateless Cryptographic Verification via KeycloakVerifier
            try:
                principal = await self._verifier.verify(token)
            except ValueError as exc:
                defect_class = str(exc)
                logger.warning(
                    "admin_token_verification_failed",
                    defect_class=defect_class,
                    path=path,
                )
                if defect_class == "missing role":
                    return error_response(
                        ForbiddenError(message="insufficient permissions"),
                        request_id=request_id,
                    )
                return error_response(
                    AuthenticationError(
                        message="Authentication credentials were missing or invalid."
                    ),
                    request_id=request_id,
                )

            # Stage 3: Defense-in-Depth Local User Row Verification (Stale-Revocation Protection)
            # WHY: IdP token says YES, but local PostgreSQL user row has the ultimate veto.
            # If the user is deactivated or deleted locally, access is denied immediately
            # without waiting for Keycloak JWT expiration.
            user_record = await self._users.get_by_keycloak_sub(principal.sub)
            if user_record is None or not user_record.active:
                logger.warning(
                    "admin_revoked_or_absent_user_denied",
                    keycloak_sub=principal.sub,
                    user_found=user_record is not None,
                    is_active=user_record.active if user_record else False,
                )
                return error_response(
                    ForbiddenError(message="insufficient permissions"),
                    request_id=request_id,
                )

            # Stage 4: Handover & Context Enrichment
            request.state.principal = principal
            bind_contextvars(
                actor_sub=principal.sub,
                actor_role=principal.role,
            )

            response = await call_next(request)
            response.headers[HEADER_REQUEST_ID] = request_id
            return response

        except Exception as exc:
            return error_response(exc, request_id=request_id)
        finally:
            clear_request_context()
