"""Mandatory security pipeline middleware for FluxPay agent gateway.

Blueprint §3 Pipeline (Frozen Order):
Stage 0: CONTEXT           — request_id generated, bound to ContextVar; cleared in finally.
Stage 1: SCOPE             — Non-/v1/ paths pass through to call_next untouched.
Stage 2: QUERY REJECTION   — Reject query strings on signed endpoints (bug-farm elimination).
Stage 3: AUTH PARSE        — FLXP1 Authorization header parsed, UUID validated, agent resolved.
Stage 4: FRESHNESS         — Stateless ±30s replay window checked against injected clock.
Stage 5: HMAC              — Raw body read (cached by BaseHTTPMiddleware) and HMAC verified.
Stage 6: BODY SIZE         — Enforce MAX_BODY_BYTES (64 KiB) limit (422 validation_failed).
Stage 7: NONCE + GATE      — Nonce validated; atomic Lua executes anti-replay, rate, quota.
Stage 8: IDEMPOTENCY       — Presence and syntax check on POST requests.
Stage 9: HANDOVER          — request.state.agent and request_id set; handler invoked.

All downstream handlers are BY CONSTRUCTION unreachable for unauthenticated traffic.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable
from uuid import UUID

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from fluxpay.config import Settings
from fluxpay.gateway import canonical
from fluxpay.gateway.canonical import (
    HEADER_AUTH,
    HEADER_IDEMPOTENCY,
    HEADER_NONCE,
    HEADER_TIMESTAMP,
    parse_authorization,
    sha256_hex,
    validate_idempotency_key,
    validate_nonce,
    validate_timestamp,
)
from fluxpay.gateway.gate import GateRunner, run_gate
from fluxpay.gateway.idempotency import (
    FastPathOutcome,
    IdempotencyFastPath,
    parse_response,
)
from fluxpay.shared.errors import (
    AuthenticationError,
    IdempotencyConflict,
    RateLimitError,
    ReplayError,
    ValidationError,
    as_fluxpay_error,
)
from fluxpay.shared.logging import (
    bind_request_context,
    clear_request_context,
    get_logger,
    new_request_id,
)
from fluxpay.shared.metrics import FLX_HTTP_REQUEST_SECONDS, FLX_HTTP_REQUESTS_TOTAL
from fluxpay.shared.vault import SecretBytes

__all__ = [
    "HEADER_REQUEST_ID",
    "MAX_BODY_BYTES",
    "SIGNED_PREFIX",
    "AgentResolver",
    "AuthenticatedAgent",
    "GatewayMiddleware",
    "error_response",
]

logger = get_logger("fluxpay.gateway.middleware")

# Route prefix for signed gateway API endpoints
SIGNED_PREFIX: Final[str] = "/v1/"

# Maximum request body size allowed (64 KiB)
MAX_BODY_BYTES: Final[int] = 64 * 1024

# Request ID correlation header attached to all HTTP responses
HEADER_REQUEST_ID: Final[str] = "X-FLX-Request-Id"


@dataclass(frozen=True, slots=True)
class AuthenticatedAgent:
    """Authenticated agent identity and effective limits passed to downstream handlers.

    Limits are effective per-agent values computed by Task 23 / 28; middleware passes them
    through directly to the atomic gate. Rate window length is global configuration.
    """

    agent_id: UUID
    external_id: str
    secret: SecretBytes
    rate_limit_max: int
    daily_quota_max: int


@runtime_checkable
class AgentResolver(Protocol):
    """Protocol seam for agent authentication and effective limit resolution.

    WHY a Protocol not a repo import:
    Middleware must not know about caching, database sessions, or registry internals
    (dependency inversion principle). Gateway integration tests run without PostgreSQL.
    Task 23 provides the production database + Redis cache implementation.
    """

    async def resolve(self, agent_id: UUID) -> AuthenticatedAgent | None:
        """Resolve an agent by UUID, returning its authenticated credentials or None."""
        ...


def error_response(exc: Exception, request_id: str | None = None) -> JSONResponse:
    """Map any domain, platform, or unhandled exception to a frozen client JSONResponse.

    WHY central:
    Guarantees the uniform wire payload shape {"error": {code, message, retryable}}
    for the entire API. Unexpected internal errors are converted to InternalError
    via as_fluxpay_error, preventing leakage of sensitive exception traces or SQL details.
    """
    flx_err = as_fluxpay_error(exc)
    headers: dict[str, str] = {}
    if request_id is not None:
        headers[HEADER_REQUEST_ID] = request_id
    return JSONResponse(
        status_code=flx_err.status,
        content=flx_err.to_payload(),
        headers=headers if headers else None,
    )


class GatewayMiddleware(BaseHTTPMiddleware):
    """Mandatory security pipeline middleware for all signed FluxPay API traffic.

    WHY BaseHTTPMiddleware:
    Known overhead (~µs task-group) vs pure-ASGI; Phase 1 headroom is 500x (Blueprint §0);
    readability + the body-cache semantics we depend on win.
    Revisit trigger: gateway p99 > 5ms at <10% CPU (Task 69 measures).
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        resolver: AgentResolver,
        runner: GateRunner,
        settings: Settings,
        clock: Callable[[], float] = time.time,
        fastpath: IdempotencyFastPath | None = None,
    ) -> None:
        super().__init__(app)
        self._resolver: AgentResolver = resolver
        self._runner: GateRunner = runner
        self._settings: Settings = settings
        self._clock: Callable[[], float] = clock
        self._fastpath: IdempotencyFastPath | None = fastpath

    def _is_signed_route(self, request: Request) -> bool:
        """Stage 1 — SCOPE: Determine if path requires FLXP1 signed authentication.

        WHY:
        Routes outside SIGNED_PREFIX ("/v1/") such as /healthz, /docs, or admin-plane
        endpoints belong to separate authentication lanes (e.g. Keycloak, Task 29)
        or are unauthenticated liveness probes.
        WHY constant not config: route scope is a deployment shape, not a tunable.
        """
        return request.url.path.startswith(SIGNED_PREFIX)

    def _reject_query_string(self, request: Request) -> None:
        """Stage 2 — QUERY-STRING REJECTION: Forbid query strings on signed endpoints.

        WHY:
        The FLXP1 signature covers PATH only. Query strings are canonicalization
        bug-farms across web clients, proxies, and runtimes. The protocol scheme
        deleted the problem entirely by forbidding query strings; the middleware
        enforces this deletion.
        """
        if request.url.query:
            raise AuthenticationError(
                details={"reason": "query_strings_forbidden"},
                message="Query strings are forbidden on signed endpoints.",
            )

    async def _parse_and_resolve_auth(
        self, request: Request, request_id: str
    ) -> tuple[AuthenticatedAgent, str]:
        """Stage 3 — AUTH PARSE: Parse FLXP1 header, resolve agent, and bind logging context.

        WHY:
        Validates authorization header grammar and verifies agent identity before
        any stateful checks. Binds agent_id into structlog ContextVar immediately
        so all subsequent pipeline decisions and errors are correlated.
        """
        auth_header = request.headers.get(HEADER_AUTH)
        if not auth_header:
            raise AuthenticationError(
                details={"reason": "missing_authorization_header"},
                message="Missing Authorization header.",
            )

        try:
            agent_uuid_str, sig = parse_authorization(auth_header)
        except ValueError as exc:
            raise AuthenticationError(details={"reason": "malformed_authorization_header"}) from exc

        try:
            agent_id = UUID(agent_uuid_str)
        except ValueError as exc:
            raise AuthenticationError(details={"reason": "invalid_agent_uuid"}) from exc

        agent = await self._resolver.resolve(agent_id)
        if agent is None or getattr(agent, "is_active", True) is False:
            raise AuthenticationError(
                details={"reason": "agent_not_found_or_inactive"},
                message="Authenticated agent not found or inactive.",
            )

        bind_request_context(request_id, str(agent.agent_id))
        return agent, sig

    def _check_freshness(self, request: Request) -> tuple[int, str]:
        """Stage 4 — FRESHNESS: Enforce stateless timestamp freshness window.

        WHY:
        Stateless timestamp check kills 99% of replay attempts with ZERO Redis
        cost. The Redis nonce tombstone handles the remaining within-window replays.
        Strict > comparison: equal to window bound passes (a 30.000s-old signature
        is inside the contract).
        """
        ts_str = request.headers.get(HEADER_TIMESTAMP)
        if not ts_str:
            raise AuthenticationError(
                details={"reason": "missing_timestamp_header"},
                message="Missing X-FLX-Timestamp header.",
            )

        try:
            validate_timestamp(ts_str)
        except ValueError as exc:
            raise AuthenticationError(details={"reason": "invalid_timestamp_header"}) from exc

        now_ms = int(self._clock() * 1000)
        ts_ms = int(ts_str)
        if abs(now_ms - ts_ms) > self._settings.replay_window_ms:
            raise ReplayError(
                details={
                    "reason": "timestamp_outside_replay_window",
                    "now_ms": str(now_ms),
                    "ts_ms": str(ts_ms),
                    "window_ms": str(self._settings.replay_window_ms),
                }
            )
        return now_ms, ts_str

    def _verify_hmac(
        self,
        request: Request,
        agent: AuthenticatedAgent,
        sig: str,
        ts_str: str,
        raw_body: bytes,
    ) -> None:
        """Stage 5 — HMAC: Verify cryptographic signature over raw body and canonical fields.

        WHY after freshness:
        Ordering saves HMAC CPU cycles on stale floods.
        WHY body read here:
        BaseHTTPMiddleware caches request._body so downstream handlers read the
        IDENTICAL bytes received on the wire.
        """
        nonce = request.headers.get(HEADER_NONCE, "")
        if not canonical.verify(
            secret=agent.secret,
            provided_sig=sig,
            method=request.method,
            path=request.url.path,
            timestamp=ts_str,
            nonce=nonce,
            body=raw_body,
        ):
            raise AuthenticationError(
                details={"reason": "signature_verification_failed"},
                message="HMAC signature verification failed.",
            )

    def _check_body_size(self, raw_body: bytes) -> None:
        """Stage 6 — BODY SIZE: Enforce maximum payload size on authenticated requests.

        WHY:
        Bounds memory consumption against payload-bloat attacks.
        WHY 422 not 413:
        Frozen taxonomy maps client schema/constraint mistakes to validation_failed.
        Task 24 OpenAPI specification documents the 64 KiB maximum body size.
        """
        if len(raw_body) >= MAX_BODY_BYTES:
            raise ValidationError(
                details={
                    "reason": "body_size_exceeded",
                    "size_bytes": str(len(raw_body)),
                    "max_bytes": str(MAX_BODY_BYTES),
                },
                message="Request payload exceeds maximum allowed size.",
            )

    async def _enforce_gate(
        self,
        request: Request,
        agent: AuthenticatedAgent,
        now_ms: int,
    ) -> None:
        """Stage 7 — NONCE + GATE: Atomic anti-replay, rate limit, and daily quota check.

        WHY:
        Executes single atomic Lua script in Valkey. Validates nonce format first
        (malformed nonce is a signing scheme error, not a rate event).
        GateUnavailable propagates as 503 retryable (fail-closed security).
        Replay returns ReplayError (401); rate limit or quota exceeded returns
        RateLimitError (429 with generic message; quota internals are internal only).
        """
        nonce = request.headers.get(HEADER_NONCE)
        if not nonce:
            raise AuthenticationError(
                details={"reason": "missing_nonce_header"},
                message="Missing X-FLX-Nonce header.",
            )

        try:
            validate_nonce(nonce)
        except ValueError as exc:
            raise AuthenticationError(details={"reason": "malformed_nonce"}) from exc

        gate_result = await run_gate(
            self._runner,
            agent_id=str(agent.agent_id),
            nonce=nonce,
            now_ms=now_ms,
            window_ms=self._settings.rate_limit_window_ms,
            rate_max=agent.rate_limit_max,
            nonce_ttl_ms=self._settings.nonce_ttl_ms,
            daily_max=agent.daily_quota_max,
            day_ttl_s=90000,
        )

        if gate_result.replayed:
            raise ReplayError(
                details={"reason": "nonce_replayed", "nonce": nonce},
            )
        if gate_result.rate_limited:
            raise RateLimitError(
                details={
                    "reason": "rate_limit_exceeded",
                    "rate_count": str(gate_result.rate_count),
                    "rate_max": str(agent.rate_limit_max),
                }
            )
        if gate_result.quota_exceeded:
            raise RateLimitError(
                details={
                    "reason": "daily_quota_exceeded",
                    "quota_used": str(gate_result.quota_used),
                    "daily_max": str(agent.daily_quota_max),
                }
            )

    def _check_idempotency_presence(self, request: Request) -> None:
        """Stage 8 — IDEMPOTENCY PRESENCE: Validate key presence and format on POST requests.

        WHY:
        All mutating operations (POST writes) require an idempotency key before
        reaching business handlers. Task 22 will insert the fast-path cache lookup
        and distributed lock acquisition immediately following this presence check.
        """
        if request.method.upper() == "POST":
            idem_key = request.headers.get(HEADER_IDEMPOTENCY)
            if not idem_key:
                raise ValidationError(
                    details={"reason": "missing_idempotency_key"},
                    message="Missing required X-FLX-Idempotency-Key header on POST request.",
                )
            try:
                validate_idempotency_key(idem_key)
            except ValueError as exc:
                raise ValidationError(
                    details={"reason": "invalid_idempotency_key"},
                    message="Invalid X-FLX-Idempotency-Key header format.",
                ) from exc

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Execute the mandatory frozen security pipeline in strict order."""
        # Stage 0 — CONTEXT: Initialize request correlation before anything else
        # WHY first: even a 401 must be correlatable in logs (Loki query by request_id)
        _start_time = time.perf_counter()
        response: Response | None = None
        request_id = new_request_id()
        bind_request_context(request_id)

        try:
            # Stage 1 — SCOPE: Pass through unauthenticated routes
            if not self._is_signed_route(request):
                response = await call_next(request)
                response.headers[HEADER_REQUEST_ID] = request_id
                return response

            # Stage 2 — QUERY-STRING REJECTION: Delete query parameter attack surface
            self._reject_query_string(request)

            # Stage 3 — AUTH PARSE: Parse authorization header and resolve agent
            agent, sig = await self._parse_and_resolve_auth(request, request_id)

            # Stage 4 — FRESHNESS: Stateless ±30s freshness window check
            now_ms, ts_str = self._check_freshness(request)

            # Stage 5 — HMAC: Verify cryptographic signature over raw body and canonical fields
            raw_body = await request.body()
            self._verify_hmac(request, agent, sig, ts_str, raw_body)

            # Stage 6 — BODY SIZE: Enforce maximum request body size limit
            self._check_body_size(raw_body)

            # Stage 7 — NONCE + GATE: Atomic anti-replay, rate limit, and daily quota check
            await self._enforce_gate(request, agent, now_ms)

            # Stage 8 — IDEMPOTENCY PRESENCE: Validate key presence on mutating verbs
            self._check_idempotency_presence(request)
            # --- Task 22 insertion point (idempotency fast-path cache check / lock acquisition)
            # --- Task 22 append
            if self._fastpath is not None and request.method.upper() == "POST":
                idem_key = request.headers[HEADER_IDEMPOTENCY]
                agent_id_str = str(agent.agent_id)
                body_hash = sha256_hex(raw_body)

                outcome, cached = await self._fastpath.begin(agent_id_str, idem_key, body_hash)

                if outcome == FastPathOutcome.REPLAY_CACHED:
                    if cached is None:
                        raise IdempotencyConflict(
                            details={"reason": "cached_response_missing", "idem_key": idem_key}
                        )
                    status_code, body = parse_response(cached)
                    response = Response(
                        content=body,
                        status_code=status_code,
                        media_type="application/json",
                        headers={
                            HEADER_REQUEST_ID: request_id,
                            "X-FLX-Idempotent-Replay": "true",
                        },
                    )
                    return response

                if outcome in (FastPathOutcome.IN_PROGRESS, FastPathOutcome.CONFLICT):
                    raise IdempotencyConflict(
                        details={
                            "agent_id": agent_id_str,
                            "idem_key": idem_key,
                            "outcome": outcome.value,
                        }
                    )

                # FastPathOutcome.PROCEED: execute downstream handler
                request.state.agent = agent
                request.state.request_id = request_id

                lock_held = True
                try:
                    response = await call_next(request)
                    raw_response_body = b""
                    body_iter = getattr(response, "body_iterator", None)
                    if body_iter is not None:
                        async for chunk in body_iter:
                            if isinstance(chunk, (bytes, bytearray)):
                                raw_response_body += bytes(chunk)
                            elif isinstance(chunk, str):
                                raw_response_body += chunk.encode("utf-8")
                    elif hasattr(response, "body"):
                        body_val = response.body
                        if isinstance(body_val, (bytes, bytearray)):
                            raw_response_body = bytes(body_val)

                    response = Response(
                        content=raw_response_body,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type=response.media_type,
                    )
                    response.headers[HEADER_REQUEST_ID] = request_id

                    if 200 <= response.status_code <= 299:
                        await self._fastpath.finish(
                            agent_id_str,
                            idem_key,
                            status=response.status_code,
                            body=raw_response_body,
                        )
                    else:
                        await self._fastpath.release(agent_id_str, idem_key)
                    lock_held = False
                    return response
                finally:
                    if lock_held:
                        await self._fastpath.release(agent_id_str, idem_key)

            # Stage 9 — HANDOVER: Attach authenticated state and invoke downstream handler
            request.state.agent = agent
            request.state.request_id = request_id
            response = await call_next(request)
            response.headers[HEADER_REQUEST_ID] = request_id
            return response

        except Exception as exc:
            flx_err = as_fluxpay_error(exc)
            logger.warning(
                "gateway_security_rejected",
                error_code=flx_err.code,
                status_code=flx_err.status,
                path=request.url.path,
                method=request.method,
            )
            response = error_response(exc, request_id=request_id)
            response.headers[HEADER_REQUEST_ID] = request_id
            return response
        finally:
            # --- Task 69 append ---
            if response is not None:
                _r = getattr(request.scope.get("route"), "path", request.url.path)
                FLX_HTTP_REQUESTS_TOTAL.labels(
                    method=request.method, route=_r, status=str(response.status_code)
                ).inc()
                FLX_HTTP_REQUEST_SECONDS.labels(route=_r).observe(
                    max(0.0, time.perf_counter() - _start_time)
                )
            clear_request_context()
