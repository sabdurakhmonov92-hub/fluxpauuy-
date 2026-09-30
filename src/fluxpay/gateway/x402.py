"""x402 payment authorization middleware for FastAPI / Starlette (RFC 7231 & EIP-3009).

Enables autonomous AI agents to pay for HTTP resources using USDC on Base L2 via
gasless EIP-3009 transfer authorizations and facilitator settlement.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import inspect
import json
import time
from decimal import Decimal
from typing import Any, Final, overload
from uuid import NAMESPACE_OID, uuid5

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Histogram
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp
from web3 import Web3

from fluxpay.gateway.x402_config import X402Config
from fluxpay.gateway.x402_eip3009 import (
    build_eip712_domain,
    normalize_nonce,
    validate_authorization_timing,
    verify_eip3009_signature,
)
from fluxpay.gateway.x402_facilitator import (
    FacilitatorClient,
    FacilitatorTimeoutError,
    FacilitatorUnavailableError,
)
from fluxpay.gateway.x402_types import (
    AgentRecord,
    AgentRegistry,
    LedgerClient,
    PaymentPayload,
    PaymentRequired,
    PaymentRequiredExtra,
    PaymentResponse,
    ReconciliationQueue,
)
from fluxpay.shared.logging import get_logger

__all__ = [
    "DEFAULT_USDC_DECIMALS",
    "FLX_X402_CHALLENGES_TOTAL",
    "FLX_X402_END_TO_END_DURATION_SECONDS",
    "FLX_X402_PAYMENTS_TOTAL",
    "FLX_X402_SETTLEMENTS_TOTAL",
    "FLX_X402_SETTLE_DURATION_SECONDS",
    "FLX_X402_VERIFY_DURATION_SECONDS",
    "DefaultAgentRegistry",
    "InMemoryReconciliationQueue",
    "X402Middleware",
]

logger = get_logger("fluxpay.gateway.x402")

DEFAULT_USDC_DECIMALS: Final[int] = 6


def _get_or_create_counter(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Counter:
    """Idempotently register or retrieve a Counter."""
    try:
        return Counter(name, documentation, labelnames=labelnames, registry=registry)
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Counter):
            return collector
        raise


def _get_or_create_histogram(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    buckets: tuple[float, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Histogram:
    """Idempotently register or retrieve a Histogram."""
    try:
        return Histogram(
            name, documentation, labelnames=labelnames, buckets=buckets, registry=registry
        )
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Histogram):
            return collector
        raise


FLX_X402_CHALLENGES_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_x402_challenges_total",
    "Total x402 payment challenges issued",
    ("route",),
)

FLX_X402_PAYMENTS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_x402_payments_total",
    "Total x402 payment authorization attempts evaluated",
    ("outcome",),
)

FLX_X402_SETTLEMENTS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_x402_settlements_total",
    "Total x402 on-chain settlements executed",
    ("outcome",),
)

FLX_X402_VERIFY_DURATION_SECONDS: Final[Histogram] = _get_or_create_histogram(
    "flx_x402_verify_duration_seconds",
    "x402 facilitator verification latency in seconds",
    (),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0),
)

FLX_X402_SETTLE_DURATION_SECONDS: Final[Histogram] = _get_or_create_histogram(
    "flx_x402_settle_duration_seconds",
    "x402 facilitator settlement latency in seconds",
    (),
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

FLX_X402_END_TO_END_DURATION_SECONDS: Final[Histogram] = _get_or_create_histogram(
    "flx_x402_end_to_end_duration_seconds",
    "Total x402 middleware processing latency in seconds",
    (),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


class DefaultAgentRegistry:
    """Default in-memory agent registry mapping on-chain addresses to AgentRecords."""

    def __init__(self) -> None:
        self._records: dict[str, AgentRecord] = {}

    async def resolve_agent(self, address: str) -> AgentRecord | None:
        """Resolve agent record by address."""
        norm = address.lower()
        return self._records.get(norm)

    async def get_or_create_agent(self, address: str) -> AgentRecord:
        """Provision deterministic AgentRecord from address."""
        norm = address.lower()
        if norm not in self._records:
            acc_id = uuid5(NAMESPACE_OID, f"agent:{norm}")
            agent_id = f"agent_{norm[2:10]}"
            self._records[norm] = AgentRecord(
                agent_id=agent_id,
                address=Web3.to_checksum_address(address),
                account_id=acc_id,
                active=True,
            )
        return self._records[norm]


class InMemoryReconciliationQueue:
    """Thread-safe queue for capturing failed ledger updates following successful settlement."""

    def __init__(self) -> None:
        self.jobs: list[dict[str, Any]] = []

    async def enqueue(self, job_data: dict[str, Any]) -> None:
        """Enqueue reconciliation job."""
        self.jobs.append(job_data)


class X402Middleware(BaseHTTPMiddleware):
    """Production-grade FastAPI middleware implementing the x402 payment protocol."""

    @overload
    def __init__(
        self,
        app: ASGIApp,
        /,
        *args: Any,
        config: X402Config | None = None,
        facilitator: FacilitatorClient | None = None,
        ledger: LedgerClient | Any | None = None,
        registry: AgentRegistry | None = None,
        redis_client: Any | None = None,
        reconciliation_queue: ReconciliationQueue | None = None,
        **kwargs: Any,
    ) -> None: ...

    @overload
    def __init__(
        self,
        app_or_config: Any = None,
        /,
        *args: Any,
        config: X402Config | None = None,
        facilitator: FacilitatorClient | None = None,
        ledger: LedgerClient | Any | None = None,
        registry: AgentRegistry | None = None,
        redis_client: Any | None = None,
        reconciliation_queue: ReconciliationQueue | None = None,
        **kwargs: Any,
    ) -> None: ...

    def __init__(
        self,
        app_or_config: Any = None,
        /,
        *args: Any,
        config: X402Config | None = None,
        facilitator: FacilitatorClient | None = None,
        ledger: LedgerClient | Any | None = None,
        registry: AgentRegistry | None = None,
        redis_client: Any | None = None,
        reconciliation_queue: ReconciliationQueue | None = None,
        **kwargs: Any,
    ) -> None:
        if app_or_config is None and config is not None:
            app_or_config = config
            config = None

        if isinstance(app_or_config, X402Config):
            # Invocation pattern: X402Middleware(config, facilitator, ledger, registry)
            app_instance: ASGIApp = kwargs.get("app", self._noop_app)
            self._config = app_or_config
            resolved_fac = args[0] if len(args) > 0 else (facilitator or kwargs.get("facilitator"))
            resolved_led = args[1] if len(args) > 1 else (ledger or kwargs.get("ledger"))
            resolved_reg = args[2] if len(args) > 2 else (registry or kwargs.get("registry"))
            self._facilitator: Any = resolved_fac
            self._ledger: Any = resolved_led
            self._registry = resolved_reg or DefaultAgentRegistry()
        else:
            # Invocation pattern: app.add_middleware(X402Middleware, config=..., ...)
            app_instance = app_or_config
            resolved_cfg = args[0] if len(args) > 0 else config
            resolved_fac = args[1] if len(args) > 1 else (facilitator or kwargs.get("facilitator"))
            resolved_led = args[2] if len(args) > 2 else (ledger or kwargs.get("ledger"))
            resolved_reg = args[3] if len(args) > 3 else (registry or kwargs.get("registry"))
            if resolved_cfg is None or resolved_fac is None or resolved_led is None:
                raise ValueError("config, facilitator, and ledger must be provided")
            self._config = resolved_cfg
            self._facilitator = resolved_fac
            self._ledger = resolved_led
            self._registry = resolved_reg or DefaultAgentRegistry()

        super().__init__(app_instance)

        self._redis_client: Any | None = redis_client
        self._reconciliation_queue: ReconciliationQueue = (
            reconciliation_queue or InMemoryReconciliationQueue()
        )
        self._nonce_cache: dict[str, float] = {}
        self._idempotency_cache: dict[str, tuple[int, bytes, dict[str, str], str]] = {}
        self._domain: dict[str, Any] = build_eip712_domain(
            name=self._config.token_name,
            version=self._config.token_version,
            chain_id=self._config.chain_id,
            verifying_contract=self._config.asset,
        )

    @staticmethod
    async def _noop_app(scope: Any, receive: Any, send: Any) -> None:
        pass

    @overload
    async def __call__(
        self,
        scope: Any,
        receive: Any,
        send: Any,
        /,
    ) -> None: ...

    @overload
    async def __call__(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
        /,
    ) -> Response: ...

    async def __call__(
        self,
        scope_or_request: Any,
        receive_or_call_next: Any = None,
        send: Any = None,
        /,
    ) -> Any:
        """Support both direct callable testing and standard ASGI execution."""
        if send is not None:
            # Standard ASGI scope, receive, send invocation
            await super().__call__(scope_or_request, receive_or_call_next, send)
            return None

        # Invocation as middleware(request, call_next)
        request = scope_or_request
        call_next = receive_or_call_next
        return await self.dispatch(request, call_next)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Core request interceptor executing x402 challenge and verification lifecycle."""
        start_time = time.perf_counter()

        if not self._config.enabled:
            return await call_next(request)

        route_path = request.url.path
        matched_price = await self._resolve_route_price(request, route_path)
        if matched_price is None:
            # Route does not require payment (<5ms passthrough overhead)
            return await call_next(request)

        # Calculate exact payment amount in integer minor units
        amount_minor = int(matched_price * (10**self._config.token_decimals))

        # Check for X-PAYMENT header
        x_payment_header = request.headers.get("x-payment")
        if not x_payment_header:
            FLX_X402_CHALLENGES_TOTAL.labels(route=route_path).inc()
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="invalid").inc()
            logger.info("x402_challenge_issued", route=route_path, amount=amount_minor)
            return self._build_challenge_response(amount_minor)

        # Enforce maximum payload size to prevent DoS
        if len(x_payment_header) > self._config.max_payload_bytes:
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="invalid").inc()
            return JSONResponse(
                status_code=400,
                content={
                    "error": "payload_too_large",
                    "message": "X-PAYMENT header exceeds maximum size",
                },
            )

        # Decode base64 payload
        try:
            raw_bytes = base64.b64decode(x_payment_header.strip(), validate=True)
            payload_dict = json.loads(raw_bytes.decode("utf-8"))
            payload = PaymentPayload.model_validate(payload_dict)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, Exception) as err:
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="invalid").inc()
            return JSONResponse(
                status_code=402,
                content={
                    "error": "invalid_signature",
                    "message": f"Malformed payment payload: {err}",
                },
            )

        agent_hash = hashlib.sha256(payload.from_address.lower().encode()).hexdigest()[:16]
        logger.info(
            "x402_payment_received",
            route=route_path,
            agent_id=agent_hash,
            amount=amount_minor,
        )

        canonical_nonce = normalize_nonce(payload.nonce)
        idem_key = f"x402:{canonical_nonce}"
        payload_hash = hashlib.sha256(raw_bytes).hexdigest()

        # 1. Check Idempotency Cache: Same X-PAYMENT twice returns cached response
        cached_resp = await self._get_idempotent_response(idem_key)
        if cached_resp is not None:
            status_code, body_bytes, headers, stored_hash = cached_resp
            if stored_hash == payload_hash:
                return Response(content=body_bytes, status_code=status_code, headers=headers)
            # Same nonce with DIFFERENT payload -> 409 Replay Conflict
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="replay").inc()
            logger.warning("x402_replay_detected", nonce=canonical_nonce, agent_id=agent_hash)
            return JSONResponse(
                status_code=409,
                content={"error": "replay", "message": "Authorization nonce has already been used"},
            )

        # 2. Replay Protection: Nonce already seen for a different execution
        if await self._is_nonce_seen(canonical_nonce):
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="replay").inc()
            logger.warning("x402_replay_detected", nonce=canonical_nonce, agent_id=agent_hash)
            return JSONResponse(
                status_code=409,
                content={"error": "replay", "message": "Authorization nonce has already been used"},
            )

        # 3. Timing Validation
        timing_valid, timing_reason = validate_authorization_timing(
            payload.valid_after, payload.valid_before
        )
        if not timing_valid:
            outcome = "expired" if "expired" in (timing_reason or "") else "invalid"
            FLX_X402_PAYMENTS_TOTAL.labels(outcome=outcome).inc()
            return JSONResponse(
                status_code=402,
                content={"error": outcome, "message": timing_reason},
            )

        # 4. Solvency and Value Validation
        if payload.value_int < amount_minor:
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="invalid").inc()
            return JSONResponse(
                status_code=402,
                content={
                    "error": "insufficient_amount",
                    "message": (
                        f"Authorized value {payload.value_int} is less than cost {amount_minor}"
                    ),
                },
            )

        if payload.to_address.lower() != self._config.pay_to.lower():
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="invalid").inc()
            return JSONResponse(
                status_code=402,
                content={
                    "error": "invalid_recipient",
                    "message": (
                        f"Authorized recipient {payload.to_address} does not match "
                        f"{self._config.pay_to}"
                    ),
                },
            )

        # 5. Signature Verification
        sig_valid, sig_reason = verify_eip3009_signature(payload, self._domain)
        if not sig_valid:
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="invalid").inc()
            return JSONResponse(
                status_code=402,
                content={"error": "invalid_signature", "message": sig_reason},
            )

        # 6. Facilitator Verification
        t_verify_start = time.perf_counter()
        try:
            verify_res = await self._facilitator.verify(payload.model_dump())
            FLX_X402_VERIFY_DURATION_SECONDS.observe(time.perf_counter() - t_verify_start)
        except (FacilitatorUnavailableError, FacilitatorTimeoutError):
            return JSONResponse(
                status_code=503,
                headers={"Retry-After": "5"},
                content={
                    "error": "facilitator_unavailable",
                    "message": "Upstream facilitator unavailable",
                },
            )

        if not verify_res.valid:
            outcome = verify_res.error or "invalid"
            if outcome == "insufficient_funds":
                FLX_X402_PAYMENTS_TOTAL.labels(outcome="invalid").inc()
                return JSONResponse(
                    status_code=402,
                    content={
                        "error": "insufficient_funds",
                        "message": verify_res.reason or "Insufficient funds",
                    },
                )
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="invalid").inc()
            return JSONResponse(
                status_code=402,
                content={
                    "error": outcome,
                    "message": verify_res.reason or "Facilitator rejected authorization",
                },
            )

        logger.info("x402_verified", agent_id=agent_hash, route=route_path)

        # 7. Facilitator Settlement
        t_settle_start = time.perf_counter()
        try:
            settle_res = await self._facilitator.settle(payload.model_dump())
            FLX_X402_SETTLE_DURATION_SECONDS.observe(time.perf_counter() - t_settle_start)
        except FacilitatorTimeoutError:
            FLX_X402_SETTLEMENTS_TOTAL.labels(outcome="timeout").inc()
            return JSONResponse(
                status_code=504,
                content={
                    "error": "settlement_timeout",
                    "message": "Settlement timed out awaiting confirmation",
                },
            )
        except FacilitatorUnavailableError:
            FLX_X402_SETTLEMENTS_TOTAL.labels(outcome="failed").inc()
            return JSONResponse(
                status_code=502,
                content={
                    "error": "settlement_failed",
                    "message": "Upstream facilitator connection failed",
                },
            )

        if not settle_res.success:
            FLX_X402_SETTLEMENTS_TOTAL.labels(outcome="failed").inc()
            return JSONResponse(
                status_code=502,
                content={
                    "error": "settlement_failed",
                    "message": settle_res.reason or "Settlement failed on-chain",
                },
            )

        FLX_X402_SETTLEMENTS_TOTAL.labels(outcome="ok").inc()
        logger.info("x402_settled", tx_hash=settle_res.tx_hash, agent_id=agent_hash)

        # 8. Record in Double-Entry Ledger
        agent_record = await self._registry.get_or_create_agent(payload.from_address)
        try:
            await self._record_ledger(
                agent_record=agent_record,
                amount_minor=amount_minor,
                idempotency_key=idem_key,
                tx_hash=settle_res.tx_hash,
            )
        except Exception as ledger_err:
            logger.critical(
                "x402_ledger_post_failed",
                error=str(ledger_err),
                tx_hash=settle_res.tx_hash,
                nonce=canonical_nonce,
                amount=amount_minor,
                agent_id=agent_record.agent_id,
            )
            # Enqueue reconciliation job for guaranteed audit recovery
            await self._reconciliation_queue.enqueue(
                {
                    "tx_hash": settle_res.tx_hash,
                    "nonce": canonical_nonce,
                    "agent_id": agent_record.agent_id,
                    "amount_minor": amount_minor,
                    "currency": "USDC",
                    "error": str(ledger_err),
                    "timestamp": time.time(),
                }
            )
            FLX_X402_PAYMENTS_TOTAL.labels(outcome="error").inc()
            return JSONResponse(
                status_code=500,
                content={
                    "error": "ledger_error",
                    "message": (
                        "Payment settled on-chain but ledger update failed; "
                        "reconciliation in progress"
                    ),
                },
            )

        # 9. Mark nonce used & record idempotency
        await self._mark_nonce_seen(canonical_nonce)

        # 10. Call downstream route handler
        response = await call_next(request)

        # 11. Attach X-PAYMENT-RESPONSE Header
        fallback_tx = f"0x{hashlib.sha256(canonical_nonce.encode()).hexdigest()}"
        settlement_receipt = PaymentResponse(
            success=True,
            tx_hash=str(settle_res.tx_hash or fallback_tx),
            network=self._config.network,
            amount=str(amount_minor),
            asset=self._config.asset,
            pay_to=self._config.pay_to,
            from_address=payload.from_address,
            nonce=canonical_nonce,
            settled_at=int(time.time()),
            block_number=settle_res.block_number,
        )
        receipt_b64 = base64.b64encode(
            settlement_receipt.model_dump_json(by_alias=True).encode()
        ).decode("ascii")
        response.headers["X-PAYMENT-RESPONSE"] = receipt_b64

        # Save to idempotency store for safe client retries
        body_content = getattr(response, "body", b"")
        await self._save_idempotent_response(
            idem_key,
            response.status_code,
            body_content,
            dict(response.headers),
            payload_hash,
        )

        FLX_X402_PAYMENTS_TOTAL.labels(outcome="ok").inc()
        FLX_X402_END_TO_END_DURATION_SECONDS.observe(time.perf_counter() - start_time)
        return response

    async def _resolve_route_price(self, request: Request, route: str) -> Decimal | None:
        """Resolve route price, honoring dynamic pricing functions or static tables."""
        if self._config.price_fn is not None:
            try:
                res = self._config.price_fn(request)
                if inspect.isawaitable(res):
                    return await res
                return res
            except Exception as err:
                logger.error("x402_dynamic_pricing_failed", error=str(err), route=route)
                return None

        # Check static route table
        if route in self._config.protected_routes:
            return self._config.protected_routes[route]

        # Check prefix/pattern matching
        for pattern, price in self._config.protected_routes.items():
            if pattern.endswith("/") and route.startswith(pattern):
                return price
        return None

    def _build_challenge_response(self, amount_minor: int) -> JSONResponse:
        """Construct RFC 7231 / x402 402 Payment Required response."""
        challenge = PaymentRequired(
            scheme=self._config.scheme,
            network=self._config.network,
            asset=self._config.asset,
            amount=str(amount_minor),
            pay_to=self._config.pay_to,
            max_timeout_seconds=self._config.max_timeout_seconds,
            extra=PaymentRequiredExtra(
                name=self._config.token_name,
                version=self._config.token_version,
                decimals=self._config.token_decimals,
            ),
        )
        challenge_json = challenge.model_dump_json(by_alias=True)
        headers = {"PAYMENT-REQUIRED": challenge_json}
        body = challenge.model_dump(by_alias=True)
        return JSONResponse(status_code=402, content=body, headers=headers)

    async def _is_nonce_seen(self, nonce: str) -> bool:
        """Check whether authorization nonce has been registered."""
        if self._redis_client is not None:
            try:
                key = f"flx:x402:nonce:{nonce}"
                exists = await self._redis_client.exists(key)
                return bool(exists)
            except Exception as err:
                logger.warning("redis_nonce_check_failed", error=str(err))

        return nonce in self._nonce_cache

    async def _mark_nonce_seen(self, nonce: str) -> None:
        """Store authorization nonce with 24h TTL."""
        if self._redis_client is not None:
            try:
                key = f"flx:x402:nonce:{nonce}"
                await self._redis_client.set(key, "1", ex=self._config.nonce_cache_ttl_s)
            except Exception as err:
                logger.warning("redis_nonce_save_failed", error=str(err))

        self._nonce_cache[nonce] = time.time() + self._config.nonce_cache_ttl_s

    async def _get_idempotent_response(
        self, idem_key: str
    ) -> tuple[int, bytes, dict[str, str], str] | None:
        """Retrieve cached response for idempotent retry."""
        if self._redis_client is not None:
            try:
                raw = await self._redis_client.get(f"flx:x402:resp:{idem_key}")
                if raw is not None:
                    data = json.loads(raw.decode("utf-8"))
                    body = base64.b64decode(data["body_b64"])
                    return data["status"], body, data["headers"], data.get("payload_hash", "")
            except Exception as err:
                logger.warning("redis_idempotency_lookup_failed", error=str(err))

        return self._idempotency_cache.get(idem_key)

    async def _save_idempotent_response(
        self,
        idem_key: str,
        status: int,
        body: bytes,
        headers: dict[str, str],
        payload_hash: str,
    ) -> None:
        """Save settled response in idempotency cache with 24h TTL."""
        if self._redis_client is not None:
            try:
                packed = json.dumps(
                    {
                        "status": status,
                        "body_b64": base64.b64encode(body).decode("ascii"),
                        "headers": headers,
                        "payload_hash": payload_hash,
                    }
                ).encode()
                await self._redis_client.set(
                    f"flx:x402:resp:{idem_key}", packed, ex=self._config.nonce_cache_ttl_s
                )
            except Exception as err:
                logger.warning("redis_idempotency_save_failed", error=str(err))

        self._idempotency_cache[idem_key] = (status, body, headers, payload_hash)

    async def _record_ledger(
        self,
        *,
        agent_record: AgentRecord,
        amount_minor: int,
        idempotency_key: str,
        tx_hash: str | None,
    ) -> None:
        """Record double-entry transaction (debit agent, credit merchant)."""
        merchant_account_id = uuid5(NAMESPACE_OID, f"merchant:{self._config.merchant_id}")

        if hasattr(self._ledger, "record_payment"):
            await self._ledger.record_payment(
                agent_id=agent_record.agent_id,
                merchant_id=self._config.merchant_id,
                amount_minor=amount_minor,
                currency="USDC",
                idempotency_key=idempotency_key,
                agent_account_id=agent_record.account_id,
                merchant_account_id=merchant_account_id,
            )
            return

        if hasattr(self._ledger, "post_transaction"):
            from fluxpay.ledger.hashchain import Direction
            from fluxpay.ledger.store import EntryDraft

            tx_uuid = uuid5(NAMESPACE_OID, idempotency_key)
            entries = (
                EntryDraft(
                    account_id=agent_record.account_id,
                    direction=Direction.DEBIT,
                    amount=amount_minor,
                    currency="USDC",
                    tx_id=tx_uuid,
                ),
                EntryDraft(
                    account_id=merchant_account_id,
                    direction=Direction.CREDIT,
                    amount=amount_minor,
                    currency="USDC",
                    tx_id=tx_uuid,
                ),
            )
            await self._ledger.post_transaction(entries)
            return

        raise AttributeError("Ledger object provides neither record_payment nor post_transaction")
