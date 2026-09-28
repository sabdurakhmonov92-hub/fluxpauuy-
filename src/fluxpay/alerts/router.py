"""SEV1 Alert Router and Dead-Man Switch Heartbeat Bridge (Task 69).

==============================================================================
THE CONTRACT OF THE SEV ROUTER
==============================================================================
1. Webhook Ingestion: Receives alerts from Prometheus Alertmanager and Sentry.
2. Shared Authentication: All ingress endpoints require a shared Bearer secret
   (`alertrouter_secret`). If unset (None), router fails closed loudly (HTTP 403).
3. Normalization: Raw vendor alert payloads are parsed into standard `NormalizedAlert`.
4. Severity Gate:
   - SEV1: Pages 24/7 immediately via TelegramChannel.
   - SEV2: Pages immediately (in-hours operational queue) via TelegramChannel.
   - SEV3: Diagnostic/informational only. Logged to structlog, NEVER pages Telegram.
5. Cry-Wolf Law (Deduplication):
   - In-memory 10-minute (600s) deduplication window keyed by alert fingerprint.
   - Repeat alerts within the window are swallowed and logged.
6. Fail-Closed-to-Record Doctrine:
   - If Telegram delivery fails, the error is persisted as a row in
     `notification_failures` via Task 43's `record_failure_pool()`.
7. Dead-Man Switch Heartbeat Bridge:
   - POST /heartbeat accepts status from periodic one-shots (Task 40/41/44/45).
   - In-memory Prometheus gauges (`flx_worker_last_success_timestamp` and
     `flx_validator_ok`) are updated and exposed on /metrics for Prometheus scraping.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Final

import asyncpg  # type: ignore[import-untyped]
import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest, make_asgi_app

from fluxpay.config import Settings, get_settings
from fluxpay.notifications.channels import TelegramChannel
from fluxpay.notifications.records import record_failure_pool
from fluxpay.shared.logging import get_logger
from fluxpay.shared.metrics import (
    FLX_VALIDATOR_OK,
    FLX_WORKER_LAST_SUCCESS_TIMESTAMP,
)

logger = get_logger("fluxpay.alerts.router")

DEFAULT_DEDUP_WINDOW_S: Final[float] = 600.0  # 10 minutes


@dataclass(frozen=True, slots=True)
class NormalizedAlert:
    """Normalized platform alert representation independent of ingress source."""

    alertname: str
    severity: str  # "SEV1", "SEV2", "SEV3"
    summary: str
    runbook_url: str
    source: str  # "alertmanager" | "sentry" | "heartbeat"
    fingerprint: str
    status: str = "firing"  # "firing" | "resolved"


def format_sev_alert(alert: NormalizedAlert) -> str:
    """Format a normalized alert into KAT-frozen plain-text notification format.

    Format contract:
    🚨 SEV1 [FluxPay] <alert>
    <summary>
    runbook: <url>
    source: <origin>
    """
    sev = alert.severity.upper()
    icon = "🚨" if sev == "SEV1" else ("⚠️" if sev == "SEV2" else "ℹ️")  # noqa: RUF001
    return (
        f"{icon} {sev} [FluxPay] {alert.alertname}\n"
        f"{alert.summary}\n"
        f"runbook: {alert.runbook_url}\n"
        f"source: {alert.source}"
    )


class AlertRouter:
    """Stateless alert routing, severity gating, and deduplication engine."""

    def __init__(
        self,
        settings: Settings,
        *,
        channel: Any | None = None,
        pool: asyncpg.Pool | None = None,
        clock: Callable[[], float] = time.time,
        dedup_window_s: float = DEFAULT_DEDUP_WINDOW_S,
    ) -> None:
        self.settings: Settings = settings
        self.channel: Any = channel
        self.pool: asyncpg.Pool | None = pool
        self.clock: Callable[[], float] = clock
        self.dedup_window_s: float = dedup_window_s
        self._sent_fingerprints: dict[str, float] = {}

    def _ensure_channel(self) -> Any:
        """Lazily initialize TelegramChannel from settings if not injected."""
        if self.channel is not None:
            return self.channel

        if self.settings.telegram_bot_token and self.settings.telegram_admin_chat_id:
            http_client = httpx.AsyncClient()
            self.channel = TelegramChannel(
                http_client,
                bot_token=self.settings.telegram_bot_token,
                chat_id=self.settings.telegram_admin_chat_id,
                retry_max=self.settings.notification_retry_max,
                backoff_base_s=self.settings.notification_backoff_base_s,
            )
            return self.channel

        # Null channel for unconfigured/test environments
        class _NullTelegramChannel:
            async def send(self, msg: str) -> None:
                logger.info("null_channel_page_emitted", message=msg)

        self.channel = _NullTelegramChannel()
        return self.channel

    def is_deduplicated(self, fingerprint: str) -> bool:
        """Check whether alert fingerprint was dispatched within dedup window."""
        now = self.clock()
        last_sent = self._sent_fingerprints.get(fingerprint, 0.0)
        return (now - last_sent) < self.dedup_window_s

    def record_dispatched(self, fingerprint: str) -> None:
        """Record dispatch timestamp for fingerprint."""
        self._sent_fingerprints[fingerprint] = self.clock()

    async def route_alert(self, alert: NormalizedAlert) -> dict[str, Any]:
        """Process alert through severity gate, dedup window, and notification transport."""
        sev = alert.severity.upper()

        # Step 1: SEV3 Log-Only Gate
        if sev == "SEV3":
            logger.info(
                "sev3_alert_logged",
                alertname=alert.alertname,
                summary=alert.summary,
                source=alert.source,
            )
            return {"status": "logged", "severity": "SEV3", "alertname": alert.alertname}

        # Step 2: Status check (non-firing alerts are not paged)
        if alert.status != "firing":
            logger.info(
                "alert_resolved_logged",
                alertname=alert.alertname,
                status=alert.status,
                fingerprint=alert.fingerprint,
            )
            return {"status": "resolved", "alertname": alert.alertname}

        # Step 3: Cry-Wolf Deduplication Gate
        if self.is_deduplicated(alert.fingerprint):
            logger.info(
                "alert_deduplicated",
                fingerprint=alert.fingerprint,
                alertname=alert.alertname,
                severity=sev,
            )
            return {
                "status": "deduplicated",
                "fingerprint": alert.fingerprint,
                "alertname": alert.alertname,
            }

        # Step 4: Format Message
        message = format_sev_alert(alert)

        # Step 5: Deliver Page via Telegram Transport
        channel = self._ensure_channel()
        try:
            await channel.send(message)
            self.record_dispatched(alert.fingerprint)
            logger.info(
                "sev_alert_dispatched",
                alertname=alert.alertname,
                severity=sev,
                fingerprint=alert.fingerprint,
            )
            return {
                "status": "sent",
                "fingerprint": alert.fingerprint,
                "alertname": alert.alertname,
                "message": message,
            }
        except Exception as exc:
            logger.error(
                "sev_alert_delivery_failed",
                alertname=alert.alertname,
                severity=sev,
                error=str(exc),
            )
            # Fail-closed-to-record doctrine: record failure in DB if pool is available
            if self.pool is not None:
                try:
                    await record_failure_pool(
                        self.pool,
                        channel="telegram",
                        subject=self.settings.telegram_admin_chat_id or "unknown",
                        purpose="sev.escalation",
                        payload={"alert": alert.alertname, "severity": sev, "message": message},
                        error=type(exc).__name__,
                    )
                except Exception as db_exc:
                    logger.error("failed_to_record_notification_failure", error=str(db_exc))
            raise


def send_heartbeat(
    worker: str,
    ok: bool = True,
    reason: str | None = None,
    *,
    ts: float | None = None,
    port: int | None = None,
    secret: str | None = None,
    timeout: float = 1.0,
) -> None:
    """Submit worker heartbeat to in-process metrics and router HTTP endpoint.

    Fails silently on connection errors: an unavailable alert router must never
    prevent an operational one-shot task from successfully finishing or exiting.
    """
    now_ts = ts if ts is not None else time.time()

    # Step 1: Update in-process Prometheus gauge metrics directly
    if ok:
        FLX_WORKER_LAST_SUCCESS_TIMESTAMP.labels(worker=worker).set(now_ts)
    FLX_VALIDATOR_OK.labels(worker=worker).set(1 if ok else 0)

    # Step 2: Forward over loopback HTTP if router process is running
    try:
        settings = get_settings()
        effective_port = port or settings.alert_router_port
        effective_secret = secret if secret is not None else settings.alertrouter_secret
        headers = {"Authorization": f"Bearer {effective_secret}"} if effective_secret else {}
        url = f"http://127.0.0.1:{effective_port}/heartbeat"
        payload = {"worker": worker, "ok": ok, "ts": now_ts, "reason": reason}
        with httpx.Client(timeout=timeout) as client:
            client.post(url, json=payload, headers=headers)
    except Exception:  # noqa: S110
        pass  # Operational one-shots must never crash if router process is offline


def _authenticate_request(request: Request, secret: str | None) -> None:
    """Fail-closed authentication guard for alert router endpoints."""
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Alert router is disabled: alertrouter_secret is unconfigured",
        )

    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "X-Alert-Router-Secret" in request.headers:
        token = request.headers["X-Alert-Router-Secret"].strip()

    if not token or token != secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid alert router credentials",
        )


def create_alert_router_app(
    router: AlertRouter | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """Construct lightweight ASGI application for the SEV alert router."""
    effective_settings = settings or (router.settings if router else get_settings())
    effective_router = router or AlertRouter(effective_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        yield

    app = FastAPI(title="FluxPay Alert Router", version="0.1.0", lifespan=lifespan)
    app.state.router = effective_router
    app.state.settings = effective_settings

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics", include_in_schema=False)
    def metrics_endpoint() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # Expose Prometheus scrape endpoint for Prometheus scraper on port 9120
    app.mount("/metrics", make_asgi_app())

    @app.post("/alertmanager")
    async def alertmanager_webhook(request: Request) -> JSONResponse:
        """Ingest and route alerts from Prometheus Alertmanager."""
        _authenticate_request(request, effective_settings.alertrouter_secret)
        payload = await request.json()

        alerts_list: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            alerts_list = payload.get("alerts", [payload])
        elif isinstance(payload, list):
            alerts_list = payload

        results: list[dict[str, Any]] = []
        for raw in alerts_list:
            labels = raw.get("labels", {})
            annotations = raw.get("annotations", {})
            alertname = labels.get("alertname", "UnknownAlert")
            severity = labels.get("severity", "SEV1").upper()
            summary = annotations.get("summary", annotations.get("description", alertname))
            runbook_url = annotations.get("runbook_url", f"docs/runbooks/{alertname}.md")
            raw_fp = raw.get("fingerprint") or f"{alertname}_{severity}_{summary}"
            fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()[:16]

            normalized = NormalizedAlert(
                alertname=alertname,
                severity=severity,
                summary=summary,
                runbook_url=runbook_url,
                source="alertmanager",
                fingerprint=fp,
                status=raw.get("status", "firing"),
            )
            res = await effective_router.route_alert(normalized)
            results.append(res)

        return JSONResponse(status_code=200, content={"status": "processed", "results": results})

    @app.post("/sentry")
    async def sentry_webhook(request: Request) -> JSONResponse:
        """Ingest and route exception webhooks from Sentry."""
        _authenticate_request(request, effective_settings.alertrouter_secret)
        payload = await request.json()

        # Handle Sentry event / issue formats
        issue = payload.get("data", {}).get("issue", payload)
        message = issue.get("title", payload.get("message", "Sentry Exception"))
        level = issue.get("level", payload.get("level", "error")).lower()

        # Sentry severity mapping
        severity = "SEV1" if level in ("fatal", "critical") else "SEV2"
        alertname = f"Sentry_{issue.get('id', 'Exception')}"
        summary = message
        runbook_url = issue.get("url", "docs/runbooks/SentryError.md")
        fp = hashlib.sha256(f"sentry_{alertname}_{summary}".encode()).hexdigest()[:16]

        normalized = NormalizedAlert(
            alertname=alertname,
            severity=severity,
            summary=summary,
            runbook_url=runbook_url,
            source="sentry",
            fingerprint=fp,
            status="firing",
        )
        res = await effective_router.route_alert(normalized)
        return JSONResponse(status_code=200, content=res)

    @app.post("/heartbeat")
    async def heartbeat(request: Request) -> JSONResponse:
        """Receive periodic one-shot heartbeat and bridge to Prometheus gauges."""
        _authenticate_request(request, effective_settings.alertrouter_secret)
        payload = await request.json()

        worker = str(payload.get("worker", "unknown"))
        ok = bool(payload.get("ok", True))
        ts = float(payload.get("ts", time.time()))
        reason = payload.get("reason")

        # Update in-memory Prometheus metrics for the scraper
        if ok:
            FLX_WORKER_LAST_SUCCESS_TIMESTAMP.labels(worker=worker).set(ts)
        FLX_VALIDATOR_OK.labels(worker=worker).set(1 if ok else 0)

        # Immediate SEV1 alert for broken validators (ChainBroken or ReconciliationMismatch)
        if not ok:
            alertname = (
                "ChainBroken"
                if "hash_validator" in worker
                else (
                    "ReconciliationMismatch"
                    if "reconciliation" in worker
                    else f"WorkerFailure_{worker}"
                )
            )
            runbook = (
                "docs/runbooks/ChainBroken.md"
                if "hash_validator" in worker
                else (
                    "docs/runbooks/ReconciliationMismatch.md"
                    if "reconciliation" in worker
                    else "docs/runbooks/WorkerStuck.md"
                )
            )
            alert = NormalizedAlert(
                alertname=alertname,
                severity="SEV1",
                summary=f"Worker '{worker}' reported fatal failure: {reason or 'failure'}",
                runbook_url=runbook,
                source="heartbeat",
                fingerprint=f"hb_fail_{worker}",
                status="firing",
            )
            await effective_router.route_alert(alert)

        return JSONResponse(
            status_code=200,
            content={"status": "ok", "worker": worker, "ok": ok, "ts": ts},
        )

    return app


def main() -> None:
    """Run alert router daemon process on configured localhost port."""
    import uvicorn

    settings = get_settings()
    app = create_alert_router_app(settings=settings)
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=settings.alert_router_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
