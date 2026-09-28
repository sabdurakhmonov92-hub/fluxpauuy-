"""Frozen Prometheus metrics registry and cardinality law definitions for FluxPay (Task 69).

==============================================================================
THE THREE LAWS OF PRODUCTION OBSERVABILITY
==============================================================================
1. METRICS answer "is it healthy": Low-overhead, fixed-cardinality counters,
   histograms, and gauges evaluated continuously across scraping intervals.
2. LOGS answer "what exactly happened": Rich, contextual, structured JSON lines
   aggregated via journald into Loki for post-facto forensic analysis.
3. ALERTS answer "who must wake up": Actionable, deduplicated pages delivered
   to the human on-call responder with explicit runbook references.
NEVER conflate them: metrics do not carry diagnostic error payloads; logs do not
drive real-time rate limiters; alerts do not page on ambient baseline noise.

==============================================================================
THE SACRED DEAD-MAN SWITCH LAW
==============================================================================
A payment platform cannot rely solely on presence-of-error signals. An audit worker
or cryptographic validator that dies silently, hangs in a deadlocked state, or stops
executing without emitting exceptions produces zero errors. Under the Dead-Man Law,
the ABSENCE of a regular success signal IS a SEV1 incident. If the hash validator does
not report a successful verification cycle within 2 hours (7200s), an immediate page fires.

==============================================================================
THE CARDINALITY LAW (WHY AGENT_ID IS REFUSED ON COUNTERS)
==============================================================================
Every unique permutation of metric label values creates an independent time-series
stored in Prometheus memory and disk chunks. In an agentic economy with millions of
autonomous agent IDs, adding `agent_id` or `payment_id` as a label explodes time-series
cardinality to millions of streams, leading to memory exhaustion (OOM), slow queries,
and scraping timeouts.
THE LAW: Labels MUST be strictly bounded low-cardinality enums (methods, HTTP status
families, outcome categories, provider identifiers). Per-agent metrics are deferred
to Phase 2 via OpenTelemetry exemplars linking metrics directly to trace IDs and Loki logs.

==============================================================================
THE MONETARY ANTI-PATTERN REFUSAL
==============================================================================
Refusal: `flx_payment_amount_minor` is deliberately NOT registered as a Prometheus metric.
Monetary amounts are discrete, exact integer quantities governed by double-entry ledger
arithmetic. Summarizing currency amounts in Prometheus violates IEEE 754 floating-point
exactness and creates high-cardinality noise. Financial totals belong exclusively in SQL
ledger balance queries, not floating-point telemetry buffers.
"""

from __future__ import annotations

from typing import Any, Final

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)

# -----------------------------------------------------------------------------
# Latency Histogram Bucket Configurations
# -----------------------------------------------------------------------------
# Tuned for an 8 tx/s baseline target: sub-millisecond to 1.0s boundaries.
HTTP_LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.005,
    0.010,
    0.025,
    0.050,
    0.075,
    0.100,
    0.250,
    0.500,
    0.750,
    1.000,
)

PROVIDER_LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.050,
    0.100,
    0.250,
    0.500,
    1.000,
    2.000,
    5.000,
    10.000,
)


def _get_or_create_counter(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Counter:
    """Idempotently register or retrieve a Counter to support interactive reload."""
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


def _get_or_create_gauge(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Gauge:
    """Idempotently register or retrieve a Gauge."""
    try:
        return Gauge(name, documentation, labelnames=labelnames, registry=registry)
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Gauge):
            return collector
        raise


# -----------------------------------------------------------------------------
# 1. HTTP GATEWAY METRICS
# -----------------------------------------------------------------------------
# Route label must ALWAYS be templated path (e.g. "/v1/payments", "/v1/payments/{tx_id}")
# to uphold the Cardinality Law at the wire.
FLX_HTTP_REQUESTS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_http_requests_total",
    "Total HTTP requests received by API gateway",
    ("method", "route", "status"),
)

FLX_HTTP_REQUEST_SECONDS: Final[Histogram] = _get_or_create_histogram(
    "flx_http_request_seconds",
    "HTTP request latency in seconds partitioned by templated route",
    ("route",),
    buckets=HTTP_LATENCY_BUCKETS,
)

# -----------------------------------------------------------------------------
# 2. MONEY PATH METRICS
# -----------------------------------------------------------------------------
# Result outcome strictly bounded to: settled | held | rejected | failed
FLX_PAYMENTS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_payments_total",
    "Total payments processed by final settlement result",
    ("result",),
)

FLX_LEDGER_OCC_RETRIES_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_ledger_occ_retries_total",
    "Total optimistic concurrency control retries in ledger writes",
    (),
)

# -----------------------------------------------------------------------------
# 3. GATE & ADMISSION METRICS
# -----------------------------------------------------------------------------
# Outcome strictly bounded to: ok | replay | rate | quota | unavail
FLX_GATE_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_gate_total",
    "Total atomic security gate decisions evaluated",
    ("outcome",),
)

# -----------------------------------------------------------------------------
# 4. IDENTITY & IDEMPOTENCY METRICS
# -----------------------------------------------------------------------------
# Tier strictly bounded to: fastpath_replay | db_replay | conflict
FLX_IDEMPOTENCY_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_idempotency_total",
    "Total idempotency evaluations by resolution tier",
    ("tier",),
)

# -----------------------------------------------------------------------------
# 5. INTEGRATIONS & UPSTREAM RAILS
# -----------------------------------------------------------------------------
# Tracks upstream health, circuit-breaker prerequisites, and external provider SLA
FLX_PROVIDER_CALLS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_provider_calls_total",
    "Total external payment/identity provider HTTP calls",
    ("provider", "op", "ok"),
)

FLX_PROVIDER_DURATION_SECONDS: Final[Histogram] = _get_or_create_histogram(
    "flx_provider_duration_seconds",
    "External provider call duration in seconds",
    ("provider", "op"),
    buckets=PROVIDER_LATENCY_BUCKETS,
)

# -----------------------------------------------------------------------------
# 6. WORKERS & BACKGROUND LIFECYCLE
# -----------------------------------------------------------------------------
FLX_WORKER_BATCHES_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_worker_batches_total",
    "Total background worker batches processed",
    ("worker",),
)

FLX_WORKER_ERRORS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_worker_errors_total",
    "Total background worker batch execution errors",
    ("worker",),
)

# Crucial source of truth for the sacred dead-man switch
FLX_WORKER_LAST_SUCCESS_TIMESTAMP: Final[Gauge] = _get_or_create_gauge(
    "flx_worker_last_success_timestamp",
    "Unix timestamp in seconds of last successful worker cycle",
    ("worker",),
)

# -----------------------------------------------------------------------------
# 7. INTEGRITY & CRYPTOGRAPHIC VALIDATORS
# -----------------------------------------------------------------------------
# 1 = healthy / ok; 0 = cryptographic chain broken or reconciliation mismatch
FLX_VALIDATOR_OK: Final[Gauge] = _get_or_create_gauge(
    "flx_validator_ok",
    "Cryptographic chain and reconciliation validator status (1=ok, 0=broken)",
    ("worker",),
)

# -----------------------------------------------------------------------------
# FROZEN METRICS CONTRACT DEFINITIONS (FOR META-TESTING & LABEL AUDITING)
# -----------------------------------------------------------------------------
FROZEN_METRIC_SPECS: Final[dict[str, dict[str, Any]]] = {
    "flx_http_requests_total": {
        "type": "counter",
        "labels": ("method", "route", "status"),
    },
    "flx_http_request_seconds": {
        "type": "histogram",
        "labels": ("route",),
    },
    "flx_payments_total": {
        "type": "counter",
        "labels": ("result",),
    },
    "flx_ledger_occ_retries_total": {
        "type": "counter",
        "labels": (),
    },
    "flx_gate_total": {
        "type": "counter",
        "labels": ("outcome",),
    },
    "flx_idempotency_total": {
        "type": "counter",
        "labels": ("tier",),
    },
    "flx_provider_calls_total": {
        "type": "counter",
        "labels": ("provider", "op", "ok"),
    },
    "flx_provider_duration_seconds": {
        "type": "histogram",
        "labels": ("provider", "op"),
    },
    "flx_worker_batches_total": {
        "type": "counter",
        "labels": ("worker",),
    },
    "flx_worker_errors_total": {
        "type": "counter",
        "labels": ("worker",),
    },
    "flx_worker_last_success_timestamp": {
        "type": "gauge",
        "labels": ("worker",),
    },
    "flx_validator_ok": {
        "type": "gauge",
        "labels": ("worker",),
    },
}
