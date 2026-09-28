"""Unit tests verifying the frozen Prometheus metrics registry (Task 69).

Validates label cardinality laws, registry name freeze, and monetary anti-pattern refusal.
"""

from __future__ import annotations

import pytest
from prometheus_client import REGISTRY

from fluxpay.shared.metrics import (
    FLX_GATE_TOTAL,
    FLX_HTTP_REQUEST_SECONDS,
    FLX_HTTP_REQUESTS_TOTAL,
    FLX_IDEMPOTENCY_TOTAL,
    FLX_LEDGER_OCC_RETRIES_TOTAL,
    FLX_PAYMENTS_TOTAL,
    FLX_PROVIDER_CALLS_TOTAL,
    FLX_PROVIDER_DURATION_SECONDS,
    FLX_VALIDATOR_OK,
    FLX_WORKER_BATCHES_TOTAL,
    FLX_WORKER_ERRORS_TOTAL,
    FLX_WORKER_LAST_SUCCESS_TIMESTAMP,
    FROZEN_METRIC_SPECS,
    HTTP_LATENCY_BUCKETS,
    PROVIDER_LATENCY_BUCKETS,
)

pytestmark = pytest.mark.unit

FORBIDDEN_CARDINALITY_LABELS = {
    "agent_id",
    "payment_id",
    "tx_id",
    "request_id",
    "account_id",
    "nonce",
    "idem_key",
    "user_id",
    "email",
}


def test_frozen_metric_specs_names_and_labels() -> None:
    """Verify that all 12 platform metrics have frozen names and bounded label sets."""
    expected_metrics = {
        "flx_http_requests_total": ("method", "route", "status"),
        "flx_http_request_seconds": ("route",),
        "flx_payments_total": ("result",),
        "flx_ledger_occ_retries_total": (),
        "flx_gate_total": ("outcome",),
        "flx_idempotency_total": ("tier",),
        "flx_provider_calls_total": ("provider", "op", "ok"),
        "flx_provider_duration_seconds": ("provider", "op"),
        "flx_worker_batches_total": ("worker",),
        "flx_worker_errors_total": ("worker",),
        "flx_worker_last_success_timestamp": ("worker",),
        "flx_validator_ok": ("worker",),
    }

    assert len(FROZEN_METRIC_SPECS) == len(expected_metrics)

    for metric_name, expected_labels in expected_metrics.items():
        assert metric_name in FROZEN_METRIC_SPECS, (
            f"Metric '{metric_name}' missing from frozen specs"
        )
        spec = FROZEN_METRIC_SPECS[metric_name]
        assert spec["labels"] == expected_labels, (
            f"Metric '{metric_name}' label contract drift: {spec['labels']} != {expected_labels}"
        )


def test_cardinality_law_no_high_cardinality_labels() -> None:
    """THE CARDINALITY LAW: No metric may include agent_id, tx_id, or request_id labels."""
    for metric_name, spec in FROZEN_METRIC_SPECS.items():
        for label in spec["labels"]:
            assert label not in FORBIDDEN_CARDINALITY_LABELS, (
                f"CARDINALITY VIOLATION in '{metric_name}': label '{label}' causes "
                "time-series explosion"
            )


def test_monetary_amount_metric_anti_pattern_refusal() -> None:
    """Refusal verification: flx_payment_amount_minor must NOT exist in the registry.

    Financial amounts belong in double-entry ledger SQL queries, not IEEE 754 floats.
    """
    assert "flx_payment_amount_minor" not in FROZEN_METRIC_SPECS
    collector_names = getattr(REGISTRY, "_names_to_collectors", {})
    assert "flx_payment_amount_minor" not in collector_names


def test_histogram_bucket_invariants() -> None:
    """Histogram bucket bounds must be strictly ascending and positive."""
    assert len(HTTP_LATENCY_BUCKETS) >= 5
    assert all(b > 0 for b in HTTP_LATENCY_BUCKETS)
    assert list(HTTP_LATENCY_BUCKETS) == sorted(HTTP_LATENCY_BUCKETS)

    assert len(PROVIDER_LATENCY_BUCKETS) >= 5
    assert all(b > 0 for b in PROVIDER_LATENCY_BUCKETS)
    assert list(PROVIDER_LATENCY_BUCKETS) == sorted(PROVIDER_LATENCY_BUCKETS)


def test_metrics_instances_callable() -> None:
    """Verify metrics instances can record observations without errors."""
    FLX_HTTP_REQUESTS_TOTAL.labels(method="POST", route="/v1/payments", status="201").inc()
    FLX_HTTP_REQUEST_SECONDS.labels(route="/v1/payments").observe(0.042)
    FLX_PAYMENTS_TOTAL.labels(result="settled").inc()
    FLX_LEDGER_OCC_RETRIES_TOTAL.inc()
    FLX_GATE_TOTAL.labels(outcome="ok").inc()
    FLX_IDEMPOTENCY_TOTAL.labels(tier="fastpath_replay").inc()
    FLX_PROVIDER_CALLS_TOTAL.labels(provider="stripe", op="charge", ok="true").inc()
    FLX_PROVIDER_DURATION_SECONDS.labels(provider="stripe", op="charge").observe(0.125)
    FLX_WORKER_BATCHES_TOTAL.labels(worker="webhook_fanout").inc()
    FLX_WORKER_ERRORS_TOTAL.labels(worker="webhook_fanout").inc()
    FLX_WORKER_LAST_SUCCESS_TIMESTAMP.labels(worker="hash_validator").set(1717000000.0)
    FLX_VALIDATOR_OK.labels(worker="hash_validator").set(1)
