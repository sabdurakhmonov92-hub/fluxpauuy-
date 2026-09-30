"""Unit tests verifying the SEV1 Alert Router and Dead-Man Switch Heartbeat (Task 69).

Validates KAT formatters, deduplication window, severity gating, fail-closed auth,
heartbeat gauge math, and alerts.yml contract specification.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml  # type: ignore[import-untyped]

from fluxpay.alerts.router import (
    AlertRouter,
    NormalizedAlert,
    create_alert_router_app,
    format_sev_alert,
    send_heartbeat,
)
from fluxpay.config import Settings
from fluxpay.shared.metrics import (
    FLX_VALIDATOR_OK,
    FLX_WORKER_LAST_SUCCESS_TIMESTAMP,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


class MockTelegramChannel:
    """Mock Telegram transport capturing dispatched messages without network I/O."""

    def __init__(self) -> None:
        self.sent_messages: list[str] = []

    async def send(self, message: str) -> None:
        self.sent_messages.append(message)


def test_format_sev_alert_kat() -> None:
    """KAT: Pure formatter produces exact byte-for-byte plain-text alert layout."""
    alert1 = NormalizedAlert(
        alertname="ChainBroken",
        severity="SEV1",
        summary="SHA-256 hash mismatch at seq 1042",
        runbook_url="docs/runbooks/ChainBroken.md",
        source="alertmanager",
        fingerprint="fp1",
    )
    expected_sev1 = (
        "🚨 SEV1 [FluxPay] ChainBroken\n"
        "SHA-256 hash mismatch at seq 1042\n"
        "runbook: docs/runbooks/ChainBroken.md\n"
        "source: alertmanager"
    )
    assert format_sev_alert(alert1) == expected_sev1

    alert2 = NormalizedAlert(
        alertname="MoneyPathErrors",
        severity="SEV2",
        summary="Payment failure rate > 0.1/s",
        runbook_url="docs/runbooks/MoneyPathErrors.md",
        source="alertmanager",
        fingerprint="fp2",
    )
    expected_sev2 = (
        "⚠️ SEV2 [FluxPay] MoneyPathErrors\n"
        "Payment failure rate > 0.1/s\n"
        "runbook: docs/runbooks/MoneyPathErrors.md\n"
        "source: alertmanager"
    )
    assert format_sev_alert(alert2) == expected_sev2

    alert3 = NormalizedAlert(
        alertname="ProviderHealth",
        severity="SEV3",
        summary="Stripe error rate elevated",
        runbook_url="docs/runbooks/ProviderHealth.md",
        source="alertmanager",
        fingerprint="fp3",
    )
    expected_sev3 = (
        "ℹ️ SEV3 [FluxPay] ProviderHealth\n"  # noqa: RUF001
        "Stripe error rate elevated\n"
        "runbook: docs/runbooks/ProviderHealth.md\n"
        "source: alertmanager"
    )
    assert format_sev_alert(alert3) == expected_sev3


@pytest.mark.asyncio
async def test_dedup_window_and_severity_gate() -> None:
    """Validate 10-minute deduplication window and SEV3 silent logging gate."""
    current_time = 1000.0

    def mock_clock() -> float:
        return current_time

    mock_channel = MockTelegramChannel()
    settings = Settings(
        pg_dsn="postgresql://fluxpay:fluxpay@localhost:5432/fluxpay",
        vault_master_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        webhook_signing_key="0123456789abcdef0123456789abcdef",
        alertrouter_secret="test-secret-32-chars-minimum-length!",  # noqa: S106
    )
    router = AlertRouter(
        settings=settings,
        channel=mock_channel,
        clock=mock_clock,
        dedup_window_s=600.0,
    )

    alert_sev1 = NormalizedAlert(
        alertname="FluxPayDown",
        severity="SEV1",
        summary="Service instance is down",
        runbook_url="docs/runbooks/FluxPayDown.md",
        source="alertmanager",
        fingerprint="fp_down_1",
    )

    # 1. First SEV1 dispatch -> delivered
    res1 = await router.route_alert(alert_sev1)
    assert res1["status"] == "sent"
    assert len(mock_channel.sent_messages) == 1

    # 2. Duplicate SEV1 within 10-minute window (at 300s) -> swallowed
    current_time = 1300.0
    res2 = await router.route_alert(alert_sev1)
    assert res2["status"] == "deduplicated"
    assert len(mock_channel.sent_messages) == 1

    # 3. Third SEV1 after 10-minute window (at 601s from first) -> delivered
    current_time = 1601.0
    res3 = await router.route_alert(alert_sev1)
    assert res3["status"] == "sent"
    assert len(mock_channel.sent_messages) == 2

    # 4. SEV3 alert -> logged only, NEVER delivered to Telegram
    alert_sev3 = NormalizedAlert(
        alertname="ProviderHealth",
        severity="SEV3",
        summary="Provider degradation notice",
        runbook_url="docs/runbooks/ProviderHealth.md",
        source="alertmanager",
        fingerprint="fp_sev3_1",
    )
    res_sev3 = await router.route_alert(alert_sev3)
    assert res_sev3["status"] == "logged"
    assert len(mock_channel.sent_messages) == 2  # Still 2, untouched!


@pytest.mark.asyncio
async def test_alert_router_api_fail_closed_auth() -> None:
    """Verify webhook ingress rejects unauthenticated calls and accepts valid bearer."""
    mock_channel = MockTelegramChannel()
    auth_token = "secret-key-12345"  # noqa: S105
    settings = Settings(
        pg_dsn="postgresql://fluxpay:fluxpay@localhost:5432/fluxpay",
        vault_master_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        webhook_signing_key="0123456789abcdef0123456789abcdef",
        alertrouter_secret=auth_token,
    )
    router = AlertRouter(settings=settings, channel=mock_channel)
    app = create_alert_router_app(router=router, settings=settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1. No Authorization header -> 403 Forbidden
        resp = await client.post("/alertmanager", json={"alerts": []})
        assert resp.status_code == 403

        # 2. Wrong Authorization header -> 403 Forbidden
        resp = await client.post(
            "/alertmanager",
            json={"alerts": []},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403

        # 3. Correct Authorization -> 200 OK
        sev1_payload = {
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "FluxPayDown", "severity": "SEV1"},
                    "annotations": {
                        "summary": "Gateway process offline",
                        "runbook_url": "docs/runbooks/FluxPayDown.md",
                    },
                    "fingerprint": "fp_http_1",
                }
            ]
        }
        resp = await client.post(
            "/alertmanager",
            json=sev1_payload,
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code == 200
        assert len(mock_channel.sent_messages) == 1
        assert "🚨 SEV1 [FluxPay] FluxPayDown" in mock_channel.sent_messages[0]


@pytest.mark.asyncio
async def test_heartbeat_bridge_and_gauge_updates() -> None:
    """Verify heartbeat endpoint updates in-memory Prometheus gauges."""
    mock_channel = MockTelegramChannel()
    auth_token = "heartbeat-secret-xyz"  # noqa: S105
    settings = Settings(
        pg_dsn="postgresql://fluxpay:fluxpay@localhost:5432/fluxpay",
        vault_master_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        webhook_signing_key="0123456789abcdef0123456789abcdef",
        alertrouter_secret=auth_token,
    )
    router = AlertRouter(settings=settings, channel=mock_channel)
    app = create_alert_router_app(router=router, settings=settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1. Success heartbeat
        ts = 1717001234.0
        resp = await client.post(
            "/heartbeat",
            json={"worker": "hash_validator", "ok": True, "ts": ts},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code == 200
        assert FLX_WORKER_LAST_SUCCESS_TIMESTAMP.labels(worker="hash_validator")._value.get() == ts
        assert FLX_VALIDATOR_OK.labels(worker="hash_validator")._value.get() == 1.0

        # 2. Failure heartbeat (Broken chain) -> immediately pages SEV1
        resp_fail = await client.post(
            "/heartbeat",
            json={
                "worker": "hash_validator",
                "ok": False,
                "ts": ts + 10,
                "reason": "hash_drift_seq_1042",
            },
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp_fail.status_code == 200
        assert FLX_VALIDATOR_OK.labels(worker="hash_validator")._value.get() == 0.0
        assert len(mock_channel.sent_messages) == 1
        assert "🚨 SEV1 [FluxPay] ChainBroken" in mock_channel.sent_messages[0]


def test_send_heartbeat_helper_in_process_and_resilient() -> None:
    """Verify send_heartbeat helper updates local metrics and handles unreachable router."""
    test_ts = 1718000000.0
    send_heartbeat("reconciliation", ok=True, ts=test_ts, port=64999)  # Non-existent port
    assert FLX_WORKER_LAST_SUCCESS_TIMESTAMP.labels(worker="reconciliation")._value.get() == test_ts
    assert FLX_VALIDATOR_OK.labels(worker="reconciliation")._value.get() == 1.0

    send_heartbeat("reconciliation", ok=False, reason="mismatch", ts=test_ts + 5, port=64999)
    assert FLX_VALIDATOR_OK.labels(worker="reconciliation")._value.get() == 0.0


def test_alerts_yml_contract_specification() -> None:
    """Parse deploy/observability/alerts.yml and verify every rule conforms to contract."""
    alerts_path = REPO_ROOT / "deploy" / "observability" / "alerts.yml"
    assert alerts_path.is_file(), f"Missing alerts file: {alerts_path}"

    with open(alerts_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "groups" in data, "alerts.yml missing groups block"
    all_rules: list[dict[str, Any]] = []
    for group in data["groups"]:
        all_rules.extend(group.get("rules", []))

    assert len(all_rules) >= 8, f"Expected at least 8 alert rules, found {len(all_rules)}"

    allowed_severities = {"SEV1", "SEV2", "SEV3"}

    for rule in all_rules:
        name = rule.get("alert")
        assert name, "Alert rule missing 'alert' name"
        labels = rule.get("labels", {})
        annotations = rule.get("annotations", {})

        # Contract Rule 1: Severity label
        severity = labels.get("severity")
        assert severity in allowed_severities, (
            f"Alert '{name}' has invalid or missing severity: '{severity}'. "
            f"Allowed: {allowed_severities}"
        )

        # Contract Rule 2: Runbook annotation
        runbook = annotations.get("runbook_url")
        assert runbook, f"Alert '{name}' missing 'runbook_url' annotation"
        assert runbook.startswith("docs/runbooks/"), (
            f"Alert '{name}' runbook_url '{runbook}' does not point to docs/runbooks/"
        )

        # For SEV1 rules: Verify the runbook file actually exists!
        if severity == "SEV1":
            runbook_file = REPO_ROOT / runbook
            assert runbook_file.is_file(), (
                f"SEV1 alert '{name}' references non-existent runbook file: {runbook_file}"
            )
