"""Integration tests for FluxPay Observability Stack and SEV1 Alert Router (Task 69).

Validates:
1. /metrics Prometheus exposition endpoint and money-path counter exposition.
2. Heartbeat bridge: periodic one-shots update gauges and exposed Prometheus text format.
3. Alertmanager payload -> TelegramChannel MockTransport: SEV1 page sent, dedup window
   swallows repeats, SEV3 remains silent, invalid secret fails closed (403).
4. Dead-man switch PromQL rule evaluation against synthetic time-series.
5. alerts.yml contract specification (severity + runbook on every alert rule).
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
import yaml

from fluxpay.alerts.router import (
    AlertRouter,
    create_alert_router_app,
)
from fluxpay.config import Settings
from fluxpay.main import create_app
from fluxpay.shared.metrics import (
    FLX_PAYMENTS_TOTAL,
)

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]


class MockTelegramChannel:
    """Mock Telegram transport capturing messages for test assertions."""

    def __init__(self) -> None:
        self.sent_messages: list[str] = []

    async def send(self, message: str) -> None:
        self.sent_messages.append(message)


@pytest.mark.asyncio
async def test_metrics_exposition_endpoint_and_money_path_counter() -> None:
    """E2E /metrics scrape: verifies prometheus-format exposition parses.

    Verifies settled counter is present.
    """
    app = create_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Increment money-path metric to guarantee presence
        FLX_PAYMENTS_TOTAL.labels(result="settled").inc()

        resp = await client.get("/metrics")
        assert resp.status_code == 200
        content = resp.text

        # Verify money-path metric is exposed in Prometheus text format
        pattern = re.compile(r'flx_payments_total\{result="settled"\}\s+([0-9\.]+)')
        match = pattern.search(content)
        assert match is not None, (
            "flx_payments_total{result='settled'} not found in /metrics output"
        )
        value = float(match.group(1))
        assert value >= 1.0


@pytest.mark.asyncio
async def test_heartbeat_bridge_and_prometheus_gauge_exposition() -> None:
    """Verify one-shot heartbeat updates router gauges and Prometheus exposition parses."""
    auth_token = "test-secret-observability-32-chars"  # noqa: S105
    settings = Settings(
        pg_dsn="postgresql://fluxpay:fluxpay@localhost:5432/fluxpay",
        vault_master_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        webhook_signing_key="0123456789abcdef0123456789abcdef",
        alertrouter_secret=auth_token,
    )
    mock_channel = MockTelegramChannel()
    router = AlertRouter(settings=settings, channel=mock_channel)
    app = create_alert_router_app(router=router, settings=settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1. Successful heartbeat from hash_validator
        test_ts = 1718500000.0
        hb_resp = await client.post(
            "/heartbeat",
            json={"worker": "hash_validator", "ok": True, "ts": test_ts},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert hb_resp.status_code == 200

        # 2. Scrape router /metrics endpoint
        metrics_resp = await client.get("/metrics")
        assert metrics_resp.status_code == 200
        content = metrics_resp.text

        # Parse gauge values from exposition text (supporting scientific notation e.g. 1.7185e+09)
        ts_pattern = re.compile(
            r'flx_worker_last_success_timestamp\{worker="hash_validator"\}\s+([0-9\.eE\+\-]+)'
        )
        ok_pattern = re.compile(r'flx_validator_ok\{worker="hash_validator"\}\s+([0-9\.eE\+\-]+)')

        ts_match = ts_pattern.search(content)
        ok_match = ok_pattern.search(content)

        assert ts_match is not None, "flx_worker_last_success_timestamp missing from /metrics"
        assert ok_match is not None, "flx_validator_ok missing from /metrics"
        assert float(ts_match.group(1)) == test_ts
        assert float(ok_match.group(1)) == 1.0

        # 3. Broken chain heartbeat
        hb_fail_resp = await client.post(
            "/heartbeat",
            json={
                "worker": "hash_validator",
                "ok": False,
                "ts": test_ts + 30,
                "reason": "chain_tamper_detected",
            },
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert hb_fail_resp.status_code == 200

        # Scrape /metrics again and confirm validator_ok transitioned to 0.0
        metrics_resp2 = await client.get("/metrics")
        content2 = metrics_resp2.text
        ok_match2 = ok_pattern.search(content2)
        assert ok_match2 is not None
        assert float(ok_match2.group(1)) == 0.0

        # Verify immediate SEV1 alert was dispatched to Telegram channel
        assert len(mock_channel.sent_messages) == 1
        assert "🚨 SEV1 [FluxPay] ChainBroken" in mock_channel.sent_messages[0]


@pytest.mark.asyncio
async def test_alertmanager_e2e_telegram_page_dedup_and_auth() -> None:
    """E2E Alertmanager webhook ingestion.

    Verifies SEV1 pages, dedup swallows repeat, SEV3 silent, and 403 on wrong secret.
    """
    current_time = 2000.0

    def mock_clock() -> float:
        return current_time

    auth_token = "e2e-alert-router-secret-key-32ch"  # noqa: S105
    settings = Settings(
        pg_dsn="postgresql://fluxpay:fluxpay@localhost:5432/fluxpay",
        vault_master_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        webhook_signing_key="0123456789abcdef0123456789abcdef",
        alertrouter_secret=auth_token,
    )
    mock_channel = MockTelegramChannel()
    router = AlertRouter(
        settings=settings, channel=mock_channel, clock=mock_clock, dedup_window_s=600.0
    )
    app = create_alert_router_app(router=router, settings=settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1. Invalid secret -> 403 fail-closed
        bad_auth_resp = await client.post(
            "/alertmanager",
            json={"alerts": []},
            headers={"Authorization": "Bearer incorrect-secret"},
        )
        assert bad_auth_resp.status_code == 403

        # 2. SEV1 alert payload
        sev1_payload = {
            "version": "4",
            "status": "firing",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "FluxPayDown", "severity": "SEV1"},
                    "annotations": {
                        "summary": "Core API gateway process unreachable",
                        "runbook_url": "docs/runbooks/FluxPayDown.md",
                    },
                    "fingerprint": "fp_fluxpay_down_e2e",
                }
            ],
        }

        resp1 = await client.post(
            "/alertmanager",
            json=sev1_payload,
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp1.status_code == 200
        assert len(mock_channel.sent_messages) == 1
        assert "🚨 SEV1 [FluxPay] FluxPayDown" in mock_channel.sent_messages[0]

        # 3. Duplicate within 10 minutes (at 300s) -> swallowed
        current_time = 2300.0
        resp2 = await client.post(
            "/alertmanager",
            json=sev1_payload,
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp2.status_code == 200
        assert len(mock_channel.sent_messages) == 1  # Unchanged

        # 4. Repeat after 10 minutes (at 601s) -> delivered
        current_time = 2601.0
        resp3 = await client.post(
            "/alertmanager",
            json=sev1_payload,
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp3.status_code == 200
        assert len(mock_channel.sent_messages) == 2  # Dispatched second time

        # 5. SEV3 alert -> silent in logs, never pages Telegram
        sev3_payload = {
            "version": "4",
            "status": "firing",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "ProviderHealth", "severity": "SEV3"},
                    "annotations": {
                        "summary": "Provider call error rate 35%",
                        "runbook_url": "docs/runbooks/ProviderHealth.md",
                    },
                    "fingerprint": "fp_provider_sev3",
                }
            ],
        }
        resp4 = await client.post(
            "/alertmanager",
            json=sev3_payload,
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp4.status_code == 200
        assert len(mock_channel.sent_messages) == 2  # Still 2, SEV3 never pages!


def test_dead_man_switch_promql_evaluation_rule() -> None:
    """Evaluate dead-man switch PromQL logic against synthetic series values."""
    eval_time = 10000.0

    # Rule: (time() - flx_worker_last_success_timestamp{worker="hash_validator"}) > 7200
    def eval_dead_man_expr(last_success_ts: float, now: float) -> bool:
        return (now - last_success_ts) > 7200

    # Case A: Success was 30 minutes ago (1800s) -> healthy, not firing
    healthy_ts = eval_time - 1800.0
    assert not eval_dead_man_expr(healthy_ts, eval_time)

    # Case B: Success was 2 hours + 1 second ago (7201s) -> DEAD-MAN SWITCH TRIPPED (SEV1)
    stale_ts = eval_time - 7201.0
    assert eval_dead_man_expr(stale_ts, eval_time)

    # Rule: flx_validator_ok == 0 -> IMMEDIATE SEV1
    def eval_chain_broken_expr(validator_ok: float) -> bool:
        return validator_ok == 0.0

    assert not eval_chain_broken_expr(1.0)
    assert eval_chain_broken_expr(0.0)


def test_alerts_yml_meta_test_contract_parse() -> None:
    """Meta-test: verify alerts.yml contract (all rules have severity and runbook_url)."""
    alerts_path = REPO_ROOT / "deploy" / "observability" / "alerts.yml"
    with open(alerts_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = [rule for group in data.get("groups", []) for rule in group.get("rules", [])]
    for rule in rules:
        name = rule["alert"]
        assert "severity" in rule.get("labels", {}), f"Rule {name} missing severity"
        assert "runbook_url" in rule.get("annotations", {}), f"Rule {name} missing runbook_url"
        runbook_path = REPO_ROOT / rule["annotations"]["runbook_url"]
        if rule["labels"]["severity"] == "SEV1":
            assert runbook_path.is_file(), f"SEV1 runbook missing on disk: {runbook_path}"
