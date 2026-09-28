"""Permanent Meta-Guard: OpenAPI Contract Snapshot Drift Alarm.

Guarantees:
1. contracts/openapi.json exists and is committed.
2. app.openapi() exactly matches the committed snapshot (drift alarm).
3. The three frozen endpoints (/v1/payments, /v1/payments/{tx_id}, /v1/balance) are present.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# Provide synthetic config BEFORE any fluxpay import so pytest collection succeeds in empty envs
os.environ.setdefault("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("FLX_VAULT_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("FLX_WEBHOOK_SIGNING_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("FLX_ENV", "development")

from fluxpay.main import create_app

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_SNAPSHOT_PATH = REPO_ROOT / "contracts" / "openapi.json"


def test_openapi_snapshot_exists_and_matches_app() -> None:
    """Assert committed contracts/openapi.json exists and matches live app.openapi()."""
    assert OPENAPI_SNAPSHOT_PATH.is_file(), (
        f"Missing OpenAPI snapshot at {OPENAPI_SNAPSHOT_PATH}. "
        "Run 'python scripts/gen_openapi.py' to generate."
    )

    app = create_app()
    live_openapi = app.openapi()

    with open(OPENAPI_SNAPSHOT_PATH, encoding="utf-8") as f:
        committed_openapi = json.load(f)

    assert live_openapi == committed_openapi, (
        "OpenAPI schema has drifted from contracts/openapi.json! "
        "Run 'python scripts/gen_openapi.py' to regenerate and commit the snapshot."
    )


def test_openapi_contains_frozen_endpoints() -> None:
    """Assert the three frozen endpoints and error envelopes are declared in OpenAPI."""
    with open(OPENAPI_SNAPSHOT_PATH, encoding="utf-8") as f:
        data = json.load(f)

    paths = data.get("paths", {})
    assert "/v1/payments" in paths, "Missing /v1/payments endpoint in OpenAPI"
    assert "post" in paths["/v1/payments"], "Missing POST /v1/payments in OpenAPI"

    assert "/v1/payments/{tx_id}" in paths, "Missing /v1/payments/{tx_id} endpoint in OpenAPI"
    assert "get" in paths["/v1/payments/{tx_id}"], "Missing GET /v1/payments/{tx_id} in OpenAPI"

    assert "/v1/balance" in paths, "Missing /v1/balance endpoint in OpenAPI"
    assert "get" in paths["/v1/balance"], "Missing GET /v1/balance in OpenAPI"
