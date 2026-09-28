"""Permanent Meta-Guard: UUIDv5 Determinism Cross-Check (bootstrap.sql <-> Python).

Changing the namespace or names breaks every environment's account identity;
this is a breaking change requiring migration.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

NAMESPACE = uuid.UUID("f1047a71-0000-5000-8000-000000000000")
EXPECTED = {
    "system": "97b333de-f2b6-5d2d-98c9-51de34590c17",
    "fees": "36723e80-972f-54bc-a5a1-76d83b2d1438",
    "treasury": "aa51a413-b2f4-5bba-9be1-96ed6c605853",
}

REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SQL_PATH = REPO_ROOT / "deploy" / "sql" / "bootstrap.sql"


def test_uuid5_determinism() -> None:
    """Assert Python stdlib uuid5 generates exactly the expected deterministic UUIDs."""
    for name, expected in EXPECTED.items():
        assert str(uuid.uuid5(NAMESPACE, name)) == expected


def test_bootstrap_sql_matches_python_uuid5() -> None:
    """Assert deploy/sql/bootstrap.sql hardcodes the exact deterministic UUIDs."""
    assert BOOTSTRAP_SQL_PATH.is_file(), f"Missing bootstrap.sql at {BOOTSTRAP_SQL_PATH}"
    content = BOOTSTRAP_SQL_PATH.read_text(encoding="utf-8")

    assert str(NAMESPACE) in content, f"bootstrap.sql must declare namespace {NAMESPACE}"
    for name, expected in EXPECTED.items():
        assert expected in content, (
            f"bootstrap.sql missing expected UUID {expected} for account '{name}'"
        )
