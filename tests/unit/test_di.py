"""Unit tests for Centralized Dependency Injection Container (Task 1.1).

Validates that di.py provides clean dependency resolution without global
singletons or import-time side-effects.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from starlette.requests import Request

from fluxpay.config import Settings
from fluxpay.di import (
    get_agent_repo,
    get_db_pool,
    get_ledger_store,
    get_payment_service,
    get_redis_client,
    get_settings_dep,
)

pytestmark = pytest.mark.unit


def _mock_request(**state_kwargs: object) -> Request:
    """Create a mock Request with given app.state attributes."""
    app_mock = MagicMock()
    for k, v in state_kwargs.items():
        setattr(app_mock.state, k, v)
    req = MagicMock(spec=Request)
    req.app = app_mock
    return req


def test_get_settings_dep_returns_settings() -> None:
    """Validate get_settings_dep resolves Settings instance."""
    mock_settings = MagicMock(spec=Settings)
    req = _mock_request(settings=mock_settings)
    settings = get_settings_dep(req)
    assert settings is mock_settings


def test_get_db_pool_resolves_from_app_state() -> None:
    """Validate get_db_pool retrieves pool from request.app.state."""
    fake_pool = MagicMock()
    req = _mock_request(pool=fake_pool)
    resolved = get_db_pool(req)
    assert resolved is fake_pool


def test_get_db_pool_raises_if_uninitialized() -> None:
    """Validate get_db_pool raises RuntimeError if pool is not in app.state."""
    req = _mock_request(pool=None)
    with pytest.raises(RuntimeError, match="Database pool is not initialized"):
        get_db_pool(req)


def test_get_redis_client_resolves_from_app_state() -> None:
    """Validate get_redis_client retrieves valkey from request.app.state."""
    fake_valkey = MagicMock()
    req = _mock_request(valkey=fake_valkey)
    resolved = get_redis_client(req)
    assert resolved is fake_valkey


def test_get_ledger_store_resolves_from_app_state() -> None:
    """Validate get_ledger_store retrieves ledger from request.app.state."""
    fake_ledger = MagicMock()
    req = _mock_request(ledger=fake_ledger)
    resolved = get_ledger_store(req)
    assert resolved is fake_ledger


def test_get_agent_repo_resolves_from_app_state() -> None:
    """Validate get_agent_repo retrieves agent_repo from request.app.state."""
    fake_repo = MagicMock()
    req = _mock_request(agent_repo=fake_repo)
    resolved = get_agent_repo(req)
    assert resolved is fake_repo


def test_get_payment_service_resolves_from_app_state() -> None:
    """Validate get_payment_service retrieves payments from request.app.state."""
    fake_payments = MagicMock()
    req = _mock_request(payments=fake_payments)
    resolved = get_payment_service(req)
    assert resolved is fake_payments
