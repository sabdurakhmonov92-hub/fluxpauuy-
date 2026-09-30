"""Unit tests for Multi-Backend Secrets Manager (Task 2.3).

Validates EnvSecretManager, LocalSecretManager, and backend factory invariants.
"""

from __future__ import annotations

import pytest

from fluxpay.shared.errors import IntegrationAuthError
from fluxpay.shared.secrets import (
    EnvSecretManager,
    LocalSecretManager,
    get_secret_manager,
)

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_env_secret_manager_retrieves_existing_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate EnvSecretManager retrieves configured environment variables."""
    monkeypatch.setenv("FLX_TEST_SECRET", "super-secret-12345")
    mgr = EnvSecretManager(prefix="FLX_")
    secret = await mgr.get_secret("TEST_SECRET")
    assert secret.get_secret_value() == "super-secret-12345"


@pytest.mark.asyncio
async def test_env_secret_manager_raises_for_missing_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate EnvSecretManager raises IntegrationAuthError when secret is missing."""
    monkeypatch.delenv("FLX_NON_EXISTENT_KEY", raising=False)
    mgr = EnvSecretManager(prefix="FLX_")
    with pytest.raises(IntegrationAuthError):
        await mgr.get_secret("NON_EXISTENT_KEY")


@pytest.mark.asyncio
async def test_local_secret_manager_in_memory_storage() -> None:
    """Validate LocalSecretManager stores and retrieves secrets in memory."""
    mgr = LocalSecretManager({"DB_PASS": "testpass"})
    secret = await mgr.get_secret("DB_PASS")
    assert secret.get_secret_value() == "testpass"

    mgr.set_secret("NEW_KEY", "new_val")
    new_secret = await mgr.get_secret("NEW_KEY")
    assert new_secret.get_secret_value() == "new_val"


def test_get_secrets_manager_factory() -> None:
    """Validate factory instantiates correct backend."""
    mgr_env = get_secret_manager("env")
    assert isinstance(mgr_env, EnvSecretManager)

    mgr_local = get_secret_manager("local")
    assert isinstance(mgr_local, LocalSecretManager)
