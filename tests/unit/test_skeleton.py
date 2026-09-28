"""Smoke tests validating repository foundation and toolchain wiring.

Purpose:
If CI or the developer environment is broken, failure MUST happen here first,
never deep inside money-path or ledger invariant tests.
"""

import asyncio
import re

import pytest

import fluxpay


@pytest.mark.unit
def test_package_import_and_version_exists() -> None:
    """Validate that the core fluxpay package imports and exposes a version attribute."""
    assert hasattr(fluxpay, "__version__")
    assert isinstance(fluxpay.__version__, str)


@pytest.mark.unit
def test_package_version_adheres_to_semver() -> None:
    """Validate that the package version strictly follows Semantic Versioning (SemVer)."""
    semver_pattern = (
        r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
        r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
        r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
    )
    assert re.match(semver_pattern, fluxpay.__version__), (
        f"Version string '{fluxpay.__version__}' does not adhere to SemVer specification."
    )


@pytest.mark.unit
async def test_asyncio_runner_executes_coroutines() -> None:
    """Validate that pytest-asyncio with asyncio_mode='auto' natively executes coroutines."""
    coroutine_executed = False

    async def sample_coroutine() -> str:
        nonlocal coroutine_executed
        await asyncio.sleep(0.001)
        coroutine_executed = True
        return "fluxpay_async_ok"

    result = await sample_coroutine()

    assert coroutine_executed is True
    assert result == "fluxpay_async_ok"
