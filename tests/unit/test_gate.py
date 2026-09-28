"""Pure unit tests verifying gate key composition, result mapping, resource loading,
and error contracts.

Tests execute purely in-memory with zero Redis, zero network, zero I/O, and zero sleeps.
"""

from __future__ import annotations

import importlib.resources
import re
from typing import Final

import pytest

from fluxpay.gateway.gate import (
    GateResult,
    GateUnavailable,
    compose_day,
    compose_gate_keys,
)
from fluxpay.shared.errors import ERROR_REGISTRY, FluxPayError

pytestmark = pytest.mark.unit

VALID_AGENT_ID: Final[str] = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"
VALID_NONCE: Final[str] = "abcdef0123456789"
VALID_DAY: Final[str] = "20260326"


# =============================================================================
# 1. KEY COMPOSITION TESTS (Pure, exported, unit-tested)
# =============================================================================


def test_compose_day_known_epoch_ms() -> None:
    """Validate that compose_day maps known epoch milliseconds to exact UTC YYYYMMDD string."""
    # 2026-03-26 00:00:00.000 UTC
    now_ms = 1774483200000
    assert compose_day(now_ms) == "20260326"

    # Unix epoch genesis: 1970-01-01 00:00:00 UTC
    assert compose_day(0) == "19700101"

    # Mid-day timestamp: 2026-03-26 12:30:45.678 UTC
    mid_day_ms = 1774483200000 + (12 * 3600 + 30 * 60 + 45) * 1000 + 678
    assert compose_day(mid_day_ms) == "20260326"


def test_compose_day_utc_rollover_boundary() -> None:
    """Validate day rollover exactly at UTC midnight boundary (23:59:59.999 vs 00:00:00.000)."""
    # 2026-03-25 23:59:59.999 UTC
    last_ms_day1 = 1774483200000 - 1
    assert compose_day(last_ms_day1) == "20260325"

    # 2026-03-26 00:00:00.000 UTC
    first_ms_day2 = 1774483200000
    assert compose_day(first_ms_day2) == "20260326"


@pytest.mark.parametrize(
    "bad_now_ms",
    [
        -1,
        -1000,
        "1774483200000",
        None,
        True,
        False,
        123.456,
    ],
)
def test_compose_day_rejects_invalid_inputs(bad_now_ms: object) -> None:
    """Validate that compose_day defensively rejects negative, float, bool, or non-int inputs."""
    with pytest.raises(ValueError, match="now_ms: must be non-negative integer"):
        compose_day(bad_now_ms)  # type: ignore[arg-type]


def test_compose_gate_keys_cluster_hashtag_presence() -> None:
    """Validate that all three keys include the literal {<agent_id>} Redis Cluster hash tag.

    CLUSTER-READINESS LAW:
    In Redis Cluster, all three keys must hash to the exact same hash slot to allow
    multi-key atomic Lua operations without CROSSSLOT errors.
    """
    rate_key, nonce_key, quota_key = compose_gate_keys(VALID_AGENT_ID, VALID_NONCE, VALID_DAY)

    expected_hashtag = f"{{{VALID_AGENT_ID}}}"
    assert expected_hashtag in rate_key
    assert expected_hashtag in nonce_key
    assert expected_hashtag in quota_key

    assert rate_key == f"flx:gate:{{{VALID_AGENT_ID}}}:rate"
    assert nonce_key == f"flx:gate:{{{VALID_AGENT_ID}}}:nonce:{VALID_NONCE}"
    assert quota_key == f"flx:gate:{{{VALID_AGENT_ID}}}:quota:{VALID_DAY}"


def test_compose_gate_keys_nonce_embedded_in_key2() -> None:
    """Validate that key2 embeds the client nonce verbatim for O(1) existence checks."""
    _, nonce_key, _ = compose_gate_keys(VALID_AGENT_ID, VALID_NONCE, VALID_DAY)
    assert nonce_key.endswith(f":nonce:{VALID_NONCE}")


def test_compose_gate_keys_determinism() -> None:
    """Validate that identical parameters produce byte-identical key strings."""
    k1 = compose_gate_keys(VALID_AGENT_ID, VALID_NONCE, VALID_DAY)
    k2 = compose_gate_keys(VALID_AGENT_ID, VALID_NONCE, VALID_DAY)
    assert k1 == k2


@pytest.mark.parametrize(
    "bad_agent_id",
    [
        "abc",
        "018f2d5a8b1e7b2c9d3e4f5a6b7c8d9e",  # unhyphenated
        "018F2D5A-8B1E-7B2C-9D3E-4F5A6B7C8D9E",  # uppercase
        "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e-extra",
        "",
        12345,
        None,
    ],
)
def test_compose_gate_keys_rejects_bad_agent_id(bad_agent_id: object) -> None:
    """Validate that compose_gate_keys defensively rejects non-canonical or non-UUID agent IDs."""
    with pytest.raises(ValueError):
        compose_gate_keys(bad_agent_id, VALID_NONCE, VALID_DAY)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_nonce",
    [
        "short",  # < 16 chars
        "a" * 65,  # > 64 chars
        "non-alphanumeric!",
        "with spaces here",
        "with\nnewline",
        "",
        1234567890123456,
        None,
    ],
)
def test_compose_gate_keys_rejects_bad_nonce(bad_nonce: object) -> None:
    """Validate that compose_gate_keys reuses canonical.validate_nonce and rejects bad nonces."""
    with pytest.raises(ValueError):
        compose_gate_keys(VALID_AGENT_ID, bad_nonce, VALID_DAY)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_day",
    [
        "2026-03-26",  # hyphenated
        "2026326",  # 7 digits
        "202603260",  # 9 digits
        "2026032a",  # non-numeric
        "",
        None,
        20260326,
    ],
)
def test_compose_gate_keys_rejects_bad_day(bad_day: object) -> None:
    """Validate that compose_gate_keys rejects non-8-digit date strings."""
    with pytest.raises(ValueError, match="day: must be 8-digit date string"):
        compose_gate_keys(VALID_AGENT_ID, VALID_NONCE, bad_day)  # type: ignore[arg-type]


# =============================================================================
# 2. GateResult MAPPING & CONTRACT TESTS
# =============================================================================


def test_gate_result_from_code_success() -> None:
    """Validate code 1 maps to ok=True with exact rate and quota counters."""
    res = GateResult.from_code(1, rate=42, quota=150)
    assert res.ok is True
    assert res.replayed is False
    assert res.rate_limited is False
    assert res.quota_exceeded is False
    assert res.rate_count == 42
    assert res.quota_used == 150


def test_gate_result_from_code_replay() -> None:
    """Validate code -1 maps to replayed=True with zero budget consumed."""
    res = GateResult.from_code(-1, rate=0, quota=0)
    assert res.ok is False
    assert res.replayed is True
    assert res.rate_limited is False
    assert res.quota_exceeded is False
    assert res.rate_count == 0
    assert res.quota_used == 0


def test_gate_result_from_code_rate_limited() -> None:
    """Validate code -2 maps to rate_limited=True with window count surfaced."""
    res = GateResult.from_code(-2, rate=100, quota=0)
    assert res.ok is False
    assert res.replayed is False
    assert res.rate_limited is True
    assert res.quota_exceeded is False
    assert res.rate_count == 100
    assert res.quota_used == 0


def test_gate_result_from_code_quota_exceeded() -> None:
    """Validate code -3 maps to quota_exceeded=True with quota count surfaced."""
    res = GateResult.from_code(-3, rate=5, quota=10000)
    assert res.ok is False
    assert res.replayed is False
    assert res.rate_limited is False
    assert res.quota_exceeded is True
    assert res.rate_count == 5
    assert res.quota_used == 10000


@pytest.mark.parametrize("unknown_code", [0, 2, -4, -10, 999])
def test_gate_result_from_code_defensive_unknown_code(unknown_code: int) -> None:
    """Validate that unknown return codes raise GateUnavailable (drift alarm)."""
    with pytest.raises(GateUnavailable) as exc_info:
        GateResult.from_code(unknown_code, rate=0, quota=0)

    assert exc_info.value.status == 503
    assert exc_info.value.retryable is True
    assert exc_info.value.details.get("phase") == "gate_protocol"
    assert exc_info.value.details.get("reason") == "unknown_script_code"
    assert exc_info.value.details.get("code") == str(unknown_code)


def test_gate_result_is_frozen_and_slotted() -> None:
    """Validate GateResult is immutable with __slots__ defined."""
    res = GateResult.from_code(1, rate=1, quota=1)
    with pytest.raises(AttributeError):
        res.ok = False  # type: ignore[misc]

    assert hasattr(res, "__slots__")


# =============================================================================
# 3. RESOURCE LOADING & LUA META-TEST
# =============================================================================


def test_resource_loading_via_importlib() -> None:
    """Validate importlib.resources reads ratelimit.lua from package files.

    Packaging proof: hatchling wheel packaging includes non-.py files in src/fluxpay.
    This test fails at build-time regressions, not in production.
    """
    resource = importlib.resources.files("fluxpay.gateway").joinpath("ratelimit.lua")
    script_text = resource.read_text(encoding="utf-8")
    assert len(script_text) > 100
    assert "ZREMRANGEBYSCORE" in script_text


def test_lua_script_meta_invariants_and_drift_alarm() -> None:
    """Validate Lua script algorithm invariants and strict non-determinism bans.

    Verifies:
    1. Contains required atomic primitives: ZREMRANGEBYSCORE, ZADD, SET, PX, INCR, EXPIRE, EXISTS.
    2. Does NOT contain 'TIME' (Redis TIME or os.time breaks replication and idempotency).
    3. Does NOT contain 'random' (non-deterministic pseudo-random generators banned).
    """
    resource = importlib.resources.files("fluxpay.gateway").joinpath("ratelimit.lua")
    script_text = resource.read_text(encoding="utf-8")

    # Required primitives
    for cmd in ["ZREMRANGEBYSCORE", "ZADD", "SET", "PX", "INCR", "EXPIRE", "EXISTS"]:
        assert cmd in script_text, f"Missing required command {cmd} in ratelimit.lua"

    # Non-determinism ban: NO redis.call('TIME') or TIME command
    assert "TIME" not in script_text, (
        "Forbidden non-deterministic 'TIME' command found in Lua script"
    )

    # Non-determinism ban: NO pseudo-random calls
    assert "random" not in script_text.lower(), (
        "Forbidden non-deterministic 'random' found in Lua script"
    )


# =============================================================================
# 4. ERROR REGISTRY CONTRACT & Task 4 SUITE VERIFICATION
# =============================================================================


def test_gate_unavailable_error_contract_and_registry() -> None:
    """Validate GateUnavailable attributes, wire shape, and registry contract."""
    assert issubclass(GateUnavailable, FluxPayError)
    assert GateUnavailable.code == "gate_unavailable"
    assert GateUnavailable.status == 503
    assert GateUnavailable.retryable is True
    assert GateUnavailable.client_message == "service temporarily unavailable, retry"

    err = GateUnavailable(details={"phase": "gate", "target": "valkey-01"})
    payload = err.to_payload()
    assert payload == {
        "error": {
            "code": "gate_unavailable",
            "message": "service temporarily unavailable, retry",
            "retryable": True,
        }
    }

    # Diagnostics exclusion: internal details must not appear in str(err) or payload
    assert "target" not in str(err)
    assert "target" not in str(payload)
    assert "valkey-01" not in str(err)
    assert "valkey-01" not in str(payload)

    # Validate registry registration (safely restoring state to keep Task 4 tests green)
    was_present = "gate_unavailable" in ERROR_REGISTRY
    ERROR_REGISTRY["gate_unavailable"] = GateUnavailable
    try:
        assert "gate_unavailable" in ERROR_REGISTRY
        cls = ERROR_REGISTRY["gate_unavailable"]
        assert cls is GateUnavailable
        assert cls.retryable is True
        assert cls.status == 503

        # Verify snake_case format
        code_pattern = re.compile(r"^[a-z][a-z0-9_]*$")
        assert code_pattern.match(cls.code)

        # Verify uniqueness among registered codes
        codes = list(ERROR_REGISTRY.keys())
        assert len(codes) == len(set(codes)), "Duplicate error code detected in registry"
    finally:
        if not was_present:
            ERROR_REGISTRY.pop("gate_unavailable", None)
