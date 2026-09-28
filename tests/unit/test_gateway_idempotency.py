"""Unit tests for idempotency fast-path Redis tier over the database state machine.

Tests verify:
- Pure classifier decision matrix completeness including the evicted-lock self-repair row.
- Boundary condition for cached == b"" (empty body).
- Strict SHA-256 body_hash format validation (length, hex, casing).
- Redis Cluster hash-tagging and key composition hygiene.
- Byte-exact response serialization, roundtrip integrity, and status validation.
- Settings configuration contract and .env.example synchronization.
"""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import Final

import pytest

from fluxpay.config import Settings, get_settings
from fluxpay.gateway.idempotency import (
    FastPathOutcome,
    classify_fastpath,
    fastpath_keys,
    pack_response,
    parse_response,
)

pytestmark = pytest.mark.unit

VALID_HASH_A: Final[str] = "a" * 64
VALID_HASH_B: Final[str] = "b" * 64


# =============================================================================
# 1. CLASSIFIER MATRIX COMPLETENESS (Zero I/O Pure Logic)
# =============================================================================


def test_classify_fresh_proceed_when_acquired_and_no_cache() -> None:
    """Validate fresh request: lock acquired + no cached response -> PROCEED."""
    outcome = classify_fastpath(
        acquired=True,
        stored_hash=None,
        cached=None,
        body_hash=VALID_HASH_A,
    )
    assert outcome == FastPathOutcome.PROCEED


def test_classify_evicted_lock_self_repair_row() -> None:
    """Validate evicted-lock self-repair row: acquired + cached present -> REPLAY_CACHED.

    WHY this test exists:
    Asserted BY NAME per Senior Notes. The lock can expire or be evicted under Redis
    memory pressure while the cached response outlives it. A mid-level engineer might
    mistakenly return PROCEED because acquired=True; our classifier detects cached presence
    and self-repairs by returning REPLAY_CACHED, avoiding a cold duplicate execution.
    """
    cached_payload = b'201|{"status":"paid"}'
    outcome = classify_fastpath(
        acquired=True,
        stored_hash=VALID_HASH_A,
        cached=cached_payload,
        body_hash=VALID_HASH_A,
    )
    assert outcome == FastPathOutcome.REPLAY_CACHED


def test_classify_conflict_when_not_acquired_and_hash_mismatch() -> None:
    """Validate fraud guard: not acquired + stored_hash != body_hash -> CONFLICT."""
    outcome = classify_fastpath(
        acquired=False,
        stored_hash=VALID_HASH_B,
        cached=None,
        body_hash=VALID_HASH_A,
    )
    assert outcome == FastPathOutcome.CONFLICT


def test_classify_conflict_when_not_acquired_stored_hash_mismatch_even_with_cached() -> None:
    """Validate fraud guard takes precedence: conflicting body is rejected even if key cached."""
    outcome = classify_fastpath(
        acquired=False,
        stored_hash=VALID_HASH_B,
        cached=b"201|{}",
        body_hash=VALID_HASH_A,
    )
    assert outcome == FastPathOutcome.CONFLICT


def test_classify_replay_when_not_acquired_and_hash_matches_with_cache() -> None:
    """Validate duplicate return:
    not acquired + stored_hash == body_hash + cached -> REPLAY_CACHED.
    """
    outcome = classify_fastpath(
        acquired=False,
        stored_hash=VALID_HASH_A,
        cached=b'201|{"status":"ok"}',
        body_hash=VALID_HASH_A,
    )
    assert outcome == FastPathOutcome.REPLAY_CACHED


def test_classify_in_progress_when_not_acquired_and_hash_matches_no_cache() -> None:
    """Validate concurrent twin:
    not acquired + stored_hash == body_hash + cached None -> IN_PROGRESS.
    """
    outcome = classify_fastpath(
        acquired=False,
        stored_hash=VALID_HASH_A,
        cached=None,
        body_hash=VALID_HASH_A,
    )
    assert outcome == FastPathOutcome.IN_PROGRESS


# =============================================================================
# 2. BOUNDARY: EMPTY CACHED BODY
# =============================================================================


def test_classify_boundary_empty_cached_body_is_replay_cached() -> None:
    """Validate boundary condition: cached == b"" (empty body) is valid and yields REPLAY_CACHED.

    `cached is not None` must be used instead of truthiness because bool(b"") is False.
    """
    # Acquired + empty cached response
    outcome_acquired = classify_fastpath(
        acquired=True,
        stored_hash=None,
        cached=b"",
        body_hash=VALID_HASH_A,
    )
    assert outcome_acquired == FastPathOutcome.REPLAY_CACHED

    # Not acquired + match + empty cached response
    outcome_unacquired = classify_fastpath(
        acquired=False,
        stored_hash=VALID_HASH_A,
        cached=b"",
        body_hash=VALID_HASH_A,
    )
    assert outcome_unacquired == FastPathOutcome.REPLAY_CACHED


# =============================================================================
# 3. BODY HASH VALIDATION (Door-Check Defense)
# =============================================================================


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "a" * 63,  # Length 63 (too short)
        "a" * 65,  # Length 65 (too long)
        ("A" * 64),  # Uppercase
        ("a" * 63) + "g",  # Non-hex character 'g'
        "",  # Empty
        "not-a-hash",
    ],
)
def test_classify_bad_body_hash_raises_value_error(invalid_hash: str) -> None:
    """Validate that malformed body_hash raises ValueError at the door."""
    with pytest.raises(ValueError, match="Invalid body_hash format"):
        classify_fastpath(
            acquired=True,
            stored_hash=None,
            cached=None,
            body_hash=invalid_hash,
        )


# =============================================================================
# 4. KEY COMPOSITION & CLUSTER CO-LOCATION
# =============================================================================


def test_fastpath_keys_cluster_hashtag_and_syntax() -> None:
    """Validate hash-tag {agent_id} in BOTH keys for Redis Cluster slot co-location."""
    agent_id = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"
    idem_key = "idemp-test-key-0123456789"

    lock_key, resp_key = fastpath_keys(agent_id, idem_key)

    assert lock_key == f"flx:idem:{{{agent_id}}}:{idem_key}"
    assert resp_key == f"flx:idem:{{{agent_id}}}:{idem_key}:resp"

    # Both keys must co-locate in same hash slot via matching {...} tag
    assert f"{{{agent_id}}}" in lock_key
    assert f"{{{agent_id}}}" in resp_key


@pytest.mark.parametrize(
    "invalid_key",
    [
        "short-key",  # < 16 chars
        "valid-length_with_underscore-1234",  # Underscore forbidden
        "a" * 129,  # > 128 chars
        "has spaces in key 01234",  # Spaces forbidden
    ],
)
def test_fastpath_keys_rejects_invalid_idempotency_key(invalid_key: str) -> None:
    """Validate that invalid idempotency keys fail fast."""
    with pytest.raises(ValueError, match="idempotency_key"):
        fastpath_keys("agent_01", invalid_key)


def test_fastpath_keys_rejects_empty_agent_id() -> None:
    """Validate agent_id must be non-empty string."""
    with pytest.raises(ValueError, match="agent_id"):
        fastpath_keys("", "valid-idempotency-key-01")


# =============================================================================
# 5. CACHE FORMAT ROUNDTRIP & BYTE-EXACT GUARANTEE
# =============================================================================


def test_cache_format_roundtrip_byte_exact() -> None:
    """Validate status 201 + unicode JSON body roundtrips byte-exact without alteration."""
    status = 201
    body_unicode = '{"recipient": "München 🚀", "amount": 5000, "note": "Café & Crêpe"}'
    raw_body = body_unicode.encode("utf-8")

    packed = pack_response(status, raw_body)
    assert packed.startswith(b"201|")
    assert packed == b"201|" + raw_body

    unpacked_status, unpacked_body = parse_response(packed)
    assert unpacked_status == 201
    assert unpacked_body == raw_body
    # Exact byte identity proof
    assert unpacked_body.decode("utf-8") == body_unicode


def test_cache_format_roundtrip_empty_body() -> None:
    """Validate empty body response packs and parses correctly."""
    packed = pack_response(204, b"")
    assert packed == b"204|"

    unpacked_status, unpacked_body = parse_response(packed)
    assert unpacked_status == 204
    assert unpacked_body == b""


@pytest.mark.parametrize(
    "malformed_payload",
    [
        b"20|{}",  # 2-digit status
        b"2001{}",  # 4-digit status without pipe
        b"abc|{}",  # Non-numeric status
        b"200",  # Truncated before pipe (< 4 bytes)
        b"",  # Empty bytes
    ],
)
def test_parse_response_malformed_prefix_fails(malformed_payload: bytes) -> None:
    """Validate malformed cached prefix raises ValueError."""
    with pytest.raises(ValueError):
        parse_response(malformed_payload)


@pytest.mark.parametrize("invalid_status", [199, 300, 400, 500])
def test_pack_and_parse_response_status_outside_2xx_fails(invalid_status: int) -> None:
    """Validate status codes outside 200..299 are rejected by pack and parse."""
    with pytest.raises(ValueError, match=r"200\.\.299"):
        pack_response(invalid_status, b"{}")

    malformed_cached = f"{invalid_status:03d}|{{}}".encode("ascii")
    with pytest.raises(ValueError, match=r"200\.\.299"):
        parse_response(malformed_cached)


# =============================================================================
# 6. CONFIG CONTRACT & .ENV.EXAMPLE SYNCHRONIZATION
# =============================================================================


def test_config_contract_idempotency_fast_ttl_s(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate Settings default for idempotency_fast_ttl_s and env override."""
    # Strip any ambient env vars and clear singleton cache
    for key in list(os.environ.keys()):
        if key.startswith("FLX_"):
            monkeypatch.delenv(key, raising=False)

    baseline = {
        "FLX_PG_DSN": "postgresql://test:test@localhost:5432/test",
        "FLX_VAULT_MASTER_KEY": base64.b64encode(b"0" * 32).decode("ascii"),
        "FLX_WEBHOOK_SIGNING_KEY": "a" * 32,
    }
    for k, v in baseline.items():
        monkeypatch.setenv(k, v)

    get_settings.cache_clear()
    default_settings = get_settings()
    assert default_settings.idempotency_fast_ttl_s == 86400  # Default 24h

    # Override via environment variable
    monkeypatch.setenv("FLX_IDEMPOTENCY_FAST_TTL_S", "43200")
    get_settings.cache_clear()
    custom_settings = Settings()
    assert custom_settings.idempotency_fast_ttl_s == 43200
    get_settings.cache_clear()


def test_env_example_contains_idempotency_fast_ttl_s() -> None:
    """Contract test: ensure .env.example declares FLX_IDEMPOTENCY_FAST_TTL_S."""
    env_example_path = Path(__file__).resolve().parents[2] / ".env.example"
    assert env_example_path.is_file(), f".env.example not found at {env_example_path}"

    content = env_example_path.read_text(encoding="utf-8")
    assert re.search(r"^(?:#\s*)?FLX_IDEMPOTENCY_FAST_TTL_S=", content, re.MULTILINE)
