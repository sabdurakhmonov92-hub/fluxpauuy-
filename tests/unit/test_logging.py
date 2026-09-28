"""Unit tests for structured logging pipeline, secret redaction, and Loki JSON contract.

Validates:
- Flat JSON structure with mandatory Loki fields (ts, level, event, module, request_id, agent_id).
- ContextVar propagation across asyncio task boundaries.
- Sink-level secret redaction across all denylisted keys, prefix variants, and case variations.
- Non-redaction of standard business fields.
- Stdlib logging bridge routing (uvicorn/gunicorn/asyncpg compatibility).
- configure_logging() idempotency and handler deduplication.
- Production (orjson) vs Development (ConsoleRenderer) renderer switching.
"""

import asyncio
import base64
import logging
import os
import uuid
from collections.abc import Generator
from typing import Any

import orjson
import pytest

from fluxpay.config import get_settings
from fluxpay.shared.logging import (
    REDACT_KEYS,
    REDACTED_VALUE,
    _orjson_serializer,
    add_structlog_module_name,
    bind_request_context,
    clear_request_context,
    configure_logging,
    get_logger,
    new_request_id,
)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Provide an isolated baseline environment with valid configuration."""
    for key in list(os.environ.keys()):
        if key.startswith("FLX_"):
            monkeypatch.delenv(key, raising=False)

    valid_vault_key = base64.b64encode(b"0" * 32).decode("ascii")
    valid_webhook_key = "a" * 32
    baseline = {
        "FLX_PG_DSN": "postgresql://test:test@localhost:5432/test",
        "FLX_VAULT_MASTER_KEY": valid_vault_key,
        "FLX_WEBHOOK_SIGNING_KEY": valid_webhook_key,
        "FLX_ENV": "production",
        "FLX_LOG_LEVEL": "INFO",
    }
    for k, v in baseline.items():
        monkeypatch.setenv(k, v)

    get_settings.cache_clear()
    return baseline


@pytest.fixture
def prod_logging(clean_env: dict[str, str]) -> Generator[None, None, None]:
    """Configure production logging and clean up context afterwards."""
    configure_logging()
    yield
    clear_request_context()
    get_settings.cache_clear()


@pytest.fixture
def dev_logging(
    clean_env: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    """Configure development logging with ConsoleRenderer."""
    monkeypatch.setenv("FLX_ENV", "development")
    get_settings.cache_clear()
    configure_logging()
    yield
    clear_request_context()
    get_settings.cache_clear()


@pytest.mark.unit
def test_prod_json_shape_and_flatness(
    prod_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate JSON shape under prod renderer: flat structure with ts, level, event, module."""
    logger = get_logger("fluxpay.test_module")
    logger.info("payment_created", payment_id="pay_01", amount=2500)

    captured = capsys.readouterr()
    lines = captured.out.strip().splitlines()
    assert len(lines) == 1

    data = orjson.loads(lines[0])
    assert isinstance(data, dict)

    # Loki contract fields
    assert data["event"] == "payment_created"
    assert data["level"] == "info"
    assert data["module"] == "fluxpay.test_module"
    assert "ts" in data
    assert data["ts"].endswith("Z")

    # Business fields
    assert data["payment_id"] == "pay_01"
    assert data["amount"] == 2500

    # Flat JSON contract: assert no nested dict values
    for key, value in data.items():
        assert not isinstance(value, dict), f"Key '{key}' contains nested dict: {value}"


@pytest.mark.unit
async def test_contextvars_propagation_across_asyncio_task(
    prod_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate ContextVar propagation across await boundaries and spawned asyncio.Task."""
    test_req_id = new_request_id()
    test_agent_id = "agent_01j"
    bind_request_context(request_id=test_req_id, agent_id=test_agent_id)

    logger = get_logger("fluxpay.async_worker")

    async def worker() -> None:
        # Await boundary
        await asyncio.sleep(0.001)
        logger.info("async_task_executed", operation="settle")

    task = asyncio.create_task(worker())
    await task

    captured = capsys.readouterr()
    line = captured.out.strip()
    data = orjson.loads(line)

    assert data["request_id"] == test_req_id
    assert data["agent_id"] == test_agent_id
    assert data["event"] == "async_task_executed"
    assert data["operation"] == "settle"


@pytest.mark.unit
def test_clear_request_context_removes_keys(
    prod_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate that clear_request_context removes keys and logging without context works."""
    bind_request_context(request_id="req_to_clear", agent_id="agent_to_clear")
    clear_request_context()

    logger = get_logger("fluxpay.context_test")
    logger.info("clean_context_event")

    captured = capsys.readouterr()
    data = orjson.loads(captured.out.strip())

    assert "request_id" not in data
    assert "agent_id" not in data
    assert data["event"] == "clean_context_event"


@pytest.mark.unit
def test_bind_request_context_optional_agent_id(
    prod_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate binding request_id with agent_id=None clears/omits agent_id."""
    # First bind both
    bind_request_context(request_id="req_initial", agent_id="agent_initial")
    # Then bind with agent_id=None
    bind_request_context(request_id="req_only")

    logger = get_logger("fluxpay.context_test")
    logger.info("only_request_id_event")

    captured = capsys.readouterr()
    data = orjson.loads(captured.out.strip())

    assert data["request_id"] == "req_only"
    assert "agent_id" not in data


@pytest.mark.unit
def test_new_request_id_format_and_uniqueness() -> None:
    """Validate new_request_id produces valid 32-char UUIDv4 hex strings."""
    rid1 = new_request_id()
    rid2 = new_request_id()

    assert len(rid1) == 32
    assert len(rid2) == 32
    assert rid1 != rid2

    # Must be valid hex parsing to UUIDv4
    parsed1 = uuid.UUID(rid1, version=4)
    parsed2 = uuid.UUID(rid2, version=4)
    assert parsed1.hex == rid1
    assert parsed2.hex == rid2


@pytest.mark.unit
def test_secret_redaction_denylist_all_keys(
    prod_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate that all keys in REDACT_KEYS are redacted, while business fields survive."""
    logger = get_logger("fluxpay.redaction_test")

    sensitive_kwargs: dict[str, Any] = {k: f"val_{k}" for k in REDACT_KEYS}
    business_kwargs: dict[str, Any] = {
        "amount": 100_000,
        "currency": "USD",
        "agent_id": "agent_alpha",
        "status": "success",
    }

    logger.info("redaction_probe", **sensitive_kwargs, **business_kwargs)

    captured = capsys.readouterr()
    data = orjson.loads(captured.out.strip())

    # Every key in REDACT_KEYS must be redacted
    for k in REDACT_KEYS:
        assert data[k] == REDACTED_VALUE, f"Key '{k}' was not redacted: {data[k]}"

    # Business fields must survive untouched
    assert data["amount"] == 100_000
    assert data["currency"] == "USD"
    assert data["agent_id"] == "agent_alpha"
    assert data["status"] == "success"


@pytest.mark.unit
def test_secret_redaction_case_insensitive_and_prefix_aware(
    prod_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate that redaction handles prefix matching and case insensitivity."""
    logger = get_logger("fluxpay.redaction_test")

    prefix_kwargs: dict[str, Any] = {
        "Signature_Hdr": "sha256=abcdef",
        "TOKEN_SECRET": "tok_xyz",
        "Key_Identifier": "kid_123",
        "body_raw": '{"sensitive": true}',
        "Authorization_Header": "Bearer secret",
        "idempotency_key_override": "idemp_override",
        "nonce_val": "nonce_123",
        "vault_master_key_v2": "master_v2",
    }
    logger.info("prefix_redaction_probe", **prefix_kwargs)

    captured = capsys.readouterr()
    data = orjson.loads(captured.out.strip())

    assert data["Signature_Hdr"] == REDACTED_VALUE
    assert data["TOKEN_SECRET"] == REDACTED_VALUE
    assert data["Key_Identifier"] == REDACTED_VALUE
    assert data["body_raw"] == REDACTED_VALUE
    assert data["Authorization_Header"] == REDACTED_VALUE
    assert data["idempotency_key_override"] == REDACTED_VALUE
    assert data["nonce_val"] == REDACTED_VALUE
    assert data["vault_master_key_v2"] == REDACTED_VALUE


@pytest.mark.unit
def test_level_filtering(
    prod_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate that at INFO log level, a debug() call produces no output."""
    logger = get_logger("fluxpay.filter_test")

    logger.debug("debug_event_must_be_silent", detail="hidden")
    logger.info("info_event_must_be_logged", detail="visible")

    captured = capsys.readouterr()
    lines = captured.out.strip().splitlines()
    assert len(lines) == 1

    data = orjson.loads(lines[0])
    assert data["event"] == "info_event_must_be_logged"
    assert "debug_event_must_be_silent" not in captured.out


@pytest.mark.unit
def test_configure_logging_idempotency(
    clean_env: dict[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate configure_logging() can be called multiple times without duplicate handlers."""
    configure_logging()
    configure_logging()

    root = logging.getLogger()
    assert len(root.handlers) == 1

    logger = get_logger("fluxpay.idempotency_test")
    logger.info("single_output_check")

    captured = capsys.readouterr()
    lines = captured.out.strip().splitlines()
    assert len(lines) == 1
    data = orjson.loads(lines[0])
    assert data["event"] == "single_output_check"


@pytest.mark.unit
def test_dev_mode_console_renderer(
    dev_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate that env='development' activates ConsoleRenderer (human-readable, non-JSON)."""
    logger = get_logger("fluxpay.dev_test")
    logger.info("developer_event", param="alpha")

    captured = capsys.readouterr()
    output = captured.out.strip()

    # Output must NOT be valid JSON
    with pytest.raises(orjson.JSONDecodeError):
        orjson.loads(output)

    # Human-readable markers
    assert "developer_event" in output
    assert "param" in output
    assert "alpha" in output


@pytest.mark.unit
def test_orjson_serializer_emits_str_not_bytes() -> None:
    """Validate _orjson_serializer returns str and never raw bytes."""
    test_dict = {"event": "test", "num": 1, "flag": True}
    result = _orjson_serializer(test_dict)

    assert isinstance(result, str)
    assert type(result) is str
    assert orjson.loads(result) == test_dict


@pytest.mark.unit
def test_stdlib_logging_bridge(
    prod_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Validate stdlib loggers route through structlog with secret redaction."""
    std_logger = logging.getLogger("uvicorn.error")
    std_logger.info(
        "Application startup complete",
        extra={"port": 8000, "secret_key": "leak_attempt"},
    )

    captured = capsys.readouterr()
    data = orjson.loads(captured.out.strip())

    assert data["event"] == "Application startup complete"
    assert data["module"] == "uvicorn.error"
    assert data["level"] == "info"
    assert data["port"] == 8000
    assert data["secret_key"] == REDACTED_VALUE
    assert "ts" in data
    assert data["ts"].endswith("Z")


@pytest.mark.unit
def test_add_structlog_module_name_branches() -> None:
    """Validate add_structlog_module_name handles record, logger, preset module, and fallback."""
    # 1. Preset module preserved
    d1 = add_structlog_module_name(None, "", {"module": "preset.module"})
    assert d1["module"] == "preset.module"

    # 2. Logger object with name
    class DummyLogger:
        name = "dummy.logger.name"

    d2 = add_structlog_module_name(DummyLogger(), "", {})
    assert d2["module"] == "dummy.logger.name"

    # 3. Fallback when neither record nor logger has a name
    d3 = add_structlog_module_name(None, "", {})
    assert d3["module"] == "fluxpay"
