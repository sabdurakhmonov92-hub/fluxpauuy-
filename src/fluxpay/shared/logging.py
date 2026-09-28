"""Structured JSON logging pipeline for Loki ingestion with sink-level secret redaction.

This module provides the central logging configuration and context propagation for FluxPay.
All logs emitted by structlog and standard library loggers (e.g. Uvicorn, Gunicorn, asyncpg)
are routed through a unified pipeline that guarantees:
1. Flat, machine-queryable JSON format optimized for Loki and Grafana.
2. ContextVar-based request correlation (request_id, agent_id) across async boundaries.
3. Sink-level secret redaction to prevent credential leakage into log storage (defense-in-depth).
4. Direct-to-stdout emission for native systemd journald collection and Loki forwarding.
"""

import logging
import sys
import uuid
from typing import Any, Final

import orjson
import structlog
from structlog.contextvars import (
    bind_contextvars,
    clear_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.dev import ConsoleRenderer
from structlog.processors import JSONRenderer, TimeStamper
from structlog.stdlib import (
    BoundLogger,
    ExtraAdder,
    LoggerFactory,
    ProcessorFormatter,
    add_log_level,
)
from structlog.typing import EventDict, Processor, WrappedLogger

from fluxpay.config import get_settings

__all__ = [
    "REDACTED_VALUE",
    "REDACT_KEYS",
    "add_structlog_module_name",
    "bind_request_context",
    "clear_request_context",
    "configure_logging",
    "get_logger",
    "new_request_id",
    "redact_secrets_processor",
]

# Module-level frozen tuple containing exact and prefix patterns for secret redaction.
# Any key matching or beginning with these substrings (case-insensitively) will have its
# value replaced with REDACTED_VALUE at the sink.
# Rationale: Logs are read by humans and shipped to third-party storage (Loki);
# redacting at the sink, not at 50 disparate call sites, guarantees defense-in-depth
# because one sink cannot forget. Full request bodies are denylisted by default.
REDACT_KEYS: Final[tuple[str, ...]] = (
    "secret",
    "password",
    "token",
    "authorization",
    "signature",
    "sig",
    "key",
    "credential",
    "idempotency_key",
    "nonce",
    "body",
    "vault_master_key",
)

REDACTED_VALUE: Final[str] = "[REDACTED]"


def redact_secrets_processor(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Walk event dict one level deep and redact matching keys (defense-in-depth invariant #7).

    Walks the event dictionary one level deep (the flat JSON contract keeps this O(N)
    and computationally inexpensive) and replaces values of any keys matching REDACT_KEYS
    (exact or prefix match, case-insensitive) with '[REDACTED]'. Full request bodies are
    denylisted by default to prevent accidental payload exfiltration.
    """
    for key in list(event_dict.keys()):
        key_lower = str(key).lower()
        if any(key_lower.startswith(rk) for rk in REDACT_KEYS):
            event_dict[key] = REDACTED_VALUE
    return event_dict


def add_structlog_module_name(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Add 'module' key to event_dict for Loki/Grafana grouping.

    Extracts the logger name or standard library LogRecord name, populating the flat
    'module' field. This enables Grafana dashboards and Loki logQL queries in Task 69
    to filter and group logs by subsystem (e.g. 'fluxpay.ledger', 'uvicorn.access')
    without needing nested JSON structure or expensive regex extractions.
    """
    if "module" not in event_dict:
        record = event_dict.get("_record")
        if record is not None and getattr(record, "name", None):
            event_dict["module"] = record.name
        elif hasattr(logger, "name") and logger.name:
            event_dict["module"] = str(logger.name)
        else:
            event_dict["module"] = "fluxpay"
    return event_dict


def _orjson_serializer(val: Any, **kwargs: Any) -> str:
    """Serialize event dictionary using orjson, returning a decoded UTF-8 string.

    orjson.dumps returns raw bytes. We wrap it to decode to str because
    ProcessorFormatter and downstream logging handlers expect a str.
    orjson is ~2-3x faster than stdlib json at high RPS and matches our
    runtime stack.
    """
    return orjson.dumps(val, default=kwargs.pop("default", str), **kwargs).decode("utf-8")


def bind_request_context(request_id: str, agent_id: str | None = None) -> None:
    """Bind request-scoped context variables (async-safe via ContextVar).

    ContextVars propagate across await boundaries and asyncio tasks created within
    the context, without polluting every function signature with tracing parameters.
    This is the only async-safe mechanism for request correlation in Python.
    """
    bind_contextvars(request_id=request_id)
    if agent_id is not None:
        bind_contextvars(agent_id=agent_id)
    else:
        unbind_contextvars("agent_id")


def clear_request_context() -> None:
    """Clear request-scoped context variables from the current async context."""
    clear_contextvars()


def new_request_id() -> str:
    """Generate a new UUIDv4 hex string for request correlation at ingress edges."""
    return uuid.uuid4().hex


def get_logger(name: str | None = None) -> BoundLogger:
    """Get a structlog BoundLogger instance wrapped around stdlib logging."""
    return structlog.stdlib.get_logger(name)


class _StdoutProxy:
    """Dynamic proxy delegating to the active sys.stdout stream.

    In production, writes directly to sys.stdout for systemd journald collection.
    In testing harnesses (pytest capsys/capfd), dynamically routes to the current
    redirected stream across fixture and test execution boundaries rather than binding
    to a stale or closed stream handle.
    """

    def write(self, s: str) -> int:
        return sys.stdout.write(s)

    def flush(self) -> None:
        sys.stdout.flush()


def configure_logging() -> None:
    """Configure structured logging pipeline and stdlib bridge (idempotent).

    Rebuilds the complete logging configuration based on application settings:
    - Sets verbosity threshold on structlog and stdlib root from settings.log_level.
    - Configures structlog processor pipeline (contextvars, level, module, ts, redaction).
    - Bridges stdlib loggers (uvicorn, gunicorn, asyncpg) through ProcessorFormatter.
    - Selects JSONRenderer (with orjson) for production and ConsoleRenderer for dev.
    - Sets cache_logger_on_first_use to True only in production for peak throughput.
    - Attaches a single StreamHandler to stdout; no file or network handlers are used
      because native systemd journald and Loki agent manage transport and shipping.
    """
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    is_prod = settings.env == "production"

    # Common processor chain executed for both structlog and stdlib log records.
    # Loki dashboards in Task 69 rely on the flat schema contract:
    # ts, level, event, module, request_id, agent_id.
    shared_processors: list[Processor] = [
        merge_contextvars,
        add_log_level,
        add_structlog_module_name,
        TimeStamper(fmt="iso", utc=True, key="ts"),
        redact_secrets_processor,
    ]

    # Renderer selection based on deployment environment
    renderer: Processor
    if is_prod:
        # orjson.dumps returns bytes; wrap to decode to str because downstream logging
        # handlers expect str. orjson is ~2-3x faster than stdlib json at high RPS,
        # matching our high-throughput payment stack.
        renderer = JSONRenderer(serializer=_orjson_serializer)
    else:
        # Developer readability in local environments
        renderer = ConsoleRenderer()

    # Configure structlog logger factory and processor chain
    structlog.configure(
        processors=[
            *shared_processors,
            ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=LoggerFactory(),
        wrapper_class=BoundLogger,
        cache_logger_on_first_use=is_prod,
    )

    # Configure stdlib ProcessorFormatter to bridge stdlib records into structlog shape
    formatter = ProcessorFormatter(
        foreign_pre_chain=[ExtraAdder(), *shared_processors],
        processors=[
            ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    # Configure root logger with a single stdout StreamHandler (systemd journald sink).
    # Application-side network/file shippers are operational liabilities; systemd + Loki agent
    # own log shipping and persistence.
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    handler = logging.StreamHandler(_StdoutProxy())
    handler.setFormatter(formatter)
    handler.setLevel(log_level)

    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)
