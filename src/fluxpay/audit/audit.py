"""System Audit Service module for FluxPay administrative operations.

Blueprint §5 System Audit Service.

Design Invariants:
1. ATOMIC RECORDING WITH MUTATION (UoW Connection Ownership):
   `record()` requires an explicit `asyncpg.Connection` parameter rather than acquiring
   its own connection from the pool. Callers pass their active Unit of Work connection,
   ensuring the audit record commits OR rolls back in the EXACT SAME transaction as the
   domain mutation. An administrative mutation without a corresponding audit row is
   structurally impossible by design.
2. INPUT VALIDATION AT THE DOOR:
   Action identifiers and target types are strictly validated against frozen domain
   grammars before any SQL is executed. Invalid grammar raises ValueError immediately.
3. FLAT SCALAR JSONB LEAF DISCIPLINE:
   The `details` payload is constrained to flat scalar values (string, integer, boolean,
   or None). Nested objects and arbitrary JSON trees are rejected to maintain consistent
   queryability and SIEM indexing performance.
4. ABSENCE OF SENSITIVE CREDENTIALS:
   Audit details must NEVER log plaintext secrets, private keys, or passwords.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

import asyncpg  # type: ignore[import-untyped]
import orjson

__all__ = [
    "AdminAction",
    "read_recent",
    "record",
]

# Action grammar: 3 to 64 lowercase alphanumeric, dot, or underscore characters
_ACTION_PATTERN: Final[str] = r"^[a-z_.]{3,64}$"
_ACTION_RE: Final[re.Pattern[str]] = re.compile(_ACTION_PATTERN)

# Allowed target entity categories
_VALID_TARGET_TYPES: Final[frozenset[str]] = frozenset({"agent", "merchant", "user", "kyc"})


@dataclass(frozen=True, slots=True)
class AdminAction:
    """Immutable value object representing an administrative action audit event."""

    action: str
    target_type: str
    target_id: str
    details: Mapping[str, str | int | bool | None]
    occurred_at: datetime
    actor_sub: str = ""
    actor_role: str = ""


async def record(
    conn: asyncpg.Connection,
    *,
    actor_sub: str,
    actor_role: str,
    action: str,
    target_type: str,
    target_id: str,
    details: Mapping[str, str | int | bool | None],
) -> None:
    """Record an administrative action to the immutable audit log within the caller's transaction.

    WHY conn-param:
    Callers MUST pass their active UnitOfWork connection (`uow.connection`). This guarantees
    that the audit row commits atomically WITH the mutation. If the mutation fails or if
    the system crashes before commit, BOTH the mutation and the audit row roll back cleanly.

    Raises:
        ValueError: If action format, target_type, target_id, actor attributes, or details
                    violate grammar and leaf scalar constraints.
    """
    if not isinstance(action, str) or not _ACTION_RE.match(action):
        raise ValueError(
            f"Invalid action format: '{action}'. Must match pattern '{_ACTION_PATTERN}'."
        )

    if not isinstance(target_type, str) or target_type not in _VALID_TARGET_TYPES:
        raise ValueError(
            f"Invalid target_type: '{target_type}'. Must be one of {_VALID_TARGET_TYPES}."
        )

    if not isinstance(target_id, str) or not target_id.strip():
        raise ValueError("target_id must be a non-empty string.")

    if not isinstance(actor_sub, str) or not actor_sub.strip():
        raise ValueError("actor_sub must be a non-empty string.")

    if not isinstance(actor_role, str) or not actor_role.strip():
        raise ValueError("actor_role must be a non-empty string.")

    # Validate JSONB leaf discipline: only string keys and scalar leaf values
    sanitized_details: dict[str, str | int | bool | None] = {}
    for key, val in details.items():
        if not isinstance(key, str) or not key:
            raise ValueError("All details keys must be non-empty strings.")
        if val is not None and not isinstance(val, (str, int, bool)):
            raise ValueError(
                f"Invalid details value for key '{key}': expected str | int | bool | None, "
                f"got {type(val).__name__}."
            )
        # Absence law: never allow plaintext secrets into audit log details
        if "secret" in key.lower() or "password" in key.lower() or "token" in key.lower():
            raise ValueError(f"Prohibited sensitive credential field in audit details: '{key}'")
        sanitized_details[key] = val

    details_json = orjson.dumps(sanitized_details).decode("utf-8")

    await conn.execute(
        """
        INSERT INTO audit_log (actor_sub, actor_role, action, target_type, target_id, details)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb);
        """,
        actor_sub,
        actor_role,
        action,
        target_type,
        target_id,
        details_json,
    )


async def read_recent(
    pool: asyncpg.Pool,
    *,
    limit: int = 50,
    target_type: str | None = None,
    target_id: str | None = None,
) -> tuple[AdminAction, ...]:
    """Retrieve recent administrative actions from the audit log.

    Provides the read path for the Admin UI and forensic compliance reviews.

    Args:
        pool: asyncpg connection pool.
        limit: Maximum number of rows to return (1 <= limit <= 200).
        target_type: Optional filter by target entity type ('agent', 'merchant', etc.).
        target_id: Optional filter by target entity identifier.

    Raises:
        ValueError: If limit is outside [1, 200] or target_type is invalid.
    """
    if limit < 1 or limit > 200:
        raise ValueError(f"limit must be between 1 and 200, got {limit}.")

    if target_type is not None and target_type not in _VALID_TARGET_TYPES:
        raise ValueError(
            f"Invalid target_type filter: '{target_type}'. Must be one of {_VALID_TARGET_TYPES}."
        )

    query: str
    params: list[Any]

    if target_type is not None and target_id is not None:
        query = """
            SELECT action, target_type, target_id, details, occurred_at, actor_sub, actor_role
            FROM audit_log
            WHERE target_type = $1 AND target_id = $2
            ORDER BY occurred_at DESC, id DESC
            LIMIT $3;
        """
        params = [target_type, target_id, limit]
    elif target_type is not None:
        query = """
            SELECT action, target_type, target_id, details, occurred_at, actor_sub, actor_role
            FROM audit_log
            WHERE target_type = $1
            ORDER BY occurred_at DESC, id DESC
            LIMIT $2;
        """
        params = [target_type, limit]
    elif target_id is not None:
        query = """
            SELECT action, target_type, target_id, details, occurred_at, actor_sub, actor_role
            FROM audit_log
            WHERE target_id = $1
            ORDER BY occurred_at DESC, id DESC
            LIMIT $2;
        """
        params = [target_id, limit]
    else:
        query = """
            SELECT action, target_type, target_id, details, occurred_at, actor_sub, actor_role
            FROM audit_log
            ORDER BY occurred_at DESC, id DESC
            LIMIT $1;
        """
        params = [limit]

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    actions: list[AdminAction] = []
    for row in rows:
        raw_details = row["details"]
        if isinstance(raw_details, str):
            details_dict = orjson.loads(raw_details)
        elif isinstance(raw_details, dict):
            details_dict = raw_details
        else:
            details_dict = {}

        actions.append(
            AdminAction(
                action=row["action"],
                target_type=row["target_type"],
                target_id=row["target_id"],
                details=details_dict,
                occurred_at=row["occurred_at"],
                actor_sub=row["actor_sub"],
                actor_role=row["actor_role"],
            )
        )

    return tuple(actions)
