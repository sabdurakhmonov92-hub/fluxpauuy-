"""Continuous Hash-Chain Validator: Hourly Integrity Audit Worker.

Blueprint §9: Continuous Hash-Chain Validator.
Runs an hourly integrity audit recalculating and cryptographically verifying the
SHA-256 ledger chain in-process using PostgresLedgerStore.verify_chain.

DESIGN LAWS & ARCHITECTURAL DISCIPLINE:
--------------------------------------
1. ZERO ENGINE MATH:
   The verification engine lives entirely within Task 16 (PostgresLedgerStore.verify_chain).
   This worker adds NO verification or cryptographic math. It is a thin operational wrapper.
2. SPEAKING CONTRACT & DEAD-MAN SWITCH:
   A silent validator is indistinguishable from a dead one. Every run emits exactly ONE
   single-line JSON report to stdout with mode="hash_validator" and scope="full", regardless
   of whether the chain is healthy or broken. Task 69 configures a dead-man switch alert
   monitoring the absence of this signal (no report in 2 hours triggers an alarm).
3. TWO-STREAM LOGGING DISCIPLINE:
   - stdout is strictly reserved for the machine-parseable JSON report (Loki / Telegram ingestion).
     NO structlog emissions on the success path to avoid corrupting single-line log aggregation.
   - stderr is used for human-actionable error traces and runbook pointers.
4. ASYMMETRIC FAILURE REPORTING:
   - Data Integrity Failure (Chain Broken): Emits the JSON report to stdout (exit code 1) and prints
     the runbook pointer to stderr. Triggers SEV1 alert.
   - Operational Failure (DB down / Misconfiguration): Emits NOTHING to stdout (exit code 2) and
     prints the error to stderr. Silence trips the dead-man switch; exit code 2 alerts operations.
5. ONE-SHOT VS. DAEMON:
   Unlike continuous poll-loop workers (Task 34 Worker), an hourly audit should not hold process
   memory idle for 3599 seconds of every hour. It is a one-shot process invoked by a systemd timer
   (Task 65).
6. NO AUTO-REPAIR:
   Data corruption in a financial ledger requires human investigation under the sanctioned runbook
   (docs/ledger.md §correction-runbook). Automated repair is strictly forbidden.
7. READ-ONLY DURABILITY NUANCE:
   synchronous_commit is NOT forced to 'on' on the database pool. Durability constraints belong to
   the transactional WRITE path (Task 13/33). The validator is a streaming read-only audit;
   inheriting the server default avoids needless write-barrier coordination overhead.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urlsplit

import asyncpg  # type: ignore[import-untyped]

from fluxpay.config import get_settings
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import ChainVerification

__all__ = [
    "EXIT_CHAIN_BROKEN",
    "EXIT_OK",
    "EXIT_OPS_FAILURE",
    "RUNBOOK_POINTER",
    "build_report",
    "determine_exit_code",
    "main",
    "map_exit_code",
    "run_once",
]

# Exit code contract inherited from Task 18 CLI
EXIT_OK: Final[int] = 0
EXIT_CHAIN_BROKEN: Final[int] = 1
EXIT_OPS_FAILURE: Final[int] = 2

# Exact runbook pointer for 3AM responders (docs/ledger.md §correction-runbook)
RUNBOOK_POINTER: Final[str] = "RUNBOOK: docs/ledger.md §correction-runbook\n"


def build_report(
    verification: ChainVerification,
    elapsed_ms: int,
    now: datetime | None = None,
) -> str:
    """Construct the single-line JSON report for Loki and Telegram ingestion.

    Superset of Task 18 CLI payload: includes all core verification fields plus
    operational metadata (mode="hash_validator", scope="full").
    Guaranteed single-line format: no internal newlines.
    """
    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    else:
        now = now.astimezone(UTC)

    checked_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "ok": verification.ok,
        "last_verified_seq": verification.last_verified_seq,
        "broken_seq": verification.broken_seq,
        "reason": verification.reason,
        "checked_at": checked_at,
        "elapsed_ms": elapsed_ms,
        "mode": "hash_validator",
        "scope": "full",
    }
    return json.dumps(payload, separators=(",", ":"))


def map_exit_code(
    verification: ChainVerification | None = None,
    error: type[BaseException] | BaseException | None = None,
) -> int:
    """Map verification outcome or exception to operational exit code.

    0 = OK: Chain unbroken.
    1 = Chain Broken: Cryptographic tampering, sequence gap, or tip mismatch.
    2 = Operational Failure: DB unreachable, configuration error, or exception.
    """
    if error is not None or verification is None:
        return EXIT_OPS_FAILURE
    if not verification.ok or verification.broken_seq is not None:
        return EXIT_CHAIN_BROKEN
    return EXIT_OK


determine_exit_code = map_exit_code


async def run_once(
    pool: asyncpg.Pool,
    *,
    from_seq: int = 1,
    to_seq: int | None = None,
) -> tuple[ChainVerification, int]:
    """Execute a single verification pass against the ledger store.

    Constructs PostgresLedgerStore(pool) internally — the ONLY composition it owns.
    Contains ZERO verification math: delegates 100% to Task 16's verify_chain.
    Returns (verification, elapsed_ms).
    """
    store = PostgresLedgerStore(pool)
    start_time = time.perf_counter()
    verification = await store.verify_chain(from_seq=from_seq, to_seq=to_seq)
    elapsed_s = time.perf_counter() - start_time
    elapsed_ms = max(0, round(elapsed_s * 1000))
    return verification, elapsed_ms


async def main() -> int:
    """Entrypoint for the hourly hash-chain validator one-shot job.

    1. Loads configuration and extracts DB host/name for leak-free error diagnostics.
    2. Creates asyncpg connection pool (min=1, max=2, server_settings={"TimeZone": "UTC"}).
       Nuance: synchronous_commit is NOT forced here because this is a read-only audit;
       durability guarantees belong to the write path.
    3. Performs timezone probe to fail fast on any timestamp drift.
    4. Invokes run_once(pool).
    5. THE SPEAKING CONTRACT: Emits exactly one single-line JSON report to stdout.
    6. Returns exit code 0 (ok), 1 (chain broken), or 2 (operational failure).
       On chain broken, emits RUNBOOK pointer to stderr.
       On operational failure, stdout is kept SILENT (tripping dead-man switch) and
       diagnostics are written to stderr.
    """
    # Step 1: Configuration & Secret Hygiene
    try:
        settings = get_settings()
        parsed_dsn = urlsplit(settings.pg_dsn)
        db_host = parsed_dsn.hostname or "unknown"
        db_name = parsed_dsn.path.lstrip("/") or "unknown"
    except Exception as exc:
        # Configuration failure: leak-safe stderr notification
        sys.stderr.write(f"Configuration failure: {exc.__class__.__name__}: {exc}\n")
        sys.stderr.flush()
        return EXIT_OPS_FAILURE

    # Step 2: Pool Creation & Timezone Verification
    pool: asyncpg.Pool | None = None
    try:
        # Pool sizing: min 1, max 2.
        # synchronous_commit nuance: Durability barrier (synchronous_commit=on) is a WRITE path
        # invariant (Task 13/33). The validator performs read-only cursor streaming; inheriting
        # the server default avoids needless write-barrier coordination overhead.
        pool = await asyncpg.create_pool(
            settings.pg_dsn,
            min_size=1,
            max_size=2,
            server_settings={"TimeZone": "UTC"},
            command_timeout=30.0,
        )

        # Fail-fast TZ probe (mirroring Task 33 composition root discipline)
        async with pool.acquire() as conn:
            tz = await conn.fetchval("SHOW timezone")
            if tz not in ("UTC", "Etc/UTC"):
                raise RuntimeError(
                    f"PostgreSQL connection timezone must be 'UTC' or 'Etc/UTC', got '{tz}'. "
                    "Ensure server_settings={'TimeZone': 'UTC'} is configured in "
                    "asyncpg.create_pool."
                )

        # Step 3: Run the audit
        verification, elapsed_ms = await run_once(pool)
    except Exception as exc:
        # Operational Failure: Unreachable DB, network partition, or pool error.
        # CRITICAL DESIGN LAW: Silence on stdout = death alarm for Loki dead-man switch.
        # Human diagnostics go to stderr. No stdout emission.
        sys.stderr.write(
            f"Operational failure in hash validator (host='{db_host}', db='{db_name}'): "
            f"{exc.__class__.__name__}: {exc}\n"
        )
        sys.stderr.flush()
        # --- Task 69 append ---
        from fluxpay.alerts.router import send_heartbeat

        send_heartbeat("hash_validator", ok=False, reason=f"{exc.__class__.__name__}: {exc}")
        return EXIT_OPS_FAILURE
    finally:
        if pool is not None:
            await pool.close()

    # Step 4: The Speaking Contract (Always speak to stdout on completed audit)
    report_json = build_report(verification, elapsed_ms)
    sys.stdout.write(report_json + "\n")
    sys.stdout.flush()

    # Step 5: Exit Code & Broken-Chain Handling
    if not verification.ok:
        # Broken chain: emit runbook pointer to stderr for the 3AM responder
        # NO auto-repair EVER: repair is a human, runbook-gated procedure.
        sys.stderr.write(RUNBOOK_POINTER)
        sys.stderr.flush()
        # --- Task 69 append ---
        from fluxpay.alerts.router import send_heartbeat

        send_heartbeat("hash_validator", ok=False, reason="chain_broken")
        return EXIT_CHAIN_BROKEN

    # --- Task 69 append ---
    from fluxpay.alerts.router import send_heartbeat

    send_heartbeat("hash_validator", ok=True)
    return EXIT_OK


if __name__ == "__main__":
    # Bare asyncio: uvloop is unnecessary complexity for an hourly one-shot job. Boring wins.
    raise SystemExit(asyncio.run(main()))
