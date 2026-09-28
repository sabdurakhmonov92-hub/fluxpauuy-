"""FluxPay Ledger Hash-Chain Verifier CLI.

Blueprint §9: Continuous Hash-Chain Validator.
Provides an ops-grade command-line interface for verifying the SHA-256
cryptographic continuity, genesis linkage, and tip consistency of the
FluxPay double-entry ledger.

OPERATIONAL CONTRACT & EXIT CODES:
----------------------------------
0 = OK: Chain is unbroken and cryptographically valid.
1 = Chain Broken: Cryptographic tampering, sequence gap, or tip mismatch detected.
    Emits forensic details (broken_seq, reason). Triggers SEV1 alert (Task 70).
2 = Operational Failure: Invalid CLI arguments, configuration failure, or database
    unreachable. Triggers ops triage ticket, NOT data integrity alert.

WHY DISTINCT EXIT CODES 1 VS 2:
Monitoring and automated alerting (Task 70, Loki, Telegram) must distinguish
a critical data integrity breach (SEV1) from an operational/infrastructure hiccup
(such as an unreachable database during a network partition or maintenance window).
Conflating both into a single non-zero exit code forces on-call engineers to manually
triage every failure by parsing text output.

SECRET HYGIENE:
Database connection strings (FLX_PG_DSN) contain sensitive credentials.
On operational failure, diagnostic output to stderr names host and database ONLY.
Usernames and passwords are never echoed or leaked in error messages.

REPORT FORMATS:
- Human (default): Timestamped summary lines with sequence ranges and elapsed time.
  On failure, points directly to the correction runbook in docs/ledger.md.
- JSON (--json): Exactly ONE single-line JSON string formatted for structured
  ingestion by log aggregation (Loki) and alerting pipelines (Task 40 / Task 70):
  {"ok":bool,"last_verified_seq":int,"broken_seq":int|null,"reason":str|null,
   "checked_at":ISO8601Z,"from_seq":int,"to_seq":int|null,"elapsed_ms":int}
"""

import argparse
import asyncio
import json
import sys
import time
from collections.abc import Sequence
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
    "main",
    "run_verification",
]

# Ops Contract Exit Codes
EXIT_OK: Final[int] = 0
EXIT_CHAIN_BROKEN: Final[int] = 1
EXIT_OPS_FAILURE: Final[int] = 2


async def run_verification(
    pool: asyncpg.Pool,
    *,
    from_seq: int = 1,
    to_seq: int | None = None,
) -> ChainVerification:
    """Run cryptographic ledger hash-chain verification against the given pool.

    ARCHITECTURAL RULE:
    This is a thin composition over PostgresLedgerStore.verify_chain.
    The verification CLI adds NO verification logic of its own, ever.
    """
    store = PostgresLedgerStore(pool)
    return await store.verify_chain(from_seq=from_seq, to_seq=to_seq)


async def _execute_verification(
    dsn: str,
    db_host: str,
    db_name: str,
    *,
    from_seq: int,
    to_seq: int | None,
    json_mode: bool,
) -> int:
    """Connect to the database, execute verification, and emit formatted report."""
    start_time = time.perf_counter()
    checked_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        pool: asyncpg.Pool = await asyncpg.create_pool(
            dsn,
            min_size=1,
            max_size=2,
        )
    except Exception as exc:
        # Secret hygiene: host and database name only; credentials never leaked
        sys.stderr.write(
            f"Database connection failure to host='{db_host}' database='{db_name}': "
            f"{exc.__class__.__name__}\n"
        )
        return EXIT_OPS_FAILURE

    try:
        async with pool:
            verification = await run_verification(pool, from_seq=from_seq, to_seq=to_seq)
    except Exception as exc:
        sys.stderr.write(
            f"Verification execution failure on host='{db_host}' database='{db_name}': "
            f"{exc.__class__.__name__}\n"
        )
        return EXIT_OPS_FAILURE

    elapsed_s = time.perf_counter() - start_time
    elapsed_ms = round(elapsed_s * 1000)

    if json_mode:
        # Single-line JSON format: Loki/Telegram ingestion payload
        payload = {
            "ok": verification.ok,
            "last_verified_seq": verification.last_verified_seq,
            "broken_seq": verification.broken_seq,
            "reason": verification.reason,
            "checked_at": checked_at,
            "from_seq": from_seq,
            "to_seq": to_seq,
            "elapsed_ms": elapsed_ms,
        }
        sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    else:
        to_str = f"to_seq={to_seq}" if to_seq is not None else "to_seq=tip"
        if verification.ok:
            entries_checked = (
                max(0, verification.last_verified_seq - from_seq + 1)
                if verification.last_verified_seq >= from_seq
                else 0
            )
            sys.stdout.write(
                f"[{checked_at}] OK: Hash chain verified. "
                f"Entries checked: {entries_checked} | "
                f"Last verified seq: {verification.last_verified_seq} | "
                f"Range: from_seq={from_seq} {to_str} | Elapsed: {elapsed_ms}ms\n"
            )
        else:
            sys.stdout.write(
                f"[{checked_at}] FAIL: Hash chain broken at seq={verification.broken_seq}. "
                f"Last verified seq: {verification.last_verified_seq} | "
                f"Reason: {verification.reason} | "
                f"Range: from_seq={from_seq} {to_str} | Elapsed: {elapsed_ms}ms\n"
                f"RUNBOOK: docs/ledger.md §correction\n"
            )
        sys.stdout.flush()

    return EXIT_OK if verification.ok else EXIT_CHAIN_BROKEN


def main(argv: Sequence[str] | None = None) -> int:
    """Parse CLI arguments, load configuration, and run hash chain verification."""
    parser = argparse.ArgumentParser(
        prog="python -m fluxpay.ledger.verify",
        description="Verify SHA-256 cryptographic hash-chain integrity of the FluxPay ledger.",
    )
    parser.add_argument(
        "--from-seq",
        type=int,
        default=1,
        help="Starting sequence number (inclusive, >= 1, default: 1)",
    )
    parser.add_argument(
        "--to-seq",
        type=int,
        default=None,
        help="Ending sequence number (inclusive, >= from-seq, default: chain tip)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit single-line JSON report for Loki/Telegram ingestion",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_OPS_FAILURE

    # Argument bounds validation
    if args.from_seq < 1:
        sys.stderr.write("Validation error: --from-seq must be >= 1\n")
        return EXIT_OPS_FAILURE
    if args.to_seq is not None:
        if args.to_seq < 1:
            sys.stderr.write("Validation error: --to-seq must be >= 1\n")
            return EXIT_OPS_FAILURE
        if args.to_seq < args.from_seq:
            sys.stderr.write(
                f"Validation error: --to-seq ({args.to_seq}) must be >= "
                f"--from-seq ({args.from_seq})\n"
            )
            return EXIT_OPS_FAILURE

    try:
        settings = get_settings()
    except Exception as exc:
        sys.stderr.write(f"Configuration failure: {exc.__class__.__name__}\n")
        return EXIT_OPS_FAILURE

    # Secret hygiene: extract non-sensitive host and database name for error logs
    parsed_dsn = urlsplit(settings.pg_dsn)
    db_host = parsed_dsn.hostname or "unknown"
    db_name = parsed_dsn.path.lstrip("/") or "unknown"

    return asyncio.run(
        _execute_verification(
            dsn=settings.pg_dsn,
            db_host=db_host,
            db_name=db_name,
            from_seq=args.from_seq,
            to_seq=args.to_seq,
            json_mode=args.json,
        )
    )
