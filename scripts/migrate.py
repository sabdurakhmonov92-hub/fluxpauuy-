#!/usr/bin/env python3
"""FluxPay Production Database Migration Runner (Part 3.2).

Applies SQL migrations sequentially from migrations/ directory with:
- Dedicated schema_migrations audit tracking
- SHA-256 checksum integrity verification (tamper detection)
- Support for --dry-run, target version targeting (--to=N), and rollback (--rollback=N)
- Strict fail-fast semantics on checksum mismatch or SQL errors
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]

from fluxpay.config import get_settings

REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = REPO_ROOT / "migrations"


class MigrationError(Exception):
    """Raised when migration fails integrity verification or execution."""


def compute_checksum(content: str) -> str:
    """Calculate SHA-256 hex digest of normalized migration SQL content."""
    normalized = content.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


async def init_migration_table(conn: asyncpg.Connection) -> None:
    """Ensure the schema_migrations tracking table exists."""
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version      TEXT        PRIMARY KEY,
            checksum     TEXT        NOT NULL,
            applied_at   TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """
    )


async def get_applied_migrations(conn: asyncpg.Connection) -> dict[str, str]:
    """Retrieve mapping of version -> checksum for all applied migrations."""
    rows = await conn.fetch("SELECT version, checksum FROM schema_migrations ORDER BY version ASC")
    return {row["version"]: row["checksum"] for row in rows}


def get_available_migrations() -> list[Path]:
    """Return sorted list of SQL migration files."""
    if not MIGRATIONS_DIR.is_dir():
        raise MigrationError(f"Migrations directory not found at: {MIGRATIONS_DIR}")
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    return files


async def run_migrations(*, dry_run: bool = False, to_version: str | None = None) -> list[str]:
    """Apply pending migrations sequentially up to optional target version."""
    settings = get_settings()
    available = get_available_migrations()
    applied_in_run: list[str] = []

    conn = await asyncpg.connect(
        settings.pg_dsn,
        server_settings={"TimeZone": "UTC", "synchronous_commit": "on"},
    )
    try:
        await init_migration_table(conn)
        applied = await get_applied_migrations(conn)

        # Check existing applied migrations for checksum tampering
        for mig_path in available:
            version = mig_path.name
            content = mig_path.read_text(encoding="utf-8")
            checksum = compute_checksum(content)

            if version in applied:
                if applied[version] != checksum:
                    raise MigrationError(
                        f"Checksum mismatch for applied migration '{version}'!\n"
                        f"Recorded in DB: {applied[version]}\n"
                        f"Current on disk: {checksum}\n"
                        "Tampering with applied migrations violates production ledger integrity."
                    )

        # Apply pending migrations
        for mig_path in available:
            version = mig_path.name
            if to_version and version > to_version:
                break

            if version in applied:
                continue

            content = mig_path.read_text(encoding="utf-8")
            checksum = compute_checksum(content)

            if dry_run:
                print(f"[DRY-RUN] Would apply migration: {version} (checksum: {checksum[:8]}...)")
                applied_in_run.append(version)
                continue

            print(f"Applying migration: {version} ...")
            async with conn.transaction():
                await conn.execute(content)
                await conn.execute(
                    "INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)",
                    version,
                    checksum,
                )
            print(f"  [OK] Applied {version}")
            applied_in_run.append(version)

        return applied_in_run
    finally:
        await conn.close()


async def rollback_migration(target_version: str, *, dry_run: bool = False) -> None:
    """Record rollback for target migration."""
    settings = get_settings()
    conn = await asyncpg.connect(
        settings.pg_dsn,
        server_settings={"TimeZone": "UTC", "synchronous_commit": "on"},
    )
    try:
        await init_migration_table(conn)
        applied = await get_applied_migrations(conn)

        if target_version not in applied:
            raise MigrationError(f"Migration {target_version} is not currently applied in DB.")

        if dry_run:
            print(f"[DRY-RUN] Would roll back migration: {target_version}")
            return

        async with conn.transaction():
            await conn.execute(
                "DELETE FROM schema_migrations WHERE version = $1",
                target_version,
            )
        print(f"  [OK] Rolled back tracking for {target_version}")
    finally:
        await conn.close()


def main() -> None:
    """CLI dispatcher for migrations."""
    parser = argparse.ArgumentParser(description="FluxPay Database Migration Runner")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate execution without modifying the database",
    )
    parser.add_argument(
        "--to",
        dest="to_version",
        default=None,
        help="Target migration version limit (e.g., 0010_notifications.sql)",
    )
    parser.add_argument(
        "--rollback",
        dest="rollback_version",
        default=None,
        help="Specific migration version to roll back (e.g., 0014_hardening_and_observability.sql)",
    )
    args = parser.parse_args()

    try:
        if args.rollback_version:
            asyncio.run(rollback_migration(args.rollback_version, dry_run=args.dry_run))
        else:
            applied = asyncio.run(run_migrations(dry_run=args.dry_run, to_version=args.to_version))
            print(f"\nMigration execution complete. {len(applied)} migration(s) processed.")
    except Exception as exc:
        sys.stderr.write(f"\n[FATAL] Migration failed: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
