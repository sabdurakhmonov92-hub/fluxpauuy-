"""Integration test suite proving the operational contract of the hash-chain validator.

TASK 40: HASH-CHAIN VALIDATOR — HOURLY INTEGRITY AUDIT (BLOCK H, PART 2)

Proves:
1. Healthy chain: seed 20 entries -> run_once -> ok=True, last_verified_seq==20, elapsed>0;
   main() via subprocess [sys.executable, "-m", "fluxpay.workers.hash_validator"] with env ->
   exit 0; stdout parses as locked JSON shape.
2. Broken chain: Task 16's tamper procedure (owner DISABLE trigger -> UPDATE amount -> re-enable;
   self-restoring) -> exit 1; JSON broken_seq == tampered seq; stderr contains RUNBOOK pointer;
   RESTORE -> re-run -> exit 0 (validator self-cleaning proof).
3. Ops failure: FLX_PG_DSN to dead port -> exit 2; stdout emits NOTHING (silence is the dead-man
   switch alarm); stderr contains host diagnostics but NO credentials.
4. Empty ledger (0 entries): ok=True, last_verified_seq==0 (day-one bootstrap state passes).
5. Continuity gap: deletion via owner -> broken with sequence discontinuity reason ->
   self-restoring.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import asyncpg  # type: ignore[import-untyped]
import pytest

from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import EntryDraft
from fluxpay.workers.hash_validator import (
    EXIT_CHAIN_BROKEN,
    EXIT_OK,
    EXIT_OPS_FAILURE,
    main,
    run_once,
)

pytestmark = pytest.mark.integration


def _make_validator_env(dsn: str) -> dict[str, str]:
    """Create isolated environment for validator subprocess execution."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("FLX_")}
    env["FLX_PG_DSN"] = dsn
    env["FLX_VAULT_MASTER_KEY"] = base64.b64encode(b"0" * 32).decode("ascii")
    env["FLX_WEBHOOK_SIGNING_KEY"] = "a" * 32
    env["FLX_KEYCLOAK_JWKS_URL"] = "https://auth.fluxpay.local/certs"
    env["FLX_KEYCLOAK_ISSUER"] = "https://auth.fluxpay.local"
    env["FLX_KEYCLOAK_AUDIENCE"] = "https://api.fluxpay.local"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    repo_root = Path(__file__).resolve().parent.parent.parent
    src_dir = repo_root / "src"
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{src_dir}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else str(src_dir)
    )
    return env


async def _reset_ledger(conn: asyncpg.Connection) -> None:
    """Reset the ledger to a clean day-one bootstrap state (0 entries, last_seq=0)."""
    await conn.execute("ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;")
    await conn.execute("DELETE FROM ledger_entries;")
    await conn.execute(
        "UPDATE ledger_chain_tip SET last_seq = 0, last_hash = 'GENESIS' WHERE singleton = TRUE;"
    )
    await conn.execute("ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;")


async def _seed_clean_entries(
    pool: asyncpg.Pool,
    conn: asyncpg.Connection,
    target_count: int = 20,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Reset ledger and seed exactly target_count entries (target_count // 2 transactions)."""
    await _reset_ledger(conn)

    sys_acc = uuid.uuid4()
    agent_acc = uuid.uuid4()
    await conn.execute(
        """
        INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
        VALUES
            ($1, 'system', $2, 'USDC', 1000000000, 0),
            ($3, 'agent', $4, 'USDC', 0, 0);
        """,
        sys_acc,
        uuid.uuid4(),
        agent_acc,
        uuid.uuid4(),
    )

    store = PostgresLedgerStore(pool)
    num_txs = target_count // 2
    for _ in range(num_txs):
        await store.post_transaction(
            [
                EntryDraft(
                    account_id=sys_acc,
                    direction=Direction.DEBIT,
                    amount=100,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=agent_acc,
                    direction=Direction.CREDIT,
                    amount=100,
                    currency="USDC",
                ),
            ]
        )

    return sys_acc, agent_acc


# =============================================================================
# 1. HEALTHY CHAIN VERIFICATION (20 SEEDED ENTRIES)
# =============================================================================


async def test_hash_validator_healthy_chain(
    db_dsn: str,
    db_pool: asyncpg.Pool,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify healthy chain: 20 entries -> run_once passes; subprocess exits 0 with JSON."""
    await _seed_clean_entries(db_pool, owner_conn, target_count=20)

    # 1. In-process run_once verification
    verification, elapsed_ms = await run_once(db_pool)
    assert verification.ok is True
    assert verification.last_verified_seq == 20
    assert verification.broken_seq is None
    assert verification.reason is None
    assert elapsed_ms >= 0

    # 2. Subprocess execution
    env = _make_validator_env(db_dsn)
    cmd = [sys.executable, "-m", "fluxpay.workers.hash_validator"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    assert proc.returncode == EXIT_OK, (
        f"Unexpected return code: {proc.returncode}, stderr: {stderr_b.decode('utf-8')}"
    )

    lines = stdout_b.decode("utf-8").strip().splitlines()
    assert len(lines) == 1, f"Expected exactly one line of JSON output, got: {lines}"

    data = json.loads(lines[0])
    assert data["ok"] is True
    assert data["last_verified_seq"] == 20
    assert data["broken_seq"] is None
    assert data["reason"] is None
    assert "checked_at" in data
    assert isinstance(data["elapsed_ms"], int)
    assert data["elapsed_ms"] >= 0
    assert data["mode"] == "hash_validator"
    assert data["scope"] == "full"


# =============================================================================
# 2. EMPTY LEDGER VERIFICATION (DAY-ONE BOOTSTRAP STATE)
# =============================================================================


async def test_hash_validator_empty_ledger(
    db_dsn: str,
    db_pool: asyncpg.Pool,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify empty ledger (0 entries): ok=True, last_verified_seq=0 (day-one bootstrap passes)."""
    await _reset_ledger(owner_conn)

    # 1. In-process run_once
    verification, _ = await run_once(db_pool)
    assert verification.ok is True
    assert verification.last_verified_seq == 0
    assert verification.broken_seq is None
    assert verification.reason is None

    # 2. Subprocess execution
    env = _make_validator_env(db_dsn)
    cmd = [sys.executable, "-m", "fluxpay.workers.hash_validator"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    assert proc.returncode == EXIT_OK, f"Process failed: {stderr_b.decode('utf-8')}"

    lines = stdout_b.decode("utf-8").strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["ok"] is True
    assert data["last_verified_seq"] == 0
    assert data["broken_seq"] is None
    assert data["mode"] == "hash_validator"
    assert data["scope"] == "full"


# =============================================================================
# 3. BROKEN CHAIN TAMPER DETECTION & SELF-CLEANING RESTORATION
# =============================================================================


async def test_hash_validator_broken_chain_tamper_detection(
    db_dsn: str,
    db_pool: asyncpg.Pool,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify broken chain: tamper detection -> exit 1, RUNBOOK pointer; restoration -> exit 0."""
    await _seed_clean_entries(db_pool, owner_conn, target_count=10)
    tamper_seq = 5

    # Capture original amount
    orig_row = await owner_conn.fetchrow(
        "SELECT amount FROM ledger_entries WHERE seq = $1;",
        tamper_seq,
    )
    assert orig_row is not None
    orig_amount: int = orig_row["amount"]

    env = _make_validator_env(db_dsn)

    try:
        # Tamper: disable trigger -> update amount -> re-enable
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "UPDATE ledger_entries SET amount = amount + 99 WHERE seq = $1;",
            tamper_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

        # 1. Run validator subprocess on tampered ledger
        cmd = [sys.executable, "-m", "fluxpay.workers.hash_validator"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await proc.communicate()

        # Contract assertions:
        # Exit code 1
        assert proc.returncode == EXIT_CHAIN_BROKEN

        # stdout emits the JSON report (Speaking Contract even on broken chain)
        stdout_str = stdout_b.decode("utf-8").strip()
        lines = stdout_str.splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["ok"] is False
        assert data["broken_seq"] == tamper_seq
        assert data["reason"] is not None and len(data["reason"]) > 0
        assert data["mode"] == "hash_validator"

        # stderr gets the runbook pointer for the 3AM responder
        stderr_str = stderr_b.decode("utf-8", errors="replace")
        assert "docs/ledger.md" in stderr_str
        assert "correction" in stderr_str

    finally:
        # Self-cleaning restoration
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "UPDATE ledger_entries SET amount = $1 WHERE seq = $2;",
            orig_amount,
            tamper_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

    # Prove chain is restored: re-run subprocess -> exit 0
    proc_restored = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "fluxpay.workers.hash_validator",
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_res_b, stderr_res_b = await proc_restored.communicate()
    assert proc_restored.returncode == EXIT_OK, (
        f"Restored verification failed: {stderr_res_b.decode('utf-8')}"
    )
    restored_data = json.loads(stdout_res_b.decode("utf-8").strip())
    assert restored_data["ok"] is True
    assert restored_data["broken_seq"] is None


# =============================================================================
# 4. CONTINUITY GAP DETECTION (SEQUENCE GAP DETECTION)
# =============================================================================


async def test_hash_validator_continuity_gap_detection(
    db_dsn: str,
    db_pool: asyncpg.Pool,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify continuity gap detection through the validator wrapper when an entry is deleted."""
    await _seed_clean_entries(db_pool, owner_conn, target_count=10)
    delete_seq = 6

    # Save complete deleted row
    saved_row = await owner_conn.fetchrow(
        "SELECT * FROM ledger_entries WHERE seq = $1;",
        delete_seq,
    )
    assert saved_row is not None

    try:
        # Delete entry under superuser connection
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "DELETE FROM ledger_entries WHERE seq = $1;",
            delete_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

        # 1. In-process check through run_once wrapper
        verification, _ = await run_once(db_pool)
        assert verification.ok is False
        assert verification.broken_seq == delete_seq
        assert verification.reason is not None
        assert (
            "discontinuity" in verification.reason.lower() or "gap" in verification.reason.lower()
        )

        # 2. Subprocess check
        env = _make_validator_env(db_dsn)
        cmd = [sys.executable, "-m", "fluxpay.workers.hash_validator"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, _ = await proc.communicate()
        assert proc.returncode == EXIT_CHAIN_BROKEN
        data = json.loads(stdout_b.decode("utf-8").strip())
        assert data["ok"] is False
        assert data["broken_seq"] == delete_seq

    finally:
        # Restore row
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            """
            INSERT INTO ledger_entries (
                seq, tx_id, account_id, direction, amount, currency,
                balance_after, version, prev_hash, entry_hash, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
            """,
            saved_row["seq"],
            saved_row["tx_id"],
            saved_row["account_id"],
            saved_row["direction"],
            saved_row["amount"],
            saved_row["currency"],
            saved_row["balance_after"],
            saved_row["version"],
            saved_row["prev_hash"],
            saved_row["entry_hash"],
            saved_row["created_at"],
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

    # Prove restoration
    verification_restored, _ = await run_once(db_pool)
    assert verification_restored.ok is True


# =============================================================================
# 5. OPERATIONAL FAILURE & SECRET HYGIENE (DEAD PORT / SILENCE CONTRACT)
# =============================================================================


async def test_hash_validator_ops_failure_dead_port_and_secret_hygiene() -> None:
    """Verify ops failure: exit 2, stdout SILENT (dead-man switch alarm), stderr has diagnostics."""
    secret_pw = "SuperSecretPasswordNeverLeakToLoki99!"  # noqa: S105
    dead_dsn = f"postgresql://opsuser:{secret_pw}@127.0.0.1:54329/fluxpay_dead"

    parsed = urlsplit(dead_dsn)
    expected_host = parsed.hostname or "127.0.0.1"

    env = _make_validator_env(dead_dsn)
    cmd = [sys.executable, "-m", "fluxpay.workers.hash_validator"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()

    # 1. Exit code 2
    assert proc.returncode == EXIT_OPS_FAILURE

    # 2. THE SILENCE CONTRACT: On ops failure, stdout MUST be completely silent.
    # The absence of signal in Loki trips the dead-man switch.
    assert stdout_b == b"", f"Expected empty stdout on ops failure, got: {stdout_b.decode()}"

    # 3. Stderr diagnostics and secret hygiene
    stderr_str = stderr_b.decode("utf-8", errors="replace")
    assert expected_host in stderr_str
    assert secret_pw not in stderr_str


# =============================================================================
# 6. IN-PROCESS MAIN EXECUTION & COVERAGE COMPLETION
# =============================================================================


async def test_hash_validator_main_in_process_happy(
    db_dsn: str,
    db_pool: asyncpg.Pool,
    owner_conn: asyncpg.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify main() entrypoint in-process on healthy ledger."""
    await _seed_clean_entries(db_pool, owner_conn, target_count=4)

    monkeypatch.setenv("FLX_PG_DSN", db_dsn)
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", base64.b64encode(b"0" * 32).decode("ascii"))
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
    monkeypatch.setenv("FLX_KEYCLOAK_JWKS_URL", "https://auth.fluxpay.local/certs")
    monkeypatch.setenv("FLX_KEYCLOAK_ISSUER", "https://auth.fluxpay.local")
    monkeypatch.setenv("FLX_KEYCLOAK_AUDIENCE", "https://api.fluxpay.local")

    from fluxpay.config import get_settings

    get_settings.cache_clear()

    exit_code = await main()
    assert exit_code == EXIT_OK
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["ok"] is True
    assert data["last_verified_seq"] == 4


async def test_hash_validator_main_in_process_broken_chain(
    db_dsn: str,
    db_pool: asyncpg.Pool,
    owner_conn: asyncpg.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify main() entrypoint in-process on broken ledger emits RUNBOOK pointer."""
    await _seed_clean_entries(db_pool, owner_conn, target_count=4)
    tamper_seq = 2

    orig_row = await owner_conn.fetchrow(
        "SELECT amount FROM ledger_entries WHERE seq = $1;",
        tamper_seq,
    )
    assert orig_row is not None
    orig_amount: int = orig_row["amount"]

    monkeypatch.setenv("FLX_PG_DSN", db_dsn)
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", base64.b64encode(b"0" * 32).decode("ascii"))
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
    monkeypatch.setenv("FLX_KEYCLOAK_JWKS_URL", "https://auth.fluxpay.local/certs")
    monkeypatch.setenv("FLX_KEYCLOAK_ISSUER", "https://auth.fluxpay.local")
    monkeypatch.setenv("FLX_KEYCLOAK_AUDIENCE", "https://api.fluxpay.local")

    from fluxpay.config import get_settings

    get_settings.cache_clear()

    try:
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "UPDATE ledger_entries SET amount = amount + 5 WHERE seq = $1;",
            tamper_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

        exit_code = await main()
        assert exit_code == EXIT_CHAIN_BROKEN
        captured = capsys.readouterr()
        data = json.loads(captured.out.strip())
        assert data["ok"] is False
        assert data["broken_seq"] == tamper_seq
        assert "docs/ledger.md" in captured.err
        assert "correction" in captured.err
    finally:
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "UPDATE ledger_entries SET amount = $1 WHERE seq = $2;",
            orig_amount,
            tamper_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )


async def test_hash_validator_main_in_process_config_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify main() entrypoint in-process handles configuration failure gracefully."""
    for key in list(os.environ.keys()):
        if key.startswith("FLX_"):
            monkeypatch.delenv(key, raising=False)

    from fluxpay.config import get_settings

    get_settings.cache_clear()

    exit_code = await main()
    assert exit_code == EXIT_OPS_FAILURE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Configuration failure" in captured.err


async def test_hash_validator_main_tz_probe_failure(
    db_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify main() catches timezone drift via the fail-fast probe."""
    monkeypatch.setenv("FLX_PG_DSN", db_dsn)
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", base64.b64encode(b"0" * 32).decode("ascii"))
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
    monkeypatch.setenv("FLX_KEYCLOAK_JWKS_URL", "https://auth.fluxpay.local/certs")
    monkeypatch.setenv("FLX_KEYCLOAK_ISSUER", "https://auth.fluxpay.local")
    monkeypatch.setenv("FLX_KEYCLOAK_AUDIENCE", "https://api.fluxpay.local")

    from fluxpay.config import get_settings

    get_settings.cache_clear()

    orig_create_pool = asyncpg.create_pool

    async def _mock_pool(*args: Any, **kwargs: Any) -> asyncpg.Pool:
        kwargs["server_settings"] = {"TimeZone": "EST"}
        return await orig_create_pool(*args, **kwargs)

    monkeypatch.setattr(asyncpg, "create_pool", _mock_pool)

    exit_code = await main()
    assert exit_code == EXIT_OPS_FAILURE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "PostgreSQL connection timezone must be 'UTC'" in captured.err
