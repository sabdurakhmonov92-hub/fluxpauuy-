"""Integration test suite proving the operational contract of the ledger verify CLI.

Proves:
1. Happy path: exit code 0, single-line JSON report, last_verified_seq accuracy, elapsed_ms present.
2. Broken chain tamper detection: exit code 1, broken_seq identification, non-empty reason,
   RUNBOOK pointer in output, and self-cleaning restoration.
3. Range bounded verification: explicit --from-seq and --to-seq bounds echoed and respected.
4. Operational failure & secret hygiene: exit code 2 on dead port; host diagnostic present in
   stderr but password strictly absent (leak-guard proven).
5. Argument validation: exit code 2 on invalid range (--from-seq > --to-seq).
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
import uuid
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import asyncpg  # type: ignore[import-untyped]
import pytest

from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import EntryDraft, LedgerTransaction
from fluxpay.ledger.verify import (
    EXIT_CHAIN_BROKEN,
    EXIT_OK,
    EXIT_OPS_FAILURE,
    main,
    run_verification,
)

pytestmark = pytest.mark.integration

AccountsFactory = Callable[..., Coroutine[Any, Any, list[uuid.UUID]]]
SeedAccountCallable = Callable[[uuid.UUID, int, str], Coroutine[Any, Any, LedgerTransaction]]


def _make_cli_env(dsn: str) -> dict[str, str]:
    """Create isolated environment for CLI subprocess execution.

    Strips ambient FLX_ vars and supplies valid baseline secrets per Task 3 discipline.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("FLX_")}
    env["FLX_PG_DSN"] = dsn
    env["FLX_VAULT_MASTER_KEY"] = base64.b64encode(b"0" * 32).decode("ascii")
    env["FLX_WEBHOOK_SIGNING_KEY"] = "a" * 32

    repo_root = Path(__file__).resolve().parent.parent.parent
    src_dir = repo_root / "src"
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{src_dir}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else str(src_dir)
    )
    return env


# =============================================================================
# 1. IN-PROCESS COVERAGE PROOF (Ensures verify package is measured in-process)
# =============================================================================


async def test_run_verification_in_process(
    db_pool: asyncpg.Pool,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
) -> None:
    """Verify run_verification directly against db_pool in-process."""
    acc_ids = await ledger_accounts_factory(count=1)
    await seed_account(acc_ids[0], 500, "USDC")

    result = await run_verification(db_pool, from_seq=1)
    assert result.ok is True
    assert result.last_verified_seq >= 2


def test_main_in_process_human_and_json_modes(
    db_dsn: str,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify main() entry point execution in-process for both report modes."""
    for key in list(os.environ.keys()):
        if key.startswith("FLX_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("FLX_PG_DSN", db_dsn)
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", base64.b64encode(b"0" * 32).decode("ascii"))
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)

    from fluxpay.config import get_settings

    get_settings.cache_clear()

    # Human mode
    code_human = main([])
    assert code_human == EXIT_OK
    captured_human = capsys.readouterr()
    assert "OK: Hash chain verified." in captured_human.out

    # JSON mode
    code_json = main(["--json"])
    assert code_json == EXIT_OK
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out.strip())
    assert data["ok"] is True
    assert "elapsed_ms" in data


# =============================================================================
# 2. SUBPROCESS OPS CONTRACT (Real CLI execution)
# =============================================================================


async def test_verify_cli_happy_path(
    db_dsn: str,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
) -> None:
    """Verify CLI exit 0, JSON output shape, and sequence verification on valid chain."""
    acc_ids = await ledger_accounts_factory(count=3)
    # Seed 3 transactions = 6 entries (Task 16 seed_account creates 2 entries per call)
    await seed_account(acc_ids[0], 1000, "USDC")
    await seed_account(acc_ids[1], 2000, "USDC")
    await seed_account(acc_ids[2], 3000, "USDC")

    env = _make_cli_env(db_dsn)
    cmd = [sys.executable, "-m", "fluxpay.ledger.verify", "--json"]
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
    assert data["last_verified_seq"] >= 6
    assert data["broken_seq"] is None
    assert data["reason"] is None
    assert "checked_at" in data
    assert data["from_seq"] == 1
    assert data["to_seq"] is None
    assert isinstance(data["elapsed_ms"], int)
    assert data["elapsed_ms"] >= 0


async def test_verify_cli_broken_chain_and_self_cleaning(
    db_dsn: str,
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify CLI exit 1 on cryptographic tampering, RUNBOOK pointer, and clean recovery."""
    acc_ids = await ledger_accounts_factory(count=2)
    await seed_account(acc_ids[0], 5000, "USDC")

    tx = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_ids[0],
                direction=Direction.DEBIT,
                amount=100,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_ids[1],
                direction=Direction.CREDIT,
                amount=100,
                currency="USDC",
            ),
        ]
    )
    tamper_seq = tx.entries[0].seq

    # Capture original row state for self-cleaning restoration
    original_row = await owner_conn.fetchrow(
        "SELECT amount FROM ledger_entries WHERE seq = $1;",
        tamper_seq,
    )
    assert original_row is not None
    orig_amount: int = original_row["amount"]

    env = _make_cli_env(db_dsn)

    try:
        # Documented DB admin correction procedure: disable trigger -> mutate -> re-enable
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "UPDATE ledger_entries SET amount = amount + 1 WHERE seq = $1;",
            tamper_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

        # 1. JSON mode: exit code 1, broken_seq == tampered seq, non-empty reason
        cmd_json = [sys.executable, "-m", "fluxpay.ledger.verify", "--json"]
        proc_json = await asyncio.create_subprocess_exec(
            *cmd_json,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_json_b, _ = await proc_json.communicate()
        assert proc_json.returncode == EXIT_CHAIN_BROKEN
        data = json.loads(stdout_json_b.decode("utf-8").strip())
        assert data["ok"] is False
        assert data["broken_seq"] == tamper_seq
        assert data["reason"] is not None and len(data["reason"]) > 0

        # 2. Human mode: exit code 1, stdout has RUNBOOK pointer
        cmd_human = [sys.executable, "-m", "fluxpay.ledger.verify"]
        proc_human = await asyncio.create_subprocess_exec(
            *cmd_human,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_human_b, _ = await proc_human.communicate()
        stdout_human = stdout_human_b.decode("utf-8")
        assert proc_human.returncode == EXIT_CHAIN_BROKEN
        assert "FAIL: Hash chain broken" in stdout_human
        assert f"seq={tamper_seq}" in stdout_human
        assert "RUNBOOK: docs/ledger.md §correction" in stdout_human

    finally:
        # Self-cleaning restore: return exact row values to keep suite green
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

    # Prove chain is restored to 100% cryptographic validity
    proc_restored = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "fluxpay.ledger.verify",
        "--json",
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_res_b, _ = await proc_restored.communicate()
    assert proc_restored.returncode == EXIT_OK
    restored_data = json.loads(stdout_res_b.decode("utf-8").strip())
    assert restored_data["ok"] is True


async def test_verify_cli_range_query(
    db_dsn: str,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
) -> None:
    """Verify CLI range query: --from-seq 4 --to-seq 6 returns last_verified_seq==6."""
    acc_ids = await ledger_accounts_factory(count=3)
    await seed_account(acc_ids[0], 1000, "USDC")
    await seed_account(acc_ids[1], 2000, "USDC")
    await seed_account(acc_ids[2], 3000, "USDC")

    env = _make_cli_env(db_dsn)
    cmd = [
        sys.executable,
        "-m",
        "fluxpay.ledger.verify",
        "--from-seq",
        "4",
        "--to-seq",
        "6",
        "--json",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    assert proc.returncode == EXIT_OK, f"Process failed with stderr: {stderr_b.decode('utf-8')}"
    data = json.loads(stdout_b.decode("utf-8").strip())
    assert data["ok"] is True
    assert data["from_seq"] == 4
    assert data["to_seq"] == 6
    assert data["last_verified_seq"] == 6


def test_verify_cli_ops_failure_dead_port_and_secret_hygiene() -> None:
    """Verify CLI exit 2 on unreachable database and proves password is never leaked to stderr."""
    secret_pw = "SuperSecretPasswordDoNotLeak987!"  # noqa: S105
    dead_dsn = f"postgresql://opsuser:{secret_pw}@127.0.0.1:54329/fluxpay_dead"

    parsed = urlsplit(dead_dsn)
    expected_host = parsed.hostname or "127.0.0.1"

    env = _make_cli_env(dead_dsn)
    cmd = [sys.executable, "-m", "fluxpay.ledger.verify"]
    proc = subprocess.run(  # noqa: S603
        cmd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == EXIT_OPS_FAILURE

    # Stderr MUST contain host for operator diagnostics
    assert expected_host in proc.stderr

    # Stderr and stdout MUST NEVER contain the password (leak-guard proven)
    assert secret_pw not in proc.stderr
    assert secret_pw not in proc.stdout


def test_verify_cli_invalid_arguments(db_dsn: str) -> None:
    """Verify CLI exit 2 on invalid arguments (--from-seq 5 --to-seq 2)."""
    env = _make_cli_env(db_dsn)
    cmd = [
        sys.executable,
        "-m",
        "fluxpay.ledger.verify",
        "--from-seq",
        "5",
        "--to-seq",
        "2",
    ]
    proc = subprocess.run(  # noqa: S603
        cmd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == EXIT_OPS_FAILURE
    assert "Validation error" in proc.stderr
