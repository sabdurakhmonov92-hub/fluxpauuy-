"""Unit test suite for Treasury Cold Payout Queue pure domain logic.

TASK 45 — COLD PAYOUT PIPELINE: 2-MAN QUEUE + EXECUTION RECORDING (BLOCK I CLOSURE)

Tests:
1. Pure voting quorum decisions (decide_from_votes matrix incl. rejection asymmetry).
2. Pure stuck payout classification and boundary conditions (classify_stuck >= 24h).
3. CustodySnapshot value object math, drift calculations, and dictionary serialization.
4. NO-KEYS security meta-test asserting absence of signing tokens across all treasury modules.
5. PayoutNotOpenError registry and wire contract validation (ErrorEnvelope roundtrip).
6. PayoutSweeper report line formatting and exit code taxonomy.
7. CLI subcommand argument parsing and validation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from fluxpay.contracts.schemas import ErrorEnvelope
from fluxpay.shared.errors import ERROR_REGISTRY, PayoutNotOpenError
from fluxpay.treasury.cli import build_parser
from fluxpay.treasury.payouts import (
    EXIT_OK,
    EXIT_OPS_FAILURE,
    REJECTS_TERMINAL,
    STUCK_PAYOUT_HOURS,
    VOTES_REQUIRED,
    CustodySnapshot,
    PayoutRecord,
    PayoutSweepReport,
    build_report_line,
    classify_stuck,
    decide_from_votes,
    map_exit_code,
)

pytestmark = pytest.mark.unit


# ==============================================================================
# 1. PURE DECISION: DECIDE_FROM_VOTES FULL MATRIX
# ==============================================================================
def test_decide_from_votes_full_matrix() -> None:
    """Validate full voting quorum matrix.

    SUBTLETY & ORDER-INVARIANCE LAW:
    Votes in the database are COUNTS after the fact. The pure function evaluates
    the aggregate outcome without regard to vote arrival order:
    - (2, 1) -> rejected: Even if 2 approves arrived first, any rejection terminates.
    - Matches Task 42's asymmetry law.
    """
    assert VOTES_REQUIRED == 2
    assert REJECTS_TERMINAL is True

    # Zero / partial votes
    assert decide_from_votes(0, 0) == "pending"
    assert decide_from_votes(1, 0) == "pending"

    # Approval threshold met
    assert decide_from_votes(2, 0) == "approved"
    assert decide_from_votes(3, 0) == "approved"

    # Rejection asymmetry: single reject terminates
    assert decide_from_votes(0, 1) == "rejected"
    assert decide_from_votes(1, 1) == "rejected"
    assert decide_from_votes(2, 1) == "rejected"
    assert decide_from_votes(3, 1) == "rejected"
    assert decide_from_votes(0, 2) == "rejected"
    assert decide_from_votes(2, 2) == "rejected"


# ==============================================================================
# 2. PURE DECISION: CLASSIFY_STUCK BOUNDARY CONDITIONS
# ==============================================================================
def test_classify_stuck_boundaries() -> None:
    """Validate boundary conditions for stuck payout alerts.

    Boundary law:
    - >= 24h (STUCK_PAYOUT_HOURS) -> stuck (True)
    - 23h 59m -> not stuck (False)
    - Only 'approved' (awaiting Safe multisig) and 'executed' (awaiting RPC confirmations)
      can be stuck. Other statuses ('requested', 'confirmed', 'rejected') are False.
    """
    now = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)
    payout_id = uuid4()

    def make_payout(status: str, updated_at: datetime) -> PayoutRecord:
        return PayoutRecord(
            payout_id=payout_id,
            rail="base_usdc",
            to_address="0x1111111111111111111111111111111111111111",
            amount_minor=1_000_000_000,
            currency="USDC",
            reason="operational",
            status=status,
            requested_by_sub="admin_test",
            created_at=updated_at,
            updated_at=updated_at,
        )

    # 1. Approved status boundaries
    just_under_24h = now - timedelta(hours=23, minutes=59, seconds=59)
    exactly_24h = now - timedelta(hours=STUCK_PAYOUT_HOURS)
    over_24h = now - timedelta(hours=25)

    assert classify_stuck(make_payout("approved", just_under_24h), now) is False
    assert classify_stuck(make_payout("approved", exactly_24h), now) is True
    assert classify_stuck(make_payout("approved", over_24h), now) is True

    # 2. Executed status boundaries
    assert classify_stuck(make_payout("executed", just_under_24h), now) is False
    assert classify_stuck(make_payout("executed", exactly_24h), now) is True
    assert classify_stuck(make_payout("executed", over_24h), now) is True

    # 3. Other statuses never classify as stuck
    assert classify_stuck(make_payout("requested", over_24h), now) is False
    assert classify_stuck(make_payout("confirmed", over_24h), now) is False
    assert classify_stuck(make_payout("rejected", over_24h), now) is False


# ==============================================================================
# 3. CUSTODY SNAPSHOT VALUE OBJECT & DRIFT MATH
# ==============================================================================
def test_custody_snapshot_math_and_serialization() -> None:
    """Validate CustodySnapshot mathematical invariants, drift, and serialization."""
    now = datetime.now(tz=UTC)
    payout = PayoutRecord(
        payout_id=uuid4(),
        rail="base_usdc",
        to_address="0x2222222222222222222222222222222222222222",
        amount_minor=50_000_000_000,
        currency="USDC",
        reason="surplus_sweep",
        status="requested",
        requested_by_sub="system",
        created_at=now,
        updated_at=now,
    )

    hot_cache = 150_000_000_000
    hot_truth = 160_000_000_000
    cold_cache = 1_000_000_000_000
    cold_truth = 990_000_000_000

    hot_drift = hot_truth - hot_cache  # +10_000_000_000
    cold_drift = cold_truth - cold_cache  # -10_000_000_000
    in_flight_total = 50_000_000_000

    snapshot = CustodySnapshot(
        rail="base_usdc",
        hot_cache=hot_cache,
        cold_cache=cold_cache,
        hot_truth=hot_truth,
        cold_truth=cold_truth,
        hot_drift=hot_drift,
        cold_drift=cold_drift,
        in_flight_total=in_flight_total,
        oldest_in_flight=(payout,),
        captured_at=now,
    )

    assert snapshot.hot_drift == 10_000_000_000
    assert snapshot.cold_drift == -10_000_000_000
    assert snapshot.in_flight_total == 50_000_000_000
    assert len(snapshot.oldest_in_flight) == 1

    d = snapshot.to_dict()
    assert d["rail"] == "base_usdc"
    assert d["hot_drift"] == 10_000_000_000
    assert d["cold_drift"] == -10_000_000_000
    assert d["in_flight_total"] == 50_000_000_000
    assert len(d["oldest_in_flight"]) == 1
    assert d["oldest_in_flight"][0]["amount_minor"] == 50_000_000_000


# ==============================================================================
# 4. NO-KEYS SECURITY META-TEST (TASK 44 LAW EXTENSION)
# ==============================================================================
def test_no_keys_in_treasury_modules() -> None:
    """Security invariant: treasury modules must NEVER contain signing or private key tokens.

    Asserts absolute absence of:
    - "private_key"
    - "signing_key"
    - "mnemonic"
    - "Signer"
    - "Account.from_key"
    Extends Task 44's verification across payouts.py and cli.py.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    treasury_dir = repo_root / "src" / "fluxpay" / "treasury"

    forbidden_tokens = [
        "private_key",
        "signing_key",
        "mnemonic",
        "Signer",
        "Account.from_key",
    ]

    files_to_check = [
        treasury_dir / "monitor.py",
        treasury_dir / "reader.py",
        treasury_dir / "payouts.py",
        treasury_dir / "cli.py",
        treasury_dir / "__init__.py",
    ]

    for file_path in files_to_check:
        assert file_path.is_file(), f"Expected treasury file not found: {file_path}"
        content = file_path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in content, (
                f"SECURITY VIOLATION: Forbidden token '{token}' discovered in "
                f"{file_path.relative_to(repo_root)}. The server must hold zero signing keys."
            )


# ==============================================================================
# 5. ERROR REGISTRY CONTRACT: PAYOUT NOT OPEN ERROR
# ==============================================================================
def test_payout_not_open_error_contract() -> None:
    """Validate that PayoutNotOpenError is properly registered in ERROR_REGISTRY and wire safe."""
    assert PayoutNotOpenError.code in ERROR_REGISTRY
    assert ERROR_REGISTRY[PayoutNotOpenError.code] is PayoutNotOpenError

    err = PayoutNotOpenError(details={"payout_id": "test-uuid", "status": "executed"})
    assert err.code == "payout_not_open"
    assert err.status == 409
    assert err.retryable is False

    # Verify ErrorEnvelope wire contract roundtrip
    payload = err.to_payload()
    envelope = ErrorEnvelope.model_validate(payload)
    assert envelope.error.code == "payout_not_open"
    assert envelope.error.retryable is False


# ==============================================================================
# 6. REPORT LINE & EXIT CODE TAXONOMY
# ==============================================================================
def test_report_line_and_exit_taxonomy() -> None:
    """Validate PayoutSweepReport serialization and exit code mapping."""
    report = PayoutSweepReport(
        mode="treasury_payout_sweep",
        confirmed=3,
        stuck=1,
        open=4,
        checked_at=datetime.now(tz=UTC).isoformat(),
        elapsed_ms=120,
    )

    line = build_report_line(report, elapsed_ms=120)
    parsed = json.loads(line)
    assert parsed["mode"] == "treasury_payout_sweep"
    assert parsed["confirmed"] == 3
    assert parsed["stuck"] == 1
    assert parsed["open"] == 4
    assert parsed["elapsed_ms"] == 120

    # Exit code mapping
    assert map_exit_code(report) == EXIT_OK
    assert map_exit_code(report, error=RuntimeError("RPC down")) == EXIT_OPS_FAILURE
    assert map_exit_code(None) == EXIT_OPS_FAILURE


# ==============================================================================
# 7. CLI ARGUMENT PARSER TESTS
# ==============================================================================
def test_cli_parser_subcommands() -> None:
    """Verify that build_parser constructs valid subcommands and flags."""
    parser = build_parser()

    # list-open
    args = parser.parse_args(["list-open", "--limit", "25", "--json"])
    assert args.command == "list-open"
    assert args.limit == 25
    assert args.json is True

    # request
    args = parser.parse_args(
        [
            "request",
            "--to-address",
            "0x1234567890123456789012345678901234567890",
            "--amount-minor",
            "5000000",
            "--reason",
            "surplus_sweep",
        ]
    )
    assert args.command == "request"
    assert args.to_address == "0x1234567890123456789012345678901234567890"
    assert args.amount_minor == 5000000
    assert args.reason == "surplus_sweep"
    assert args.rail == "base_usdc"
    assert args.currency == "USDC"

    # vote
    test_uuid = str(uuid4())
    args = parser.parse_args(
        [
            "vote",
            "--payout-id",
            test_uuid,
            "--voter-sub",
            "admin_alice",
            "--vote",
            "approve",
            "--note",
            "verified on-chain",
        ]
    )
    assert args.command == "vote"
    assert args.payout_id == test_uuid
    assert args.voter_sub == "admin_alice"
    assert args.vote == "approve"
    assert args.note == "verified on-chain"

    # record
    tx_hash = "0x" + "a" * 64
    args = parser.parse_args(
        [
            "record",
            "--payout-id",
            test_uuid,
            "--tx-hash",
            tx_hash,
            "--recorded-by-sub",
            "ops_bob",
        ]
    )
    assert args.command == "record"
    assert args.payout_id == test_uuid
    assert args.tx_hash == tx_hash
    assert args.recorded_by_sub == "ops_bob"

    # confirm
    args = parser.parse_args(["confirm", "--payout-id", test_uuid])
    assert args.command == "confirm"
    assert args.payout_id == test_uuid

    # snapshot
    args = parser.parse_args(["snapshot", "--rail", "base_usdc"])
    assert args.command == "snapshot"
    assert args.rail == "base_usdc"
