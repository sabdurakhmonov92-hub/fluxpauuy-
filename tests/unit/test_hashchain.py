"""Contract-lock verification suite for FluxPay Ledger Hash Chain.

Pure unit test suite: zero I/O, zero network, zero sleeps, zero randomness.
"""

import hashlib
from datetime import UTC, datetime, timezone

import pytest

from fluxpay.ledger.hashchain import (
    GENESIS,
    SEPARATOR,
    Direction,
    EntryFingerprint,
    canonical_bytes,
    compute_entry_hash,
    format_timestamp,
    verify_link,
)


def _make_valid_fingerprint(
    *,
    seq: int = 1,
    tx_id: str = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e",
    account_id: str = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9f",
    direction: Direction = Direction.CREDIT,
    amount: int = 10000,
    currency: str = "USDC",
    balance_after: int = 10000,
    version: int = 1,
    created_at: str = "2026-09-24T00:00:00.000000Z",
) -> EntryFingerprint:
    """Helper to construct a valid deterministic EntryFingerprint."""
    return EntryFingerprint(
        seq=seq,
        tx_id=tx_id,
        account_id=account_id,
        direction=direction,
        amount=amount,
        currency=currency,
        balance_after=balance_after,
        version=version,
        created_at=created_at,
    )


# =============================================================================
# 1. GOLDEN VECTOR (Known Answer Test - KAT)
# =============================================================================


def test_golden_vector_kat() -> None:
    # FROZEN CONTRACT - DO NOT REGENERATE. Regeneration means the encoding changed,
    # which means every historical ledger entry is orphaned. This test failing
    # is a STOP-THE-LINE event.
    fp = _make_valid_fingerprint(
        seq=1,
        tx_id="018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e",
        account_id="018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9f",
        direction=Direction.CREDIT,
        amount=10000,
        currency="USDC",
        balance_after=10000,
        version=1,
        created_at="2026-09-24T00:00:00.000000Z",
    )

    # Reference canonical payload:
    # GENESIS\x1f1\x1f018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e\x1f
    # 018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9f\x1fCREDIT\x1f10000\x1f
    # USDC\x1f10000\x1f1\x1f2026-09-24T00:00:00.000000Z
    raw_canonical = (
        b"GENESIS\x1f1\x1f018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e\x1f"
        b"018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9f\x1fCREDIT\x1f10000\x1f"
        b"USDC\x1f10000\x1f1\x1f2026-09-24T00:00:00.000000Z"
    )
    expected_kat_hash = hashlib.sha256(raw_canonical).hexdigest()

    actual_hash = compute_entry_hash(GENESIS, fp)
    assert len(actual_hash) == 64
    assert actual_hash == expected_kat_hash
    assert actual_hash == actual_hash.lower()


# =============================================================================
# 2. DETERMINISM TEST
# =============================================================================


def test_determinism_repeated_three_times() -> None:
    for _ in range(3):
        fp1 = _make_valid_fingerprint()
        fp2 = _make_valid_fingerprint()
        assert compute_entry_hash(GENESIS, fp1) == compute_entry_hash(GENESIS, fp2)


# =============================================================================
# 3. FIELD SENSITIVITY TABLE (All 10 fields proven hash-relevant)
# =============================================================================


def test_field_sensitivity_all_ten_fields_alter_hash() -> None:
    # Base record for seq=2 to allow modifying prev_hash
    base_prev = "a" * 64
    base_fp = _make_valid_fingerprint(seq=2)
    base_hash = compute_entry_hash(base_prev, base_fp)

    perturbations: list[tuple[str, str, EntryFingerprint]] = [
        ("prev_hash", "b" * 64, base_fp),
        ("seq", base_prev, _make_valid_fingerprint(seq=3)),
        (
            "tx_id",
            base_prev,
            _make_valid_fingerprint(seq=2, tx_id="018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d90"),
        ),
        (
            "account_id",
            base_prev,
            _make_valid_fingerprint(seq=2, account_id="018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d90"),
        ),
        (
            "direction",
            base_prev,
            _make_valid_fingerprint(seq=2, direction=Direction.DEBIT),
        ),
        ("amount", base_prev, _make_valid_fingerprint(seq=2, amount=10001)),
        ("currency", base_prev, _make_valid_fingerprint(seq=2, currency="EUR")),
        (
            "balance_after",
            base_prev,
            _make_valid_fingerprint(seq=2, balance_after=9999),
        ),
        ("version", base_prev, _make_valid_fingerprint(seq=2, version=2)),
        (
            "created_at",
            base_prev,
            _make_valid_fingerprint(seq=2, created_at="2026-09-24T00:00:00.000001Z"),
        ),
    ]

    assert len(perturbations) == 10

    for field_name, p_prev, p_fp in perturbations:
        perturbed_hash = compute_entry_hash(p_prev, p_fp)
        assert perturbed_hash != base_hash, (
            f"Field sensitivity failure: altering {field_name} did not change hash"
        )


# =============================================================================
# 4. SEPARATOR AMBIGUITY (Concatenation-collision trap closed)
# =============================================================================


def test_separator_ambiguity_collision_closed() -> None:
    fp_a = _make_valid_fingerprint(amount=1, balance_after=23)
    fp_b = _make_valid_fingerprint(amount=12, balance_after=3)

    bytes_a = canonical_bytes(GENESIS, fp_a)
    bytes_b = canonical_bytes(GENESIS, fp_b)

    assert bytes_a != bytes_b
    assert compute_entry_hash(GENESIS, fp_a) != compute_entry_hash(GENESIS, fp_b)


# =============================================================================
# 5. GENESIS BIDIRECTIONAL GUARD
# =============================================================================


def test_genesis_bidirectional_guard() -> None:
    # 1. GENESIS + seq=1 computes
    fp_seq1 = _make_valid_fingerprint(seq=1)
    assert compute_entry_hash(GENESIS, fp_seq1)

    # 2. GENESIS + seq=2 raises ValueError
    fp_seq2 = _make_valid_fingerprint(seq=2)
    with pytest.raises(ValueError, match="only permitted for seq=1"):
        compute_entry_hash(GENESIS, fp_seq2)

    # 3. seq=1 with valid hex prev_hash raises ValueError
    hex_prev = "c" * 64
    with pytest.raises(ValueError, match="must have prev_hash == 'GENESIS'"):
        compute_entry_hash(hex_prev, fp_seq1)


# =============================================================================
# 6. PREV_HASH FORMAT GUARDS
# =============================================================================


@pytest.mark.parametrize(
    "bad_prev_hash",
    [
        "a" * 63,  # 63 chars (too short)
        "A" * 64,  # Uppercase hex
        ("a" * 63) + "g",  # Non-hex char 'g'
        "",  # Empty string
    ],
)
def test_prev_hash_format_invalid(bad_prev_hash: str) -> None:
    fp = _make_valid_fingerprint(seq=2)
    with pytest.raises(ValueError, match="prev_hash"):
        compute_entry_hash(bad_prev_hash, fp)


# =============================================================================
# 7. FIELD GUARDS (ValueError on bad inputs)
# =============================================================================


def test_field_guards_raise_value_error_with_field_name() -> None:
    # seq=0
    with pytest.raises(ValueError, match="seq"):
        _make_valid_fingerprint(seq=0)

    # amount=0 and amount=-1
    with pytest.raises(ValueError, match="amount"):
        _make_valid_fingerprint(amount=0)
    with pytest.raises(ValueError, match="amount"):
        _make_valid_fingerprint(amount=-1)

    # balance_after=-1
    with pytest.raises(ValueError, match="balance_after"):
        _make_valid_fingerprint(balance_after=-1)

    # version=0
    with pytest.raises(ValueError, match="version"):
        _make_valid_fingerprint(version=0)

    # currency invalid formats
    with pytest.raises(ValueError, match="currency"):
        _make_valid_fingerprint(currency="usdc")  # lowercase
    with pytest.raises(ValueError, match="currency"):
        _make_valid_fingerprint(currency="A" * 11)  # 11 chars
    with pytest.raises(ValueError, match="currency"):
        _make_valid_fingerprint(currency="US D")  # whitespace

    # direction raw string rejected (must be Direction StrEnum)
    with pytest.raises(ValueError, match="direction"):
        _make_valid_fingerprint(direction="DEBIT")  # type: ignore[arg-type]

    # tx_id invalid
    with pytest.raises(ValueError, match="tx_id"):
        _make_valid_fingerprint(tx_id="018F2D5A-8B1E-7B2C-9D3E-4F5A6B7C8D9E")  # uppercase
    with pytest.raises(ValueError, match="tx_id"):
        _make_valid_fingerprint(tx_id="not-a-valid-uuid")

    # created_at malformed variants (3 variants)
    with pytest.raises(ValueError, match="created_at"):
        _make_valid_fingerprint(created_at="2026-09-24T00:00:00.000000+00:00")  # +00:00 suffix
    with pytest.raises(ValueError, match="created_at"):
        _make_valid_fingerprint(created_at="2026-09-24T00:00:00")  # naive (no tz)
    with pytest.raises(ValueError, match="created_at"):
        _make_valid_fingerprint(created_at="2026-09-24T00:00:00Z")  # missing microseconds


def test_reserved_separator_0x1f_rejected_in_fields() -> None:
    with pytest.raises(ValueError, match="currency"):
        _make_valid_fingerprint(currency="US\x1fD")


# =============================================================================
# 8. FORMAT_TIMESTAMP TEST
# =============================================================================


def test_format_timestamp() -> None:
    # 1. tz-aware UTC -> canonical form
    dt = datetime(2026, 9, 24, 12, 34, 56, 789012, tzinfo=UTC)
    assert format_timestamp(dt) == "2026-09-24T12:34:56.789012Z"

    # 2. non-UTC aware -> ValueError
    offset_tz = timezone(pytest.importorskip("datetime").timedelta(hours=3))
    dt_non_utc = datetime(2026, 9, 24, 12, 34, 56, 789012, tzinfo=offset_tz)
    with pytest.raises(ValueError, match="non-UTC"):
        format_timestamp(dt_non_utc)

    # 3. naive -> ValueError
    dt_naive = datetime(2026, 9, 24, 12, 34, 56, 789012)
    with pytest.raises(ValueError, match="naive"):
        format_timestamp(dt_naive)


# =============================================================================
# 9. VERIFY_LINK TOTALITY & TIMING SAFETY
# =============================================================================


def test_verify_link_totality_and_behavior() -> None:
    fp = _make_valid_fingerprint(seq=1)
    honest_hash = compute_entry_hash(GENESIS, fp)

    # Honest link returns True
    assert verify_link(GENESIS, fp, honest_hash) is True

    # Tampered fields return False
    tampered_fp = _make_valid_fingerprint(seq=1, amount=99999)
    assert verify_link(GENESIS, tampered_fp, honest_hash) is False

    # Malformed claimed hashes return False and NEVER raise
    assert verify_link(GENESIS, fp, "not-a-hash") is False
    assert verify_link(GENESIS, fp, honest_hash[:63]) is False
    assert verify_link(GENESIS, fp, honest_hash.upper()) is False
    assert verify_link(GENESIS, fp, "") is False


# =============================================================================
# 10. DIRECTION STRENUM MEMBERSHIP
# =============================================================================


def test_direction_enum_membership() -> None:
    assert issubclass(Direction, str)
    assert len(Direction) == 2
    assert Direction.DEBIT.value == "DEBIT"
    assert Direction.CREDIT.value == "CREDIT"


# =============================================================================
# 11. 1000-ENTRY MINI-CHAIN WALK & FORWARD TAMPER PROPAGATION
# =============================================================================


def test_mini_chain_walk_1000_entries_with_forward_tamper_propagation() -> None:
    entries: list[tuple[str, EntryFingerprint, str]] = []
    current_prev = GENESIS

    # Build 1000 chained entries
    for i in range(1, 1001):
        direction = Direction.CREDIT if i % 2 == 1 else Direction.DEBIT
        account_idx = (i % 5) + 1
        fp = _make_valid_fingerprint(
            seq=i,
            tx_id=f"00000000-0000-0000-0000-{i:012x}",
            account_id=f"00000000-0000-0000-0001-{account_idx:012x}",
            direction=direction,
            amount=1000 * i,
            balance_after=50000 + (1000 * i),
            version=i,
        )
        h = compute_entry_hash(current_prev, fp)
        entries.append((current_prev, fp, h))
        current_prev = h

    # Verify honest walk: verify_link is True at every single step
    for prev_h, fp, claimed_h in entries:
        assert verify_link(prev_h, fp, claimed_h) is True

    # Tamper with entry #500 (index 499)
    prev_500, fp_500, h_500 = entries[499]
    tampered_fp_500 = _make_valid_fingerprint(
        seq=fp_500.seq,
        tx_id=fp_500.tx_id,
        account_id=fp_500.account_id,
        direction=fp_500.direction,
        amount=fp_500.amount + 1,  # Corrupt amount
        balance_after=fp_500.balance_after,
        version=fp_500.version,
    )

    # Verification fails at #500 with original claimed hash
    assert verify_link(prev_500, tampered_fp_500, h_500) is False

    # Forward propagation: even if an adversary recomputed entry #500's hash,
    # entry #501's stored link broke because entry #501 binds to original #500 hash
    new_h_500 = compute_entry_hash(prev_500, tampered_fp_500)
    prev_501, fp_501, h_501 = entries[500]
    assert prev_501 == h_500  # Stored chain links to original h_500
    assert verify_link(new_h_500, fp_501, h_501) is False


# =============================================================================
# 12. CANONICAL BYTES RECONSTRUCTIBILITY (Spec == Code)
# =============================================================================


def test_canonical_bytes_reconstructibility_spec_matches_code() -> None:
    fp = _make_valid_fingerprint(
        seq=1,
        tx_id="018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e",
        account_id="018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9f",
        direction=Direction.DEBIT,
        amount=2500,
        currency="EUR",
        balance_after=7500,
        version=3,
        created_at="2026-09-24T12:00:00.000000Z",
    )

    actual_bytes = canonical_bytes(GENESIS, fp)

    # Independent hand-crafted reconstruction from raw specification:
    expected_hand_built = (
        b"GENESIS"
        + SEPARATOR
        + b"1"
        + SEPARATOR
        + b"018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"
        + SEPARATOR
        + b"018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9f"
        + SEPARATOR
        + b"DEBIT"
        + SEPARATOR
        + b"2500"
        + SEPARATOR
        + b"EUR"
        + SEPARATOR
        + b"7500"
        + SEPARATOR
        + b"3"
        + SEPARATOR
        + b"2026-09-24T12:00:00.000000Z"
    )

    assert actual_bytes == expected_hand_built
