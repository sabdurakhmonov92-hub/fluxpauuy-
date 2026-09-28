"""Sustained-write ledger throughput and correctness smoke test suite.

Blueprint §0 and §9 Invariants under sustained load:
- Correctness first, speed second.
- Monotonic consecutive sequence allocation (strictly gapless 1..N).
- 1000 sequential balanced transactions across pair rotations.
- 100 concurrent transactions (10 rounds x asyncio.gather(10 txs)).
- Cryptographic hash-chain continuity from genesis (from_seq=1) to tip.
- Tip singleton table cross-check matches terminal chain state.
- Sustained throughput floor >= 20 tx/s (proves >= 2.5x headroom over
  production target of 8 tx/s).
"""

import asyncio
import time
import uuid
from collections.abc import Callable, Coroutine
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import pytest

from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import EntryDraft, LedgerTransaction

# Excluded from CI default test run via addopts -m "not throughput" in pyproject.toml.
# Executed explicitly via `make smoke` during local/nightly performance audits.
pytestmark = pytest.mark.throughput

AccountsFactory = Callable[..., Coroutine[Any, Any, list[uuid.UUID]]]


async def test_sustained_write_ledger_throughput(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify ledger correctness and throughput under sequential and concurrent loads."""
    # Seed: 1 system account (initial balance, Task 16 factory), 50 agent accounts
    system_ids = await ledger_accounts_factory(
        owner_type="system",
        currency="USDC",
        count=1,
        initial_balance=100_000_000_000,
    )
    system_id = system_ids[0]

    agent_ids = await ledger_accounts_factory(
        owner_type="agent",
        currency="USDC",
        count=50,
        initial_balance=0,
    )

    tip_before = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_before is not None
    seq_start = int(tip_before["last_seq"])

    # =========================================================================
    # PHASE A: 1000 sequential balanced transactions (pair rotations)
    # =========================================================================
    num_seq_txs = 1000
    start_a = time.perf_counter()

    seq_tx_results: list[LedgerTransaction] = []
    for i in range(num_seq_txs):
        target_agent = agent_ids[i % 50]
        tx = await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=system_id,
                    direction=Direction.DEBIT,
                    amount=100,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=target_agent,
                    direction=Direction.CREDIT,
                    amount=100,
                    currency="USDC",
                ),
            ]
        )
        seq_tx_results.append(tx)

    elapsed_a = time.perf_counter() - start_a
    tps_a = num_seq_txs / elapsed_a if elapsed_a > 0 else 0.0
    print(f"\n[THROUGHPUT] Phase A (1000 sequential txs): {elapsed_a:.2f}s | {tps_a:.1f} tx/s")

    # Floor assert: sequential >= 20 tx/s
    assert tps_a >= 20.0, (
        f"Sequential throughput {tps_a:.1f} tx/s below floor of 20 tx/s: "
        "below floor → investigate local env before trusting other perf numbers; "
        "production target is 8 tx/s (Blueprint §0) — this floor proves ≥2.5x headroom"
    )

    # =========================================================================
    # PHASE B: 10 rounds x asyncio.gather(10 txs) = 100 concurrent
    # =========================================================================
    num_rounds = 10
    txs_per_round = 10
    total_concurrent_txs = num_rounds * txs_per_round
    start_b = time.perf_counter()

    concurrent_tx_results: list[LedgerTransaction] = []

    async def _post_concurrent(agent_id: uuid.UUID) -> LedgerTransaction:
        return await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=system_id,
                    direction=Direction.DEBIT,
                    amount=50,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=agent_id,
                    direction=Direction.CREDIT,
                    amount=50,
                    currency="USDC",
                ),
            ]
        )

    for round_idx in range(num_rounds):
        round_agents = [
            agent_ids[(round_idx * txs_per_round + j) % 50] for j in range(txs_per_round)
        ]
        round_results = await asyncio.gather(*[_post_concurrent(acc) for acc in round_agents])
        concurrent_tx_results.extend(round_results)

    elapsed_b = time.perf_counter() - start_b
    tps_b = total_concurrent_txs / elapsed_b if elapsed_b > 0 else 0.0
    print(f"[THROUGHPUT] Phase B (100 concurrent txs): {elapsed_b:.2f}s | {tps_b:.1f} tx/s")

    # =========================================================================
    # ALWAYS ASSERTED (Correctness first, speed second)
    # =========================================================================
    all_results = seq_tx_results + concurrent_tx_results
    total_txs = num_seq_txs + total_concurrent_txs  # 1100 transactions
    assert len(all_results) == total_txs

    # Zero failures: every transaction committed 2 entries
    total_entries = total_txs * 2  # 2200 entries
    allocated_seqs = sorted(e.seq for tx in all_results for e in tx.entries)
    assert len(allocated_seqs) == total_entries

    # Strict sequence continuity: strictly consecutive integers
    expected_seqs = list(range(seq_start + 1, seq_start + total_entries + 1))
    assert allocated_seqs == expected_seqs

    # Cryptographic hash chain verification from genesis (from_seq=1)
    verification = await ledger_store.verify_chain(from_seq=1)
    assert verification.ok is True
    assert verification.last_verified_seq == seq_start + total_entries
    assert verification.broken_seq is None
    assert verification.reason is None

    # Tip cross-check: mutable tip table matches verified terminal entry
    tip_after = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_after is not None
    assert int(tip_after["last_seq"]) == seq_start + total_entries
    assert tip_after["last_hash"] == all_results[-1].entries[-1].entry_hash
