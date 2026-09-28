"""Treasury Foundation: Custody Schema & Hot Wallet Monitor (Block I).

=============================================================================
THE ACCOUNTING MAP: ASSETS VS. LIABILITIES
=============================================================================
The central accounting truth of digital asset infrastructure:
The internal ledger records LIABILITIES (what the platform owes to agents
and merchants). Custody is where the backing ASSETS live in the external
world (on-chain hot wallets and cold multisig vaults). Conflating them is
the catastrophic category error that destroys financial platforms.

1. INTERNAL LEDGER = LIABILITIES:
   The double-entry ledger entries in `ledger_entries` (Task 13, 16) track
   agent balances and merchant settlement obligations. Every unit of currency
   credited to an agent account is a liability owed by the platform.

2. SYSTEM ACCOUNT = EXTERNAL-WORLD MIRROR:
   The system account (Task 27 seed via deploy/sql/bootstrap.sql) serves as the
   mirror of the external world for customer deposit and withdrawal flows.
   When an agent deposits funds, external assets arrive on-chain, and the internal
   ledger credits the agent while debiting the system account. The system account
   is the bridge where liabilities meet external claims.

3. TREASURY INTERNAL ACCOUNT = DEV/TEST SEEDING ARTIFACT ONLY:
   The internal treasury account created during bootstrap exists solely as an
   artifact for development environment seeding and testing. In production
   accounting, it is informational only (as established in Task 41).

4. CUSTODY SPLIT IS NOT LEDGER ENTRIES:
   The custody split between the EVM hot wallet and the cold vault (Gnosis Safe
   2-of-3 multisig) is tracked strictly in the `wallet_state` table and via
   live on-chain reads (`OnChainReader`). It is NEVER posted as internal ledger
   entries. Moving funds between the hot wallet and the cold vault changes CUSTODY
   of backing assets; it does NOT alter platform liabilities to agents or
   merchants. Posting a hot-to-cold rebalance to the double-entry ledger would be
   a category error that corrupts financial reporting.

=============================================================================
THE TWO LAWS OF THE TREASURY SUBSYSTEM
=============================================================================
LAW 1: THE OBSERVE-PROPOSE LAW
The server that can MOVE money is the server that WILL lose it.
Therefore, the server OBSERVES on-chain reality and PROPOSES operational
actions; human operators behind a 2-of-3 multisig EXECUTE transactions;
and the server RECORDS the results. Every automation in this subsystem
terminates at a database queue entry (`cold_payouts`) or an administrative alert
— never at a broadcasted or signed transfer.

LAW 2: THE NO-KEYS LAW
The server holds zero cryptographic credentials capable of initiating or
authorizing on-chain transfers. No seed phrases, no signing credentials,
and no direct transaction broadcast interfaces exist within the codebase.
The cold vault is an air-gapped Gnosis Safe requiring 2-of-3 independent human
signatures. Even in the event of total server compromise, the adversary cannot
exfiltrate backing assets because the server is fundamentally incapable of moving
money on its own.

=============================================================================
MODULE MAP
=============================================================================
- `monitor.py`:
  One-shot hot wallet monitor invoked via systemd timer (15-minute cadence).
  Reads on-chain balances, refreshes `wallet_state` caches, evaluates water-level
  thresholds with hysteresis, creates surplus sweep requests, and fires alerts.
- `payouts.py`:
  Cold payout queue machine and 2-man authorization workflow (Task 45).
- `reader.py`:
  The blockchain observation seam (`OnChainReader` Protocol and `TxStatus`).
  Abstracts EVM reads so the treasury subsystem remains decoupled from RPC
  clients until Task 50 connects the Base L2 adapter.
"""

from __future__ import annotations

from fluxpay.treasury.monitor import (
    EXIT_OK,
    EXIT_OPS_FAILURE,
    HotWalletMonitor,
    MonitorReport,
    ThresholdVerdict,
    build_report_line,
    evaluate,
    main,
    map_exit_code,
)
from fluxpay.treasury.reader import FakeReader, OnChainReader, TxStatus

__all__ = [
    "EXIT_OK",
    "EXIT_OPS_FAILURE",
    "FakeReader",
    "HotWalletMonitor",
    "MonitorReport",
    "OnChainReader",
    "ThresholdVerdict",
    "TxStatus",
    "build_report_line",
    "evaluate",
    "main",
    "map_exit_code",
]
