"""Operational CLI for Treasury Cold Payout Queue and Custody Snapshot.

FluxPay v3 | Institutional Cold Vault Operations
Usage:
    python -m fluxpay.treasury.cli list-open [--limit 50] [--json]
    python -m fluxpay.treasury.cli request --to-address 0x... --amount-minor 1000000000 \
        [--rail base_usdc] [--currency USDC] [--reason operational] [--json]
    python -m fluxpay.treasury.cli vote --payout-id <UUID> --voter-sub <SUB> \
        [--voter-role admin] --vote <approve|reject> [--note "review"] [--json]
    python -m fluxpay.treasury.cli record --payout-id <UUID> --tx-hash 0x... \
        [--recorded-by-sub admin_cli] [--json]
    python -m fluxpay.treasury.cli confirm --payout-id <UUID> [--json]
    python -m fluxpay.treasury.cli snapshot [--rail base_usdc] [--json]

SECURITY & PHASE 1 TRUST TRADE-OFF:
1. CLI TRUST & SEPARATION OF DUTIES:
   Voting via this CLI directly bypasses Keycloak OIDC token exchange. This is an
   explicit, documented Phase 1 operational design choice. Because the physical
   multisig execution occurs off-server in the Gnosis Safe UI (2-of-3 threshold),
   the CLI acts only on the database approval queue. Server shell access is restricted
   strictly to authenticated institutional infrastructure staff (Task 68 SSH hardening
   acts as the compensating control). Phase 2 introduces HTTP endpoints under Task 29's
   admin plane with signed Keycloak JWT bearer authentication.
2. ABSENCE OF SIGNING CAPABILITY:
   This CLI cannot construct, sign, or broadcast blockchain transactions. It records
   the receipt of off-chain execution (`tx_hash`) and queries read-only status.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Awaitable, Callable, Sequence

import asyncpg  # type: ignore[import-untyped]

from fluxpay.config import get_settings
from fluxpay.shared.logging import get_logger
from fluxpay.treasury.payouts import (
    EXIT_OK,
    EXIT_OPS_FAILURE,
    PayoutService,
    custody_snapshot,
)
from fluxpay.treasury.reader import OnChainReader, TxStatus

logger = get_logger("fluxpay.treasury.cli")

__all__ = [
    "build_parser",
    "main",
    "run_cli",
]


class _DefaultCliReader:
    """Read-only blockchain stub for Phase 1 CLI commands before Task 50 RPC wiring."""

    async def read_hot_balance(self, rail: str) -> int:
        return 0

    async def read_cold_balance(self, rail: str) -> int:
        return 0

    async def get_tx_status(self, rail: str, tx_hash: str) -> TxStatus:
        return TxStatus(confirmed=False, confirmations=0)


def build_parser() -> argparse.ArgumentParser:
    """Construct top-level CLI argument parser and subcommands."""
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--json", action="store_true", help="Format output as JSON")

    parser = argparse.ArgumentParser(
        prog="fluxpay.treasury.cli",
        description="Institutional Treasury Cold Payout Management CLI",
        parents=[common_parser],
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommand to execute")

    # 1. list-open
    p_list = subparsers.add_parser(
        "list-open", parents=[common_parser], help="List open payout queue items"
    )
    p_list.add_argument("--limit", type=int, default=50, help="Maximum items to return (1-200)")

    # 2. request
    p_req = subparsers.add_parser(
        "request", parents=[common_parser], help="Request a new cold payout"
    )
    p_req.add_argument("--to-address", required=True, help="Target EVM address (0x...)")
    p_req.add_argument("--amount-minor", type=int, required=True, help="Amount in minor units")
    p_req.add_argument("--rail", default="base_usdc", help="Target rail (default: base_usdc)")
    p_req.add_argument("--currency", default="USDC", help="Currency code (default: USDC)")
    p_req.add_argument(
        "--reason",
        choices=["surplus_sweep", "operational", "rebalance"],
        default="operational",
        help="Payout reason category",
    )
    p_req.add_argument("--requested-by-sub", default="admin_cli", help="Requester identifier")

    # 3. vote
    p_vote = subparsers.add_parser(
        "vote", parents=[common_parser], help="Cast approval or rejection vote"
    )
    p_vote.add_argument("--payout-id", required=True, help="Payout UUID")
    p_vote.add_argument("--voter-sub", required=True, help="Keycloak subject of voter")
    p_vote.add_argument("--voter-role", default="admin", help="Role of voter (must be admin)")
    p_vote.add_argument(
        "--vote", choices=["approve", "reject"], required=True, help="Vote decision"
    )
    p_vote.add_argument("--note", default="", help="Optional audit rationale context")

    # 4. record
    p_rec = subparsers.add_parser(
        "record", parents=[common_parser], help="Record on-chain multisig execution receipt"
    )
    p_rec.add_argument("--payout-id", required=True, help="Payout UUID")
    p_rec.add_argument("--tx-hash", required=True, help="On-chain tx hash (0x + 64 hex)")
    p_rec.add_argument("--recorded-by-sub", default="admin_cli", help="Operator identifier")

    # 5. confirm
    p_conf = subparsers.add_parser(
        "confirm", parents=[common_parser], help="Attempt confirmation via OnChainReader"
    )
    p_conf.add_argument("--payout-id", required=True, help="Payout UUID")

    # 6. snapshot
    p_snap = subparsers.add_parser(
        "snapshot", parents=[common_parser], help="Capture custody reconciliation snapshot"
    )
    p_snap.add_argument("--rail", default="base_usdc", help="Rail identifier (default: base_usdc)")

    return parser


async def run_cli(
    args_list: Sequence[str] | None = None,
    pool: asyncpg.Pool | None = None,
    reader: OnChainReader | None = None,
    alert: Callable[[str], Awaitable[None]] | None = None,
) -> int:
    """Execute parsed CLI command against PayoutService and output results."""
    parser = build_parser()
    try:
        args = parser.parse_args(args_list)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1

    pool_created_here = False
    if pool is None:
        try:
            settings = get_settings()
            pool = await asyncpg.create_pool(
                settings.pg_dsn,
                min_size=1,
                max_size=2,
                server_settings={"TimeZone": "UTC"},
                command_timeout=30.0,
            )
            pool_created_here = True
        except Exception as exc:
            msg = f"Operational failure: database pool creation failed: {exc}"
            if getattr(args, "json", False):
                sys.stdout.write(json.dumps({"error": msg}) + "\n")
            else:
                sys.stderr.write(msg + "\n")
            return EXIT_OPS_FAILURE

    try:
        active_reader: OnChainReader = reader if reader is not None else _DefaultCliReader()

        async def _cli_alert(m: str) -> None:
            if alert is not None:
                res = alert(m)
                if asyncio.iscoroutine(res):
                    await res
            else:
                logger.info("treasury_cli_alert", message=m)

        service = PayoutService(pool=pool, reader=active_reader, alert=_cli_alert)

        if args.command == "list-open":
            payouts = await service.list_open(limit=args.limit)
            if args.json:
                sys.stdout.write(json.dumps([p.to_dict() for p in payouts]) + "\n")
            else:
                if not payouts:
                    sys.stdout.write("No open payouts found.\n")
                else:
                    sys.stdout.write(f"OPEN PAYOUTS ({len(payouts)}):\n")
                    for p in payouts:
                        sys.stdout.write(
                            f" - {p.payout_id} [{p.status.upper()}] rail={p.rail} "
                            f"amount={p.amount_minor} {p.currency} to={p.to_address} "
                            f"(votes: {p.votes_for} approve, {p.votes_against} reject)\n"
                        )
            return EXIT_OK

        elif args.command == "request":
            record = await service.request(
                rail=args.rail,
                to_address=args.to_address,
                amount_minor=args.amount_minor,
                currency=args.currency,
                reason=args.reason,
                requested_by_sub=args.requested_by_sub,
            )
            if args.json:
                sys.stdout.write(json.dumps(record.to_dict()) + "\n")
            else:
                sys.stdout.write(
                    f"Payout requested: id={record.payout_id} status={record.status} "
                    f"amount={record.amount_minor} {record.currency}\n"
                )
            return EXIT_OK

        elif args.command == "vote":
            outcome = await service.vote(
                payout_id=args.payout_id,
                voter_sub=args.voter_sub,
                voter_role=args.voter_role,
                vote=args.vote,
                note=args.note,
            )
            if args.json:
                sys.stdout.write(json.dumps(outcome.to_dict()) + "\n")
            else:
                sys.stdout.write(
                    f"Vote recorded: status={outcome.status} "
                    f"(votes: {outcome.votes_for} approve, {outcome.votes_against} reject)\n"
                )
            return EXIT_OK

        elif args.command == "record":
            record = await service.record_execution(
                payout_id=args.payout_id,
                tx_hash=args.tx_hash,
                recorded_by_sub=args.recorded_by_sub,
            )
            if args.json:
                sys.stdout.write(json.dumps(record.to_dict()) + "\n")
            else:
                sys.stdout.write(
                    f"Execution recorded: id={record.payout_id} tx_hash={record.tx_hash} "
                    f"status={record.status}\n"
                )
            return EXIT_OK

        elif args.command == "confirm":
            confirmed_record = await service.confirm_if_ready(payout_id=args.payout_id)
            if confirmed_record is None:
                if args.json:
                    payload = {"confirmed": False, "payout_id": args.payout_id}
                    sys.stdout.write(json.dumps(payload) + "\n")
                else:
                    sys.stdout.write(f"Payout {args.payout_id} is not confirmed on-chain yet.\n")
            else:
                if args.json:
                    sys.stdout.write(json.dumps(confirmed_record.to_dict()) + "\n")
                else:
                    sys.stdout.write(
                        f"Payout confirmed: id={confirmed_record.payout_id} "
                        f"status={confirmed_record.status} "
                        f"confirmed_at={confirmed_record.confirmed_at}\n"
                    )
            return EXIT_OK

        elif args.command == "snapshot":
            snap = await custody_snapshot(pool=pool, reader=active_reader, rail=args.rail)
            if args.json:
                sys.stdout.write(json.dumps(snap.to_dict()) + "\n")
            else:
                sys.stdout.write(
                    f"CUSTODY SNAPSHOT ({snap.rail}) at {snap.captured_at.isoformat()}:\n"
                    f" - Hot Wallet: cache={snap.hot_cache} truth={snap.hot_truth} "
                    f"drift={snap.hot_drift}\n"
                    f" - Cold Vault: cache={snap.cold_cache} truth={snap.cold_truth} "
                    f"drift={snap.cold_drift}\n"
                    f" - In-Flight Total: {snap.in_flight_total} minor units\n"
                    f" - Oldest In-Flight Payouts: {len(snap.oldest_in_flight)} items\n"
                )
            return EXIT_OK

        return EXIT_OK
    except Exception as exc:
        msg = f"Operational failure: {exc.__class__.__name__}: {exc}"
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps({"error": msg}) + "\n")
        else:
            sys.stderr.write(msg + "\n")
        return EXIT_OPS_FAILURE
    finally:
        if pool_created_here and pool is not None:
            await pool.close()


async def main() -> int:
    """Async main wrapper executing sys.argv."""
    return await run_cli(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
