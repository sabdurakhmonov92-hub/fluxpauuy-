"""Treasury hot wallet monitor: One-shot custody observation and threshold engine.

Blueprint §8: Hot wallet monitoring, threshold evaluation, and surplus sweep proposing.

DESIGN LAWS & ARCHITECTURAL DISCIPLINE:
--------------------------------------
1. THE OBSERVE-PROPOSE LAW:
   The server that can MOVE money is the server that WILL lose it.
   This worker OBSERVES on-chain hot and cold balances and PROPOSES actions.
   Top-up conditions trigger administrative alerts so humans can fund the hot
   wallet from cold storage. Surplus balances create rows in the `cold_payouts`
   queue (`reason='surplus_sweep'`). Execution of cold payouts is strictly
   reserved for human administrators behind a Gnosis Safe 2-of-3 multisig.
   Every automation ends at an alert or a queue record — never at a broadcasted
   transfer.

2. THE NO-KEYS META-GUARD:
   The server holds zero credentials capable of signing or executing on-chain
   transactions. No seed phrases, no signing credentials, and no direct transaction
   broadcast interfaces exist within this codebase. Even in the event of complete
   host takeover, the attacker cannot drain custody assets.

3. CONTROL-SYSTEMS HYSTERESIS:
   When hot wallet balance breaches `high_water_minor`, the surplus sweep amount
   is calculated to sweep to the MIDPOINT between `low_water_minor` and
   `high_water_minor`:
       sweep_amount = hot_balance - ((low_water + high_water) // 2)
   WHY MIDPOINT: Sweeping only to `high_water_minor` leaves the balance resting
   precisely on the trigger threshold. Any subsequent micro-inflow would re-trigger
   the sweep proposal immediately. Sweeping to midpoint leaves symmetric headroom
   below the ceiling and above the floor, dampening oscillation (control-systems
   hysteresis).

4. ACTIVE-SWEEP IDEMPOTENCY GUARD:
   If a non-terminal sweep request already exists in `cold_payouts` for the rail
   (`status NOT IN ('confirmed', 'rejected')`), no new payout request is created.
   Hysteresis prevents immediate re-triggering, while the active-sweep check
   guarantees that pending human approvals block duplicate payout proposals.
   Once confirmed or rejected, subsequent runs are unblocked if the balance
   remains above the high-water mark.

5. TOP-UP RESTORATION POLICY:
   When hot wallet balance drops below `low_water_minor`, the suggested top-up
   restores the balance to twice the low-water mark:
       suggested_topup = (low_water * 2) - hot_balance
   This ensures that the hot wallet receives sufficient operational headroom
   to service anticipated outbound settlement volume without repeated alarms.

6. ONE-SHOT MONITOR VS. DAEMON:
   Following Task 40's precedent, hot wallet monitoring runs as a periodic
   one-shot process managed by a systemd timer (15-minute cadence).
   It avoids holding long-lived idle daemon processes in memory while ensuring
   timely alerts.

7. SPEAKING CONTRACT & EXIT TAXONOMY SPLIT:
   Every successful run emits exactly ONE single-line JSON report to stdout
   with mode="treasury_monitor".
   EXIT CODE 0: The machine ran and completed its check, regardless of verdict
   (healthy, top-up required, sweep due, or reader error). Alerts handle money
   and operational policy conditions.
   EXIT CODE 2: Operational failure (database unreachable, configuration error,
   or unhandled exception). Systemd failure hooks alert on process death.
   Task 40's exit 1 (chain broken) belongs to the cryptographic integrity domain;
   in the treasury domain, threshold breaches are operational policy conditions,
   not software defects.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal
from urllib.parse import urlsplit
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import httpx

from fluxpay.config import get_settings
from fluxpay.notifications.channels import TelegramChannel
from fluxpay.notifications.records import record_failure_pool
from fluxpay.shared.logging import get_logger
from fluxpay.treasury.reader import OnChainReader, TxStatus

__all__ = [
    "EXIT_OK",
    "EXIT_OPS_FAILURE",
    "HotWalletMonitor",
    "MonitorReport",
    "ThresholdVerdict",
    "build_report_line",
    "evaluate",
    "main",
    "map_exit_code",
]

logger = get_logger("fluxpay.treasury.monitor")

EXIT_OK: Final[int] = 0
EXIT_OPS_FAILURE: Final[int] = 2


@dataclass(frozen=True)
class ThresholdVerdict:
    """Outcome of pure threshold math against hot wallet balance."""

    action: Literal["ok", "topup_required", "sweep_due"]
    detail: str
    amount: int = 0


def evaluate(*, hot_balance: int, low: int, high: int) -> ThresholdVerdict:
    """Evaluate hot wallet balance against low- and high-water thresholds.

    Pure deterministic function with zero I/O.

    Rules:
    - high <= low: Invariant violation -> raises ValueError.
    - hot < low: topup_required, suggested = (low * 2) - hot.
    - hot > high: sweep_due, sweep = hot - ((low + high) // 2) (midpoint hysteresis).
    - hot == low: ok (strict < boundary).
    - hot == high: ok (strict > boundary).
    - low < hot < high: ok.
    """
    if high <= low:
        raise ValueError(
            f"high water threshold ({high}) must be strictly greater than "
            f"low water threshold ({low})"
        )

    if hot_balance < low:
        suggested = (low * 2) - hot_balance
        return ThresholdVerdict(
            action="topup_required",
            detail=f"hot balance {hot_balance} below low water {low}; suggested topup: {suggested}",
            amount=suggested,
        )

    if hot_balance > high:
        midpoint = (low + high) // 2
        sweep_amount = hot_balance - midpoint
        return ThresholdVerdict(
            action="sweep_due",
            detail=(
                f"hot balance {hot_balance} exceeds high water {high}; sweep amount: {sweep_amount}"
            ),
            amount=sweep_amount,
        )

    return ThresholdVerdict(
        action="ok",
        detail=f"hot balance {hot_balance} within operational thresholds [{low}, {high}]",
        amount=0,
    )


@dataclass(frozen=True)
class MonitorReport:
    """Structured report returned by a single monitoring run."""

    rail: str
    hot_balance: int
    cold_balance: int
    verdict: ThresholdVerdict
    synced: bool
    alerted: bool
    sweep_request_id: UUID | None


class HotWalletMonitor:
    """One-shot custody observation engine."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        reader: OnChainReader,
        alert: Callable[[str], Awaitable[None]],
        now: Callable[[], float] = time.time,
        rail: str = "base_usdc",
    ) -> None:
        self._pool = pool
        self._reader = reader
        self._alert = alert
        self._now = now
        self._rail = rail

    async def _send_alert(self, msg: str) -> None:
        """Deliver alert via transport; record failure on error (Task 43 discipline)."""
        try:
            await self._alert(msg)
        except Exception as exc:
            logger.error("treasury_alert_dispatch_failed", error=str(exc), message=msg)
            try:
                await record_failure_pool(
                    self._pool,
                    channel="telegram",
                    subject="treasury_admin",
                    purpose="treasury.alert",
                    payload={"message": msg, "rail": self._rail},
                    error=exc.__class__.__name__,
                )
            except Exception as rec_err:
                logger.error("treasury_failure_record_failed", error=str(rec_err))

    async def run_once(self) -> MonitorReport:
        """Execute one complete observation and threshold evaluation cycle."""
        current_ts = self._now()
        current_dt = datetime.fromtimestamp(current_ts, tz=UTC)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT hot_address, cold_address, hot_balance_minor, cold_balance_minor,
                       low_water_minor, high_water_minor, last_synced_at, sync_status
                FROM wallet_state
                WHERE rail = $1;
                """,
                self._rail,
            )
            if row is None:
                raise RuntimeError(f"No wallet_state row configured for rail '{self._rail}'")

            cold_address = row["cold_address"]
            low_water = row["low_water_minor"]
            high_water = row["high_water_minor"]
            prev_synced_at = row["last_synced_at"]

            # Staleness guard: check if previous sync was over 30 minutes ago (or never)
            was_stale = (
                prev_synced_at is None or (current_dt - prev_synced_at).total_seconds() > 1800
            )

            # Step 1: Read balances from on-chain reader
            synced = False
            alerted = False
            sweep_request_id: UUID | None = None

            try:
                hot_balance = await self._reader.read_hot_balance(self._rail)
                cold_balance = await self._reader.read_cold_balance(self._rail)
                synced = True
            except Exception as exc:
                logger.warning("on_chain_reader_sync_failed", rail=self._rail, error=str(exc))
                # Observation fail-open: update sync_status to reader_error
                await conn.execute(
                    """
                    UPDATE wallet_state
                    SET sync_status = 'reader_error',
                        updated_at = $2
                    WHERE rail = $1;
                    """,
                    self._rail,
                    current_dt,
                )
                await self._send_alert(f"wallet sync FAILED ({self._rail}): {exc}")
                alerted = True

                if was_stale:
                    await self._send_alert(
                        f"custody data STALE — decisions unreliable ({self._rail})"
                    )

                return MonitorReport(
                    rail=self._rail,
                    hot_balance=row["hot_balance_minor"],
                    cold_balance=row["cold_balance_minor"],
                    verdict=ThresholdVerdict(
                        action="ok",
                        detail=f"wallet sync failed for {self._rail}; observation fail-open",
                        amount=0,
                    ),
                    synced=False,
                    alerted=alerted,
                    sweep_request_id=None,
                )

            # Step 2: Update cached balances upon successful sync
            await conn.execute(
                """
                UPDATE wallet_state
                SET hot_balance_minor = $1,
                    cold_balance_minor = $2,
                    last_synced_at = $3,
                    sync_status = 'ok',
                    updated_at = $3
                WHERE rail = $4;
                """,
                hot_balance,
                cold_balance,
                current_dt,
                self._rail,
            )

            # Step 3: Threshold evaluation
            verdict = evaluate(hot_balance=hot_balance, low=low_water, high=high_water)

            if verdict.action == "topup_required":
                msg = (
                    f"hot wallet topup required on rail {self._rail}: "
                    f"current balance {hot_balance}, low water {low_water}, "
                    f"suggested topup {verdict.amount}"
                )
                await self._send_alert(msg)
                alerted = True

            elif verdict.action == "sweep_due":
                # Check for active non-terminal sweep
                active_sweep_id = await conn.fetchval(
                    """
                    SELECT payout_id
                    FROM cold_payouts
                    WHERE rail = $1
                      AND reason = 'surplus_sweep'
                      AND status NOT IN ('confirmed', 'rejected')
                    LIMIT 1;
                    """,
                    self._rail,
                )

                if active_sweep_id is not None:
                    sweep_request_id = active_sweep_id
                    # Idempotent suppression: an active proposal is already in flight
                else:
                    new_payout_id = await conn.fetchval(
                        """
                        INSERT INTO cold_payouts (
                            rail, to_address, amount_minor, currency,
                            reason, status, requested_by_sub
                        ) VALUES (
                            $1, $2, $3, 'USDC', 'surplus_sweep', 'requested', 'system'
                        ) RETURNING payout_id;
                        """,
                        self._rail,
                        cold_address,
                        verdict.amount,
                    )
                    sweep_request_id = new_payout_id
                    await self._send_alert(
                        f"sweep request CREATED (needs 2 approvals): "
                        f"payout_id={new_payout_id}, rail={self._rail}, amount={verdict.amount}"
                    )
                    alerted = True

            return MonitorReport(
                rail=self._rail,
                hot_balance=hot_balance,
                cold_balance=cold_balance,
                verdict=verdict,
                synced=synced,
                alerted=alerted,
                sweep_request_id=sweep_request_id,
            )


def build_report_line(
    report: MonitorReport,
    elapsed_ms: int,
    now: datetime | None = None,
) -> str:
    """Format single-line JSON report for Loki and operational ingestion."""
    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    else:
        now = now.astimezone(UTC)

    checked_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "mode": "treasury_monitor",
        "rail": report.rail,
        "hot_balance": report.hot_balance,
        "cold_balance": report.cold_balance,
        "verdict": report.verdict.action,
        "sweep_request_id": str(report.sweep_request_id) if report.sweep_request_id else None,
        "synced": report.synced,
        "alerted": report.alerted,
        "checked_at": checked_at,
        "elapsed_ms": elapsed_ms,
    }
    return json.dumps(payload, separators=(",", ":"))


def map_exit_code(
    report: MonitorReport | None = None,
    error: type[BaseException] | BaseException | None = None,
) -> int:
    """Map monitoring outcome to operational process exit code.

    EXIT_OK (0): Monitor ran and completed its check. Alerts handle policy events.
    EXIT_OPS_FAILURE (2): Process or infrastructure failure (DB down, crash).
    """
    if error is not None or report is None:
        return EXIT_OPS_FAILURE
    return EXIT_OK


class _DefaultOnChainReader:
    """Default reader used when Task 50 on-chain RPC adapter is not yet wired."""

    async def read_hot_balance(self, rail: str) -> int:
        raise RuntimeError(f"On-chain reader not configured for rail '{rail}' (Task 50 seam)")

    async def read_cold_balance(self, rail: str) -> int:
        raise RuntimeError(f"On-chain reader not configured for rail '{rail}' (Task 50 seam)")

    async def get_tx_status(self, rail: str, tx_hash: str) -> TxStatus:
        raise RuntimeError(f"On-chain reader not configured for rail '{rail}' (Task 50 seam)")


async def main(
    pool: asyncpg.Pool | None = None,
    reader: OnChainReader | None = None,
    alert: Callable[[str], Awaitable[None]] | None = None,
    now: Callable[[], float] = time.time,
    rail: str = "base_usdc",
) -> int:
    """Entrypoint for the 15-minute treasury hot wallet monitor one-shot job."""
    start_time = time.perf_counter()
    pool_created_here = False

    if pool is None:
        try:
            settings = get_settings()
            parsed_dsn = urlsplit(settings.pg_dsn)
            db_host = parsed_dsn.hostname or "unknown"
            db_name = parsed_dsn.path.lstrip("/") or "unknown"
        except Exception as exc:
            sys.stderr.write(f"Configuration failure: {exc.__class__.__name__}: {exc}\n")
            sys.stderr.flush()
            return EXIT_OPS_FAILURE

        try:
            pool = await asyncpg.create_pool(
                settings.pg_dsn,
                min_size=1,
                max_size=2,
                server_settings={"TimeZone": "UTC"},
                command_timeout=30.0,
            )
            pool_created_here = True

            async with pool.acquire() as conn:
                tz = await conn.fetchval("SHOW timezone")
                if tz not in ("UTC", "Etc/UTC"):
                    raise RuntimeError(f"PostgreSQL connection timezone must be UTC, got '{tz}'")
        except Exception as exc:
            sys.stderr.write(
                f"Operational failure in treasury monitor (host='{db_host}', db='{db_name}'): "
                f"{exc.__class__.__name__}: {exc}\n"
            )
            sys.stderr.flush()
            return EXIT_OPS_FAILURE

    http_client: httpx.AsyncClient | None = None
    try:
        active_alert: Callable[[str], Awaitable[None]]
        if alert is not None:
            active_alert = alert
        else:
            settings = get_settings()
            if settings.telegram_bot_token and settings.telegram_admin_chat_id:
                http_client = httpx.AsyncClient()
                channel = TelegramChannel(
                    http_client,
                    bot_token=settings.telegram_bot_token,
                    chat_id=settings.telegram_admin_chat_id,
                    retry_max=settings.notification_retry_max,
                    backoff_base_s=settings.notification_backoff_base_s,
                )
                active_alert = channel.send
            else:

                async def _log_alert(msg: str) -> None:
                    logger.info("treasury_alert_emitted", alert_message=msg)

                active_alert = _log_alert

        active_reader: OnChainReader = reader if reader is not None else _DefaultOnChainReader()

        monitor = HotWalletMonitor(
            pool=pool,
            reader=active_reader,
            alert=active_alert,
            now=now,
            rail=rail,
        )
        report = await monitor.run_once()
        elapsed_s = time.perf_counter() - start_time
        elapsed_ms = max(0, round(elapsed_s * 1000))

        report_line = build_report_line(report, elapsed_ms)
        sys.stdout.write(report_line + "\n")
        sys.stdout.flush()

        code = map_exit_code(report)
        # --- Task 69 append ---
        from fluxpay.alerts.router import send_heartbeat

        send_heartbeat("treasury_monitor", ok=(code == 0))
        return code
    except Exception as exc:
        # --- Task 69 append ---
        from fluxpay.alerts.router import send_heartbeat

        send_heartbeat("treasury_monitor", ok=False, reason=str(exc))
        sys.stderr.write(f"Operational failure in treasury monitor run: {exc}\n")
        sys.stderr.flush()
        return EXIT_OPS_FAILURE
    finally:
        if http_client is not None:
            await http_client.aclose()
        if pool_created_here and pool is not None:
            await pool.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
