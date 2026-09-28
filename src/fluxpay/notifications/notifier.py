"""Task 42's AdminNotifier Protocol — live implementation (Task 43).

==============================================================================
MUTE-VS-CRY-WOLF DOCTRINE
==============================================================================
Payment infrastructure notification systems fail in two opposite directions:

MUTE (silent failure): The 3 AM on-call engineer learns about the hold
  backlog from a merchant complaint. The notification channel errored silently,
  the alert never arrived, the hold sat for 12 hours.

CRY WOLF (alert fatigue): Every routine operation fires an alert. After 200
  "hold processed" pings in a shift, the SEV1 about a stalled queue buries
  under the noise. The engineer starts ignoring all alerts.

This module targets the deliberately narrow middle: admin notifications are
FEW and LOUD. The hold lifecycle (pending/settled/rejected) is the operational
event that requires a human to act or confirm action. That is the only category
wired here. Future SEV escalations route through the same TelegramChannel
transport (Task 70's alert router), but are a separate concern.

FAIL-CLOSED-TO-RECORD: When a channel raises NotificationFailed, we do NOT
propagate the exception to the caller. The calling code (ApprovalService,
ApprovalsWorker) has already committed the hold state transition. Raising
from the notifier would crash the caller's post-commit phase and potentially
leave the hold state inconsistent with the notification state. Instead, we
write a notification_failures row. The sweep worker re-dispatches every 15
minutes. A missed notification is ALWAYS a row, NEVER silence.

WHY NO BUS FOR ADMIN NOTICES (per Task 42 decision):
  The AdminNotifier Protocol is synchronous at the application level (async,
  but direct call — not via broker). Admin notices are FEW: one per hold
  lifecycle event (pending, settled, rejected). A message bus introduces
  broker availability as a dependency for operational safety. If the broker
  is down, the admin alert is also down — defeating the purpose. Direct HTTP
  with a DB failure ledger is simpler, observable, and broker-independent.

==============================================================================
PHASE 1 MERCHANT EMAIL HONESTY NOTE
==============================================================================
Phase 1 schema (Task 26/29): merchants have no email column. KYC decision
emails to merchants are therefore a PHASE 2 product decision requiring:
  1. A schema migration adding merchants.email (or a contacts table).
  2. A product decision on consent and unsubscribe flows.
  3. A regulatory review for payment notification content.

For Phase 1, merchant communications = dashboard-only (Task 62). The
EmailChannel ships as proven infrastructure for future USER-facing system
emails (admin invites, etc.) and is fully tested. KYC email is documented
here as a deliberate gap, not hacked around with admin email as a proxy.

==============================================================================
LOGGING STUB (LoggingAdminNotifier)
==============================================================================
When telegram_bot_token is None (local dev, CI without bot), the composition
root in main.py selects LoggingAdminNotifier. This notifier logs at INFO via
structlog and makes zero HTTP calls. Local developer runs see all notification
events in structured logs without needing a real Telegram bot, while the
behavior contract (log per event) is testable with caplog.

This replaces Task 42's informal LoggingAdminNotifier stub (defined in
service.py for the tests there). Both classes implement AdminNotifier Protocol.
Task 42's class is preserved in service.py for backward compatibility; this
file provides the canonical production-composition notifier selection.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import asyncpg  # type: ignore[import-untyped]

from fluxpay.approvals.service import AdminNotifier
from fluxpay.notifications.channels import NotificationFailed, TelegramChannel
from fluxpay.notifications.records import record_failure_pool
from fluxpay.risk.quarantine import HoldRecord
from fluxpay.shared.logging import get_logger

__all__ = [
    "AdminNotifier",
    "LoggingAdminNotifier",
    "LoggingStubNotifier",
    "TelegramAdminNotifier",
    "format_hold_pending",
    "format_hold_rejected",
    "format_hold_settled",
]

logger = get_logger("fluxpay.notifications.notifier")


# ==============================================================================
# PURE FORMATTER FUNCTIONS (module-level, unit-tested, frozen)
# ==============================================================================
# WHY module-level pure functions instead of methods:
#   - Testable in complete isolation without constructing notifier objects.
#   - Output format is the content specification for Task 62's dashboard display.
#   - Frozen: Telegram triage depends on stable message layout. Layout changes
#     require test updates (KAT-style literal comparison) to prevent accidental
#     regression.
#   - WHY EMOJI: Visual triage at 3 AM. A green check vs. red X is instantly
#     classifiable without reading the full message. Emoji are Unicode; they
#     work in plaintext Telegram without parse_mode.
# ==============================================================================


def format_hold_pending(hold: HoldRecord) -> str:
    """Format a LOUD operator alert for a hold awaiting human approval.

    Layout is frozen — changes must be accompanied by test literal updates.
    This is the message that reaches an admin's phone at 3 AM.
    """
    return (
        f"🚨 HOLD pending approval\n"
        f"id: {hold.hold_id}\n"
        f"agent: {hold.agent_id}\n"
        f"amount: {hold.amount_minor} {hold.currency}\n"
        f"reason: {hold.reason}\n"
        f"Approve: dashboard → admin/holds (Task 62)"
    )


def format_hold_settled(hold: HoldRecord, tx_id: Any) -> str:
    """Format a calm confirmation that a hold was approved and settled."""
    return (
        f"✅ HOLD settled\n"
        f"id: {hold.hold_id}\n"
        f"agent: {hold.agent_id}\n"
        f"amount: {hold.amount_minor} {hold.currency}\n"
        f"tx_id: {tx_id}"
    )


def format_hold_rejected(hold: HoldRecord) -> str:
    """Format a calm confirmation that a hold was rejected."""
    return (
        f"❌ HOLD rejected\n"
        f"id: {hold.hold_id}\n"
        f"agent: {hold.agent_id}\n"
        f"amount: {hold.amount_minor} {hold.currency}\n"
        f"reason: {hold.reason}"
    )


# ==============================================================================
# LIVE IMPLEMENTATION (Task 42's Protocol)
# ==============================================================================


class TelegramAdminNotifier:
    """Production AdminNotifier: routes hold lifecycle alerts via TelegramChannel.

    Implements the AdminNotifier Protocol from fluxpay.approvals.service.

    Failure discipline (fail-closed-to-record):
      On NotificationFailed, we record to notification_failures via the pool
      rather than raising. The caller (ApprovalService or ApprovalsWorker)
      has already committed the hold state transition. Raising would crash
      the post-commit phase. The sweep worker re-dispatches. A missed alert
      is ALWAYS a row, NEVER silence. See module docstring.
    """

    def __init__(
        self,
        channel: TelegramChannel,
        pool: asyncpg.Pool,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._channel = channel
        self._pool = pool
        self._now = now

    async def notify_hold_pending(self, hold: HoldRecord) -> None:
        """Alert operators that a payment hold requires review (LOUD path)."""
        text = format_hold_pending(hold)
        await self._dispatch(
            text=text,
            purpose="hold.pending",
            hold=hold,
        )

    async def notify_hold_settled(self, hold: HoldRecord, outcome: Any) -> None:
        """Confirm to operators that a hold was approved and settled."""
        tx_id = getattr(outcome, "tx_id", str(outcome))
        text = format_hold_settled(hold, tx_id)
        await self._dispatch(
            text=text,
            purpose="hold.settled",
            hold=hold,
        )

    async def notify_hold_rejected(self, hold: HoldRecord, outcome: Any) -> None:
        """Confirm to operators that a hold was rejected."""
        text = format_hold_rejected(hold)
        await self._dispatch(
            text=text,
            purpose="hold.rejected",
            hold=hold,
        )

    async def _dispatch(self, *, text: str, purpose: str, hold: HoldRecord) -> None:
        """Send via channel; on NotificationFailed record to failure ledger."""
        try:
            await self._channel.send(text)
            logger.info(
                "admin_notifier_sent",
                purpose=purpose,
                hold_id=str(hold.hold_id),
            )
        except NotificationFailed as exc:
            defect_class = str(exc).split(" ")[0] if str(exc) else "notification_failed"
            logger.error(
                "admin_notifier_failed_recording",
                purpose=purpose,
                hold_id=str(hold.hold_id),
                defect_class=defect_class,
            )
            # Fail-closed-to-record: missing alert → DB row, not silence
            await record_failure_pool(
                self._pool,
                channel="telegram",
                subject=self._channel.chat_id,
                purpose=purpose,
                payload={
                    "hold_id": str(hold.hold_id),
                    "agent_id": str(hold.agent_id),
                    "amount_minor": hold.amount_minor,
                    "currency": hold.currency,
                    "reason": hold.reason,
                    "purpose": purpose,
                    "text": text,
                },
                error=defect_class,
            )


# ==============================================================================
# LOGGING STUB (disabled-mode / local dev)
# ==============================================================================


class LoggingStubNotifier:
    """Formal logging stub for AdminNotifier — used when Telegram is not configured.

    Implements AdminNotifier Protocol. Selected by the composition root in
    main.py when settings.telegram_bot_token is None. Logs at INFO via
    structlog so local developer runs see all notification events in structured
    logs without needing a real Telegram bot. Zero HTTP calls.

    WHY formal: Task 42 defined an informal stub inside service.py for tests.
    This class is the production-composition-root stub, also re-exported from
    fluxpay.approvals.service for backward compatibility (the import alias there
    is a 1-line re-export, marked).
    """

    async def notify_hold_pending(self, hold: HoldRecord) -> None:
        logger.info(
            "admin_notify_hold_pending",
            hold_id=str(hold.hold_id),
            agent_id=str(hold.agent_id),
            amount_minor=hold.amount_minor,
            currency=hold.currency,
            reason=hold.reason,
        )

    async def notify_hold_settled(self, hold: HoldRecord, outcome: Any) -> None:
        logger.info(
            "admin_notify_hold_settled",
            hold_id=str(hold.hold_id),
            agent_id=str(hold.agent_id),
            outcome=str(outcome),
        )

    async def notify_hold_rejected(self, hold: HoldRecord, outcome: Any) -> None:
        logger.info(
            "admin_notify_hold_rejected",
            hold_id=str(hold.hold_id),
            agent_id=str(hold.agent_id),
            reason=hold.reason,
        )


# Task 42 compatibility re-export
LoggingAdminNotifier = LoggingStubNotifier

# Verify both classes satisfy the AdminNotifier protocol by duck-typing at import time.
# (AdminNotifier Protocol is not @runtime_checkable; check for required method names instead.)
_REQUIRED_METHODS = ("notify_hold_pending", "notify_hold_settled", "notify_hold_rejected")
for _cls in (TelegramAdminNotifier, LoggingStubNotifier):
    for _meth in _REQUIRED_METHODS:
        if not hasattr(_cls, _meth):
            raise TypeError(f"{_cls.__name__} missing AdminNotifier method: {_meth}")
