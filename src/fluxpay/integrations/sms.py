"""Twilio SMS integration stub (Block J, Task 55/56 consolidation).

==============================================================================
A2P 10DLC REGISTRATION ECONOMICS & THE REAL BLOCKER FOR FINTECH SMS
==============================================================================
In modern financial infrastructure, sending outbound transactional or security SMS
messages (2FA, fraud holds, payout OTPs) is not a simple HTTP POST to an aggregator.
The true bottleneck is carrier regulation and compliance economics:

1. A2P 10DLC (Application-to-Person 10-Digit Long Code) Registration:
   Major US and global carriers (AT&T, Verizon, T-Mobile via The Campaign Registry)
   mandate formal brand registration (EIN/tax ID verification, company officer KYC)
   and Campaign Vetting before any machine-sent SMS will be delivered. Unregistered
   traffic faces 100% carrier filtering and aggressive monetary penalties.

2. Campaign Vetting & Carrier Surcharges:
   Fintech OTP/security alert campaigns require strict opt-in / opt-out proof
   (STOP/HELP handling), privacy policy disclosures, and carrier per-message pass-through
   surcharges that alter unit economics compared to push/email channels.

3. International Fraud & Toll Fraud (Artificially Inflated Traffic / AIT):
   SMS verification numbers in high-risk jurisdictions require risk pre-scoring
   (Twilio Lookup / Verify API) to prevent botnets from burning carrier SMS balances.

4. Task 43 Channel Pattern as Future Home:
   When live SMS routing is enabled in Phase 2, Twilio will be wired as a channel
   in `fluxpay.notifications.channels` conforming to the NotificationChannel contract,
   mirroring the live Telegram and SendGrid channels built in Task 43.
"""

from __future__ import annotations

from typing import Any

from fluxpay.shared.logging import get_logger

__all__ = ["TwilioSmsStub"]

logger = get_logger("fluxpay.integrations.sms")


class TwilioSmsStub:
    """Phase 2 Twilio SMS channel stub.

    Healthcheck returns False and send raises NotImplementedError with
    comprehensive flow documentation.
    """

    def __init__(
        self,
        *,
        account_sid: str | None = None,
        auth_token: str | None = None,
        from_number: str | None = None,
    ) -> None:
        self._account_sid = account_sid
        self._auth_token = auth_token
        self._from_number = from_number

    async def healthcheck(self) -> bool:
        """Twilio SMS is a Phase 2 stub; always returns False."""
        return False

    async def send(self, *args: Any, **kwargs: Any) -> None:
        """Outbound SMS delivery is not activated in Phase 1.

        Raises:
            NotImplementedError: detailing A2P 10DLC registration requirements
                                 and referencing Task 43 channel pattern.
        """
        raise NotImplementedError(
            "Twilio SMS is not active in Phase 1. Delivery requires A2P 10DLC "
            "brand registration, campaign vetting with The Campaign Registry, "
            "and carrier pass-through configuration. See Task 43 channel pattern "
            "(fluxpay.notifications.channels) for future live wiring."
        )
