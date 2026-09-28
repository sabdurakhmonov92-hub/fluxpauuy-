"""Manual KYC verification provider adapter (Block J, Task 55).

==============================================================================
THE MANUAL MODE ESSAY: FIRST-CLASS CITIZEN, NOT A MISSING FEATURE
==============================================================================
In Phase 1, automated external provider verification may be disabled or unconfigured
in staging, local dev, or regulated environments where compliance officers manually
inspect corporate registry filings and passport certified translations.

ManualProvider makes this Phase 1 human-decided workflow a FIRST-CLASS CITIZEN.

WHY A CLASS, NOT AN IF-BRANCH:
If manual mode were an `if provider == 'manual'` branch inside the orchestrator or
router, every future service, worker, and dashboard controller would be polluted
with conditional branching. By implementing the identical `KycProvider` protocol:
1. The `KycOrchestrator` remains completely provider-blind forever.
2. The merchant registration lifecycle never branches on provider type.
3. Swapping from manual mode to Sumsub or Trulioo is purely a CONFIGURATION CHANGE,
   never a code change.

THE AUTHORITY TRUTH:
The manual review process is healthy by definition (healthcheck() -> True) because
the administrative operator IS the engine. Verification requests remain 'pending'
until an authorized admin principal explicitly approves or rejects the record
via Task 29's `/admin/kyc/{id}/decide` endpoint.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fluxpay.integrations.kyc.protocol import KycState, VerificationStart

__all__ = ["ManualProvider"]


class ManualProvider:
    """Zero-I/O manual KYC provider.

    Satisfies KycProvider protocol without making any network calls or requiring
    external API credentials.
    """

    async def start_verification(self, *, subject_ref: str) -> VerificationStart:
        """Start manual verification session.

        Returns our own subject_ref (kyc_request row ID) as provider reference.
        No hosted redirect URL exists for manual review.
        """
        return VerificationStart(ref=subject_ref, redirect_url=None)

    async def fetch_status(self, ref: str) -> KycState:
        """Fetch manual status.

        Always returns 'pending' forever until an admin decides the request
        via Task 29's decide endpoint.
        """
        return KycState(status="pending", raw={})

    def verify_webhook(
        self, *, payload: bytes, headers: Mapping[str, str]
    ) -> dict[str, Any] | None:
        """Manual mode receives no external webhooks."""
        return None

    async def healthcheck(self) -> bool:
        """Manual verification engine is always healthy (admin is the engine)."""
        return True
