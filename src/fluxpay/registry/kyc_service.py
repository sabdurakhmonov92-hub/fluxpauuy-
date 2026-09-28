"""Provider-blind KYC orchestration service (Block J, Task 55).

==============================================================================
THE AUTHORITY LAW & ORCHESTRATION ARCHITECTURE
==============================================================================
The KYC orchestrator mediates between FluxPay's domain entity (`kyc_requests`)
and external compliance verification providers (`KycProvider`).

1. THE AUTHORITY LAW:
   The provider RECOMMENDS; the platform DECIDES.
   Automated verification responses from Sumsub or Trulioo never overwrite
   or modify `kyc_requests.status`. The decision authority remains strictly with
   Task 29's `/admin/kyc/{id}/decide` endpoint.

2. WHY ORCHESTRATOR PERSISTS NOTHING FROM PROVIDER RECOMMENDATIONS:
   When `sync_from_provider(kyc_request_id)` is invoked, the orchestrator queries
   the provider and returns `KycState` directly to the caller (e.g. Task 62's
   admin dashboard view). It does NOT write provider verdicts to the database:
   - Schema integrity: `kyc_requests` has no `provider_status` column (Task 26 frozen).
   - Traceability: When a compliance officer decides a request, they copy relevant
     provider context into `notes`. The resulting audit log records who decided and
     why, preserving a clean, human-anchored decision trail.

3. AUDIT ON START (TASK 29 DISCIPLINE):
   Initiating verification (`start()`) is an administrative action. It executes
   inside a Unit of Work and writes an audit row (`action='kyc.start'`, `target_type='kyc'`)
   mirroring Task 29's connection-parameter audit discipline.
"""

from __future__ import annotations

import uuid

import asyncpg  # type: ignore[import-untyped]

from fluxpay.audit import audit
from fluxpay.integrations.kyc.protocol import KycProvider, KycState, VerificationStart
from fluxpay.shared.errors import NotFoundError, ValidationError
from fluxpay.shared.logging import get_logger
from fluxpay.shared.uow import UnitOfWork

__all__ = ["KycOrchestrator"]

logger = get_logger("fluxpay.registry.kyc_service")


class KycOrchestrator:
    """Provider-blind KYC orchestrator coordinating verification sessions."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        providers: dict[str, KycProvider],
        default_provider: str = "manual",
    ) -> None:
        self._pool = pool
        self._providers = providers
        self._default_provider = default_provider

    async def start(
        self,
        kyc_request_id: uuid.UUID,
        *,
        provider: str | None = None,
        actor_sub: str = "admin",
        actor_role: str = "admin",
    ) -> VerificationStart:
        """Start a verification session for a pending KYC request.

        Args:
            kyc_request_id: The UUID of the pending kyc_requests record.
            provider: Optional override provider name ('manual', 'sumsub', 'trulioo').
                      Defaults to self._default_provider.
            actor_sub: Subject of admin principal initiating verification.
            actor_role: Role of admin principal.

        Returns:
            VerificationStart with provider ref and optional hosted redirect URL.

        Raises:
            ValidationError: If provider is unknown or verification was already started.
            NotFoundError: If kyc_request does not exist, is already decided, or
                           the subject merchant does not exist.
        """
        provider_name = provider or self._default_provider
        if provider_name not in self._providers:
            raise ValidationError(
                message=f"Unknown or unconfigured KYC provider: '{provider_name}'",
                details={"provider": provider_name},
            )

        provider_adapter = self._providers[provider_name]

        async with UnitOfWork(self._pool) as uow:
            # Row lock to prevent race conditions during start
            row = await uow.connection.fetchrow(
                """
                SELECT id, subject_type, subject_id, status, provider, provider_ref
                FROM kyc_requests
                WHERE id = $1
                FOR UPDATE;
                """,
                kyc_request_id,
            )

            if row is None:
                raise NotFoundError(message="KYC request not found.")

            if row["status"] != "pending":
                raise NotFoundError(message="KYC request not found or already decided.")

            # Double-start guard: reject if verification was already initiated
            if row["provider_ref"] != "":
                raise ValidationError(
                    message="KYC verification already started for this request.",
                    details={"kyc_id": str(kyc_request_id), "provider_ref": row["provider_ref"]},
                )

            # Check subject merchant exists
            merchant = await uow.connection.fetchrow(
                "SELECT id FROM merchants WHERE id = $1;",
                row["subject_id"],
            )
            if merchant is None:
                raise NotFoundError(message="Subject merchant not found.")

            # Call provider adapter to initiate verification
            start_result = await provider_adapter.start_verification(
                subject_ref=str(kyc_request_id)
            )

            # Update row with provider name and provider_ref
            updated = await uow.connection.fetchrow(
                """
                UPDATE kyc_requests
                SET provider = $1,
                    provider_ref = $2,
                    updated_at = now()
                WHERE id = $3 AND status = 'pending'
                RETURNING id;
                """,
                provider_name,
                start_result.ref,
                kyc_request_id,
            )
            if updated is None:
                raise NotFoundError(message="KYC request not found or already decided.")

            # Record audit row for the start action (Task 29 audit law)
            await audit.record(
                uow.connection,
                actor_sub=actor_sub,
                actor_role=actor_role,
                action="kyc.start",
                target_type="kyc",
                target_id=str(kyc_request_id),
                details={
                    "provider": provider_name,
                    "provider_ref": start_result.ref,
                },
            )

            return start_result

    async def sync_from_provider(self, kyc_request_id: uuid.UUID) -> KycState:
        """Fetch current verification status from the configured provider.

        THE AUTHORITY LAW:
        Returns provider KycState to the caller (e.g. admin dashboard).
        Leaves kyc_requests.status completely UNMODIFIED in the database.
        The platform admin remains the sole approval authority.

        Args:
            kyc_request_id: The UUID of the kyc_requests record.

        Returns:
            KycState containing provider normalized status and raw payload.

        Raises:
            NotFoundError: If kyc_request does not exist.
            ValidationError: If provider name on row is unknown.
        """
        async with UnitOfWork(self._pool) as uow:
            row = await uow.connection.fetchrow(
                """
                SELECT id, provider, provider_ref, status
                FROM kyc_requests
                WHERE id = $1;
                """,
                kyc_request_id,
            )

        if row is None:
            raise NotFoundError(message="KYC request not found.")

        provider_name = row["provider"]
        if provider_name not in self._providers:
            raise ValidationError(
                message=f"Unknown or unconfigured KYC provider: '{provider_name}'",
                details={"provider": provider_name},
            )

        provider_adapter = self._providers[provider_name]
        return await provider_adapter.fetch_status(row["provider_ref"])
