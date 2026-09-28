"""Fiat external rail stubs and capabilities metadata (Block J, Part 4 / Task 53).

==============================================================================
THE HONEST STUBS DOCTRINE
==============================================================================
A stub without an architectural flow document is technical debt that rots into
abandoned code. A stub with an architectural flow document is a binding contract
ready for immediate engineering execution when business priorities allocate capacity.

Traditional banking rails (SWIFT, SEPA, ACH) operate on fundamentally disparate
settlement horizons, clearing protocols, messaging standards (ISO 20022 vs NACHA),
and economic models compared to instant push-based crypto rails or unified merchant
gateways (Stripe). Rather than feigning partial implementation or generating empty
dummy methods that fail silently at runtime, these classes honestly declare their
capabilities as unimplemented (`implemented=False`) and report dead on health probes
(`healthcheck() -> False`).

==============================================================================
WHY STUBS AS CLASSES RATHER THAN FUNCTIONS
==============================================================================
1. PROTOCOL CONFORMANCE:
   In Phase 2, concrete adapters replace these stubs cleanly via Dependency Injection
   at the application composition root. Defining class-level interfaces ensures
   structural typing (Protocols) and lifecycle parity across all rail integrations.

2. DASHBOARD RAIL STATUS PANEL (TASK 62 HANDOFF):
   Task 62's administrative operations dashboard inspects rail capabilities at boot
   to render rail operational statuses. Classes expose structured metadata via
   `CAPABILITIES: RailCapabilities`, preventing UI components from reporting
   fake-alive status for offline or unintegrated payment rails.

3. DISABLED-MODE STUB LAW:
   `healthcheck()` returns strictly `False`. Stubs report dead, not fake-alive.
   Monitors and health probes (Task 69) must never detect a green signal from an
   unimplemented banking rail.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

__all__ = [
    "ACHStub",
    "FiatRailStub",
    "RailCapabilities",
    "SEPAStub",
    "SWIFTStub",
]


@dataclass(frozen=True, slots=True)
class RailCapabilities:
    """Immutable rail capability record for administrative and dashboard inspection.

    Attributes:
        rail: Canonical rail identifier ('swift', 'sepa', 'ach').
        implemented: Whether the rail has a live production-ready implementation.
        phase: Delivery roadmap phase (e.g. Phase 2 for Wise-backed, Phase 3 for direct).
        flow_summary: High-level architectural settlement mechanics and operational model.
    """

    rail: str
    implemented: bool
    phase: int
    flow_summary: str


class FiatRailStub:
    """Base class for deferred traditional banking rail integrations.

    Adheres to the Disabled-Mode Stub Law: stubs report dead (`False`) on healthcheck
    to prevent monitoring probes and administrative dashboards from diagnosing
    unimplemented rails as healthy.
    """

    CAPABILITIES: ClassVar[RailCapabilities]

    @property
    def capabilities(self) -> RailCapabilities:
        """Access the frozen rail capabilities record."""
        return self.CAPABILITIES

    async def healthcheck(self) -> bool:
        """Health probe adhering to the Disabled-Mode Stub Law.

        Returns:
            False unconditionally. Stubs report dead, not fake-alive.
        """
        return False

    async def initiate_transfer(self, *args: Any, **kwargs: Any) -> Any:
        """Attempt to initiate an outbound transfer or payout.

        Raises:
            NotImplementedError: Unconditionally, carrying Phase roadmap pointer and flow summary.
        """
        raise NotImplementedError(
            f"Rail '{self.CAPABILITIES.rail.upper()}' is not implemented in Phase 1 "
            f"(Roadmap: Phase {self.CAPABILITIES.phase}). "
            f"Flow summary: {self.CAPABILITIES.flow_summary} (See Task 53/54 specification)."
        )

    async def initiate_payout(self, *args: Any, **kwargs: Any) -> Any:
        """Treasury payout pipeline compatibility alias for initiate_transfer."""
        return await self.initiate_transfer(*args, **kwargs)

    async def execute_transfer(self, *args: Any, **kwargs: Any) -> Any:
        """Transfer execution compatibility alias for initiate_transfer."""
        return await self.initiate_transfer(*args, **kwargs)


class SWIFTStub(FiatRailStub):
    """SWIFT (Society for Worldwide Interbank Financial Telecommunication) Wire Stub.

    ==========================================================================
    ARCHITECTURAL FLOW DOCUMENT: SWIFT CORRESPONDENT BANKING
    ==========================================================================
    Settlement Mechanics:
      SWIFT is a financial messaging network (MT103 / ISO 20022 pacs.008), not a
      clearing house or settlement ledger. Moving funds across borders requires a
      chain of bilateral correspondent banking relationships:
      1. Originating Bank -> Intermediary Correspondent Bank -> Beneficiary Bank.
      2. Nostro/Vostro accounts are debited and credited along the correspondent chain.
      3. Typical settlement duration: 1 to 5 business days depending on time zones,
         currency pairs, and intermediary clearing windows.

    Account Requirements:
      - Beneficiary Account Number or IBAN (International Bank Account Number).
      - Beneficiary Bank SWIFT BIC (Bank Identifier Code) / ISO 9362.
      - Full beneficiary entity legal name, physical address, and remittance purpose.

    Economics & Treasury Ops Model:
      - Fixed network and correspondent charges ($15 to $50 per wire) plus lifting
        fees charged by intermediary banks (OUR vs BEN vs SHA charge codes).
      - Significant FX spread markups (100 to 300 bps) applied by correspondent desks.
      - Phase 3 Roadmap: Direct SWIFT messaging or correspondent relationship access
        requires minimum treasury liquidity commitments ($10M+) and specialized
        treasury operations personnel managing manual exception queues and repair items.
    """

    CAPABILITIES: ClassVar[RailCapabilities] = RailCapabilities(
        rail="swift",
        implemented=False,
        phase=3,
        flow_summary=(
            "Correspondent-bank cross-border wire messaging (MT103/pacs.008) requiring "
            "IBAN+BIC; manual treasury exception queue and correspondent FX spread (Phase 3)."
        ),
    )


class SEPAStub(FiatRailStub):
    """SEPA (Single Euro Payments Area) Credit Transfer Stub.

    ==========================================================================
    ARCHITECTURAL FLOW DOCUMENT: SEPA CREDIT TRANSFER (SCT & SCT INST)
    ==========================================================================
    Settlement Mechanics:
      SEPA harmonizes cashless Euro payments across the EU/EEA:
      - SEPA Credit Transfer (SCT): Batch clearing via STEP2 or RT1, typically
        executing next business day (D+1).
      - SEPA Instant Credit Transfer (SCT Inst): Real-time pan-European clearing
        under 10 seconds, 24/7/365, with maximum transaction limits (€100k).

    Consolidation Economics (Riding on Wise):
      - Direct participant status in RT1/STEP2 or TARGET2 requires an ECB banking
        license or specialized EMI sponsor partnership, requiring €500k+ collateral.
      - In Phase 2, FluxPay will NOT establish direct clearing connections. Instead,
        SEPA transfers will RIDE on Wise's existing SEPA rails or Stripe Payouts.
      - Wise operates as a direct SCT participant, converting internal payout requests
        into instant SEPA transfers at near-interbank exchange rates and sub-euro fee
        schedules (<€0.50), eliminating direct infrastructure overhead.
    """

    CAPABILITIES: ClassVar[RailCapabilities] = RailCapabilities(
        rail="sepa",
        implemented=False,
        phase=2,
        flow_summary=(
            "SEPA Credit Transfer (SCT/SCT Inst) clearing in EUR; consolidated to ride on "
            "Wise/Stripe rail infrastructure in Phase 2 rather than direct bank connection."
        ),
    )


class ACHStub(FiatRailStub):
    """ACH (Automated Clearing House) Direct Deposit & Debit Stub.

    ==========================================================================
    ARCHITECTURAL FLOW DOCUMENT: NACHA ACH ORIGINATION
    ==========================================================================
    Settlement Mechanics:
      The US ACH network is an electronic batch clearing system governed by NACHA
      and operated by the Federal Reserve (FedACH) and The Clearing House (EPN):
      - ACH Credit (Push): Employer payroll, merchant disbursements, supplier payouts.
      - ACH Debit (Pull): Consumer invoice collection, recurring subscriptions.
      - Settlement Windows: Standard ACH clears in 1 to 3 business days; Same-Day ACH
        settles within designated intraday clearing windows.

    Return Windows & Finality Risks:
      - ACH transfers lack immediate finality. Consumer accounts maintain a 60-calendar-day
        unauthorized debit dispute window (Return Reason Codes R05, R07, R10, R11).
      - Commercial accounts maintain a 2-business-day return window (R01 Insufficient Funds,
        R02 Account Closed, R03 No Account).
      - A payout executed via ACH cannot be presumed final until return risk windows decay.

    Consolidation Economics:
      - Direct ODFI (Originating Depository Financial Institution) origination requires
        stringent credit underwriting, collateral holdbacks, and NACHA compliance audits.
      - Phase 2 candidate: Payouts ride on Stripe Payouts (ACH Direct Deposit) or Wise US
        local account infrastructure, leveraging their ODFI sponsorship and automated
        return code handling.
    """

    CAPABILITIES: ClassVar[RailCapabilities] = RailCapabilities(
        rail="ach",
        implemented=False,
        phase=2,
        flow_summary=(
            "NACHA ACH batch clearing for USD disbursements; 1-3 business day settlement "
            "with return risk window; consolidated to ride on Stripe Payouts / Wise in Phase 2."
        ),
    )
