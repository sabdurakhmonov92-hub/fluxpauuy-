"""Integration Base Client & External Rail Adapters (Block J).

==============================================================================
MODULE MAP (BLOCK J EXTERNAL RAILS)
==============================================================================
Block J connects FluxPay to external rails, providers, and payment networks:
- Crypto RPCs & OnChain Readers (Tasks 44/45): OnChainReader adapters inherit
  BaseClient to provide reliable multi-attempt RPC queries with standard backoff.
- Stripe (Task 50): Card acquiring, payment intents, card refunds, and payouts.
- Wise (Task 52): Fiat rails, cross-border payouts, and IBAN/SWIFT settlement.
- KYC / Identity Providers (Task 55): Sanctions screening, identity verification.
- Messaging & Alerts: Provider status checks and downstream notification bridges.

LINEAGE & GRANDFATHERED ADAPTERS:
Task 43 implemented Telegram and SendGrid Email notification channels using its own
injected httpx.AsyncClient pattern. Those channels PREDATE BaseClient and remain
as-is (grandfathered; no refactoring of Task 43 in this task). BaseClient establishes
the canonical architecture and unified adapter contract for everything built AFTER.

==============================================================================
THE ISOLATION LAW (Blueprint §6 invariant #9)
==============================================================================
Adapters import ONLY:
- Python standard library
- httpx
- fluxpay.shared.errors
- fluxpay.shared.logging
- fluxpay.shared.vault

NEVER each other. NEVER business core (ledger, payments, risk, registry,
wallet, treasury, gateway).
Enforced permanently by CI meta-test (test_isolation_law_import_allowlist).

==============================================================================
THE ADAPTER LIFECYCLE LAW
==============================================================================
Client instances are constructed strictly at the composition root (main.py / worker boot)
with an injected httpx.AsyncClient whose connection pooling, timeouts, and lifecycle
are owned by the application runtime.
NO module-level AsyncClient instances are permitted anywhere across integrations.
Enforced permanently by CI meta-test (test_injection_law_no_module_level_async_client).

==============================================================================
THE DISABLED-MODE LAW
==============================================================================
A provider with None configuration is disabled LOUDLY at the composition root,
mirroring Task 43's stub pattern. No overengineered DisabledProviderError class or
ProviderEnabled protocols: consumers (monitors, notifiers, workers) maintain clean
None-guards, and unconfigured adapters are simply never wired into the runtime graph.
"""

from .base import BaseClient, ProviderCall

__all__ = [
    "BaseClient",
    "ProviderCall",
]
