"""FluxPay Gateway Subsystem.

Gateway Pipeline Architecture Map:
    canonical.py (Task 19: frozen signing scheme)
    -> ratelimit.lua (Task 20: atomic rate-limit and replay gate)
    -> middleware.py (Task 21: HTTP pipeline and request lifecycle)
    -> x402.py (Agent-facing HTTP 402 payment protocol)

Leaf-first imports:
    Lower-level pure cryptographic leaves (canonical.py) have zero project
    dependencies and are imported first by higher-level pipeline middleware.
"""

from fluxpay.gateway.x402 import DefaultAgentRegistry, X402Middleware
from fluxpay.gateway.x402_config import X402Config
from fluxpay.gateway.x402_facilitator import (
    CircleFacilitator,
    CoinbaseCDPFacilitator,
    FacilitatorClient,
    HttpFacilitatorClient,
    SelfHostedFacilitator,
)
from fluxpay.gateway.x402_types import (
    AgentRecord,
    AgentRegistry,
    LedgerClient,
    PaymentPayload,
    PaymentRequired,
    PaymentResponse,
    SettleResult,
    VerifyResult,
)

__all__ = [
    "AgentRecord",
    "AgentRegistry",
    "CircleFacilitator",
    "CoinbaseCDPFacilitator",
    "DefaultAgentRegistry",
    "FacilitatorClient",
    "HttpFacilitatorClient",
    "LedgerClient",
    "PaymentPayload",
    "PaymentRequired",
    "PaymentResponse",
    "SelfHostedFacilitator",
    "SettleResult",
    "VerifyResult",
    "X402Config",
    "X402Middleware",
]
