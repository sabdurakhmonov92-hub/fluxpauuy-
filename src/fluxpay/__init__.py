"""FluxPay: High-throughput payment platform for autonomous AI agents.

Module Architecture:
--------------------
The platform is structured as a modular monolith consisting of 12 decoupled modules:

1. gateway: Ingress API, client authentication, rate limiting, and request routing.
2. ledger: Immutable double-entry bookkeeping engine, balance tracking, and audit journals.
3. payments: Payment lifecycle orchestration, intent state machines, and execution logic.
4. registry: Agent identity management, KYA/KYC verification, and authorization policies.
5. risk: Real-time fraud detection, velocity evaluation, and anomaly mitigation.
6. wallet: Virtual agent balances, pre-funded allocations, and allowance controls.
7. treasury: Liquidity management, bank sweeping, FX conversion, and settlement flows.
8. notifications: Outbound webhook dispatching, event streaming, and agent notifications.
9. audit: Cryptographic proof generation, regulatory compliance trails, and immutable logs.
10. integrations: Adapters for external banking rails, card networks, and settlement partners.
11. workers: Distributed asynchronous job processing, reconciliation, and background tasks.
12. shared: Foundational domain primitives, monetary types, cryptographic utils, and base schemas.

Import Direction Rule:
----------------------
Modules depend strictly downward along the dependency hierarchy (gateway -> shared).
A module may never import into a lateral neighbor's internal implementation details.
Shared domain abstractions and interfaces must reside within `shared` or be exposed
via the public interface of the upstream provider module.
"""

__version__ = "0.1.0"
