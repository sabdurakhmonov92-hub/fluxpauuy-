"""FluxPay SEV1 Alert Router package (Task 69).

Provides Prometheus Alertmanager and Sentry webhook ingestion, severity gating,
fingerprint deduplication, and automated escalation to the Telegram ops channel.
"""

from __future__ import annotations

from fluxpay.alerts.router import (
    AlertRouter,
    NormalizedAlert,
    create_alert_router_app,
    format_sev_alert,
    send_heartbeat,
)

__all__ = [
    "AlertRouter",
    "NormalizedAlert",
    "create_alert_router_app",
    "format_sev_alert",
    "send_heartbeat",
]
