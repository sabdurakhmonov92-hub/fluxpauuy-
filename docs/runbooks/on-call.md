# Runbook: On-Call Rotation & Escalation Procedures (`on-call.md`)

## 1. On-Call Responsibilities
- **Primary On-Call**: 24/7 pager duty. Must acknowledge SEV1 alerts within 5 minutes.
- **Secondary On-Call**: Escalation backup if primary does not acknowledge within 10 minutes.
- **Tools**: PagerDuty, Grafana Observability Dashboards, AWS Console, Kubernetes CLI.

## 2. Escalation Matrix

| Role | Contact Mechanism | Escalation Window |
| :--- | :--- | :--- |
| **Primary Engineer** | PagerDuty Mobile / Call | 0 - 10 minutes |
| **Secondary Engineer** | PagerDuty Call | 10 - 20 minutes |
| **Engineering Lead / VP** | Phone / SMS | 20+ minutes or any ongoing SEV1 |
| **Chief Information Security Officer (CISO)** | Direct Phone | Immediate upon suspected security breach |

## 3. Shift Handover Procedure
Every Monday at 10:00 UTC:
1. Review all alerts and incidents from preceding 7 days.
2. Verify active alert suppression rules or scheduled maintenance windows.
3. Check hot wallet balances and pending ledger reconciliations.
4. Transfer primary pager in PagerDuty.
