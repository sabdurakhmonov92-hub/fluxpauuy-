# Runbook: FluxPayDown (SEV1)

## 1. Symptom
Prometheus alert `FluxPayDown` is firing: all or one API gateway process instances report `up == 0` for > 2 minutes. Ingress traffic is failing with connection refused or 502 Bad Gateway from Nginx.

## 2. First Command (Triage)
```bash
sudo systemctl status 'fluxpay-api@*' --no-pager
sudo journalctl -u 'fluxpay-api@*' -n 50 --no-pager
```

## 3. Remediation & Escalation
1. Verify PostgreSQL and Valkey connectivity: `pg_isready -h localhost` and `redis-cli ping`.
2. Attempt graceful restart: `sudo systemctl restart 'fluxpay-api@*'`.
3. If sockets fail to bind or database times out, escalate immediately to Infrastructure Lead.
4. Cross-references: See [architecture](file:///c:/Users/User/Desktop/fluxpauy/docs/dev.md) and [gateway](file:///c:/Users/User/Desktop/fluxpauy/docs/gateway.md).
