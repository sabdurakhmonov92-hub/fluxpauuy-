# Runbook: Production Deployment (`deploy.md`)

## 1. Overview & SLA Target
- **Purpose**: Zero-downtime rolling deployment of FluxPay API and workers.
- **RTO**: < 60 seconds (rolling restart).
- **RPO**: 0 (all state in persistent PostgreSQL with `synchronous_commit=on`).
- **Owner**: DevOps / Release Engineering.

## 2. Pre-Deployment Verification
1. Ensure git tree is clean and on the target release tag:
   ```bash
   git status
   git tag --verify v3.0.0
   ```
2. Verify all quality gates passed on CI:
   - `mypy --strict` passes with 0 errors.
   - `ruff check` passes with 0 warnings.
   - Full test suite passes.
3. Validate required environment configuration:
   ```bash
   python -c "from fluxpay.config import get_settings; print(get_settings().env)"
   ```

## 3. Step-by-Step Deployment Procedure
1. Execute database migrations in dry-run mode first:
   ```bash
   python scripts/migrate.py --dry-run
   ```
2. Apply pending migrations transactionally:
   ```bash
   python scripts/migrate.py
   ```
3. Trigger rolling deployment via deployment script:
   ```bash
   bash scripts/deploy.sh production latest
   ```
4. Verify HTTP readiness endpoint:
   ```bash
   curl -f http://localhost:8000/ready
   ```

## 4. Post-Deployment Smoke Checks
1. Submit test balance query:
   ```bash
   curl -H "X-Request-Id: $(uuidgen)" http://localhost:8000/health
   ```
2. Verify Prometheus metric scraping:
   ```bash
   curl -s http://localhost:8000/metrics | grep flx_http_requests_total
   ```
3. Monitor Grafana Overview dashboard for 10 minutes to verify zero 5xx rate spikes.

## 5. Escalation & Abort
If any step fails or error rate exceeds 0.1%, execute immediate rollback:
```bash
bash scripts/rollback.sh production
```
