# Runbook: Emergency Rollback (`rollback.md`)

## 1. Overview
- **Trigger**: Post-deployment error spike (> 1%), failed readiness probe, or SEV1 alert.
- **Goal**: Revert running binaries to the previous stable release within 60 seconds.

## 2. Immediate Rollback Execution
Run the automated emergency rollback script:
```bash
bash scripts/rollback.sh production
```

## 3. Containerized Rollback Steps (Docker Compose)
1. Point compose service to previous container tag:
   ```bash
   docker compose -f docker-compose.prod.yml down
   docker compose -f docker-compose.prod.yml up -d --scale fluxpay-api=3
   ```
2. Verify rollback health:
   ```bash
   curl -f http://localhost:8000/ready
   ```

## 4. Bare-Metal Rollback Steps (Systemd)
1. Repoint symlink to previous release directory:
   ```bash
   ln -sfn /opt/fluxpay/releases/previous /opt/fluxpay/current
   ```
2. Restart systemd services:
   ```bash
   sudo systemctl restart fluxpay-api.service
   sudo systemctl restart fluxpay-worker.service
   ```
3. Verify status:
   ```bash
   sudo systemctl status fluxpay-api.service
   ```

## 5. Post-Rollback Tasks
1. Notify incident response channel: `#incident-response`.
2. Lock deployments until post-mortem is conducted.
