# Runbook: KMS & Master Secret Key Rotation (`key-rotation.md`)

## 1. Overview & Policy
- **Rotation Frequency**: Cloud KMS signing keys every 12 months; Vault master key every 6 months.
- **Fail-Closed Rule**: If KMS key is disabled or inaccessible, the platform immediately rejects signing requests.

## 2. Zero-Downtime AWS KMS Signing Key Rotation Procedure
1. Create new asymmetric KMS signing key in AWS Console / Terraform:
   ```bash
   aws kms create-key --key-spec ECC_SECG_P256K1 --key-usage SIGN_VERIFY --origin AWS_KMS
   ```
2. Retrieve the Ethereum address corresponding to the new key:
   ```bash
   python -c "from fluxpay.shared.kms_aws import AwsKmsSigner; signer = AwsKmsSigner(key_id='$NEW_KEY_ID'); print(signer.get_address())"
   ```
3. Fund the new address with native ETH for gas on Base L2:
   ```bash
   # Minimum 0.05 ETH for gas buffer
   ```
4. Update `FLX_KMS_KEY_ID` in Secrets Manager / `.env.production`.
5. Perform rolling restart of `fluxpay-worker` and `fluxpay-api`:
   ```bash
   sudo systemctl reload-or-restart fluxpay-api.service
   sudo systemctl restart fluxpay-worker.service
   ```
6. Verify outbound transaction signing:
   ```bash
   python scripts/health_check.sh
   ```
7. Retain the old key in ENABLED state for 72 hours to allow in-flight transaction confirmation.

## 3. Vault Master Key Rotation (Envelope Re-Encryption)
1. Generate new 32-byte AES key:
   ```bash
   NEW_KEY=$(openssl rand -base64 32)
   ```
2. Run database vault re-encryption migration:
   ```bash
   FLX_NEW_VAULT_KEY="${NEW_KEY}" python scripts/rotate_vault_keys.py
   ```
3. Update `FLX_VAULT_MASTER_KEY` across all instances.
