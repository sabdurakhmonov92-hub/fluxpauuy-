# Runbook: Hot Wallet Refill Procedure (`hot-wallet-refill.md`)

## 1. Overview & Triggers
- **Triggers**:
  - Alert `HotWalletEthLow` (native ETH < 0.005 ETH on Base L2).
  - Outbound settlement USDC balance < $5,000 threshold.
- **Custody Policy**: Cold reserves are held in multi-sig Gnosis Safe. Hot wallets hold max 24 hours of operational volume.

## 2. Refill Native Gas (Base L2 ETH)
1. Verify current hot wallet gas balance:
   ```bash
   python -c "from fluxpay.integrations.base_l2 import check_gas_balance; print(check_gas_balance())"
   ```
2. Initiate transfer of 0.1 ETH from Treasury Safe to hot wallet address on Base L2.
3. Wait for 1 block confirmation on Base.
4. Verify Prometheus metric updates:
   ```bash
   curl -s http://localhost:8000/metrics | grep flx_hot_wallet_eth_balance
   ```

## 3. Refill USDC Outbound Settlement Liquidity
1. Query active agent pending withdrawals:
   ```bash
   python -c "from fluxpay.treasury.payouts import get_pending_payout_volume; print(get_pending_payout_volume())"
   ```
2. Submit transaction from Gnosis Safe to transfer necessary USDC to BaseL2Writer hot wallet.
3. Verify USDC balance reflects in `/metrics` and `/ready` probes.
