from __future__ import annotations

import os
from datetime import UTC, datetime

import httpx

print("=================================================================")
print("TEST 1: HELIUS SOLANA MAINNET RPC")
print("=================================================================")
helius_key = os.environ.get("HELIUS_API_KEY", "833ff947-6d6c-4c38-ab29-3a7fb4582727")
helius_url = f"https://mainnet.helius-rpc.com/?api-key={helius_key}"

with httpx.Client(timeout=10.0) as client:
    # 1. Fetch current slot
    res1 = client.post(
        helius_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "getSlot"},
        headers={"Content-Type": "application/json"},
    )
    slot = res1.json()["result"]
    print(f"[+] Solana Mainnet Hozirgi Slot Raqami: #{slot:,}")

    # 2. Fetch latest blockhash
    res2 = client.post(
        helius_url,
        json={"jsonrpc": "2.0", "id": 2, "method": "getLatestBlockhash"},
        headers={"Content-Type": "application/json"},
    )
    blockhash = res2.json()["result"]["value"]["blockhash"]
    print(f"[+] Solana Mainnet Jonli Xesh-kodi: {blockhash}")

    # 3. Fetch cluster version
    res3 = client.post(
        helius_url,
        json={"jsonrpc": "2.0", "id": 3, "method": "getVersion"},
        headers={"Content-Type": "application/json"},
    )
    version = res3.json()["result"]["solana-core"]
    print(f"[+] Solana Validator Core Versiyasi: {version}")

print("\n=================================================================")
print("TEST 2: TRONGRID TRON MAINNET API")
print("=================================================================")
tron_key = os.environ.get("TRON_API_KEY", "2972dd8e-7625-4ae0-873e-21ee90b7fc64")
tron_url = "https://api.trongrid.io/wallet/getnowblock"

with httpx.Client(timeout=10.0) as client:
    res_tron = client.post(tron_url, headers={"TRON-PRO-API-KEY": tron_key})
    tron_data = res_tron.json()
    raw = tron_data["block_header"]["raw_data"]
    block_num = raw["number"]
    block_time = datetime.fromtimestamp(raw["timestamp"] / 1000.0, UTC)
    tx_count = len(tron_data.get("transactions", []))

    print(f"[+] TRON Mainnet Hozirgi Blok Raqami: #{block_num:,}")
    print(f"[+] TRON Blok Yaratilgan Aniq Vaqt: {block_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"[+] Ushbu Blokdagi Haqiqiy Tranzaksiyalar Soni: {tx_count} ta real tranzaksiya")
    print(f"[+] TRON Blokni Tasdiqlagan Validator: {raw.get('witness_address')}")
    print("=================================================================")
    print("NATIJA: Ikkala API kalit ham 100% REAL va ayni daqiqada ISHLAYAPTI!")
    print("=================================================================")
