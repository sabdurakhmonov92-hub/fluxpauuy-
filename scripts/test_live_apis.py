import os
import urllib.request
import json
import datetime

print("=================================================================")
print("TEST 1: HELIUS SOLANA MAINNET RPC")
print("=================================================================")
helius_key = os.environ.get("HELIUS_API_KEY", "833ff947-6d6c-4c38-ab29-3a7fb4582727")
helius_url = f"https://mainnet.helius-rpc.com/?api-key={helius_key}"

# 1. Fetch current slot
req1 = urllib.request.Request(
    helius_url,
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getSlot"}).encode(),
    headers={"Content-Type": "application/json"}
)
res1 = urllib.request.urlopen(req1)
slot = json.loads(res1.read().decode())["result"]
print(f"[+] Solana Mainnet Hozirgi Slot Raqami: #{slot:,}")

# 2. Fetch latest blockhash
req2 = urllib.request.Request(
    helius_url,
    data=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "getLatestBlockhash"}).encode(),
    headers={"Content-Type": "application/json"}
)
res2 = urllib.request.urlopen(req2)
blockhash = json.loads(res2.read().decode())["result"]["value"]["blockhash"]
print(f"[+] Solana Mainnet Jonli Xesh-kodi: {blockhash}")

# 3. Fetch cluster version
req3 = urllib.request.Request(
    helius_url,
    data=json.dumps({"jsonrpc": "2.0", "id": 3, "method": "getVersion"}).encode(),
    headers={"Content-Type": "application/json"}
)
res3 = urllib.request.urlopen(req3)
version = json.loads(res3.read().decode())["result"]["solana-core"]
print(f"[+] Solana Validator Core Versiyasi: {version}")

print("\n=================================================================")
print("TEST 2: TRONGRID TRON MAINNET API")
print("=================================================================")
tron_key = os.environ.get("TRON_API_KEY", "2972dd8e-7625-4ae0-873e-21ee90b7fc64")
tron_url = "https://api.trongrid.io/wallet/getnowblock"
req_tron = urllib.request.Request(
    tron_url,
    headers={"TRON-PRO-API-KEY": tron_key}
)
res_tron = urllib.request.urlopen(req_tron)
tron_data = json.loads(res_tron.read().decode())
raw = tron_data["block_header"]["raw_data"]
block_num = raw["number"]
block_time = datetime.datetime.fromtimestamp(raw["timestamp"] / 1000.0, datetime.timezone.utc)
tx_count = len(tron_data.get("transactions", []))

print(f"[+] TRON Mainnet Hozirgi Blok Raqami: #{block_num:,}")
print(f"[+] TRON Blok Yaratilgan Aniq Vaqt: {block_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
print(f"[+] Ushbu Blokdagi Haqiqiy Tranzaksiyalar Soni: {tx_count} ta real tranzaksiya")
print(f"[+] TRON Blokni Tasdiqlagan Validator: {raw.get('witness_address')}")
print("=================================================================")
print("NATIJA: Ikkala API kalit ham 100% REAL va ayni daqiqada ISHLAYAPTI!")
print("=================================================================")
