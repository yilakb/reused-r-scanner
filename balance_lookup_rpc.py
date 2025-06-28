import csv
import json
import requests

RPC_URL = "http://127.0.0.1:8332/"
RPC_USER = "bitcoin_user"
RPC_PASSWORD = "your_secure_password_123"
INPUT_FILE = "recovered_Private_Key.txt"
OUTPUT_FILE = "nonzero_balances.txt"

def call_rpc(method, params=None):
    headers = {'content-type': 'application/json'}
    payload = json.dumps({
        "method": method,
        "params": params or [],
        "jsonrpc": "2.0",
        "id": 0,
    })
    response = requests.post(RPC_URL, headers=headers, data=payload, auth=(RPC_USER, RPC_PASSWORD))
    response.raise_for_status()
    return response.json()

def get_utxo_balance(address):
    try:
        result = call_rpc("scantxoutset", ["start", [{"desc": f"addr({address})"}]])
        return result.get("result", {}).get("total_amount", 0)
    except Exception as e:
        print(f"[!] Failed to fetch balance for {address}: {e}")
        return 0

def main():
    print("Checking balances using scantxoutset...")

    # Fix UTF-8 BOM issue and load CSV cleanly
    with open(INPUT_FILE, newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        rows = list(reader)

    with open(OUTPUT_FILE, "w", encoding='utf-8') as out_file:
        out_file.write("private_key,uncompressed_address,balance\n")
        for row in rows:
            pk = row["private_key"].strip().replace('"', '')
            addr = row["uncompressed_address"].strip().replace('"', '')
            balance = get_utxo_balance(addr)
            if balance > 0:
                print(f"💰 {addr} has balance: {balance}")
                out_file.write(f"{pk},{addr},{balance}\n")
            else:
                print(f"➖ {addr} has zero balance")

if __name__ == "__main__":
    main()
