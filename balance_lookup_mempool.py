import csv
import requests
import time
import concurrent.futures

INPUT_FILE = "recovered_Private_Key.txt"
OUTPUT_FILE = "nonzero_balances.txt"
API_URL = "https://mempool.space/api/address/{}"
BATCH_SIZE = 10
SLEEP_SECONDS = 5  # Delay between batches

def get_confirmed_balance(entry):
    privkey = entry["private_key"]
    results = []

    for key in ["uncompressed_address", "compressed_address"]:
        address = entry.get(key)
        if not address:
            continue
        try:
            url = API_URL.format(address)
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            funded = data['chain_stats']['funded_txo_sum']
            spent = data['chain_stats']['spent_txo_sum']
            balance = funded - spent
            results.append((privkey, key, address, balance))
        except Exception as e:
            print(f"[!] Failed to get balance for {address}: {e}")
            results.append((privkey, key, address, None))

    return results

def main():
    with open(INPUT_FILE, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        headers = [h.strip().replace('"', '') for h in reader.fieldnames]
        if "private_key" not in headers or ("uncompressed_address" not in headers and "compressed_address" not in headers):
            print("❌ ERROR: Required headers are missing.")
            return

        entries = []
        for row in reader:
            entry = {
                "private_key": row.get('private_key') or row.get('"private_key"'),
                "uncompressed_address": row.get('uncompressed_address') or row.get('"uncompressed_address"'),
                "compressed_address": row.get('compressed_address') or row.get('"compressed_address"')
            }
            if entry["private_key"]:
                entries.append(entry)

    print(f"🔍 Checking {len(entries)} entries (up to 2 addresses each) in batches of {BATCH_SIZE}...")

    results = []

    for i in range(0, len(entries), BATCH_SIZE):
        batch = entries[i:i + BATCH_SIZE]
        print(f"🚀 Processing batch {i // BATCH_SIZE + 1}...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            batch_results = executor.map(get_confirmed_balance, batch)

        for addr_results in batch_results:
            for privkey, addr_type, address, balance in addr_results:
                if balance is None:
                    continue
                if balance > 0:
                    print(f"✅ {addr_type} {address} has {balance} sats")
                    results.append((privkey, addr_type, address, balance))
                else:
                    print(f"➖ {addr_type} {address} has zero balance")

        time.sleep(SLEEP_SECONDS)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("private_key,address_type,address,balance_sats\n")
        for privkey, addr_type, address, balance in results:
            f.write(f"{privkey},{addr_type},{address},{balance}\n")

    print(f"\n✅ Done. Found {len(results)} address entries with non-zero balance.")
    print(f"📁 Saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
