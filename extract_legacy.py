#!/usr/bin/env python3
"""
Extract pubkey info from private keys and compare with TX1 and TX2 input pubkeys
"""

import hashlib
import base58
from ecdsa import SigningKey, SECP256k1
import json
import os
import re
import requests
import base64

# RPC credentials
RPC_USER = 'bitcoin_user'
RPC_PASSWORD = 'your_secure_password_123'
RPC_HOST = '127.0.0.1'
RPC_PORT = 8332


def rpc_request(method, params=None):
    url = f'http://{RPC_HOST}:{RPC_PORT}/'
    headers = {'content-type': 'application/json'}
    payload = {"method": method, "params": params or [], "jsonrpc": "2.0", "id": 0}
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASSWORD}".encode()).decode()
    response = requests.post(url, json=payload, headers={**headers, "Authorization": f"Basic {auth}"})
    response.raise_for_status()
    return response.json()['result']


def extract_pubkey_from_input(txid, idx):
    try:
        raw = rpc_request("getrawtransaction", [txid, True])
        vin = raw.get('vin', [])
        if idx >= len(vin): return None
        asm = vin[idx].get('scriptSig', {}).get('asm', '')
        return asm.split()[-1] if asm else None
    except Exception as e:
        print(f"[!] Failed to extract pubkey from {txid}:{idx}: {e}")
        return None


def pubkey_to_address(pubkey_bytes):
    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hash160 = ripemd160.digest()
    versioned_hash = b'\x00' + hash160
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
    address_bytes = versioned_hash + checksum
    address = base58.b58encode(address_bytes).decode('utf-8')
    return address, hash160.hex()


def generate_pubkey_from_private(private_key_hex):
    private_key_int = int(private_key_hex, 16)
    signing_key = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
    public_key_point = signing_key.get_verifying_key().pubkey.point
    if public_key_point.y() % 2 == 0:
        compressed_pubkey = b'\x02' + public_key_point.x().to_bytes(32, byteorder='big')
    else:
        compressed_pubkey = b'\x03' + public_key_point.x().to_bytes(32, byteorder='big')
    uncompressed_pubkey = b'\x04' + public_key_point.x().to_bytes(32, byteorder='big') + public_key_point.y().to_bytes(32, byteorder='big')
    compressed_address, compressed_hash160 = pubkey_to_address(compressed_pubkey)
    uncompressed_address, uncompressed_hash160 = pubkey_to_address(uncompressed_pubkey)
    return {
        'private_key': private_key_hex,
        'compressed_pubkey': compressed_pubkey.hex(),
        'uncompressed_pubkey': uncompressed_pubkey.hex(),
        'compressed_address': compressed_address,
        'uncompressed_address': uncompressed_address,
        'compressed_hash160': compressed_hash160,
        'uncompressed_hash160': uncompressed_hash160
    }


def parse_entries_from_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    entries = []
    current = {}
    for line in lines:
        line = line.strip()
        if line.startswith("Private Key Recovered:") or line.startswith("✅ Private Key Recovered:"):
            if current: entries.append(current)
            current = {'private_key': re.search(r'([a-fA-F0-9]{64})', line).group(1)}
        elif line.startswith("TX1:"):
            parts = line.split()
            current['tx1'] = parts[1]
            current['vin1'] = int(parts[3])
        elif line.startswith("TX2:"):
            parts = line.split()
            current['tx2'] = parts[1]
            current['vin2'] = int(parts[3])
    if current: entries.append(current)
    return entries


def main():
    input_file = 'legacy_scan_output.txt'
    output_file = 'recovered_legacy_pk.json'
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Input file not found: {input_file}")
        # Create empty output file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
        print(f"Created empty output file: {output_file}")
        return
    
    entries = parse_entries_from_file(input_file)
    print(f"Total key entries: {len(entries)}")

    out = []
    for entry in entries:
        result = generate_pubkey_from_private(entry['private_key'])
        tx1_pub = extract_pubkey_from_input(entry['tx1'], entry['vin1'])
        tx2_pub = extract_pubkey_from_input(entry['tx2'], entry['vin2'])
        result.update({
            'tx1': entry['tx1'], 'tx1_input': entry['vin1'],
            'tx2': entry['tx2'], 'tx2_input': entry['vin2'],
            'tx1_match': tx1_pub in [result['compressed_pubkey'], result['uncompressed_pubkey']],
            'tx2_match': tx2_pub in [result['compressed_pubkey'], result['uncompressed_pubkey']]
        })
        out.append(result)

    # Always rewrite the file (not append)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2)
    print(f"Output written to: {output_file}")
    print(f"Processed {len(out)} entries")


if __name__ == "__main__":
    main()
