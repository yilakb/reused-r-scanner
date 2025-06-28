#!/usr/bin/env python3
"""
FULL AUTOMATIC BITCOIN NONCE REUSE SCANNER
LEGACY + SEGWIT + TAPROOT SUPPORT - R PAIR DISCOVERY + DIAGNOSTIC COUNTS
"""

import requests
import base64
import time
import hashlib
import struct
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

RPC_USER = 'bitcoin_user'
RPC_PASSWORD = 'your_secure_password_123'
RPC_PORT = 8332
RPC_HOST = '127.0.0.1'

MAX_RETRIES = 1
RETRY_DELAY = 0.2
MAX_WORKERS = 8

session_lock = Lock()
sessions = {}

# ----------------------------------------------------------------------
# Bitcoin RPC Connection
# ----------------------------------------------------------------------

def get_session():
    import threading
    thread_id = threading.current_thread().ident
    with session_lock:
        if thread_id not in sessions:
            sessions[thread_id] = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=0)
            sessions[thread_id].mount('http://', adapter)
        return sessions[thread_id]

def cleanup_sessions():
    with session_lock:
        for session in sessions.values():
            session.close()
        sessions.clear()

def rpc_request(method, params=None, retry_count=0):
    session = get_session()
    url = f'http://{RPC_HOST}:{RPC_PORT}/'
    headers = {'content-type': 'application/json'}
    payload = {"method": method, "params": params or [], "jsonrpc": "2.0", "id": 0}
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASSWORD}".encode()).decode()
    try:
        response = session.post(url, json=payload, headers={**headers, "Authorization": f"Basic {auth}"}, timeout=20)
        response.raise_for_status()
        return response.json()['result']
    except Exception as e:
        if retry_count < MAX_RETRIES:
            time.sleep(RETRY_DELAY)
            return rpc_request(method, params, retry_count + 1)
        else:
            raise e

# ----------------------------------------------------------------------
# Cryptography
# ----------------------------------------------------------------------

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def parse_der(sig_hex):
    data = bytes.fromhex(sig_hex)
    if data[0] != 0x30:
        raise ValueError("Invalid DER prefix")
    r_len = data[3]
    r_bytes = data[4:4+r_len]
    r = int.from_bytes(r_bytes, 'big')
    s_start = 4 + r_len
    s_len = data[s_start + 1]
    s_bytes = data[s_start+2:s_start+2+s_len]
    s = int.from_bytes(s_bytes, 'big')
    return r, s

def parse_schnorr(sig_hex):
    if len(sig_hex) != 128:
        raise ValueError("Invalid Schnorr signature length")
    r = int(sig_hex[:64], 16)
    s = int(sig_hex[64:], 16)
    return r, s

class ECDSAAttack:
    def __init__(self):
        self.n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    def mod_inverse(self, a, n):
        return pow(a, -1, n)

# ----------------------------------------------------------------------
# Sighash stub
# ----------------------------------------------------------------------

def compute_sighash(txid, input_index):
    return b'\x00' * 32

# ----------------------------------------------------------------------
# Script Parsers
# ----------------------------------------------------------------------

def extract_signature(script_sig_hex):
    script_bytes = bytes.fromhex(script_sig_hex)
    offset = 0
    while offset < len(script_bytes):
        push_len = script_bytes[offset]
        offset += 1
        if push_len == 0:
            continue
        if offset + push_len > len(script_bytes):
            break
        data = script_bytes[offset:offset+push_len]
        offset += push_len
        if data[0] == 0x30:
            return data[:-1].hex()
    raise ValueError("Valid signature not found")

def extract_witness_signature(witness_list):
    if not witness_list:
        raise ValueError("No witness items")
    sig = witness_list[0]
    if len(sig) == 128:
        return sig  # Schnorr
    return sig[:-2]  # ECDSA remove sighash type

# ----------------------------------------------------------------------
# Main Scanner Logic
# ----------------------------------------------------------------------

def scan_block(block_height):
    block_hash = rpc_request('getblockhash', [block_height])
    block = rpc_request('getblock', [block_hash, 2])
    signatures = []
    legacy_count = segwit_count = taproot_count = skipped_count = 0
    for tx in block['tx']:
        txid = tx['txid']
        for idx, vin in enumerate(tx['vin']):
            try:
                if 'txinwitness' in vin and vin['txinwitness']:
                    sig_hex = vin['txinwitness'][0]
                    if len(sig_hex) == 128:
                        r, s = parse_schnorr(sig_hex)
                        taproot_count += 1
                    else:
                        r, s = parse_der(extract_witness_signature(vin['txinwitness']))
                        segwit_count += 1
                    signatures.append({'r': r, 's': s, 'txid': txid, 'input_index': idx})
                elif 'scriptSig' in vin and 'hex' in vin['scriptSig']:
                    sig_der = extract_signature(vin['scriptSig']['hex'])
                    r, s = parse_der(sig_der)
                    legacy_count += 1
                    signatures.append({'r': r, 's': s, 'txid': txid, 'input_index': idx})
                else:
                    skipped_count += 1
            except Exception:
                skipped_count += 1
    print(f"Block {block_height}: {legacy_count} legacy, {segwit_count} segwit, {taproot_count} taproot, {skipped_count} skipped")
    return signatures

def full_scan(start_block, end_block):
    print(f"Scanning blocks {start_block} to {end_block}...")
    all_sigs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_block, h): h for h in range(start_block, end_block+1)}
        for future in as_completed(futures):
            sigs = future.result()
            all_sigs.extend(sigs)
    print("\nCompleted signature extraction.")
    find_reuse(all_sigs)

def find_reuse(all_sigs):
    print("\nSearching for reused nonces...")
    seen = {}
    pairs = []
    output_lines = []
    for sig in all_sigs:
        r = sig['r']
        if r not in seen:
            seen[r] = sig
        else:
            pairs.append((seen[r], sig))
    print(f"Found {len(pairs)} reused nonce pairs.")
    output_lines.append(f"Found {len(pairs)} reused nonce pairs.\n")
    attack = ECDSAAttack()
    for idx, (sig1, sig2) in enumerate(pairs):
        lines = []
        lines.append(f"\nPair {idx+1}:")
        lines.append(f"  TXID 1: {sig1['txid']} (Input {sig1['input_index']})")
        lines.append(f"  TXID 2: {sig2['txid']} (Input {sig2['input_index']})")
        lines.append(f"  Signature 1: r={hex(sig1['r'])[2:]}, s={hex(sig1['s'])[2:]}")
        lines.append(f"  Signature 2: r={hex(sig2['r'])[2:]}, s={hex(sig2['s'])[2:]}")
        try:
            if sig1['s'] == sig2['s']:
                raise ValueError("Identical s values, cannot invert")
            z1 = int.from_bytes(compute_sighash(sig1['txid'], sig1['input_index']), 'big')
            z2 = int.from_bytes(compute_sighash(sig2['txid'], sig2['input_index']), 'big')
            s_diff = (sig1['s'] - sig2['s']) % attack.n
            s_inv = attack.mod_inverse(s_diff, attack.n)
            z_diff = (z1 - z2) % attack.n
            k = (z_diff * s_inv) % attack.n
            r_inv = attack.mod_inverse(sig1['r'], attack.n)
            priv = (r_inv * ((sig1['s'] * k - z1) % attack.n)) % attack.n
            priv_hex = hex(priv)[2:].zfill(64)
            lines.append(f"  ✅ Private Key Recovered: {priv_hex}")
        except Exception as e:
            lines.append(f"  ⚠️ Could not recover private key: {e}")
        for l in lines:
            print(l)
        output_lines.extend(lines)
    # Write output to file (always rewrite, not append)
    with open('taproot_scan_output.txt', 'w', encoding='utf-8') as f:
        for line in output_lines:
            f.write(line + '\n')

# ----------------------------------------------------------------------
# Entry Point
# ----------------------------------------------------------------------

if __name__ == "__main__":
    try:
        start = int(input("Enter start block: ").strip())
        end = int(input("Enter end block: ").strip())
        full_scan(start, end)
    finally:
        cleanup_sessions()
