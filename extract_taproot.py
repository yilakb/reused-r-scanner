#!/usr/bin/env python3
"""
Recover private keys from reused nonces logged in output_pk_taproot.txt
Outputs recovery results in structured JSON format to recovered_pk.json
"""

import requests
import base64
import time
import hashlib
import struct
import json
import os
from ecdsa.util import sigdecode_der
from ecdsa import SECP256k1, SigningKey
from threading import Lock
import binascii
from bech32 import encode_segwit_address

# RPC Configuration
RPC_USER = 'bitcoin_user'
RPC_PASSWORD = 'your_secure_password_123'
RPC_PORT = 8332
RPC_HOST = '127.0.0.1'

session_lock = Lock()
sessions = {}


def get_session():
    import threading
    thread_id = threading.current_thread().ident
    with session_lock:
        if thread_id not in sessions:
            sessions[thread_id] = requests.Session()
        return sessions[thread_id]


def rpc_request(method, params=None, retry_count=0):
    session = get_session()
    url = f'http://{RPC_HOST}:{RPC_PORT}/'
    headers = {'content-type': 'application/json'}
    payload = {"method": method, "params": params or [], "jsonrpc": "2.0", "id": 0}
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASSWORD}".encode()).decode()
    try:
        response = session.post(url, json=payload, headers={**headers, "Authorization": f"Basic {auth}"}, timeout=30)
        response.raise_for_status()
        return response.json()['result']
    except Exception as e:
        if retry_count < 3:
            time.sleep(0.5)
            return rpc_request(method, params, retry_count + 1)
        raise e


# Curve parameters
n = SECP256k1.order


def modinv(a, n):
    return pow(a, -1, n)


def double_sha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()


def parse_output_file(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()

    pairs = []
    temp = {}
    for line in lines:
        if line.startswith('  TXID 1:'):
            temp['txid1'], temp['idx1'] = line.split()[2], int(line.split()[-1].strip(')'))
        elif line.startswith('  TXID 2:'):
            temp['txid2'], temp['idx2'] = line.split()[2], int(line.split()[-1].strip(')'))
        elif line.startswith('  Signature 1:'):
            temp['r'] = int(line.split('r=')[1].split(',')[0], 16)
            temp['s1'] = int(line.split('s=')[1], 16)
        elif line.startswith('  Signature 2:'):
            temp['s2'] = int(line.split('s=')[1], 16)
        elif line.startswith('Pair') and temp:
            pairs.append(temp.copy())
            temp.clear()
    if temp:
        pairs.append(temp)
    return pairs


def get_sighash(txid, vin_index):
    tx = rpc_request("getrawtransaction", [txid, True])
    vin = tx['vin'][vin_index]
    prev_tx = rpc_request("getrawtransaction", [vin['txid'], True])
    prev_out = prev_tx['vout'][vin['vout']]
    script = prev_out['scriptPubKey']['hex']
    script_type = prev_out['scriptPubKey']['type']
    address_used = prev_out['scriptPubKey'].get('address', None)
    amount = int(prev_out['value'] * 1e8)

    if script_type == 'witness_v0_keyhash':
        hash_prevouts = double_sha256(b''.join([
            bytes.fromhex(v['txid'])[::-1] + struct.pack('<I', v['vout']) for v in tx['vin']
        ]))
        hash_sequence = double_sha256(b''.join([
            struct.pack('<I', v.get('sequence', 0xffffffff)) for v in tx['vin']
        ]))
        hash_outputs = double_sha256(b''.join([
            struct.pack('<Q', int(o['value'] * 1e8)) + bytes.fromhex(o['scriptPubKey']['hex']) for o in tx['vout']
        ]))

        outpoint = bytes.fromhex(vin['txid'])[::-1] + struct.pack('<I', vin['vout'])
        script_code = bytes.fromhex(script)
        amount_bytes = struct.pack('<Q', amount)
        sequence = struct.pack('<I', vin.get('sequence', 0xffffffff))

        preimage = (
            struct.pack('<I', tx['version']) + hash_prevouts + hash_sequence +
            outpoint + script_code + amount_bytes + sequence +
            hash_outputs + struct.pack('<I', tx['locktime']) + struct.pack('<I', 1)
        )
        return int.from_bytes(double_sha256(preimage), 'big'), script_type, script, address_used

    elif script_type == 'witness_v1_taproot':  # Taproot (dummy)
        return 0, script_type, script, address_used

    else:
        return 0, script_type, script, address_used


def derive_info(pubkey_bytes, script_type, priv_hex):
    compressed = pubkey_bytes
    uncompressed = b'\x04' + SigningKey.from_string(binascii.unhexlify(priv_hex), curve=SECP256k1).get_verifying_key().to_string()
    hash160_c = hash160(compressed)
    hash160_u = hash160(uncompressed)
    if script_type == 'witness_v0_keyhash':
        address = encode_segwit_address("bc", 0, hash160_c)
    elif script_type == 'witness_v1_taproot':
        address = encode_segwit_address("bc", 1, compressed[1:])
    else:
        address = "Unknown"

    return address, compressed.hex(), uncompressed.hex(), hash160_c.hex(), hash160_u.hex()


def recover_privkey(pair):
    try:
        r, s1, s2 = pair['r'], pair['s1'], pair['s2']
        if r == 0 or s1 == s2:
            return None
        z1, script_type, script, original_address = get_sighash(pair['txid1'], pair['idx1'])
        z2, _, _, _ = get_sighash(pair['txid2'], pair['idx2'])
        k = ((z1 - z2) * modinv(s1 - s2, n)) % n
        priv = ((s1 * k - z1) * modinv(r, n)) % n
        priv_hex = hex(priv)[2:].zfill(64)
        sk = SigningKey.from_secret_exponent(priv, curve=SECP256k1)
        vk = sk.get_verifying_key()
        pub_compressed = b'\x02' + vk.to_string()[0:32] if vk.to_string()[63] % 2 == 0 else b'\x03' + vk.to_string()[0:32]
        address, comp_hex, uncomp_hex, hash160c, hash160u = derive_info(pub_compressed, script_type, priv_hex)
        match1 = (address == original_address)

        z3, _, _, used2 = get_sighash(pair['txid2'], pair['idx2'])
        match2 = (address == used2)

        return {
            "private_key": priv_hex,
            "compressed_pubkey": comp_hex,
            "uncompressed_pubkey": uncomp_hex,
            "compressed_address": address,
            "uncompressed_address": address,  # placeholder, we only derive 1
            "compressed_hash160": hash160c,
            "uncompressed_hash160": hash160u,
            "tx1": pair['txid1'],
            "tx1_input": pair['idx1'],
            "tx2": pair['txid2'],
            "tx2_input": pair['idx2'],
            "tx1_match": match1,
            "tx2_match": match2,
            "Used_in_TX": original_address or used2 or ""
        }
    except Exception:
        return None


# Main
if __name__ == "__main__":
    input_file = "taproot_scan_output.txt"
    output_file = "recovered_taproot_pk.json"
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Input file not found: {input_file}")
        # Create empty output file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
        print(f"Created empty output file: {output_file}")
        exit(0)
    
    pairs = parse_output_file(input_file)
    print(f"Total pairs found: {len(pairs)}")
    
    results = []
    for i, pair in enumerate(pairs):
        result = recover_privkey(pair)
        if result:
            results.append(result)
            print(f"Pair {i+1} processed")
        else:
            print(f"Could not recover key for pair {i+1}")

    # Always rewrite the file (not append)
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\nRecovery complete. {len(results)} keys written to {output_file}")
    print(f"Processed {len(pairs)} pairs total")
