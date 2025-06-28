#!/usr/bin/env python3
"""
Flask Backend for Bitcoin Reused-R Scanner Toolkit
Provides API endpoints for the frontend interface
"""

from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
import subprocess
import threading
import time
import json
import os
import re
import requests
import base64
from datetime import datetime
import logging

app = Flask(__name__)
CORS(app)

# Configuration
RPC_USER = 'bitcoin_user'
RPC_PASSWORD = 'your_secure_password_123'
RPC_PORT = 8332
RPC_HOST = '127.0.0.1'

# Global variables for scan state
scan_state = {
    'legacy': {
        'in_progress': False,
        'start_block': 0,
        'end_block': 0,
        'current_block': 0,
        'blocks_scanned': 0,
        'signatures_found': 0,
        'reuse_pairs': 0,
        'keys_recovered': 0,
        'logs': [],
        'process': None
    },
    'taproot': {
        'in_progress': False,
        'start_block': 0,
        'end_block': 0,
        'current_block': 0,
        'blocks_scanned': 0,
        'signatures_found': 0,
        'reuse_pairs': 0,
        'keys_recovered': 0,
        'logs': [],
        'process': None
    }
}

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def rpc_request(method, params=None):
    """Make Bitcoin RPC request"""
    url = f'http://{RPC_HOST}:{RPC_PORT}/'
    headers = {'content-type': 'application/json'}
    payload = {"method": method, "params": params or [], "jsonrpc": "2.0", "id": 0}
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASSWORD}".encode()).decode()
    
    try:
        response = requests.post(url, json=payload, headers={**headers, "Authorization": f"Basic {auth}"}, timeout=10)
        response.raise_for_status()
        return response.json()['result']
    except Exception as e:
        logger.error(f"RPC request failed: {e}")
        return None

def add_log(mode, message, log_type='info'):
    """Add log entry to scan state"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    log_entry = {
        'timestamp': timestamp,
        'message': message,
        'type': log_type
    }
    scan_state[mode]['logs'].append(log_entry)
    
    # Keep only last 100 logs
    if len(scan_state[mode]['logs']) > 100:
        scan_state[mode]['logs'] = scan_state[mode]['logs'][-100:]

def run_extraction_script(mode):
    """Run the appropriate extraction script after scan completes"""
    if mode == 'legacy':
        script_name = 'extract_legacy.py'
    elif mode == 'taproot':
        script_name = 'extract_taproot.py'
    else:
        return
    
    try:
        add_log(mode, f"Running {script_name} to extract and validate keys...", 'info')
        
        # Run extraction script
        try:
            process = subprocess.Popen(
                ['python', script_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',  # Replace problematic characters
                cwd=os.getcwd()
            )
        except FileNotFoundError:
            # Fallback to python3
            process = subprocess.Popen(
                ['python3', script_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',  # Replace problematic characters
                cwd=os.getcwd()
            )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            add_log(mode, f"{script_name} completed successfully", 'success')
            
            # Parse output for useful information
            for line in stdout.split('\n'):
                if line.strip():
                    if 'Total key entries:' in line:
                        add_log(mode, f"{line.strip()}", 'info')
                    elif 'Output written to:' in line:
                        add_log(mode, f"{line.strip()}", 'success')
            
            # Count valid matches and update final statistics
            count_valid_matches(mode)
            
        else:
            add_log(mode, f"{script_name} completed with warnings", 'warning')
            if stderr:
                add_log(mode, f"Errors: {stderr.strip()}", 'error')
            # Still try to count results even if there were warnings
            count_valid_matches(mode)
        
    except Exception as e:
        add_log(mode, f"Failed to run {script_name}: {str(e)}", 'error')
        # Try to count results anyway in case some were produced
        try:
            count_valid_matches(mode)
        except:
            pass

def clear_previous_results(mode):
    """Clear previous scan output files to ensure clean results"""
    files_to_clear = [
        f'{mode}_scan_output.txt',
        f'recovered_{mode}_pk.json'
    ]
    
    for filename in files_to_clear:
        try:
            if os.path.exists(filename):
                os.remove(filename)
                logger.info(f"Cleared previous file: {filename}")
        except Exception as e:
            logger.warning(f"Could not clear file {filename}: {e}")

def count_valid_matches(mode):
    """Count and log results with valid matches"""
    try:
        json_file = f'recovered_{mode}_pk.json'
        if not os.path.exists(json_file):
            add_log(mode, f"No results file found: {json_file}", 'warning')
            return
        
        with open(json_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
        
        if not results:
            add_log(mode, "No keys were recovered from this scan", 'info')
            # Update scan state with final count
            scan_state[mode]['keys_recovered'] = 0
            return
        
        # Count total results
        total_keys = len(results)
        
        # Count valid matches (both tx1_match and tx2_match are true)
        valid_matches = [r for r in results if r.get('tx1_match') == True and r.get('tx2_match') == True]
        valid_count = len(valid_matches)
        
        # Count partial matches
        partial_matches = [r for r in results if (r.get('tx1_match') == True) != (r.get('tx2_match') == True)]
        partial_count = len(partial_matches)
        
        # Update scan state with final statistics
        scan_state[mode]['keys_recovered'] = total_keys
        
        # If we have reuse pairs info, also update that
        if total_keys > 0 and scan_state[mode]['reuse_pairs'] == 0:
            # Estimate reuse pairs from recovered keys (rough approximation)
            scan_state[mode]['reuse_pairs'] = total_keys
        
        # Log summary
        add_log(mode, f"Extraction Summary:", 'success')
        add_log(mode, f"   Total Keys Recovered: {total_keys}", 'info')
        add_log(mode, f"   Valid Matches (both TX): {valid_count}", 'success')
        add_log(mode, f"   Partial Matches: {partial_count}", 'warning')
        add_log(mode, f"   Invalid Matches: {total_keys - valid_count - partial_count}", 'error')
        
        if valid_count > 0:
            add_log(mode, f"Found {valid_count} fully validated private keys!", 'success')
            
            # Log some details about valid matches
            for i, match in enumerate(valid_matches[:3]):  # Show first 3
                addr_compressed = match.get('compressed_address', 'N/A')
                addr_uncompressed = match.get('uncompressed_address', 'N/A')
                add_log(mode, f"   Key #{i+1}: {addr_compressed}", 'success')
            
            if len(valid_matches) > 3:
                add_log(mode, f"   ... and {len(valid_matches) - 3} more", 'info')
        else:
            add_log(mode, "No fully validated matches found", 'warning')
        
        # Update scan state with final counts
        scan_state[mode]['keys_recovered'] = valid_count
        
        # Log final update to trigger frontend refresh
        add_log(mode, f"Statistics updated: {valid_count} validated keys ready for display", 'success')
        
    except Exception as e:
        add_log(mode, f"Error analyzing results: {str(e)}", 'error')

def run_scan_script(mode, start_block, end_block):
    """Run the appropriate scan script in a separate thread"""
    script_name = 'scan_legacy.py' if mode == 'legacy' else 'scan_taproot.py'
    
    try:
        add_log(mode, f"Starting {mode} scan from block {start_block} to {end_block}")
        
        # Create input for the script with real-time output
        process = subprocess.Popen(
            ['python', script_name],  # Try 'python' first, fallback to 'python3'
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True,
            cwd=os.getcwd()
        )
        
        scan_state[mode]['process'] = process
        
        # Send block range to stdin
        input_data = f"{start_block}\n{end_block}\n"
        process.stdin.write(input_data)
        process.stdin.flush()
        process.stdin.close()
        
        # Read output line by line in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                add_log(mode, line, 'info')
                
                # Parse different types of output for progress updates
                if 'Block' in line:
                    # Try multiple formats to catch all variations
                    
                    # Format 1: "Block 123: 45 signatures found"
                    match = re.search(r'Block (\d+): (\d+) signatures found', line)
                    if match:
                        block_num = int(match.group(1))
                        sig_count = int(match.group(2))
                        scan_state[mode]['current_block'] = block_num
                        scan_state[mode]['blocks_scanned'] += 1
                        scan_state[mode]['signatures_found'] += sig_count
                        logger.info(f"Parsed block {block_num}: {sig_count} signatures. Total blocks: {scan_state[mode]['blocks_scanned']}, Total sigs: {scan_state[mode]['signatures_found']}")
                        add_log(mode, f"✅ Block {block_num}: {sig_count} signatures processed")
                        continue
                    
                    # Format 2: "Block 123: 45 signatures"
                    match = re.search(r'Block (\d+): (\d+) signatures', line)
                    if match:
                        block_num = int(match.group(1))
                        sig_count = int(match.group(2))
                        scan_state[mode]['current_block'] = block_num
                        scan_state[mode]['blocks_scanned'] += 1
                        scan_state[mode]['signatures_found'] += sig_count
                        add_log(mode, f"✅ Block {block_num}: {sig_count} signatures processed")
                        continue
                    
                    # Format 3: Taproot format "Block 123: 10 legacy, 5 segwit, 2 taproot, 3 skipped"
                    match = re.search(r'Block (\d+): (\d+) legacy, (\d+) segwit, (\d+) taproot, (\d+) skipped', line)
                    if match:
                        block_num = int(match.group(1))
                        legacy_count = int(match.group(2))
                        segwit_count = int(match.group(3))
                        taproot_count = int(match.group(4))
                        total_sigs = legacy_count + segwit_count + taproot_count
                        scan_state[mode]['current_block'] = block_num
                        scan_state[mode]['blocks_scanned'] += 1
                        scan_state[mode]['signatures_found'] += total_sigs
                        add_log(mode, f"✅ Block {block_num}: {total_sigs} total signatures ({legacy_count} legacy, {segwit_count} segwit, {taproot_count} taproot)")
                        continue
                    
                    # Format 4: Just "Block 123" - count as scanned even without signature info
                    match = re.search(r'Block (\d+)', line)
                    if match:
                        block_num = int(match.group(1))
                        scan_state[mode]['current_block'] = block_num
                        scan_state[mode]['blocks_scanned'] += 1
                        add_log(mode, f"📊 Block {block_num}: processed")
                
                elif 'reused nonce pairs' in line:
                    match = re.search(r'Found (\d+) reused nonce pairs', line)
                    if match:
                        pairs_count = int(match.group(1))
                        scan_state[mode]['reuse_pairs'] = pairs_count
                        add_log(mode, f"Found {pairs_count} reused nonce pairs", 'success')
                
                elif 'Private Key Recovered' in line or '✅ Private Key Recovered' in line:
                    scan_state[mode]['keys_recovered'] += 1
                    add_log(mode, "Private key recovered!", 'success')
                
                elif 'Completed signature extraction' in line:
                    add_log(mode, "Signature extraction completed", 'success')
                
                elif 'Searching for reused nonces' in line:
                    add_log(mode, "Analyzing signatures for nonce reuse...", 'info')
        
        # Check for any remaining stderr output
        stderr_output = process.stderr.read()
        if stderr_output:
            add_log(mode, f"Script errors: {stderr_output}", 'error')
        
        # Wait for process to complete
        return_code = process.wait()
        
        if return_code == 0:
            add_log(mode, f"{mode.capitalize()} scan completed successfully", 'success')
            add_log(mode, "Starting key extraction and validation...", 'info')
            
            # Automatically run extraction script after scan completes
            run_extraction_script(mode)
            
            # Mark scan as completed only after extraction
            add_log(mode, "Scan and extraction process completed", 'success')
        else:
            add_log(mode, f"{mode.capitalize()} scan completed with errors (code: {return_code})", 'warning')
        
    except FileNotFoundError:
        # Try with python3 if python fails
        try:
            add_log(mode, "Retrying with python3...", 'info')
            process = subprocess.Popen(
                ['python3', script_name],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                cwd=os.getcwd()
            )
            
            scan_state[mode]['process'] = process
            
            # Send block range to stdin
            input_data = f"{start_block}\n{end_block}\n"
            process.stdin.write(input_data)
            process.stdin.flush()
            process.stdin.close()
            
            # Read output line by line in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    add_log(mode, line, 'info')
                    
                    # Same parsing logic as above
                    if 'Block' in line:
                        # Format 1: "Block 123: 45 signatures found"
                        match = re.search(r'Block (\d+): (\d+) signatures found', line)
                        if match:
                            block_num = int(match.group(1))
                            sig_count = int(match.group(2))
                            scan_state[mode]['current_block'] = block_num
                            scan_state[mode]['blocks_scanned'] += 1
                            scan_state[mode]['signatures_found'] += sig_count
                            continue
                        
                        # Format 2: "Block 123: 45 signatures"
                        match = re.search(r'Block (\d+): (\d+) signatures', line)
                        if match:
                            block_num = int(match.group(1))
                            sig_count = int(match.group(2))
                            scan_state[mode]['current_block'] = block_num
                            scan_state[mode]['blocks_scanned'] += 1
                            scan_state[mode]['signatures_found'] += sig_count
                            continue
                        
                        # Format 3: Taproot format
                        match = re.search(r'Block (\d+): (\d+) legacy, (\d+) segwit, (\d+) taproot, (\d+) skipped', line)
                        if match:
                            block_num = int(match.group(1))
                            legacy_count = int(match.group(2))
                            segwit_count = int(match.group(3))
                            taproot_count = int(match.group(4))
                            total_sigs = legacy_count + segwit_count + taproot_count
                            scan_state[mode]['current_block'] = block_num
                            scan_state[mode]['blocks_scanned'] += 1
                            scan_state[mode]['signatures_found'] += total_sigs
                            continue
                        
                        # Format 4: Just "Block 123"
                        match = re.search(r'Block (\d+)', line)
                        if match:
                            block_num = int(match.group(1))
                            scan_state[mode]['current_block'] = block_num
                            scan_state[mode]['blocks_scanned'] += 1
                    
                    elif 'reused nonce pairs' in line:
                        match = re.search(r'Found (\d+) reused nonce pairs', line)
                        if match:
                            scan_state[mode]['reuse_pairs'] = int(match.group(1))
                    
                    elif 'Private Key Recovered' in line or '✅ Private Key Recovered' in line:
                        scan_state[mode]['keys_recovered'] += 1
            
            stderr_output = process.stderr.read()
            if stderr_output:
                add_log(mode, f"Script errors: {stderr_output}", 'error')
            
            return_code = process.wait()
            if return_code == 0:
                add_log(mode, f"{mode.capitalize()} scan completed successfully", 'success')
                add_log(mode, "Starting key extraction and validation...", 'info')
                
                # Automatically run extraction script after scan completes
                run_extraction_script(mode)
                
                # Mark scan as completed only after extraction
                add_log(mode, "Scan and extraction process completed", 'success')
            else:
                add_log(mode, f"{mode.capitalize()} scan completed with errors (code: {return_code})", 'warning')
                
        except Exception as e:
            add_log(mode, f"Scan failed: {str(e)}", 'error')
    
    except Exception as e:
        add_log(mode, f"Scan failed: {str(e)}", 'error')
    finally:
        # Only mark as not in progress after everything is complete
        scan_state[mode]['in_progress'] = False
        scan_state[mode]['process'] = None

def get_scan_results(mode, only_valid_matches=True):
    """Load and parse scan results, optionally filtering for valid matches only"""
    try:
        # Load JSON results
        json_file = f'recovered_{mode}_pk.json'
        if os.path.exists(json_file):
            with open(json_file, 'r', encoding='utf-8') as f:
                results = json.load(f)
                
                if only_valid_matches:
                    # Filter for entries where both tx1_match and tx2_match are true
                    valid_results = [r for r in results if r.get('tx1_match') == True and r.get('tx2_match') == True]
                    logger.info(f"Filtered results: {len(valid_results)} valid matches out of {len(results)} total")
                    return valid_results
                else:
                    return results
        
        # Load text results (fallback)
        txt_file = f'{mode}_scan_output.txt'
        if os.path.exists(txt_file):
            with open(txt_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Parse text output to extract basic info
                results = []
                lines = content.split('\n')
                current_result = {}
                
                for line in lines:
                    if 'Private Key Recovered:' in line or '✅ Private Key Recovered:' in line:
                        if current_result:
                            results.append(current_result)
                        # Extract private key from line
                        key_match = re.search(r'([a-fA-F0-9]{64})', line)
                        if key_match:
                            current_result = {'private_key': key_match.group(1)}
                    elif 'TX1:' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            current_result['tx1'] = parts[1]
                            current_result['tx1_input'] = int(parts[3])
                    elif 'TX2:' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            current_result['tx2'] = parts[1]
                            current_result['tx2_input'] = int(parts[3])
                
                if current_result:
                    results.append(current_result)
                
                return results
        
        return []
        
    except Exception as e:
        logger.error(f"Error loading results: {e}")
        return []

@app.route('/')
def index():
    """Serve the main interface"""
    return send_file('index.html')

@app.route('/api/current-height')
def get_current_height():
    """Get current Bitcoin block height"""
    try:
        height = rpc_request('getblockcount')
        return jsonify({'height': height if height else 0})
    except Exception as e:
        logger.error(f"Error getting current height: {e}")
        return jsonify({'height': 0})

@app.route('/api/start-scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    try:
        data = request.get_json()
        mode = data.get('mode', 'legacy')
        start_block = int(data.get('startBlock', 0))
        end_block = int(data.get('endBlock', 1000))
        
        if scan_state[mode]['in_progress']:
            return jsonify({'error': 'Scan already in progress'}), 400
        
        # Clear previous output files
        clear_previous_results(mode)
        
        # Reset scan state
        scan_state[mode].update({
            'in_progress': True,
            'start_block': start_block,
            'end_block': end_block,
            'current_block': start_block,
            'blocks_scanned': 0,
            'signatures_found': 0,
            'reuse_pairs': 0,
            'keys_recovered': 0,
            'logs': []
        })
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_scan_script,
            args=(mode, start_block, end_block)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'message': 'Scan started successfully'})
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-progress')
def get_scan_progress():
    """Get current scan progress"""
    try:
        mode = request.args.get('mode', 'legacy')
        state = scan_state[mode]
        
        # Debug logging
        logger.info(f"Progress request for {mode}: in_progress={state['in_progress']}, blocks_scanned={state['blocks_scanned']}, signatures_found={state['signatures_found']}")
        
        if not state['in_progress']:
            # Return final statistics even when completed
            return jsonify({
                'completed': True,
                'start_block': state['start_block'],
                'end_block': state['end_block'],
                'current_block': state['current_block'],
                'blocks_scanned': state['blocks_scanned'],
                'signatures_found': state['signatures_found'],
                'reuse_pairs': state['reuse_pairs'],
                'keys_recovered': state['keys_recovered']
            })
        
        progress_data = {
            'completed': False,
            'start_block': state['start_block'],
            'end_block': state['end_block'],
            'current_block': state['current_block'],
            'blocks_scanned': state['blocks_scanned'],
            'signatures_found': state['signatures_found'],
            'reuse_pairs': state['reuse_pairs'],
            'keys_recovered': state['keys_recovered']
        }
        
        return jsonify(progress_data)
        
    except Exception as e:
        logger.error(f"Error getting progress: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-log')
def get_scan_log():
    """Get scan logs"""
    try:
        mode = request.args.get('mode', 'legacy')
        logs = scan_state[mode]['logs']
        
        # Return only new logs since last request
        last_log_count = request.args.get('last_count', 0)
        new_logs = logs[int(last_log_count):]
        
        return jsonify({'logs': new_logs})
        
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-results')
def get_scan_results_api():
    """Get scan results"""
    try:
        mode = request.args.get('mode', 'legacy')
        show_all = request.args.get('show_all', 'false').lower() == 'true'
        
        # By default, only show valid matches (both tx1_match and tx2_match are true)
        results = get_scan_results(mode, only_valid_matches=not show_all)
        
        return jsonify({
            'results': results,
            'filtered': not show_all,
            'count': len(results)
        })
        
    except Exception as e:
        logger.error(f"Error getting results: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/download-results')
def download_results():
    """Download scan results as JSON"""
    try:
        mode = request.args.get('mode', 'legacy')
        show_all = request.args.get('show_all', 'false').lower() == 'true'
        
        # By default, only download valid matches
        results = get_scan_results(mode, only_valid_matches=not show_all)
        
        # Create temporary file
        suffix = '_all' if show_all else '_valid_only'
        filename = f'{mode}_scan_results{suffix}.json'
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        return send_file(filename, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Error downloading results: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-balances', methods=['POST'])
def check_balances():
    """Check balances for recovered addresses"""
    try:
        data = request.get_json()
        mode = data.get('mode', 'legacy')
        show_all = data.get('show_all', False)
        
        # By default, only check balances for valid matches
        results = get_scan_results(mode, only_valid_matches=not show_all)
        
        balances = []
        
        for result in results:
            # Check both compressed and uncompressed addresses
            addresses = []
            if 'compressed_address' in result:
                addresses.append(result['compressed_address'])
            if 'uncompressed_address' in result:
                addresses.append(result['uncompressed_address'])
            
            for address in addresses:
                try:
                    # Use scantxoutset for balance checking
                    balance_result = rpc_request('scantxoutset', ['start', [{'desc': f'addr({address})'}]])
                    if balance_result:
                        balance = balance_result.get('total_amount', 0)
                        balances.append({
                            'address': address,
                            'balance': balance,
                            'private_key': result.get('private_key', '')
                        })
                except Exception as e:
                    logger.error(f"Error checking balance for {address}: {e}")
        
        return jsonify({'balances': balances})
        
    except Exception as e:
        logger.error(f"Error checking balances: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop-scan', methods=['POST'])
def stop_scan():
    """Stop current scan"""
    try:
        data = request.get_json()
        mode = data.get('mode', 'legacy')
        
        if scan_state[mode]['process']:
            scan_state[mode]['process'].terminate()
            scan_state[mode]['in_progress'] = False
            add_log(mode, 'Scan stopped by user', 'warning')
        
        return jsonify({'message': 'Scan stopped'})
        
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-status')
def get_scan_status():
    """Get overall scan status"""
    try:
        status = {}
        for mode in ['legacy', 'taproot']:
            status[mode] = {
                'in_progress': scan_state[mode]['in_progress'],
                'blocks_scanned': scan_state[mode]['blocks_scanned'],
                'keys_recovered': scan_state[mode]['keys_recovered']
            }
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Set console encoding for Windows compatibility
    import sys
    if sys.platform.startswith('win'):
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    
    print("Starting Bitcoin Reused-R Scanner Backend...")
    print("Frontend will be available at: http://localhost:5000")
    print("Make sure your Bitcoin node is running and RPC is configured")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 