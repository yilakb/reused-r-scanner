#!/usr/bin/env python3
"""
Startup script for Bitcoin Reused-R Scanner Toolkit
Checks dependencies and launches the web interface
"""

import sys
import subprocess
import os
import importlib.util

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = [
        'flask',
        'flask_cors', 
        'requests',
        'ecdsa',
        'base58'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        spec = importlib.util.find_spec(package)
        if spec is None:
            missing_packages.append(package)
        else:
            print(f"✅ {package} is installed")
    
    if missing_packages:
        print(f"\n❌ Missing packages: {', '.join(missing_packages)}")
        print("Install them with: pip install -r requirements.txt")
        return False
    
    return True

def check_bitcoin_rpc():
    """Check if Bitcoin RPC is accessible"""
    try:
        import requests
        import base64
        
        # Test RPC connection
        url = 'http://127.0.0.1:8332/'
        headers = {'content-type': 'application/json'}
        payload = {"method": "getblockcount", "params": [], "jsonrpc": "2.0", "id": 0}
        auth = base64.b64encode(b"bitcoin_user:your_secure_password_123").decode()
        
        response = requests.post(url, json=payload, headers={**headers, "Authorization": f"Basic {auth}"}, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            if 'result' in result:
                print(f"✅ Bitcoin RPC connected (Height: {result['result']})")
                return True
            else:
                print("⚠️ Bitcoin RPC responded but with error")
                return False
        else:
            print(f"⚠️ Bitcoin RPC connection failed (Status: {response.status_code})")
            return False
            
    except Exception as e:
        print(f"⚠️ Bitcoin RPC not accessible: {e}")
        print("Make sure Bitcoin Core is running and RPC is configured")
        return False

def check_files():
    """Check if required files exist"""
    required_files = [
        'index.html',
        'app.py',
        'scan_legacy.py',
        'scan_taproot.py'
    ]
    
    missing_files = []
    
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file} found")
        else:
            missing_files.append(file)
            print(f"❌ {file} missing")
    
    if missing_files:
        print(f"\n❌ Missing files: {', '.join(missing_files)}")
        return False
    
    return True

def main():
    """Main startup function"""
    print("🚀 Bitcoin Reused-R Scanner Toolkit")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    print("\n📦 Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    
    print("\n📁 Checking files...")
    if not check_files():
        sys.exit(1)
    
    print("\n🔗 Checking Bitcoin RPC...")
    bitcoin_ok = check_bitcoin_rpc()
    if not bitcoin_ok:
        print("\n⚠️ Warning: Bitcoin RPC not accessible")
        print("The scanner will work but balance checking may fail")
        print("Make sure to configure RPC settings in the script files")
    
    print("\n🎯 Starting web interface...")
    print("📱 Frontend will be available at: http://localhost:5000")
    print("🔧 Backend API will be available at: http://localhost:5000/api/")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        # Import and run Flask app
        from app import app
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 