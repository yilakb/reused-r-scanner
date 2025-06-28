# Bitcoin Reused-R Scanner Toolkit

A comprehensive security analysis tool for detecting and exploiting ECDSA nonce reuse vulnerabilities in Bitcoin transactions. This toolkit includes both command-line scanning tools and a modern web interface for easy interaction.

## 🚨 Security Notice

This tool is designed for **security research and educational purposes only**. It demonstrates a real cryptographic vulnerability in ECDSA signatures. Use responsibly and only on systems you own or have explicit permission to test.

## 🎯 Features

### Core Scanning Capabilities
- **Legacy P2PKH Support**: Scan traditional Bitcoin addresses
- **SegWit P2WPKH Support**: Scan native SegWit addresses
- **Taproot P2TR Support**: Scan Schnorr signature addresses
- **Cross-Transaction Analysis**: Detect nonce reuse across different transactions
- **Real-time Progress Tracking**: Monitor scan progress with detailed statistics
- **Private Key Recovery**: Automatically recover private keys from vulnerable signatures

### Web Interface Features
- **Modern UI**: Clean, responsive design with Bootstrap 5
- **Mode Selection**: Toggle between Legacy and SegWit/Taproot scanning
- **Block Range Configuration**: Specify custom block ranges for scanning
- **Real-time Progress**: Live progress bars and statistics
- **Log Streaming**: Real-time scan logs with timestamps
- **Result Display**: Formatted display of recovered private keys
- **Balance Checking**: Verify if recovered addresses have funds
- **Download Options**: Export results in JSON format
  ![image](https://github.com/user-attachments/assets/7cf1a937-703b-4e22-a837-349507240a75)


## 📋 Prerequisites

### System Requirements
- Python 3.7 or higher
- Bitcoin Core node (for RPC access)
- 8GB+ RAM (for large block ranges)
- Stable internet connection

### Bitcoin Node Setup
1. Install Bitcoin Core
2. Enable RPC in `bitcoin.conf`:
   ```
   server=1
   rpcuser=bitcoin_user
   rpcpassword=your_secure_password_123
   rpcport=8332
   rpcallowip=127.0.0.1
   ```
3. Start Bitcoin Core and wait for initial sync

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd reused_r_scanner
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure RPC Settings
Edit the RPC credentials in the following files:
- `scan_legacy.py`
- `scan_taproot.py`
- `app.py`
- `balance_lookup_rpc.py`

Update these variables:
```python
RPC_USER = 'your_bitcoin_rpc_user'
RPC_PASSWORD = 'your_bitcoin_rpc_password'
RPC_PORT = 8332
RPC_HOST = '127.0.0.1'
```

## 🚀 Usage

### Web Interface (Recommended)

1. **Start the Backend Server**
   ```bash
   python app.py
   ```

2. **Access the Web Interface**
   Open your browser and navigate to: `http://localhost:5000`

3. **Configure Scan Settings**
   - Select scan mode (Legacy or SegWit/Taproot)
   - Enter block range (start and end blocks)
   - Click "Start Scan"

4. **Monitor Progress**
   - Watch real-time progress bars
   - View live scan logs
   - Check statistics (blocks scanned, signatures found, etc.)

5. **Review Results**
   - View recovered private keys in formatted cards
   - Check transaction match status
   - Download results as JSON
   - Verify address balances

### Command Line Interface

#### Legacy Scanning
```bash
python scan_legacy.py
# Enter start block when prompted
# Enter end block when prompted
```

#### Taproot/SegWit Scanning
```bash
python scan_taproot.py
# Enter start block when prompted
# Enter end block when prompted
```

#### Extract and Validate Results
```bash
# For legacy results
python extract_legacy.py

# For taproot results
python extract_taproot.py
```

#### Check Balances
```bash
# Using RPC (requires Bitcoin node)
python balance_lookup_rpc.py

# Using mempool.space API
python balance_lookup_mempool.py
```

## 📊 Understanding the Results

### Scan Output Files
- `legacy_scan_output.txt` / `taproot_scan_output.txt`: Raw scan results
- `recovered_legacy_pk.json` / `recovered_taproot_pk.json`: Structured key data
- `nonzero_balances.txt`: Addresses with non-zero balances

### Result Structure
Each recovered key includes:
```json
{
  "private_key": "64-character hex string",
  "compressed_pubkey": "66-character hex string",
  "uncompressed_pubkey": "130-character hex string",
  "compressed_address": "Base58 address",
  "uncompressed_address": "Base58 address",
  "tx1": "Transaction ID 1",
  "tx1_input": 0,
  "tx2": "Transaction ID 2",
  "tx2_input": 0,
  "tx1_match": true,
  "tx2_match": true
}
```

## 🔧 Configuration Options

### Performance Tuning
- **MAX_WORKERS**: Number of concurrent threads (default: 8)
- **MAX_RETRIES**: RPC retry attempts (default: 1)
- **RETRY_DELAY**: Delay between retries (default: 0.2s)

### Block Range Guidelines
- **Small Range**: 1-1000 blocks (quick testing)
- **Medium Range**: 1000-10000 blocks (moderate scanning)
- **Large Range**: 10000+ blocks (comprehensive analysis)

## 🛡️ Security Considerations

### Best Practices
1. **Use Testnet**: Test on Bitcoin testnet first
2. **Isolated Environment**: Run in a dedicated VM or container
3. **Secure RPC**: Use strong passwords and restrict RPC access
4. **Regular Updates**: Keep Bitcoin Core and dependencies updated

### Ethical Usage
- Only scan blocks you own or have permission to analyze :) 
- Respect privacy and don't exploit found vulnerabilities
- Report significant findings to the Bitcoin community
- Use for educational and research purposes only

## 🐛 Troubleshooting

### Common Issues

#### RPC Connection Failed
```
Error: Connection refused
```
**Solution**: Ensure Bitcoin Core is running and RPC is properly configured

#### Permission Denied
```
Error: Permission denied when running scripts
```
**Solution**: Make scripts executable: `chmod +x *.py`

#### Memory Issues
```
Error: Out of memory during large scans
```
**Solution**: Reduce block range or increase system RAM

#### Flask Import Error
```
Error: No module named 'flask'
```
**Solution**: Install dependencies: `pip install -r requirements.txt`

### Debug Mode
Enable debug logging by setting:
```python
logging.basicConfig(level=logging.DEBUG)
```

## 📈 Performance Tips

1. **Use SSD Storage**: Faster block data access
2. **Optimize Block Range**: Start with smaller ranges for testing
3. **Monitor Resources**: Watch CPU and memory usage
4. **Network Optimization**: Use local Bitcoin node for faster RPC calls

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided "as is" without warranty. The authors are not responsible for any misuse or damage caused by this software. Use at your own risk and in accordance with applicable laws and regulations.

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review existing GitHub issues
3. Create a new issue with detailed information

---

**Remember**: This tool demonstrates real cryptographic vulnerabilities. Use responsibly and ethically! 
