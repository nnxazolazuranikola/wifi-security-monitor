# WiFi Security Monitor

Comprehensive WiFi security toolkit with two powerful tools:
1. **Deauth Attack Detector** - Detects and analyzes WiFi deauthentication attacks with behavioral analysis
2. **Network Device Monitor** - Tracks all network devices, detects suspicious activity, and identifies IoT devices

## Features

### 🛡️ Deauth Attack Detector (`deauth_detector.py`)
- 🔍 **Dual-band monitoring** (2.4GHz & 5GHz)
- 🧠 **Behavioral analysis** - Detects attacks through timing patterns, RSSI variations, and sequence anomalies
- 🎭 **MAC spoofing detection** - Identifies attackers impersonating routers
- 📊 **Smart threat scoring** - Differentiates legitimate router behavior from attacks
- 📝 **Forensic logging** - Detailed evidence collection for investigation

### 📡 Network Device Monitor (`network_monitor.py`)
- 👀 **Device tracking** - Monitor all devices on your network
- 🔧 **IoT detection** - Identifies ESP32, cameras, smart home devices
- 📊 **Persistent database** - Tracks total connection time and history
- ⚠️ **Suspicious device alerts** - Detects unknown/new devices
- 🏠 **"Belongs here" detection** - Automatically identifies regular devices
- 📈 **Connection statistics** - See which devices are always present

### 🌐 Universal
- Works with any **monitor mode** capable WiFi adapter
- Run both tools simultaneously with 2 adapters

## How It Works

Instead of relying on hardware MAC addresses (which most adapters don't expose), this scanner uses advanced behavioral fingerprinting:

- **Timing Analysis**: Legitimate routers have consistent timing; attack tools show irregular patterns
- **RSSI Tracking**: Sudden signal strength changes indicate device switching
- **Sequence Numbers**: Duplicate or anomalous sequence numbers reveal spoofing
- **Rate Analysis**: Attack tools often use unusual transmission rates
- **Legitimacy Scoring**: Multi-factor assessment determines if a router MAC is genuine

## Requirements

### Hardware
- WiFi adapter supporting **monitor mode**
- Tested chipsets: Atheros (ath9k), Ralink/MediaTek (RT2800, MT7612U), Realtek (RTL8812AU)
- Popular adapters: Alfa AWUS036NHA, TP-Link TL-WN722N, Alfa AWUS036ACH

### Software
- Linux (tested on Raspberry Pi & Ubuntu)
- Python 3.7+
- Root/sudo access (required for monitor mode)

## Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/wifi-security-monitor.git
cd wifi-security-monitor

# Install dependencies
pip3 install -r requirements.txt

# Enable monitor mode on your adapter
sudo airmon-ng start wlan0  # Replace wlan0 with your interface
```

## Configuration

Edit `config.json` before running:

```json
{
  "network": {
    "interface": "wlan1",           // Your monitor mode interface
    "channels": [11, 112],          // Channels to monitor (2.4GHz, 5GHz)
    "whitelist_macs": [             // Your router's MAC addresses
      "aa:bb:cc:dd:ee:ff"
    ],
    "local_device_macs": [          // Your devices to protect
      "11:22:33:44:55:66"
    ]
  }
}
```

**Finding your router MAC**: Check router label or run `iwconfig` while connected

**Finding your device MAC**: Run `ip link show` or `ifconfig`

## Usage

### Deauth Attack Detector
```bash
# Configure (first time)
cp config.example.json config.json
nano config.json  # Set your interface and optional MACs

# Start monitoring
sudo python3 deauth_detector.py

# Check logs
tail -f attacker_evidence.log
```

### Network Device Monitor
```bash
# Configure (first time)
cp monitor_config.example.json monitor_config.json
nano monitor_config.json  # Set your interface

# Start monitoring
sudo python3 network_monitor.py

# Check logs
tail -f network_devices.log
cat device_database.json  # See device history
```

### Run Both Simultaneously (Requires 2 WiFi Adapters)
```bash
# Terminal 1: Deauth detector on wlan1
sudo python3 deauth_detector.py

# Terminal 2: Network monitor on wlan2
sudo python3 network_monitor.py
```

## Understanding Output

### Threat Levels
- 🟢 **LOW (0-39)**: Likely legitimate activity
- 🟡 **MEDIUM (40-69)**: Suspicious, monitor closely  
- 🔴 **CRITICAL (70-100)**: Active attack detected

### Legitimacy Score
- 🟢 **80-100%**: Genuine router behavior
- 🟡 **50-79%**: Uncertain, verify manually
- 🔴 **0-49%**: Likely spoofed/malicious

### Example Output
```
🚨 ATTACK #5 DETECTED - 2025-12-21 22:15:30 ⚠️ ATTACKING YOUR NETWORK!
   THREAT LEVEL: 🔴 CRITICAL (85/100)
   
⚠️  ATTACKER IDENTIFICATION:
    Packet Source:     aa:bb:cc:dd:ee:ff (UnknownVendor)
    🔴 LEGITIMACY:     15% - LIKELY SPOOFED!
    
📡 SIGNAL ANALYSIS:
    Signal Strength:   -65 dBm
    Est. Distance:     ~12m
```

## Supported Adapters

### Confirmed Working
- Alfa AWUS036NHA (Atheros AR9271) ✅
- Alfa AWUS036ACH (Realtek RTL8812AU) ✅
- TP-Link TL-WN722N v1 (Atheros AR9271) ✅
- Panda PAU09 (Ralink RT5372) ✅

### Known Limitations
- Most adapters don't expose hardware MAC addresses - scanner compensates with behavioral analysis
- 5GHz monitoring requires 5GHz-capable adapter
- Built-in laptop WiFi typically doesn't support monitor mode

## Troubleshooting

**"No such device" error**
```bash
# Verify interface exists
iwconfig

# Enable monitor mode
sudo airmon-ng start wlan0
```

**"Operation not permitted"**
```bash
# Run with sudo
sudo python3 deauth_detector.py
```

**No detections**
- Verify channels match your router's frequency
- Check interface is in monitor mode: `iwconfig wlan1`
- Ensure no other processes using adapter: `sudo airmon-ng check kill`

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is for **authorized security testing only**

- Only use on networks you own or have explicit permission to test
- Monitor mode may violate local regulations in some jurisdictions
- Unauthorized network monitoring may be illegal in your country
- Author assumes no liability for misuse

## How to Test

Generate test deauth packets (for testing on your own network only):

```bash
# From another device in monitor mode
sudo aireplay-ng --deauth 5 -a ROUTER_MAC -c CLIENT_MAC wlan1mon
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test on multiple adapters if possible
4. Submit pull request with clear description

## License

Apache License 2.0 - See LICENSE file for details

## Acknowledgments

- Scapy library for packet manipulation
- WiFi security research community
- Inspired by real-world pentesting needs

## Support

- Report bugs via GitHub Issues
- Questions? Open a Discussion
- Security issues: email privately (don't open public issue)

---

**Made with ❤️ for network security**
