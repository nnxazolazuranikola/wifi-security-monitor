# WiFi Security Monitor Documentation

Welcome to the WiFi Security Monitor documentation. This comprehensive toolkit provides two powerful tools for monitoring WiFi security and network activity.

## Quick Links

- [Getting Started Guide](getting-started.md)
- [Project Summary](project-summary.md)
- [Architecture Overview](architecture.md)
- [Deauth Detector Guide](deauth-detector.md)
- [Network Monitor Guide](network-monitor.md)
- [Configuration Reference](configuration.md)
- [API Reference](api-reference.md)
- [Troubleshooting](troubleshooting.md)
- [FAQ](faq.md)

## Overview

The WiFi Security Monitor consists of two main components:

### 1. Deauth Attack Detector (`deauth_detector.py`)
A sophisticated tool that detects and analyzes WiFi deauthentication attacks using behavioral analysis instead of relying on hardware MAC addresses. It identifies:
- Deauth/Disassociation attacks
- MAC spoofing attempts
- Router impersonation
- Attack patterns and timing anomalies

### 2. Network Device Monitor (`network_monitor.py`)
A comprehensive network monitoring tool that:
- Tracks all devices on your network
- Identifies IoT devices (ESP32, cameras, smart home devices)
- Detects suspicious or unknown devices
- Maintains persistent connection history
- Provides connection statistics

## Key Features

- 🔍 **Dual-band monitoring** - Supports both 2.4GHz and 5GHz
- 🧠 **Behavioral analysis** - Advanced pattern recognition
- 🎭 **MAC spoofing detection** - Identifies impersonation attempts
- 📊 **Smart threat scoring** - Differentiates legitimate from malicious activity
- 📝 **Forensic logging** - Detailed evidence collection
- 📈 **Connection statistics** - Historical tracking and analysis
- 🏠 **Device classification** - Automatic identification of device types

## Requirements

### Hardware
- WiFi adapter with **monitor mode** support
- Tested chipsets: Atheros (ath9k), Ralink/MediaTek (RT2800, MT7612U), Realtek (RTL8812AU)
- Popular adapters: Alfa AWUS036NHA, TP-Link TL-WN722N, Alfa AWUS036ACH

### Software
- Linux (tested on Raspberry Pi & Ubuntu)
- Python 3.7+
- Root/sudo access (required for monitor mode)
- Scapy 2.5.0+

## Quick Start

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/wifi-security-monitor.git
cd wifi-security-monitor

# Install dependencies
pip3 install -r requirements.txt

# Enable monitor mode
sudo airmon-ng start wlan0

# Configure
cp config.example.json config.json
nano config.json

# Run
sudo python3 deauth_detector.py
```

For detailed installation instructions, see the [Getting Started Guide](getting-started.md).

## Documentation Structure

- **Getting Started** - Installation, setup, and first run
- **Architecture** - System design and technical details
- **Tool Guides** - Detailed usage for each tool
- **Configuration** - Complete configuration reference
- **API Reference** - Code documentation and API details
- **Troubleshooting** - Common issues and solutions
- **FAQ** - Frequently asked questions

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: Check the guides in this docs folder
- Examples: See `config.example.json` and `monitor_config.example.json`
