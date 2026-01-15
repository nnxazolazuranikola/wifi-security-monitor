# Getting Started

This guide will help you install and configure the WiFi Security Monitor tools.

## Prerequisites

Before you begin, ensure you have:

1. **Linux System** - Tested on Ubuntu 20.04+, Raspberry Pi OS
2. **WiFi Adapter** - Must support monitor mode
3. **Python 3.7+** - Check with `python3 --version`
4. **Root Access** - Required for monitor mode operations

## Checking WiFi Adapter Compatibility

### Identify Your Adapter
```bash
# List network interfaces
iwconfig

# Check adapter chipset
lsusb | grep -i wireless
```

### Recommended Adapters
- **Alfa AWUS036NHA** - Atheros AR9271 (2.4GHz)
- **TP-Link TL-WN722N v1** - Atheros AR9271 (2.4GHz)
- **Alfa AWUS036ACH** - Realtek RTL8812AU (Dual-band)
- **AWUS036ACM** - MediaTek MT7612U (Dual-band)

### Test Monitor Mode
```bash
# Install aircrack-ng suite if needed
sudo apt-get install aircrack-ng

# Enable monitor mode
sudo airmon-ng start wlan0

# Check if monitor interface was created
iwconfig
# Look for wlan0mon or similar
```

## Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/wifi-security-monitor.git
cd wifi-security-monitor
```

### Step 2: Install Dependencies
```bash
# Update package list
sudo apt-get update

# Install Python dependencies
pip3 install -r requirements.txt

# If you encounter issues, install system packages
sudo apt-get install python3-pip python3-scapy
```

### Step 3: Verify Installation
```bash
# Test configuration validator
python3 test_config.py

# Check Python imports
python3 -c "from scapy.all import *; print('Scapy OK')"
```

## Configuration

### Deauth Detector Setup

1. **Copy example configuration:**
```bash
cp config.example.json config.json
```

2. **Edit configuration:**
```bash
nano config.json
```

3. **Essential settings:**
```json
{
  "network": {
    "interface": "wlan0mon",        // Your monitor mode interface
    "channels": [11, 112],          // Channels to monitor
    "whitelist_macs": [             // Your router MAC(s)
      "aa:bb:cc:dd:ee:ff"
    ],
    "local_device_macs": [          // Your devices to protect
      "11:22:33:44:55:66"
    ]
  }
}
```

**Finding Your Router MAC:**
- Check the label on your router
- Run `iwconfig` while connected
- Check router admin interface

**Finding Your Device MAC:**
```bash
# Linux
ip link show

# View all network interfaces
ifconfig
```

### Network Monitor Setup

1. **Copy example configuration:**
```bash
cp monitor_config.example.json monitor_config.json
```

2. **Edit configuration:**
```bash
nano monitor_config.json
```

3. **Essential settings:**
```json
{
  "network": {
    "interface": "wlan0mon",
    "channels": [1, 6, 11, 36, 40, 44, 48],
    "known_devices": [              // Your router MACs
      "aa:bb:cc:dd:ee:ff"
    ]
  },
  "alerts": {
    "alert_on_new_device": true,
    "alert_on_iot_device": true
  }
}
```

## First Run

### Running Deauth Detector

1. **Enable monitor mode:**
```bash
sudo airmon-ng start wlan0
```

2. **Start the detector:**
```bash
sudo python3 deauth_detector.py
```

3. **Expected output:**
```
🛡️  WiFi Deauth Attack Detector Started
📡 Interface: wlan0mon
📻 Monitoring channels: [11, 112]
⏱️  Channel dwell time: 1.5s

[2025-12-27 10:30:15] 📊 Monitoring channel 11...
```

4. **Check logs:**
```bash
# View real-time logs
tail -f attacker_evidence.log

# View all events
cat attacker_evidence.log
```

### Running Network Monitor

1. **Start the monitor:**
```bash
sudo python3 network_monitor.py
```

2. **Expected output:**
```
📡 WiFi Network Device Monitor Started
🔍 Interface: wlan0mon
📻 Scanning channels: [1, 6, 11, 36, 40, 44, 48]

[10:30:15] 👤 New device: aa:bb:cc:dd:ee:ff
           Manufacturer: Apple Inc.
           Signal: -45 dBm
           Status: KNOWN DEVICE ✓
```

3. **Check device database:**
```bash
# View stored device information
cat data/device_database.json | python3 -m json.tool
```

## Running Both Tools Simultaneously

If you have two WiFi adapters:

```bash
# Terminal 1: Deauth detector on wlan0mon
sudo python3 deauth_detector.py

# Terminal 2: Network monitor on wlan1mon
sudo python3 network_monitor.py
```

## Quick Setup Script

For automated setup:

```bash
# Make setup script executable
chmod +x setup.sh

# Run setup
./setup.sh
```

The script will:
- Check for required dependencies
- Enable monitor mode
- Create configuration files from examples
- Guide you through basic configuration

## Stopping the Tools

### Graceful Shutdown
Press `Ctrl+C` in the terminal running the tool.

### Disable Monitor Mode
```bash
# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Restart NetworkManager if needed
sudo systemctl restart NetworkManager
```

## Testing Your Setup

### 1. Verify Monitor Mode
```bash
# Check interface status
iwconfig wlan0mon

# Should show "Mode:Monitor"
```

### 2. Test Packet Capture
```bash
# Capture a few packets to test
sudo timeout 10s tcpdump -i wlan0mon -c 10

# You should see WiFi frames
```

### 3. Configuration Validator
```bash
# Test configuration files
python3 test_config.py
```

## Next Steps

- Read the [Deauth Detector Guide](deauth-detector.md) for detailed usage
- Read the [Network Monitor Guide](network-monitor.md) for monitoring features
- Check [Configuration Reference](configuration.md) for all options
- See [Troubleshooting](troubleshooting.md) if you encounter issues

## Common First-Run Issues

### Interface Not Found
**Problem:** "Interface wlan0mon not found"
**Solution:** 
```bash
# Check actual interface name
iwconfig

# Use correct name in config.json
```

### Permission Denied
**Problem:** "Permission denied"
**Solution:** Run with sudo
```bash
sudo python3 deauth_detector.py
```

### No Packets Received
**Problem:** Tool runs but shows no activity
**Solution:**
1. Verify monitor mode is active: `iwconfig`
2. Check channel settings match your network
3. Ensure adapter supports the frequency band

### Scapy Import Error
**Problem:** "ModuleNotFoundError: No module named 'scapy'"
**Solution:**
```bash
# Install scapy
pip3 install scapy

# Or use system package
sudo apt-get install python3-scapy
```

For more issues, see [Troubleshooting](troubleshooting.md).
