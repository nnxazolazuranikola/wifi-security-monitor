# Troubleshooting Guide

Common issues and solutions for the WiFi Security Monitor toolkit.

## General Issues

### Installation Problems

#### Issue: "Command not found: pip3"
**Problem:** Python package manager not installed

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-pip

# Fedora/RHEL
sudo dnf install python3-pip

# Arch
sudo pacman -S python-pip
```

#### Issue: "Permission denied" when installing packages
**Problem:** Insufficient permissions

**Solution:**
```bash
# Install for current user only
pip3 install --user scapy

# Or use sudo (not recommended for general use)
sudo pip3 install scapy

# Better: Use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install scapy
```

#### Issue: "ModuleNotFoundError: No module named 'scapy'"
**Problem:** Scapy not installed or wrong Python version

**Solution:**
```bash
# Verify Python version
python3 --version  # Should be 3.7+

# Install scapy
pip3 install scapy

# If still failing, try system package
sudo apt-get install python3-scapy

# Verify installation
python3 -c "from scapy.all import *; print('OK')"
```

### Monitor Mode Issues

#### Issue: "Interface not found: wlan0mon"
**Problem:** Monitor mode not enabled or wrong interface name

**Solution:**
```bash
# Check available interfaces
iwconfig

# Enable monitor mode
sudo airmon-ng start wlan0

# Check new interface name
iwconfig
# Look for wlan0mon, mon0, or similar

# Update config.json with correct name
```

#### Issue: "Monitor mode not supported"
**Problem:** Adapter doesn't support monitor mode

**Solution:**
1. Check chipset compatibility:
```bash
lsusb | grep -i wireless
# Google the chipset name + "monitor mode"
```

2. Install proper drivers:
```bash
# For Realtek (RTL8812AU example)
sudo apt-get install realtek-rtl88xxau-dkms

# Check kernel modules
lsmod | grep 80211
```

3. Consider purchasing compatible adapter (see Getting Started guide)

#### Issue: "Operation not permitted" or "Permission denied"
**Problem:** Need root privileges

**Solution:**
```bash
# Run with sudo
sudo python3 deauth_detector.py

# Or give capabilities (advanced)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

#### Issue: Monitor mode stops working after reboot
**Problem:** NetworkManager interferes

**Solution:**
```bash
# Method 1: Stop NetworkManager from managing interface
# Edit /etc/NetworkManager/NetworkManager.conf
# Add under [keyfile]:
unmanaged-devices=interface-name:wlan0

# Restart NetworkManager
sudo systemctl restart NetworkManager

# Method 2: Create startup script
cat > ~/start_monitor.sh << 'EOF'
#!/bin/bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
EOF
chmod +x ~/start_monitor.sh
```

### Configuration Issues

#### Issue: "config.json not found"
**Problem:** Configuration file missing

**Solution:**
```bash
# Copy example
cp config.example.json config.json

# Edit configuration
nano config.json

# Validate
python3 test_config.py
```

#### Issue: "Error parsing config.json: Expecting value"
**Problem:** JSON syntax error

**Solution:**
```bash
# Validate JSON syntax
python3 -m json.tool config.json

# Common mistakes:
# - Trailing comma in last array/object element
# - Missing quotes around strings
# - Comments (not allowed in JSON)

# Correct format:
{
  "network": {
    "interface": "wlan0mon",  // Remove this comment!
    "channels": [1, 6, 11]    // And this one!
  }
}

# Should be:
{
  "network": {
    "interface": "wlan0mon",
    "channels": [1, 6, 11]
  }
}
```

#### Issue: "Invalid MAC address format"
**Problem:** MAC addresses not formatted correctly

**Solution:**
```json
// Wrong:
"whitelist_macs": ["AA:BB:CC:DD:EE:FF"]

// Correct (lowercase, colons):
"whitelist_macs": ["aa:bb:cc:dd:ee:ff"]
```

## Deauth Detector Issues

### No Deauths Detected

#### Issue: Tool runs but shows no activity
**Problem:** Various causes

**Diagnosis:**
```bash
# 1. Verify interface is capturing
sudo tcpdump -i wlan0mon -c 100
# Should see WiFi frames

# 2. Check correct channel
iwconfig wlan0mon
# Compare with your router's channel

# 3. Test with specific channel
# In config.json:
"channels": [6],  // Your router's channel
"channel_dwell_time": 0  // Don't hop
```

**Solutions:**
- Wrong channel: Update config to include your network's channel
- Adapter range: Move closer to network
- No attacks: Normal! Means network is secure

#### Issue: Stuck on one channel, not hopping
**Problem:** Channel hopping not working

**Solution:**
```bash
# Verify permissions for channel switching
sudo python3 deauth_detector.py

# Check channel hopping code
# Monitor output for "📊 Monitoring channel X..."
# Should change every 1.5 seconds (or your dwell time)

# Test manual channel change
sudo iwconfig wlan0mon channel 11
iwconfig wlan0mon  # Verify changed
```

### False Positives

#### Issue: Too many "suspicious" alerts for legitimate traffic
**Problem:** Thresholds too sensitive for environment

**Solution:**
```json
// Adjust in config.json:
{
  "detection": {
    "rssi_jump_threshold": 25,      // Increase from 20
    "legitimacy_threshold": 40.0,   // Lower from 50
    "threat_reduction_percentage": 10  // Reduce from 15
  },
  "network": {
    "whitelist_macs": [
      "your:router:mac:here"  // Add your router
    ]
  }
}
```

#### Issue: Your own router flagged as suspicious
**Problem:** Not whitelisted or environmental factors

**Solution:**
```json
// Add to whitelist
"whitelist_macs": [
  "aa:bb:cc:dd:ee:ff"  // Your router MAC
]

// Verify MAC address is correct
// Check router label or run while connected:
iwconfig  // Look for "Access Point:" address
```

### Performance Issues

#### Issue: High CPU usage
**Problem:** Processing too many packets

**Solution:**
```python
# In deauth_detector.py, add frame filtering
def packet_handler(pkt):
    # Early return for irrelevant frames
    if not pkt.haslayer(Dot11Deauth):
        if not pkt.haslayer(Dot11Disassoc):
            return
    # ... rest of code
```

```json
// Reduce channel count
"channels": [11]  // Single channel

// Increase dwell time
"channel_dwell_time": 2.0
```

#### Issue: Output scrolling too fast
**Problem:** Too verbose

**Solution:**
```json
// In config.json:
{
  "output": {
    "show_all_deauths": false,  // Only suspicious
    "verbose": false
  }
}

// Or pipe to less
sudo python3 deauth_detector.py | less
```

## Network Monitor Issues

### No Devices Detected

#### Issue: Monitor runs but finds no devices
**Problem:** Wrong channel or timing

**Diagnosis:**
```bash
# Test packet capture
sudo tcpdump -i wlan0mon -e -c 50
# Should see MAC addresses

# Check device is actually transmitting
# - Phone: Open WiFi settings (phone broadcasts probes)
# - Laptop: Browse internet (data frames)

# Verify channel range includes your network
# Your router is on channel 6, config should include 6
```

**Solution:**
```json
// Ensure your network's channel is monitored
"channels": [1, 6, 11]  // Include your channel

// Increase dwell time for more captures
"channel_dwell_time": 2.0

// Try comprehensive scan
"channels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
```

### Database Issues

#### Issue: Database not saving
**Problem:** Permission or path issues

**Diagnosis:**
```bash
# Check directory exists
ls -la data/

# Check permissions
ls -l data/device_database.json

# Check disk space
df -h

# Monitor for error messages
tail -f network_monitor.log
```

**Solution:**
```bash
# Create directory if missing
mkdir -p data

# Fix permissions
sudo chown $USER:$USER data/
chmod 755 data/

# Verify writable
touch data/test.txt && rm data/test.txt
```

#### Issue: Database corrupted
**Problem:** JSON parse error

**Solution:**
```bash
# Backup current (even if corrupt)
cp data/device_database.json data/device_database.corrupt

# Try to repair
python3 -m json.tool data/device_database.json > data/device_database.fixed.json
mv data/device_database.fixed.json data/device_database.json

# If unfixable, restore from backup
cp data/device_database.json.backup data/device_database.json

# Or start fresh
rm data/device_database.json
# Will be recreated on next run
```

#### Issue: "Unknown" manufacturer for all devices
**Problem:** OUI lookup failing

**Solution:**
```bash
# Check internet connection (if using online lookup)
ping 8.8.8.8

# Verify scapy's OUI database
python3 << EOF
from scapy.all import *
print(get_manufacturer("aa:bb:cc"))
EOF

# Update scapy
pip3 install --upgrade scapy

# Note: Random MACs will always show "Unknown" (privacy feature)
```

### Alert Issues

#### Issue: Too many new device alerts
**Problem:** High-traffic environment or wrong known_devices list

**Solution:**
```json
// Add legitimate devices to known list
"known_devices": [
  "aa:bb:cc:dd:ee:ff",
  "11:22:33:44:55:66"
  // ... all your expected devices
]

// Or disable new device alerts
"alert_on_new_device": false

// Keep IoT alerts
"alert_on_iot_device": true
```

#### Issue: Missing IoT devices
**Problem:** Detection patterns incomplete

**Solution:**
```json
// Add custom patterns
"iot_detection": {
  "enabled": true,
  "oui_patterns": [
    "espressif",
    "tuya",
    "shenzhen",
    "xiaomi",      // Add your IoT brands
    "sonoff"
  ],
  "name_patterns": [
    "esp",
    "cam",
    "smart",
    "sensor",      // Add patterns
    "bulb",
    "plug"
  ]
}

// Check database manually
cat data/device_database.json | jq '.[] | select(.manufacturer | contains("Espressif"))'
```

## System-Level Issues

### WiFi Adapter Problems

#### Issue: Adapter not recognized
**Problem:** Driver missing or hardware issue

**Solution:**
```bash
# Check USB devices
lsusb

# Check kernel messages
dmesg | tail -20

# Check if driver loaded
lsmod | grep -i wifi
lsmod | grep 80211

# Install firmware if needed
sudo apt-get install firmware-linux-nonfree

# Try different USB port
# Try rebooting
```

#### Issue: Adapter disconnects randomly
**Problem:** Power management or driver instability

**Solution:**
```bash
# Disable USB autosuspend
echo -1 | sudo tee /sys/module/usbcore/parameters/autosuspend

# Make permanent
# Edit /etc/default/grub:
GRUB_CMDLINE_LINUX_DEFAULT="... usbcore.autosuspend=-1"
sudo update-grub
sudo reboot

# Check for driver updates
sudo apt-get update
sudo apt-get upgrade

# Monitor dmesg for errors
dmesg -w
```

#### Issue: Monitor mode works but drops packets
**Problem:** Adapter limitations or interference

**Solution:**
```bash
# Reduce channel count
# In config: "channels": [6]

# Increase channel dwell time
# In config: "channel_dwell_time": 2.0

# Move adapter away from interference
# - Use USB extension cable
# - Away from other electronics

# Try different channels (5GHz often cleaner)
"channels": [36, 40, 44, 48]
```

### Python/Scapy Issues

#### Issue: "RuntimeError: This must be run as root"
**Problem:** Scapy needs root for raw sockets

**Solution:**
```bash
# Always use sudo
sudo python3 deauth_detector.py

# Check if running as root
sudo whoami  # Should output "root"
```

#### Issue: Scapy warnings about IPv6 or routing
**Problem:** Non-critical Scapy warnings

**Solution:**
```python
# Add to top of script to suppress
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
```

#### Issue: "socket.error: [Errno 19] No such device"
**Problem:** Interface name wrong or doesn't exist

**Solution:**
```bash
# List all interfaces
ip link show

# Update config with correct name
"interface": "wlan0mon"  // Match actual interface name
```

## Logging Issues

### Log File Problems

#### Issue: Log file too large
**Problem:** Continuous monitoring without rotation

**Solution:**
```bash
# Implement log rotation
# Create /etc/logrotate.d/wifi-monitor:
/path/to/attacker_evidence.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}

# Manual rotation
mv attacker_evidence.log attacker_evidence.log.1
gzip attacker_evidence.log.1

# Or clear periodically
> attacker_evidence.log  # Truncate
```

#### Issue: Can't read log file
**Problem:** Permission or encoding issues

**Solution:**
```bash
# Check permissions
ls -l attacker_evidence.log

# Fix permissions
chmod 644 attacker_evidence.log

# Check encoding
file attacker_evidence.log

# Read with proper encoding
cat attacker_evidence.log | less

# Remove binary/color codes
cat attacker_evidence.log | sed 's/\x1b\[[0-9;]*m//g' > clean_log.txt
```

## Diagnostic Commands

### Check System Status
```bash
#!/bin/bash
# System diagnostic script

echo "=== WiFi Interfaces ==="
iwconfig

echo -e "\n=== USB Devices ==="
lsusb | grep -i wireless

echo -e "\n=== Kernel Modules ==="
lsmod | grep -E "80211|wifi"

echo -e "\n=== Python Version ==="
python3 --version

echo -e "\n=== Scapy Installation ==="
python3 -c "from scapy.all import *; print('Scapy OK')" 2>&1

echo -e "\n=== Monitor Mode Test ==="
sudo iwconfig wlan0mon 2>&1 | head -5

echo -e "\n=== Configuration Files ==="
ls -lh config*.json monitor_config*.json 2>/dev/null
```

Save as `diagnostics.sh`, run: `bash diagnostics.sh`

### Test Packet Capture
```bash
#!/bin/bash
# Test packet capture for 10 seconds

INTERFACE="wlan0mon"

echo "Testing packet capture on $INTERFACE for 10 seconds..."
echo "You should see WiFi frames..."

sudo timeout 10s tcpdump -i $INTERFACE -e -c 50 2>&1

echo -e "\nIf you saw MAC addresses and frame info, capture is working!"
```

### Configuration Validator
```bash
#!/bin/bash
# Validate configuration

echo "=== Checking Configurations ==="

# Check files exist
for file in config.json monitor_config.json; do
    if [ -f "$file" ]; then
        echo "✓ $file exists"
        
        # Validate JSON
        if python3 -m json.tool "$file" > /dev/null 2>&1; then
            echo "✓ $file is valid JSON"
        else
            echo "✗ $file has JSON syntax errors"
            python3 -m json.tool "$file"
        fi
    else
        echo "✗ $file not found"
    fi
done

# Check interface
IFACE=$(python3 -c "import json; print(json.load(open('config.json'))['network']['interface'])" 2>/dev/null)
if [ ! -z "$IFACE" ]; then
    if iwconfig "$IFACE" > /dev/null 2>&1; then
        echo "✓ Interface $IFACE exists"
    else
        echo "✗ Interface $IFACE not found"
    fi
fi
```

## Getting Help

### Before Asking for Help

Collect this information:

1. **System Info:**
```bash
uname -a
python3 --version
pip3 list | grep scapy
lsusb | grep -i wireless
```

2. **Configuration:**
```bash
cat config.json
```
(Remove any sensitive MACs)

3. **Error Messages:**
```bash
# Full error output
sudo python3 deauth_detector.py 2>&1 | tee error.log
```

4. **What You've Tried:**
- Steps taken
- Changes made
- Results observed

### Where to Get Help

- **GitHub Issues:** https://github.com/YOUR_USERNAME/wifi-security-monitor/issues
- **Documentation:** Check all docs/ files
- **Scapy Documentation:** https://scapy.readthedocs.io/
- **WiFi/Linux Forums:** Include diagnostic info

### Reporting Bugs

Include:
1. System information (see above)
2. Steps to reproduce
3. Expected behavior
4. Actual behavior
5. Configuration files (sanitized)
6. Full error messages

## Common Error Messages

### "OSError: [Errno 19] No such device"
→ Interface doesn't exist or name is wrong
→ Check `iwconfig` output

### "PermissionError: [Errno 1] Operation not permitted"
→ Need to run with sudo
→ Check file permissions for logs/database

### "socket.error: No route to host"
→ Network interface not properly configured
→ May need to disable NetworkManager

### "IndexError: list index out of range"
→ Likely configuration parsing error
→ Validate JSON syntax

### "KeyError: 'network'"
→ Configuration missing required section
→ Compare with example configuration

### "AttributeError: 'NoneType' object has no attribute"
→ Null/missing data in packet processing
→ Usually non-critical, can be ignored

## Prevention

### Regular Maintenance

```bash
# Weekly checks
1. Verify configurations still valid
2. Check log file sizes
3. Backup device database
4. Update software

# Monthly
1. Update Scapy: pip3 install --upgrade scapy
2. Update system: sudo apt-get update && sudo apt-get upgrade
3. Review documentation for updates
4. Test on different channels
```

### Best Practices

1. **Always use example configs as base**
2. **Validate after every config change**
3. **Keep backups of working configurations**
4. **Monitor logs for errors**
5. **Test in controlled environment first**

## Still Having Issues?

If you've tried everything:

1. Start fresh with example configuration
2. Test with single channel, minimal settings
3. Try different WiFi adapter
4. Check hardware (USB port, cable, power)
5. Review system logs: `dmesg`, `journalctl`
6. Ask for help with full diagnostic info

---

**Related Resources:**
- [Getting Started Guide](getting-started.md)
- [Configuration Reference](configuration.md)
- [FAQ](faq.md)
