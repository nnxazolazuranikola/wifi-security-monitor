# Network Device Monitor Guide

Complete guide to using the Network Device Monitor for tracking and analyzing WiFi network devices.

## Overview

The Network Device Monitor provides comprehensive visibility into all devices on your WiFi network, tracking connection history, identifying device types, and detecting suspicious activity.

## Key Features

- **Device Discovery** - Automatic detection of all network devices
- **Manufacturer Identification** - OUI lookup for device vendors
- **IoT Detection** - Identifies smart home devices, cameras, ESP32 boards
- **Connection Tracking** - Historical data on all connections
- **Persistent Database** - Maintains device history across restarts
- **Suspicious Device Alerts** - Notifications for unknown devices
- **"Belongs Here" Detection** - Automatically recognizes regular devices

## How It Works

### Packet Monitoring

The monitor captures and analyzes:
- Probe requests (devices searching for networks)
- Association/reassociation requests
- Data frames (active connections)
- Management frames (network operations)

### Device Information Gathering

For each device, tracks:
- MAC address
- Manufacturer (from OUI database)
- Signal strength (RSSI)
- First and last seen timestamps
- Total connection time
- Connection count
- Hostnames (when available)
- Connected SSIDs
- Device type (smartphone, IoT, computer, etc.)

### Classification

**Device Types:**
- Smartphone
- Laptop/Computer
- IoT Device
- Camera
- Smart Home Device
- Gaming Console
- Unknown

**Status Indicators:**
- ✓ KNOWN DEVICE (in your configured list)
- ⚠️ NEW DEVICE (first time seen)
- 🏠 BELONGS HERE (regular visitor)
- 🤖 IOT DEVICE (smart device detected)
- ❓ UNKNOWN (not yet classified)

## Configuration

### Basic Configuration

Edit `monitor_config.json`:

```json
{
  "network": {
    "interface": "wlan0mon",
    "channels": [1, 6, 11, 36, 40, 44, 48],
    "channel_dwell_time": 1.5,
    "known_devices": []
  },
  "alerts": {
    "alert_on_new_device": true,
    "alert_on_iot_device": true,
    "alert_sound": false
  },
  "output": {
    "show_all_devices": true,
    "show_statistics": true,
    "color_output": true,
    "log_file": "network_monitor.log"
  },
  "database": {
    "path": "data/device_database.json",
    "save_interval": 60,
    "backup_enabled": true
  }
}
```

### Channel Configuration

**Comprehensive Scanning:**
```json
// All common 2.4GHz channels
"channels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

// All common 5GHz channels
"channels": [36, 40, 44, 48, 52, 56, 60, 64, 
             100, 104, 108, 112, 116, 120, 124, 128,
             132, 136, 140, 144, 149, 153, 157, 161, 165]
```

**Quick Scan (Non-overlapping):**
```json
"channels": [1, 6, 11]  // 2.4GHz only
```

**Dual-Band Optimized:**
```json
"channels": [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
```

**Single Channel Deep Monitoring:**
```json
"channels": [6],
"channel_dwell_time": 0  // Stay on one channel
```

### Known Devices

Add devices you want to track:

```json
"known_devices": [
  "aa:bb:cc:dd:ee:ff",  // Your router
  "11:22:33:44:55:66",  // Your laptop
  "aa:bb:cc:11:22:33"   // Your phone
]
```

**Effects:**
- Marked as "KNOWN DEVICE ✓"
- No new device alerts
- Highlighted in output
- Priority tracking

### Alert Configuration

```json
"alerts": {
  "alert_on_new_device": true,    // Alert for first-time devices
  "alert_on_iot_device": true,    // Alert for IoT detection
  "alert_sound": false            // Play sound (requires system support)
}
```

## Running the Monitor

### Basic Usage

```bash
# Start monitoring
sudo python3 network_monitor.py
```

### Expected Output

```
📡 WiFi Network Device Monitor Started
🔍 Interface: wlan0mon
📻 Scanning channels: [1, 6, 11, 36, 40, 44, 48]
⏱️  Channel dwell time: 1.5s
💾 Database: data/device_database.json

[2025-12-27 10:30:15] 📊 Scanning channel 1...

[10:30:18] 👤 NEW DEVICE DETECTED ⚠️
           MAC: aa:bb:cc:dd:ee:ff
           Manufacturer: Apple Inc.
           Device Type: Smartphone
           Signal: -45 dBm
           Channel: 1
           Status: NEW DEVICE

[10:30:22] 👤 Device Update
           MAC: 11:22:33:44:55:66
           Manufacturer: Dell Inc.
           Device Type: Laptop
           Signal: -52 dBm
           Status: KNOWN DEVICE ✓
           Connected: 45m 23s
           Total Time: 12h 34m

[10:30:35] 🤖 IOT DEVICE DETECTED
           MAC: 24:62:ab:xx:xx:xx
           Manufacturer: Espressif Inc.
           Device Type: ESP32
           Signal: -68 dBm
           Indicators: ESP32, WiFi Chip
           Status: NEW IOT DEVICE ⚠️

[10:31:00] 📊 --- Statistics (60s) ---
           Total Devices: 12
           Active Now: 8
           New Devices: 2
           IoT Devices: 3
           Known Devices: 7
           Unknown: 3
           
           Most Active:
           1. aa:bb:cc:dd:ee:ff (Apple iPhone) - 2h 15m
           2. 11:22:33:44:55:66 (Dell Laptop) - 1h 45m
           3. 24:62:ab:xx:xx:xx (ESP32 Board) - 45m
```

### Output Format

**Device Information:**
- MAC address
- Manufacturer name
- Device type classification
- Signal strength (RSSI in dBm)
- Channel detected on
- Status indicators
- Connection time

**Statistics:**
- Total unique devices seen
- Currently active devices
- New devices detected
- IoT device count
- Known vs unknown ratio

## Device Database

### Database Structure

Location: `data/device_database.json`

```json
{
  "aa:bb:cc:dd:ee:ff": {
    "mac": "aa:bb:cc:dd:ee:ff",
    "manufacturer": "Apple Inc.",
    "device_type": "smartphone",
    "first_seen": "2025-12-20T10:00:00",
    "last_seen": "2025-12-27T12:30:00",
    "total_connection_time": 86400,
    "connection_count": 25,
    "belongs_here": true,
    "hostnames": ["iPhone-12", "Johns-iPhone"],
    "ssids": ["MyNetwork", "MyNetwork-5G"],
    "is_iot": false,
    "iot_indicators": [],
    "signal_history": [-45, -42, -48, -43],
    "notes": ""
  }
}
```

### Querying the Database

**View all devices:**
```bash
cat data/device_database.json | python3 -m json.tool
```

**Count devices:**
```bash
cat data/device_database.json | jq 'length'
```

**Find IoT devices:**
```bash
cat data/device_database.json | jq 'to_entries[] | select(.value.is_iot == true) | .value'
```

**Devices by manufacturer:**
```bash
cat data/device_database.json | jq 'to_entries[] | select(.value.manufacturer | contains("Apple")) | .value'
```

**Regular devices (belongs here):**
```bash
cat data/device_database.json | jq 'to_entries[] | select(.value.belongs_here == true) | .value'
```

**Recent devices (last 24h):**
```bash
# Requires date filtering script
python3 -c "
import json
from datetime import datetime, timedelta
with open('data/device_database.json') as f:
    data = json.load(f)
cutoff = datetime.now() - timedelta(days=1)
recent = {k:v for k,v in data.items() 
          if datetime.fromisoformat(v['last_seen']) > cutoff}
print(json.dumps(recent, indent=2))
"
```

### Database Maintenance

**Backup database:**
```bash
cp data/device_database.json data/device_database.backup.json
```

**Reset database:**
```bash
# Backup first!
rm data/device_database.json
# Will be recreated on next run
```

**Merge databases:**
```python
import json

# Load two databases
with open('db1.json') as f:
    db1 = json.load(f)
with open('db2.json') as f:
    db2 = json.load(f)

# Merge (db2 overwrites db1 for conflicts)
merged = {**db1, **db2}

# Save merged
with open('merged_db.json', 'w') as f:
    json.dump(merged, f, indent=2)
```

## IoT Device Detection

### Detection Criteria

**MAC OUI Patterns:**
- Espressif Systems (ESP32/ESP8266)
- Broadcom (Many IoT devices)
- Tuya Smart
- Shenzhen manufacturers

**Device Name Patterns:**
- Contains: camera, cam, esp, iot, smart, sensor
- Examples: "Smart-Bulb", "ESP32-Camera", "Ring-Doorbell"

**Behavioral Patterns:**
- Always connected (24/7 uptime)
- Limited frame types
- Specific probe patterns

### Common IoT Devices

**Smart Home:**
- Smart bulbs (Philips Hue, LIFX)
- Smart plugs (TP-Link, Wemo)
- Thermostats (Nest, Ecobee)
- Smart speakers (Echo, Google Home)

**Security:**
- IP cameras (Ring, Arlo, Nest Cam)
- Video doorbells
- Motion sensors
- Door locks

**DIY/Maker:**
- ESP32 boards
- ESP8266 boards
- Arduino with WiFi
- Raspberry Pi

**Entertainment:**
- Smart TVs
- Streaming devices (Roku, Fire TV)
- Gaming consoles

## Use Cases

### 1. Network Inventory

**Goal:** Complete list of all devices

**Method:**
```bash
# Run for 24 hours
sudo python3 network_monitor.py

# Export inventory
cat data/device_database.json | jq -r '.[] | "\(.mac)\t\(.manufacturer)\t\(.device_type)"'
```

**Output:**
```
aa:bb:cc:dd:ee:ff    Apple Inc.          smartphone
11:22:33:44:55:66    Dell Inc.           laptop
24:62:ab:xx:xx:xx    Espressif Inc.      iot
```

### 2. Security Monitoring

**Goal:** Detect unauthorized devices

**Setup:**
```json
// Add all authorized devices
"known_devices": [
  "aa:bb:cc:dd:ee:ff",
  "11:22:33:44:55:66"
],
"alert_on_new_device": true
```

**Monitor:**
- Run continuously
- Check logs for new device alerts
- Investigate unknown devices

### 3. IoT Audit

**Goal:** Find all IoT devices

**Method:**
```bash
# Run monitor
sudo python3 network_monitor.py

# After sufficient time, query IoT devices
cat data/device_database.json | jq '.[] | select(.is_iot == true)'
```

**Review:**
- Check each IoT device purpose
- Verify security (updated firmware?)
- Consider network segmentation

### 4. Connection Analysis

**Goal:** Who's always connected?

**Query:**
```bash
# Devices with high connection count
cat data/device_database.json | jq '.[] | select(.connection_count > 10) | {mac, manufacturer, belongs_here, total_time: .total_connection_time}'

# Convert seconds to readable time
cat data/device_database.json | jq -r '.[] | "\(.mac)\t\(.manufacturer)\t\(.total_connection_time / 3600 | floor) hours"' | sort -k3 -rn
```

### 5. Troubleshooting Network Issues

**Goal:** Find problematic devices

**Indicators:**
- Devices constantly connecting/disconnecting
- Weak signal devices
- Unknown devices causing interference

**Method:**
- Monitor signal strengths
- Track connection patterns
- Correlate with network issues

## Advanced Usage

### Hostname Discovery

The monitor attempts to capture hostnames through:
- mDNS broadcasts
- DHCP requests
- DNS queries
- Probe requests

**View devices with hostnames:**
```bash
cat data/device_database.json | jq '.[] | select(.hostnames | length > 0) | {mac, hostnames}'
```

### Signal Strength Tracking

**Distance estimation:**
```
Distance ≈ 10^((TxPower - RSSI) / (10 * PathLoss))

Strong signal: -30 to -50 dBm (nearby)
Medium signal: -50 to -70 dBm (normal)
Weak signal: -70 to -90 dBm (far/obstacles)
```

**Find nearby devices:**
```bash
# Devices with strong signal (likely nearby)
# Check current signal in real-time output
```

### Export for Analysis

**CSV Export:**
```bash
echo "MAC,Manufacturer,Type,First_Seen,Last_Seen,Total_Time,Belongs_Here,Is_IoT" > devices.csv
cat data/device_database.json | jq -r '.[] | [.mac, .manufacturer, .device_type, .first_seen, .last_seen, .total_connection_time, .belongs_here, .is_iot] | @csv' >> devices.csv
```

**Import to spreadsheet:**
- Open devices.csv in Excel/LibreOffice
- Analyze with pivot tables
- Create visualizations

## Troubleshooting

### No Devices Detected

**Causes:**
- Wrong channel
- Interface not in monitor mode
- No active devices nearby

**Solutions:**
```bash
# Verify monitor mode
iwconfig wlan0mon

# Test packet capture
sudo tcpdump -i wlan0mon -c 100

# Check channel range
# Ensure it includes your network's channel
```

### Database Not Saving

**Check:**
```bash
# Verify directory exists
ls -la data/

# Check permissions
ls -l data/device_database.json

# Monitor logs for save errors
tail -f network_monitor.log
```

### Manufacturer Shows "Unknown"

**Causes:**
- Locally administered MAC (random MAC)
- Manufacturer not in OUI database
- Privacy features enabled

**Notes:**
- Modern phones use random MACs for privacy
- Not an error, device is protecting privacy

### Missing Some Devices

**Causes:**
- Device not active during scan
- Channel hopping missed device
- Device on different frequency band

**Solutions:**
1. Increase monitoring time
2. Add more channels
3. Monitor specific channel continuously

## Best Practices

### 1. Regular Monitoring

```bash
# Run during different times
# Morning scan
sudo python3 network_monitor.py &

# Evening scan (different devices active)
```

### 2. Maintain Known Device List

- Add all authorized devices
- Update when purchasing new devices
- Remove old/sold devices

### 3. Review Regularly

```bash
# Weekly review
cat data/device_database.json | jq '.[] | select(.belongs_here == false)'

# Check for new IoT devices
cat data/device_database.json | jq '.[] | select(.is_iot == true and .belongs_here == false)'
```

### 4. Security Hygiene

- Investigate all unknown devices
- Verify IoT device security
- Consider guest network for IoT
- Update device firmware regularly

### 5. Database Backups

```bash
# Daily backup script
#!/bin/bash
DATE=$(date +%Y%m%d)
cp data/device_database.json backups/device_db_$DATE.json

# Keep last 7 days
find backups/ -name "device_db_*.json" -mtime +7 -delete
```

## Integration Ideas

### Alert Notifications

**Email alerts for new devices:**
```python
import smtplib
# Add to monitor code when new device detected
send_email(f"New device: {mac} - {manufacturer}")
```

**Telegram bot:**
```python
import requests
telegram_bot_send("🚨 New device detected on network!")
```

### Web Dashboard

**Export data for web UI:**
```python
# Generate JSON for web dashboard
with open('web/data.json', 'w') as f:
    json.dump(devices, f)
```

### SIEM Integration

**Export logs in CEF format:**
```python
# Common Event Format for SIEM
cef_log = f"CEF:0|WiFiMonitor|Monitor|1.0|NEW_DEVICE|{mac}|5|..."
```

## Related Resources

- [Configuration Reference](configuration.md)
- [Troubleshooting Guide](troubleshooting.md)
- [API Reference](api-reference.md)
- [Architecture Overview](architecture.md)
