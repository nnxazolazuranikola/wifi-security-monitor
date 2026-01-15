# Configuration Reference

Complete reference for all configuration options in the WiFi Security Monitor toolkit.

## Configuration Files

- **`config.json`** - Deauth Attack Detector configuration
- **`monitor_config.json`** - Network Device Monitor configuration
- **`test_config.py`** - Configuration validator script

## Deauth Detector Configuration (config.json)

### Complete Configuration Template

```json
{
  "network": {
    "interface": "wlan0mon",
    "channels": [11, 112],
    "channel_dwell_time": 1.5,
    "whitelist_macs": [],
    "local_device_macs": []
  },
  "detection": {
    "rssi_jump_threshold": 20,
    "low_rate_threshold": 6.0,
    "timing_cv_threshold": 0.8,
    "sequence_gap_threshold": 100,
    "burst_threshold_ms": 500,
    "legitimacy_threshold": 50.0,
    "threat_reduction_percentage": 15
  },
  "output": {
    "show_all_deauths": true,
    "show_legitimacy_scores": true,
    "color_output": true,
    "log_file": "attacker_evidence.log",
    "verbose": false
  },
  "wifi": {
    "tx_power_dbm": 20,
    "path_loss_exponent": 3.5
  }
}
```

### Network Settings

#### `interface`
- **Type:** String
- **Required:** Yes
- **Description:** Monitor mode WiFi interface name
- **Examples:** 
  - `"wlan0mon"` - Common naming
  - `"wlan1mon"` - Second adapter
  - `"mon0"` - Older naming convention
- **How to find:** Run `iwconfig` to see available interfaces

#### `channels`
- **Type:** Array of integers
- **Required:** Yes
- **Description:** WiFi channels to monitor
- **Range:** 
  - 2.4GHz: 1-14 (14 Japan only)
  - 5GHz: 36-165 (varies by country)
- **Examples:**
  ```json
  "channels": [11]                    // Single channel
  "channels": [1, 6, 11]              // 2.4GHz non-overlapping
  "channels": [36, 40, 44, 48]        // 5GHz range
  "channels": [11, 112]               // Dual-band
  ```
- **Performance:** More channels = less time per channel

#### `channel_dwell_time`
- **Type:** Float
- **Required:** Yes
- **Unit:** Seconds
- **Description:** Time to spend on each channel before hopping
- **Default:** 1.5
- **Range:** 0.5 - 10.0
- **Special:** Set to 0 to disable hopping (single channel mode)
- **Trade-offs:**
  - **Lower (0.5-1.0):** Faster scanning, may miss events
  - **Higher (2.0-5.0):** More thorough, slower cycling
  - **0:** Deep monitoring of single channel

#### `whitelist_macs`
- **Type:** Array of strings
- **Required:** No
- **Description:** Trusted router MAC addresses
- **Format:** Lowercase, colon-separated: `"aa:bb:cc:dd:ee:ff"`
- **Effect:** Adds +20% to legitimacy score
- **Use case:** Reduce false positives for your own routers
- **Example:**
  ```json
  "whitelist_macs": [
    "aa:bb:cc:dd:ee:ff",  // Main router 2.4GHz
    "aa:bb:cc:dd:ee:fe"   // Main router 5GHz
  ]
  ```

#### `local_device_macs`
- **Type:** Array of strings
- **Required:** No
- **Description:** Your devices to specifically monitor
- **Format:** Lowercase, colon-separated
- **Effect:** Highlights attacks targeting these devices
- **Example:**
  ```json
  "local_device_macs": [
    "11:22:33:44:55:66",  // Your laptop
    "aa:bb:cc:11:22:33",  // Your phone
    "44:55:66:77:88:99"   // Your tablet
  ]
  ```

### Detection Settings

#### `rssi_jump_threshold`
- **Type:** Integer
- **Unit:** dBm
- **Default:** 20
- **Range:** 10-50
- **Description:** Minimum RSSI change to flag as suspicious
- **Rationale:** Real routers don't teleport; signal shouldn't jump suddenly
- **Tuning:**
  - **10-15:** Very sensitive, may flag roaming
  - **20-25:** Balanced (recommended)
  - **30-40:** Conservative, only obvious spoofing

#### `low_rate_threshold`
- **Type:** Float
- **Unit:** Mbps
- **Default:** 6.0
- **Range:** 1.0-24.0
- **Description:** Transmission rates below this are flagged
- **Rationale:** Attack tools often use low rates; routers use 6+ Mbps
- **Common rates:**
  - 1.0, 2.0 Mbps - Very suspicious
  - 6.0 Mbps - Minimum standard rate
  - 12, 24, 54 Mbps - Common legitimate rates

#### `timing_cv_threshold`
- **Type:** Float
- **Default:** 0.8
- **Range:** 0.3-2.0
- **Description:** Coefficient of variation threshold for timing irregularity
- **Calculation:** `CV = StdDev / Mean`
- **Rationale:** 
  - Legitimate: Consistent timing (CV < 0.5)
  - Attack: Burst patterns (CV > 0.8)
- **Tuning:**
  - **0.5:** Strict, catches subtle patterns
  - **0.8:** Balanced (recommended)
  - **1.2:** Only obvious burst attacks

#### `sequence_gap_threshold`
- **Type:** Integer
- **Default:** 100
- **Range:** 50-500
- **Description:** Maximum allowed gap in sequence numbers
- **Rationale:** Sequence numbers increment; large gaps indicate spoofing
- **Tuning:**
  - **50:** Sensitive to sequence anomalies
  - **100:** Balanced (recommended)
  - **200:** Tolerant of normal variations

#### `burst_threshold_ms`
- **Type:** Integer
- **Unit:** Milliseconds
- **Default:** 500
- **Range:** 100-2000
- **Description:** Multiple deauths within this time = burst attack
- **Effect:** Flagged in logs as burst pattern
- **Example:** 10 deauths in 500ms = obvious attack

#### `legitimacy_threshold`
- **Type:** Float
- **Unit:** Percentage
- **Default:** 50.0
- **Range:** 0-100
- **Description:** Score below this = marked as suspicious
- **Scoring:**
  - Start: 60% base score
  - Penalties: -15% per anomaly
  - Whitelist bonus: +20%
- **Tuning:**
  - **30-40:** Very suspicious only
  - **50-60:** Balanced (recommended)
  - **70-80:** Conservative, few alerts

#### `threat_reduction_percentage`
- **Type:** Integer
- **Unit:** Percentage
- **Default:** 15
- **Range:** 5-30
- **Description:** Score penalty per anomaly detected
- **Effect:** Each red flag reduces legitimacy by this amount
- **Example:** 
  - Base: 60%
  - RSSI jump: -15% → 45%
  - Timing anomaly: -15% → 30%
  - Rate anomaly: -15% → 15%

### Output Settings

#### `show_all_deauths`
- **Type:** Boolean
- **Default:** true
- **Description:** Show all deauth frames or only suspicious ones
- **Values:**
  - `true`: Show all with legitimacy scores
  - `false`: Only show suspicious (below threshold)

#### `show_legitimacy_scores`
- **Type:** Boolean
- **Default:** true
- **Description:** Display calculated legitimacy percentages
- **Effect:** Shows "Legitimacy: 85% ✓" or "Legitimacy: 25% ⚠️"

#### `color_output`
- **Type:** Boolean
- **Default:** true
- **Description:** Use ANSI colors in terminal output
- **Effect:**
  - Green: Legitimate (✓)
  - Red: Suspicious (⚠️)
  - Yellow: Warnings (🚩)
- **Disable if:** Logging to file or using non-color terminal

#### `log_file`
- **Type:** String
- **Default:** `"attacker_evidence.log"`
- **Description:** Path to log file for detailed evidence
- **Location:** Relative to script directory or absolute path
- **Rotation:** Manually implement or use external tool

#### `verbose`
- **Type:** Boolean
- **Default:** false
- **Description:** Enable detailed debug output
- **Use case:** Troubleshooting, development
- **Warning:** Very chatty, not for normal operation

### WiFi Settings

#### `tx_power_dbm`
- **Type:** Integer
- **Unit:** dBm
- **Default:** 20
- **Range:** 10-30
- **Description:** Typical WiFi transmit power for distance estimation
- **Common values:**
  - 15 dBm - Low power devices
  - 20 dBm - Standard routers (recommended)
  - 27-30 dBm - High power routers

#### `path_loss_exponent`
- **Type:** Float
- **Default:** 3.5
- **Range:** 2.0-4.0
- **Description:** Environmental path loss factor for distance calculation
- **Common values:**
  - 2.0 - Free space (outdoor, no obstacles)
  - 3.0 - Office environment
  - 3.5 - Home environment (recommended)
  - 4.0 - Dense obstacles (multiple walls)
- **Use:** Distance ≈ 10^((TxPower - RSSI) / (10 * PathLoss))

## Network Monitor Configuration (monitor_config.json)

### Complete Configuration Template

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
    "log_file": "network_monitor.log",
    "refresh_interval": 5
  },
  "database": {
    "path": "data/device_database.json",
    "save_interval": 60,
    "backup_enabled": true,
    "backup_path": "data/backups/"
  },
  "device_classification": {
    "belongs_here_threshold": {
      "connection_count": 3,
      "total_time_seconds": 3600
    },
    "iot_detection": {
      "enabled": true,
      "oui_patterns": ["espressif", "tuya", "shenzhen"],
      "name_patterns": ["esp", "cam", "iot", "smart"]
    }
  }
}
```

### Network Settings (Monitor)

#### `interface`
- Same as Deauth Detector
- Monitor mode interface name

#### `channels`
- **Recommended:** More channels for better device discovery
- **Examples:**
  ```json
  // Comprehensive 2.4GHz
  "channels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
  
  // Quick scan
  "channels": [1, 6, 11]
  
  // Dual-band
  "channels": [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
  
  // Your network only
  "channels": [6]  // If you know your channel
  ```

#### `channel_dwell_time`
- **Default:** 1.5 seconds
- **Recommendation:** 1.0-2.0 for device discovery
- **Single channel:** Set to 0 for deep monitoring

#### `known_devices`
- **Type:** Array of MAC addresses
- **Purpose:** Devices you expect to see
- **Effect:**
  - No "new device" alerts
  - Marked as "KNOWN DEVICE ✓"
  - Highlighted in output
- **Include:**
  - Your router(s)
  - Your devices (phones, laptops)
  - Family devices
  - Regular IoT devices

### Alert Settings

#### `alert_on_new_device`
- **Type:** Boolean
- **Default:** true
- **Description:** Alert when a never-before-seen device appears
- **Use case:** Security monitoring
- **Disable if:** High-traffic area, many visitors

#### `alert_on_iot_device`
- **Type:** Boolean
- **Default:** true
- **Description:** Alert when IoT device detected
- **Use case:** IoT security audit
- **Disable if:** Many known IoT devices

#### `alert_sound`
- **Type:** Boolean
- **Default:** false
- **Description:** Play system sound on alerts
- **Requires:** System bell/beep support
- **Warning:** Can be annoying with many alerts

### Output Settings (Monitor)

#### `show_all_devices`
- **Type:** Boolean
- **Default:** true
- **Values:**
  - `true`: Show all detected devices
  - `false`: Only show new/suspicious devices

#### `show_statistics`
- **Type:** Boolean
- **Default:** true
- **Description:** Display periodic statistics summary
- **Interval:** Typically every 60 seconds

#### `refresh_interval`
- **Type:** Integer
- **Unit:** Seconds
- **Default:** 5
- **Description:** How often to update device display
- **Range:** 1-30
- **Recommendation:** 5 for monitoring, 10-30 for logging

### Database Settings

#### `path`
- **Type:** String
- **Default:** `"data/device_database.json"`
- **Description:** Location of persistent device database
- **Note:** Directory created automatically if missing

#### `save_interval`
- **Type:** Integer
- **Unit:** Seconds
- **Default:** 60
- **Description:** How often to save database to disk
- **Trade-off:**
  - **Lower (30):** More frequent saves, less data loss risk
  - **Higher (120):** Less I/O, slight data loss risk

#### `backup_enabled`
- **Type:** Boolean
- **Default:** true
- **Description:** Create backup before saving
- **Backup naming:** `device_database.json.backup`

#### `backup_path`
- **Type:** String
- **Default:** `"data/backups/"`
- **Description:** Directory for timestamped backups
- **Note:** Must exist or be creatable

### Device Classification Settings

#### `belongs_here_threshold`

##### `connection_count`
- **Type:** Integer
- **Default:** 3
- **Description:** Minimum connections to be marked as "belongs here"
- **Effect:** Device marked with 🏠 indicator
- **Tuning:**
  - **1-2:** Very permissive
  - **3-5:** Balanced (recommended)
  - **10+:** Conservative, only regulars

##### `total_time_seconds`
- **Type:** Integer
- **Unit:** Seconds
- **Default:** 3600 (1 hour)
- **Description:** Minimum total connection time for "belongs here"
- **Examples:**
  - 1800 (30 min)
  - 3600 (1 hour) - recommended
  - 7200 (2 hours)

#### `iot_detection`

##### `enabled`
- **Type:** Boolean
- **Default:** true
- **Description:** Enable IoT device detection

##### `oui_patterns`
- **Type:** Array of strings
- **Default:** `["espressif", "tuya", "shenzhen"]`
- **Description:** Manufacturer names that indicate IoT
- **Customize:** Add your IoT brands
- **Example:**
  ```json
  "oui_patterns": [
    "espressif",
    "tuya", 
    "shenzhen",
    "xiaomi",
    "sonoff",
    "broadlink"
  ]
  ```

##### `name_patterns`
- **Type:** Array of strings
- **Default:** `["esp", "cam", "iot", "smart"]`
- **Description:** Substrings in device names that indicate IoT
- **Case:** Insensitive
- **Example:**
  ```json
  "name_patterns": [
    "esp",
    "cam",
    "camera",
    "iot",
    "smart",
    "sensor",
    "bulb",
    "plug",
    "switch"
  ]
  ```

## Configuration Validation

### Using test_config.py

```bash
# Validate configuration files
python3 test_config.py

# Expected output:
✓ config.json is valid
✓ monitor_config.json is valid
✓ All required fields present
✓ Interface 'wlan0mon' found
✓ Channels are valid
```

### Manual Validation

```python
import json

# Load and validate
with open('config.json') as f:
    config = json.load(f)
    
# Check required fields
required = ['network', 'detection', 'output', 'wifi']
for field in required:
    assert field in config
    
# Validate interface
import subprocess
result = subprocess.run(['iwconfig', config['network']['interface']], 
                       capture_output=True)
assert result.returncode == 0
```

## Best Practices

### 1. Start with Defaults
- Use example configs as base
- Modify incrementally
- Test after each change

### 2. Document Your Changes
```json
{
  "network": {
    "interface": "wlan1mon",  // Using second adapter
    "channels": [6],           // Locked to my network channel
  }
}
```

### 3. Backup Configurations
```bash
# Before making changes
cp config.json config.json.backup
cp monitor_config.json monitor_config.json.backup
```

### 4. Version Control
```bash
git add config.json monitor_config.json
git commit -m "Tuned detection thresholds for home environment"
```

### 5. Environment-Specific Configs
```
config.home.json        # Home network settings
config.work.json        # Work network settings
config.travel.json      # Hotel/public WiFi
```

```bash
# Switch configs
cp config.home.json config.json
```

## Common Configuration Scenarios

### Scenario 1: High Security Home
```json
{
  "network": {
    "channels": [6],  // Your network only
    "whitelist_macs": ["your:router:mac"],
    "local_device_macs": ["all", "your", "devices"]
  },
  "detection": {
    "legitimacy_threshold": 60.0,  // Strict
    "threat_reduction_percentage": 20  // Harsh penalties
  },
  "alerts": {
    "alert_on_new_device": true,
    "alert_on_iot_device": true
  }
}
```

### Scenario 2: Apartment/Dense Environment
```json
{
  "network": {
    "channels": [1, 6, 11],  // All 2.4GHz
    "channel_dwell_time": 2.0  // Longer capture
  },
  "detection": {
    "rssi_jump_threshold": 25,  // Less sensitive
    "legitimacy_threshold": 45.0  // More tolerant
  }
}
```

### Scenario 3: IoT Audit
```json
{
  "network": {
    "channels": [1, 6, 11, 36, 40, 44, 48]
  },
  "alerts": {
    "alert_on_new_device": true,
    "alert_on_iot_device": true
  },
  "device_classification": {
    "iot_detection": {
      "enabled": true,
      "oui_patterns": ["all", "iot", "manufacturers"],
      "name_patterns": ["extensive", "list"]
    }
  }
}
```

### Scenario 4: Continuous Monitoring
```json
{
  "network": {
    "channels": [11],  // Single channel
    "channel_dwell_time": 0  // No hopping
  },
  "database": {
    "save_interval": 30,  // Frequent saves
    "backup_enabled": true
  },
  "output": {
    "log_file": "/var/log/wifi-monitor.log"  // Persistent location
  }
}
```

## Related Resources

- [Getting Started Guide](getting-started.md)
- [Deauth Detector Guide](deauth-detector.md)
- [Network Monitor Guide](network-monitor.md)
- [Troubleshooting](troubleshooting.md)
