# API Reference

Technical reference for the WiFi Security Monitor codebase, including functions, classes, and extension points.

## Module Overview

### deauth_detector.py

Main deauthentication attack detection module.

**Key Functions:**
- `packet_handler(pkt)` - Main packet processing function
- `analyze_legitimacy(src_mac, metadata)` - Behavioral analysis engine
- `channel_hopper()` - Background channel switching thread
- `print_statistics()` - Periodic statistics output

### network_monitor.py

Network device monitoring and tracking module.

**Key Functions:**
- `packet_handler(pkt)` - Packet processing for device discovery
- `classify_device(mac, info)` - Device type identification
- `detect_iot(mac, info)` - IoT device detection
- `save_database()` - Persistent storage management
- `channel_hopper()` - Channel management

## Deauth Detector API

### Main Entry Point

```python
def main():
    """
    Main entry point for deauth detector.
    Initializes monitoring, starts channel hopper, begins packet capture.
    """
```

### Packet Processing

#### packet_handler(pkt)

```python
def packet_handler(pkt):
    """
    Process captured packets looking for deauth/disassoc frames.
    
    Args:
        pkt (scapy.Packet): Captured WiFi packet
        
    Returns:
        None
        
    Side Effects:
        - Updates global tracking dictionaries
        - Prints alerts for suspicious activity
        - Logs evidence to file
        
    Details:
        - Filters for Dot11Deauth and Dot11Disassoc frames
        - Extracts metadata (RSSI, rate, sequence)
        - Calls analyze_legitimacy() for scoring
        - Handles both targeted and broadcast deauths
    """
```

**Usage Example:**
```python
# Called automatically by scapy.sniff()
sniff(iface=interface, prn=packet_handler, store=False)

# Can also be called directly for testing:
from scapy.all import *
pkt = Dot11()/Dot11Deauth()
packet_handler(pkt)
```

### Behavioral Analysis

#### analyze_legitimacy(src_mac, metadata)

```python
def analyze_legitimacy(src_mac, metadata):
    """
    Analyze behavioral patterns to determine if deauth is legitimate.
    
    Args:
        src_mac (str): Source MAC address (claimed sender)
        metadata (dict): Frame metadata
            {
                'rssi': int,           # Signal strength in dBm
                'rate': float,         # Transmission rate in Mbps
                'sequence': int,       # Sequence number
                'timestamp': float,    # Time of capture
                'channel': int         # Channel number
            }
    
    Returns:
        tuple: (legitimacy_score: float, red_flags: list)
            legitimacy_score: 0-100 percentage
            red_flags: List of detected anomalies
            
    Scoring Logic:
        Base score: 60%
        Whitelist bonus: +20%
        Per anomaly: -threat_reduction_percentage%
        
    Red Flags Detected:
        - RSSI jump > threshold
        - Timing CV > threshold
        - Sequence gap > threshold
        - Low transmission rate
        - Burst attack pattern
    """
```

**Usage Example:**
```python
metadata = {
    'rssi': -45,
    'rate': 54.0,
    'sequence': 1234,
    'timestamp': time.time(),
    'channel': 11
}

score, flags = analyze_legitimacy("aa:bb:cc:dd:ee:ff", metadata)

if score < legitimacy_threshold:
    print(f"Suspicious! Score: {score}%, Flags: {flags}")
```

### Channel Management

#### channel_hopper()

```python
def channel_hopper():
    """
    Background thread that cycles through configured channels.
    
    Global Variables Used:
        CHANNELS (list): List of channels to monitor
        DWELL_TIME (float): Seconds to spend on each channel
        interface (str): Monitor mode interface name
        running (bool): Thread control flag
        current_channel (int): Currently monitored channel
        
    Returns:
        None
        
    Behavior:
        - Runs in infinite loop while running=True
        - Sets interface to each channel sequentially
        - Sleeps for DWELL_TIME between changes
        - If DWELL_TIME=0, stays on first channel
        - Updates current_channel global
    """
```

**Controlling:**
```python
import threading

# Start channel hopper
hopper_thread = threading.Thread(target=channel_hopper, daemon=True)
hopper_thread.start()

# Stop channel hopper
running = False
hopper_thread.join()
```

### Helper Functions

#### set_channel(interface, channel)

```python
def set_channel(interface, channel):
    """
    Change WiFi interface to specified channel.
    
    Args:
        interface (str): Monitor mode interface name
        channel (int): Channel number (1-14, 36-165)
        
    Returns:
        bool: True if successful, False otherwise
        
    Raises:
        None (errors logged but not raised)
        
    Implementation:
        subprocess.run(["iwconfig", interface, "channel", str(channel)])
    """
```

#### calculate_distance(rssi, tx_power=20, path_loss_exp=3.5)

```python
def calculate_distance(rssi, tx_power=20, path_loss_exp=3.5):
    """
    Estimate distance to transmitter using RSSI.
    
    Args:
        rssi (int): Received signal strength in dBm
        tx_power (int): Transmitter power in dBm (default: 20)
        path_loss_exp (float): Environmental path loss exponent (default: 3.5)
        
    Returns:
        float: Estimated distance in meters
        
    Formula:
        Distance = 10^((TxPower - RSSI) / (10 * PathLoss))
        
    Accuracy:
        ±30-50% due to environmental factors
        
    Example:
        distance = calculate_distance(-45, 20, 3.5)
        # Returns: ~7.4 meters
    """
```

#### get_manufacturer(mac)

```python
def get_manufacturer(mac):
    """
    Look up manufacturer from MAC OUI (first 3 octets).
    
    Args:
        mac (str): MAC address in format "aa:bb:cc:dd:ee:ff"
        
    Returns:
        str: Manufacturer name or "Unknown"
        
    Database:
        Uses scapy's built-in OUI database
        
    Example:
        manufacturer = get_manufacturer("aa:bb:cc:dd:ee:ff")
        # Returns: "Apple Inc." or "Unknown"
    """
```

### Data Structures

#### Router Tracking

```python
# Global dictionary tracking router behavior
router_metadata = {
    "aa:bb:cc:dd:ee:ff": {
        "rssi_history": deque(maxlen=10),      # Recent signal strengths
        "timing_intervals": deque(maxlen=20),   # Inter-frame intervals
        "sequence_numbers": deque(maxlen=10),   # Recent sequence numbers
        "last_seen": 0.0,                       # Timestamp
        "deauth_count": 0,                      # Total deauths
        "rates": [],                            # Transmission rates
        "channels": set()                       # Seen on channels
    }
}
```

#### Protected Devices

```python
# Tracks attacks against your devices
protected_attacks = {
    "11:22:33:44:55:66": {
        "attack_count": 15,
        "last_attack": 1735294800.0,
        "attackers": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:67"]
    }
}
```

### Configuration Schema

```python
config = {
    "network": {
        "interface": str,              # Monitor mode interface
        "channels": [int],             # List of channels
        "channel_dwell_time": float,   # Seconds per channel
        "whitelist_macs": [str],       # Trusted router MACs
        "local_device_macs": [str]     # Your devices
    },
    "detection": {
        "rssi_jump_threshold": int,           # dBm
        "low_rate_threshold": float,          # Mbps
        "timing_cv_threshold": float,         # Coefficient of variation
        "sequence_gap_threshold": int,        # Sequence numbers
        "burst_threshold_ms": int,            # Milliseconds
        "legitimacy_threshold": float,        # Percentage
        "threat_reduction_percentage": int    # Penalty per anomaly
    },
    "output": {
        "show_all_deauths": bool,
        "show_legitimacy_scores": bool,
        "color_output": bool,
        "log_file": str,
        "verbose": bool
    },
    "wifi": {
        "tx_power_dbm": int,
        "path_loss_exponent": float
    }
}
```

## Network Monitor API

### Main Entry Point

```python
def main():
    """
    Main entry point for network monitor.
    Initializes device tracking, starts threads, begins monitoring.
    """
```

### Packet Processing

#### packet_handler(pkt)

```python
def packet_handler(pkt):
    """
    Process packets to discover and track network devices.
    
    Args:
        pkt (scapy.Packet): Captured WiFi packet
        
    Returns:
        None
        
    Side Effects:
        - Updates devices dictionary
        - Prints device discoveries/updates
        - Triggers alerts for new/IoT devices
        
    Details:
        - Extracts source and destination MACs
        - Filters for relevant frames (data, management)
        - Updates device information
        - Calculates connection times
        - Classifies device types
    """
```

### Device Classification

#### classify_device(mac, info)

```python
def classify_device(mac, info):
    """
    Classify device type based on available information.
    
    Args:
        mac (str): Device MAC address
        info (dict): Device information
            {
                'manufacturer': str,
                'hostnames': [str],
                'probe_ssids': [str],
                'frame_types': set
            }
    
    Returns:
        str: Device type classification
            - 'smartphone'
            - 'laptop'
            - 'iot'
            - 'camera'
            - 'smart_home'
            - 'gaming'
            - 'unknown'
    
    Classification Logic:
        1. Check manufacturer patterns
        2. Analyze hostname patterns
        3. Examine frame type behavior
        4. Default to 'unknown'
    """
```

**Usage Example:**
```python
info = {
    'manufacturer': 'Apple Inc.',
    'hostnames': ['iPhone-12'],
    'probe_ssids': ['MyNetwork'],
    'frame_types': {0, 2, 4}  # Management, data types
}

device_type = classify_device("aa:bb:cc:dd:ee:ff", info)
# Returns: 'smartphone'
```

#### detect_iot(mac, info)

```python
def detect_iot(mac, info):
    """
    Detect if device is an IoT device.
    
    Args:
        mac (str): Device MAC address
        info (dict): Device information
    
    Returns:
        tuple: (is_iot: bool, indicators: list)
            is_iot: True if IoT device detected
            indicators: List of matching patterns
    
    Detection Criteria:
        - Manufacturer OUI match (Espressif, Tuya, etc.)
        - Hostname patterns (ESP, camera, smart, etc.)
        - Always-on behavior
        - Limited frame types
    
    Example:
        is_iot, indicators = detect_iot(mac, info)
        if is_iot:
            print(f"IoT device: {indicators}")
    """
```

### Device Tracking

#### update_device(mac, **kwargs)

```python
def update_device(mac, **kwargs):
    """
    Update device information in tracking database.
    
    Args:
        mac (str): Device MAC address
        **kwargs: Fields to update
            manufacturer (str)
            hostname (str)
            ssid (str)
            rssi (int)
            channel (int)
            device_type (str)
            
    Returns:
        dict: Updated device record
        
    Side Effects:
        - Creates device entry if new
        - Updates last_seen timestamp
        - Increments connection_count
        - Updates belongs_here status
        - Appends to signal_history
    """
```

### Database Management

#### save_database()

```python
def save_database():
    """
    Save device database to disk.
    
    Global Variables:
        devices (dict): Current device data
        DATABASE_PATH (str): File path for JSON database
        
    Returns:
        bool: True if successful, False otherwise
        
    Behavior:
        - Creates backup if enabled
        - Writes JSON with indent=2
        - Handles errors gracefully
        - Logs save operations
        
    Thread Safety:
        - Called from timer thread
        - May need locking for concurrent access
    """
```

#### load_database()

```python
def load_database():
    """
    Load device database from disk.
    
    Returns:
        dict: Device database or empty dict if not found
        
    Behavior:
        - Creates data directory if missing
        - Handles corrupted JSON gracefully
        - Restores from backup if needed
        - Initializes empty database if new
    """
```

### Helper Functions

#### belongs_here(device)

```python
def belongs_here(device):
    """
    Determine if device is a regular on the network.
    
    Args:
        device (dict): Device record
        
    Returns:
        bool: True if device "belongs here"
        
    Criteria:
        - connection_count >= threshold (default: 3)
        - total_connection_time >= threshold (default: 3600s)
        
    Example:
        if belongs_here(devices[mac]):
            print("Regular device")
    """
```

#### format_duration(seconds)

```python
def format_duration(seconds):
    """
    Format seconds into human-readable duration.
    
    Args:
        seconds (int): Duration in seconds
        
    Returns:
        str: Formatted string
        
    Example:
        format_duration(3665)
        # Returns: "1h 1m 5s"
        
        format_duration(125)
        # Returns: "2m 5s"
    """
```

### Data Structures

#### Device Record

```python
device = {
    "mac": str,                      # MAC address
    "manufacturer": str,             # From OUI lookup
    "device_type": str,              # Classification
    "first_seen": str,               # ISO timestamp
    "last_seen": str,                # ISO timestamp
    "total_connection_time": int,    # Seconds
    "connection_count": int,         # Number of connections
    "belongs_here": bool,            # Regular device flag
    "hostnames": [str],              # Collected hostnames
    "ssids": [str],                  # Connected SSIDs
    "is_iot": bool,                  # IoT device flag
    "iot_indicators": [str],         # IoT detection reasons
    "signal_history": [int],         # Recent RSSI values
    "channels_seen": [int],          # Channels detected on
    "notes": str                     # User notes
}
```

#### Global Devices Dictionary

```python
# Active device tracking
devices = {
    "aa:bb:cc:dd:ee:ff": device_record,
    "11:22:33:44:55:66": device_record,
    # ...
}
```

### Configuration Schema

```python
monitor_config = {
    "network": {
        "interface": str,
        "channels": [int],
        "channel_dwell_time": float,
        "known_devices": [str]
    },
    "alerts": {
        "alert_on_new_device": bool,
        "alert_on_iot_device": bool,
        "alert_sound": bool
    },
    "output": {
        "show_all_devices": bool,
        "show_statistics": bool,
        "color_output": bool,
        "log_file": str,
        "refresh_interval": int
    },
    "database": {
        "path": str,
        "save_interval": int,
        "backup_enabled": bool,
        "backup_path": str
    },
    "device_classification": {
        "belongs_here_threshold": {
            "connection_count": int,
            "total_time_seconds": int
        },
        "iot_detection": {
            "enabled": bool,
            "oui_patterns": [str],
            "name_patterns": [str]
        }
    }
}
```

## Extension Points

### Adding Custom Detection Logic

```python
# In deauth_detector.py

def custom_detection_method(frame, metadata):
    """
    Add your custom detection algorithm.
    
    Args:
        frame: Scapy packet
        metadata: Frame metadata dict
        
    Returns:
        tuple: (is_suspicious: bool, confidence: float)
    """
    # Your analysis here
    if your_condition:
        return True, 0.85  # 85% confidence
    return False, 0.0

# Call in packet_handler():
suspicious, confidence = custom_detection_method(pkt, metadata)
if suspicious:
    score -= confidence * 20  # Adjust legitimacy score
```

### Custom Device Classification

```python
# In network_monitor.py

def custom_device_classifier(mac, info):
    """Add custom device type identification."""
    
    # Check for specific device patterns
    if 'Nest' in info.get('manufacturer', ''):
        return 'smart_thermostat'
    
    if any('Ring' in h for h in info.get('hostnames', [])):
        return 'doorbell'
    
    # Fall back to default classifier
    return classify_device(mac, info)

# Replace in code:
# device_type = classify_device(mac, info)
device_type = custom_device_classifier(mac, info)
```

### Output Plugins

```python
class OutputPlugin:
    """Base class for output plugins."""
    
    def on_deauth(self, event):
        """Called when deauth detected."""
        pass
    
    def on_device_found(self, device):
        """Called when new device discovered."""
        pass

class MQTTOutput(OutputPlugin):
    """Example: Send events to MQTT broker."""
    
    def __init__(self, broker, port=1883):
        import paho.mqtt.client as mqtt
        self.client = mqtt.Client()
        self.client.connect(broker, port)
    
    def on_deauth(self, event):
        payload = json.dumps(event)
        self.client.publish("wifi/deauth", payload)
    
    def on_device_found(self, device):
        payload = json.dumps(device)
        self.client.publish("wifi/device", payload)

# Usage:
mqtt_output = MQTTOutput("homeassistant.local")
# Call in packet handlers:
mqtt_output.on_deauth(event_data)
```

### Alert Handlers

```python
def alert_handler(alert_type, data):
    """
    Custom alert handler.
    
    Args:
        alert_type (str): 'new_device', 'iot_device', 'suspicious_deauth'
        data (dict): Alert details
    """
    
    if alert_type == 'new_device':
        send_email(f"New device: {data['mac']}")
    
    elif alert_type == 'suspicious_deauth':
        if data['legitimacy'] < 30:
            send_sms(f"Possible attack detected!")
    
    elif alert_type == 'iot_device':
        log_to_file(f"IoT device found: {data}")

# Integrate in main code:
if is_new_device:
    alert_handler('new_device', device_data)
```

## Scapy Integration

### Common Scapy Layers

```python
from scapy.all import *

# 802.11 Layers
Dot11              # Base WiFi frame
Dot11Beacon        # Beacon frame
Dot11ProbeReq      # Probe request
Dot11ProbeResp     # Probe response
Dot11AssoReq       # Association request
Dot11AssoResp      # Association response
Dot11Deauth        # Deauthentication
Dot11Disassoc      # Disassociation

# RadioTap
RadioTap           # Capture metadata layer
```

### Accessing Frame Data

```python
def extract_frame_info(pkt):
    """Extract common frame information."""
    
    info = {}
    
    # RadioTap metadata
    if pkt.haslayer(RadioTap):
        info['rssi'] = pkt[RadioTap].dBm_AntSignal
        info['rate'] = pkt[RadioTap].Rate
    
    # 802.11 header
    if pkt.haslayer(Dot11):
        info['src'] = pkt[Dot11].addr2      # Transmitter
        info['dst'] = pkt[Dot11].addr1      # Receiver
        info['bssid'] = pkt[Dot11].addr3    # BSSID
        info['seq'] = pkt[Dot11].SC >> 4    # Sequence number
    
    # Deauth specific
    if pkt.haslayer(Dot11Deauth):
        info['reason'] = pkt[Dot11Deauth].reason
    
    return info
```

### Creating Test Packets

```python
# Create test deauth frame
test_pkt = RadioTap() / \
           Dot11(addr1="ff:ff:ff:ff:ff:ff",
                 addr2="aa:bb:cc:dd:ee:ff",
                 addr3="aa:bb:cc:dd:ee:ff") / \
           Dot11Deauth(reason=7)

# Process with handler
packet_handler(test_pkt)
```

## Testing

### Unit Test Example

```python
import unittest
from unittest.mock import Mock, patch

class TestDeauthDetector(unittest.TestCase):
    
    def test_analyze_legitimacy_high_score(self):
        """Test legitimate router gets high score."""
        metadata = {
            'rssi': -45,
            'rate': 54.0,
            'sequence': 1000,
            'timestamp': time.time()
        }
        
        score, flags = analyze_legitimacy("aa:bb:cc:dd:ee:ff", metadata)
        
        self.assertGreater(score, 70)
        self.assertEqual(len(flags), 0)
    
    def test_rssi_jump_detection(self):
        """Test RSSI jump is flagged."""
        mac = "test:mac:addr"
        
        # First packet - establish baseline
        metadata1 = {'rssi': -45, 'rate': 54.0, 'sequence': 1000, 'timestamp': time.time()}
        analyze_legitimacy(mac, metadata1)
        
        # Second packet - big RSSI jump
        metadata2 = {'rssi': -20, 'rate': 54.0, 'sequence': 1001, 'timestamp': time.time()}
        score, flags = analyze_legitimacy(mac, metadata2)
        
        self.assertIn('RSSI jump', ' '.join(flags))
        self.assertLess(score, 50)

if __name__ == '__main__':
    unittest.main()
```

### Integration Test Example

```python
def test_full_detection_pipeline():
    """Test complete detection workflow."""
    
    # Create test packet
    test_pkt = RadioTap(dBm_AntSignal=-45, Rate=54) / \
               Dot11(addr2="aa:bb:cc:dd:ee:ff") / \
               Dot11Deauth(reason=7)
    
    # Process packet
    with patch('builtins.print'):  # Suppress output
        packet_handler(test_pkt)
    
    # Verify tracking updated
    assert "aa:bb:cc:dd:ee:ff" in router_metadata
    assert router_metadata["aa:bb:cc:dd:ee:ff"]["deauth_count"] > 0
```

## Performance Considerations

### Optimization Tips

1. **Filter packets early:**
```python
def packet_handler(pkt):
    # Quick reject
    if not pkt.haslayer(Dot11):
        return
    # ... rest of processing
```

2. **Use bounded collections:**
```python
from collections import deque
rssi_history = deque(maxlen=10)  # Auto-removes old entries
```

3. **Minimize I/O:**
```python
# Buffer writes
log_buffer = []
if len(log_buffer) > 100:
    with open(log_file, 'a') as f:
        f.writelines(log_buffer)
    log_buffer.clear()
```

4. **Efficient MAC lookups:**
```python
# Cache OUI lookups
oui_cache = {}
def get_manufacturer_cached(mac):
    oui = mac[:8]  # First 3 octets
    if oui not in oui_cache:
        oui_cache[oui] = get_manufacturer(mac)
    return oui_cache[oui]
```

## Related Documentation

- [Architecture Overview](architecture.md) - System design details
- [Deauth Detector Guide](deauth-detector.md) - Usage guide
- [Network Monitor Guide](network-monitor.md) - Monitoring guide
- [Configuration Reference](configuration.md) - All settings

---

For more code examples, see the source files:
- [deauth_detector.py](../deauth_detector.py)
- [network_monitor.py](../network_monitor.py)
