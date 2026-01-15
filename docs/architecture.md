# Architecture Overview

This document describes the technical architecture and design decisions of the WiFi Security Monitor toolkit.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WiFi Security Monitor                     │
├─────────────────────────────────┬───────────────────────────┤
│    Deauth Attack Detector       │   Network Device Monitor  │
│    (deauth_detector.py)         │   (network_monitor.py)    │
├─────────────────────────────────┴───────────────────────────┤
│                      Scapy Packet Layer                      │
├──────────────────────────────────────────────────────────────┤
│                   Monitor Mode Interface                     │
│                      (wlan0mon, etc.)                        │
├──────────────────────────────────────────────────────────────┤
│                    WiFi Hardware Adapter                     │
└──────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Packet Capture Layer

Both tools use **Scapy** for packet capture and analysis:

```python
# Packet sniffing with filtering
sniff(iface=interface, 
      prn=packet_handler,
      store=False,
      monitor=True)
```

**Key Features:**
- Zero-copy packet processing
- Real-time packet inspection
- 802.11 frame parsing
- RadioTap header access

### 2. Channel Management

Multi-channel monitoring via thread-based channel hopping:

```python
def channel_hopper():
    while running:
        for channel in CHANNELS:
            set_channel(interface, channel)
            time.sleep(DWELL_TIME)
```

**Design Decisions:**
- Dwell time configurable (default: 1.5s)
- Supports 2.4GHz and 5GHz bands
- Non-blocking operation
- Synchronized with packet handler

### 3. Behavioral Analysis Engine (Deauth Detector)

#### Multi-Factor Scoring System

```
Legitimacy Score = Base Score (60%)
                 - RSSI Penalties
                 - Timing Penalties  
                 - Sequence Penalties
                 - Rate Penalties
                 + Whitelist Bonus
```

#### Detection Algorithms

**1. Timing Analysis**
```python
# Coefficient of Variation
cv = std_dev / mean
if cv > threshold:
    timing_penalty += score_reduction
```

**2. RSSI Jump Detection**
```python
rssi_jump = abs(current_rssi - previous_rssi)
if rssi_jump > 20:  # dBm
    rssi_penalty += score_reduction
```

**3. Sequence Number Analysis**
```python
gap = current_seq - last_seq
if gap > 100 or gap < 0:
    sequence_penalty += score_reduction
```

**4. Rate Analysis**
```python
if tx_rate < 6.0:  # Mbps
    rate_penalty += score_reduction
```

### 4. Device Tracking System (Network Monitor)

#### Device Database Schema

```json
{
  "aa:bb:cc:dd:ee:ff": {
    "mac": "aa:bb:cc:dd:ee:ff",
    "manufacturer": "Apple Inc.",
    "device_type": "smartphone",
    "first_seen": "2025-12-27T10:00:00",
    "last_seen": "2025-12-27T12:30:00",
    "total_connection_time": 9000,
    "connection_count": 5,
    "belongs_here": true,
    "hostnames": ["iPhone-12"],
    "ssids": ["MyNetwork"],
    "is_iot": false,
    "iot_indicators": []
  }
}
```

#### Device Classification

**IoT Detection Signals:**
- MAC OUI patterns (ESP32, Espressif)
- Device names (Camera, Smart, IoT)
- Behavior patterns (always-on devices)
- Limited capability indicators

**"Belongs Here" Logic:**
```python
if connection_count > 3 and total_time > 1_hour:
    belongs_here = True
```

## Data Flow

### Deauth Detector Flow

```
1. Packet Captured (Monitor Mode)
   ↓
2. Frame Type Classification
   ↓
3. Deauth/Disassoc Detection
   ↓
4. MAC Address Extraction
   ↓
5. Behavioral Analysis
   - RSSI tracking
   - Timing analysis
   - Sequence checking
   - Rate analysis
   ↓
6. Legitimacy Scoring
   ↓
7. Threat Assessment
   ↓
8. Output & Logging
```

### Network Monitor Flow

```
1. Packet Captured (Monitor Mode)
   ↓
2. MAC Address Extraction (Source/Dest)
   ↓
3. Device Information Gathering
   - OUI lookup (manufacturer)
   - Signal strength
   - Frame types
   ↓
4. Device Classification
   - Type detection
   - IoT identification
   - Known vs unknown
   ↓
5. Database Update
   - Connection time tracking
   - Statistics update
   - Persistent storage
   ↓
6. Alert Generation
   ↓
7. Display & Logging
```

## Threading Model

### Deauth Detector Threads

1. **Main Thread** - Packet capture and analysis
2. **Channel Hopper** - Background channel switching
3. **Statistics Thread** - Periodic summary output

### Network Monitor Threads

1. **Main Thread** - Packet capture
2. **Channel Hopper** - Channel management
3. **Database Saver** - Periodic persistence (every 60s)
4. **Statistics Display** - UI updates

**Thread Safety:**
- Shared data structures protected by locks
- Thread-local packet buffers
- Atomic state updates

## Configuration System

### Hierarchical Configuration

```
config.json (user settings)
    ↓
Runtime configuration
    ↓
Default values (fallback)
```

### Configuration Validation

```python
def validate_config():
    # Check required fields
    # Validate data types
    # Verify value ranges
    # Test network interface
```

**Validation performed at startup:**
- Interface existence
- Channel validity
- MAC address format
- Threshold ranges
- File permissions

## Performance Optimizations

### 1. Packet Processing
- No packet storage (`store=False` in sniff)
- Inline processing without queuing
- Early packet rejection for irrelevant frames

### 2. Memory Management
- Fixed-size deques for history
- Periodic cleanup of stale data
- Bounded log files with rotation

### 3. CPU Efficiency
- Minimal regex usage
- Cached OUI lookups
- Optimized dictionary access
- Thread sleep during channel dwell

### 4. I/O Operations
- Buffered file writes
- Batch database saves
- Async logging when possible

## Monitoring Accuracy

### Why Not Use Hardware MAC?

Most WiFi adapters don't expose:
- Transmitter MAC from RadioTap
- True source MAC in promiscuous mode
- Hardware-level frame metadata

**Solution:** Behavioral fingerprinting

### Behavioral Fingerprinting Advantages

1. **Works on any adapter** - No hardware requirements
2. **More accurate** - Identifies actual attack patterns
3. **No false filtering** - Shows all traffic with assessment
4. **Attack resilient** - Can't be easily bypassed

### Known Limitations

1. **Channel hopping** - Can miss events during channel switch
2. **Hidden networks** - Limited visibility
3. **Encrypted frames** - Can't analyze payload
4. **Legitimate variations** - Routers can show some anomalies

**Mitigations:**
- Configurable thresholds
- Multi-factor scoring
- Legitimacy score weighting
- User whitelisting

## Security Considerations

### Privileges Required
- Root access for monitor mode
- Raw socket access
- Interface control

### Data Privacy
- No payload capture
- MAC addresses only
- Local storage only
- No external transmission

### Safe Defaults
- Conservative thresholds
- Whitelist support
- No automatic blocking
- Evidence-based alerts

## Extensibility

### Adding Detection Methods

```python
def custom_detection(frame, metadata):
    """
    Custom detection logic
    Returns: (is_suspicious, confidence_score)
    """
    # Your analysis here
    return suspicious, score
```

### Adding Device Types

```python
IOT_PATTERNS = {
    'camera': ['cam', 'webcam', 'ipcam'],
    'custom_type': ['pattern1', 'pattern2']
}
```

### Output Plugins

```python
class CustomOutput:
    def log_event(self, event):
        # Custom logging logic
        pass
```

## Design Patterns

### Observer Pattern
- Event-driven packet processing
- Callback-based notifications
- Decoupled components

### Strategy Pattern
- Pluggable detection algorithms
- Configurable scoring methods
- Runtime behavior selection

### Singleton Pattern
- Global configuration
- Shared device database
- Single monitor instance

## Future Architecture Considerations

### Scalability
- Multi-adapter support
- Distributed monitoring
- Central aggregation

### Real-time Processing
- Stream processing pipeline
- Event queuing system
- Async I/O operations

### Integration
- REST API for queries
- WebSocket for real-time updates
- Export to SIEM systems

## Testing Strategy

### Unit Tests
- Configuration validation
- Scoring algorithms
- Device classification

### Integration Tests
- Packet capture simulation
- Database operations
- Thread synchronization

### Performance Tests
- High packet rate handling
- Memory leak detection
- CPU utilization profiling

## Documentation Standards

- Inline code comments for complex logic
- Docstrings for public functions
- Configuration examples
- Architecture diagrams
- API documentation

---

For implementation details, see:
- [Deauth Detector Guide](deauth-detector.md)
- [Network Monitor Guide](network-monitor.md)
- [API Reference](api-reference.md)
