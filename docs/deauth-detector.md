# Deauth Attack Detector Guide

Comprehensive guide to using the Deauth Attack Detector for monitoring and analyzing WiFi deauthentication attacks.

## Overview

The Deauth Attack Detector monitors WiFi traffic for deauthentication and disassociation frames, using behavioral analysis to identify legitimate router behavior versus malicious attacks.

## How Deauth Attacks Work

### Attack Mechanism
1. Attacker uses tools like `aireplay-ng` or `mdk4`
2. Sends spoofed deauth/disassoc frames
3. Impersonates router MAC address
4. Disconnects clients from network
5. Can enable man-in-the-middle attacks

### Why Detection is Hard
- Frames can be easily spoofed
- Most adapters don't expose true transmitter MAC
- Legitimate routers also send deauth frames
- No payload encryption on management frames

## Detection Methodology

### Behavioral Analysis

Instead of trusting MAC addresses, we analyze behavior:

#### 1. Timing Patterns
**Legitimate routers:**
- Consistent timing between frames
- Regular intervals
- Low coefficient of variation

**Attack tools:**
- Burst patterns
- Irregular intervals
- High coefficient of variation

```python
cv = std_dev(intervals) / mean(intervals)
if cv > 0.8:  # High variation
    suspicious = True
```

#### 2. RSSI Tracking
**Legitimate routers:**
- Stable signal strength
- Gradual changes only
- Physical location fixed

**Spoofed frames:**
- Sudden signal jumps (>20 dBm)
- Inconsistent power levels
- Multiple "locations" for same MAC

```python
rssi_jump = abs(current_rssi - previous_rssi)
if rssi_jump > 20:
    possible_spoofing = True
```

#### 3. Sequence Numbers
**Legitimate routers:**
- Sequential numbering
- Predictable increments
- Rarely duplicate

**Attack tools:**
- Random sequences
- Large gaps
- Duplicate numbers

```python
if seq_gap > 100 or seq_gap < 0:
    sequence_anomaly = True
```

#### 4. Transmission Rates
**Legitimate routers:**
- Standard rates (6, 12, 24, 54 Mbps)
- Consistent rate selection

**Attack tools:**
- Unusual rates
- Very low rates
- Rate mismatches

## Configuration

### Basic Configuration

Edit `config.json`:

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
    "log_file": "attacker_evidence.log"
  },
  "wifi": {
    "tx_power_dbm": 20,
    "path_loss_exponent": 3.5
  }
}
```

### Channel Configuration

**2.4 GHz Channels:**
```json
"channels": [1, 6, 11]  // Non-overlapping
```

**5 GHz Channels:**
```json
"channels": [36, 40, 44, 48, 149, 153, 157, 161]
```

**Dual-Band:**
```json
"channels": [11, 112]  // One from each band
```

**Monitor Single Channel:**
```json
"channels": [11],
"channel_dwell_time": 0  // Stay on one channel
```

### Whitelist Configuration

Add your router's MAC to reduce false positives:

```json
"whitelist_macs": [
  "aa:bb:cc:dd:ee:ff",  // Your 2.4GHz router
  "aa:bb:cc:dd:ee:fe"   // Your 5GHz router
]
```

**Effect:** Adds +20% to legitimacy score

### Protected Devices

Monitor specific devices:

```json
"local_device_macs": [
  "11:22:33:44:55:66",  // Your laptop
  "aa:bb:cc:dd:11:22"   // Your phone
]
```

**Effect:** Highlights attacks against these devices

### Detection Thresholds

#### RSSI Jump Threshold
```json
"rssi_jump_threshold": 20  // dBm
```
- **Lower (10-15):** More sensitive, may flag roaming
- **Default (20):** Balanced
- **Higher (30):** Less sensitive, miss some attacks

#### Timing CV Threshold
```json
"timing_cv_threshold": 0.8
```
- **Lower (0.5):** More strict, catches subtle patterns
- **Default (0.8):** Balanced
- **Higher (1.0):** Only obvious attacks

#### Sequence Gap Threshold
```json
"sequence_gap_threshold": 100
```
- **Lower (50):** More sensitive to sequence anomalies
- **Default (100):** Standard
- **Higher (200):** Allow more variation

#### Legitimacy Threshold
```json
"legitimacy_threshold": 50.0  // Percentage
```
- **Below threshold:** Marked as suspicious
- **Above threshold:** Likely legitimate
- **Recommended:** 40-60 range

## Running the Detector

### Basic Usage

```bash
# Start monitoring
sudo python3 deauth_detector.py
```

### Expected Output

```
🛡️  WiFi Deauth Attack Detector Started
📡 Interface: wlan0mon
📻 Monitoring channels: [11, 112]
⏱️  Channel dwell time: 1.5s
📋 Whitelist: aa:bb:cc:dd:ee:ff
👤 Protected: 11:22:33:44:55:66

[2025-12-27 10:30:15] 📊 Monitoring channel 11...

[10:30:22] ⚠️  DEAUTH DETECTED
           From: aa:bb:cc:dd:ee:ff (Your Router)
           To: 11:22:33:44:55:66
           Reason: Class 3 frame from non-associated station
           Channel: 11
           RSSI: -45 dBm
           Legitimacy: 85% ✓ LIKELY LEGITIMATE
           
[10:30:45] 🚨 SUSPICIOUS DEAUTH
           From: aa:bb:cc:dd:ee:ff (SPOOFED?)
           To: BROADCAST
           Reason: Unspecified
           Channel: 11
           RSSI: -72 dBm → -35 dBm (JUMP: 37 dBm) 🚩
           Timing CV: 1.23 (IRREGULAR) 🚩
           Rate: 1.0 Mbps (LOW) 🚩
           Legitimacy: 25% ⚠️  SUSPICIOUS

[10:31:00] 📊 --- Statistics (60s) ---
           Total Deauths: 156
           Unique Sources: 2
           Suspicious: 134 (85.9%)
           Protected Device Attacks: 89
```

### Output Indicators

**Legitimacy Levels:**
- ✓ **LIKELY LEGITIMATE** (>70%) - Green
- ⚠️  **SUSPICIOUS** (<50%) - Red/Yellow
- 🚩 **RED FLAGS** - Specific anomalies detected

**Red Flag Indicators:**
- 🚩 RSSI Jump detected
- 🚩 Irregular timing pattern
- 🚩 Low transmission rate
- 🚩 Sequence number anomaly
- 🚩 Burst attack pattern

## Log Analysis

### Log File Format

```
[2025-12-27 10:30:45] SUSPICIOUS DEAUTH ATTACK
Source MAC: aa:bb:cc:dd:ee:ff
Destination: 11:22:33:44:55:66
Channel: 11
RSSI: -35 dBm
Rate: 1.0 Mbps
Sequence: 1234
Reason: Unspecified

RED FLAGS:
- RSSI jump: 37 dBm (previous: -72 dBm)
- Timing CV: 1.23 (threshold: 0.8)
- Low transmission rate: 1.0 Mbps

Legitimacy Score: 25%
Threat Level: HIGH
```

### Analyzing Logs

**Search for attacks:**
```bash
# All suspicious events
grep "SUSPICIOUS" attacker_evidence.log

# High-confidence attacks
grep "Legitimacy.*[0-3][0-9]%" attacker_evidence.log

# Attacks on specific device
grep "11:22:33:44:55:66" attacker_evidence.log
```

**Count attacks:**
```bash
# Total suspicious deauths
grep -c "SUSPICIOUS" attacker_evidence.log

# Unique attacker MACs
grep "Source MAC:" attacker_evidence.log | sort -u | wc -l
```

**Time-based analysis:**
```bash
# Events in time window
awk '/10:30:00/,/10:35:00/' attacker_evidence.log
```

## Attack Scenarios

### Scenario 1: Targeted Attack

**Pattern:**
- Focused on one device
- High rate of deauths
- Consistent source MAC (spoofed router)

**Detection:**
```
[10:30:15] 🚨 ATTACK on 11:22:33:44:55:66
[10:30:16] 🚨 ATTACK on 11:22:33:44:55:66
[10:30:17] 🚨 ATTACK on 11:22:33:44:55:66
Legitimacy: 20-30%
```

**Action:**
- Identify attack MAC
- Physical location finding (RSSI)
- Document evidence

### Scenario 2: Network-Wide Attack

**Pattern:**
- Broadcast deauths
- Affects all clients
- Rapid succession

**Detection:**
```
[10:30:15] 🚨 BROADCAST DEAUTH
Destination: FF:FF:FF:FF:FF:FF
Rate: 200+ per minute
Legitimacy: <30%
```

**Action:**
- All clients disconnected
- Find attacker location
- Contact authorities if needed

### Scenario 3: Legitimate Router Activity

**Pattern:**
- Occasional deauths
- Specific reasons (e.g., idle timeout)
- Consistent RSSI and timing

**Detection:**
```
[10:30:15] ⚠️  DEAUTH from router
Reason: Inactivity timeout
Legitimacy: 85% ✓
```

**Action:**
- Normal operation
- No concern

## Advanced Usage

### Find Attacker Location

Use RSSI to estimate distance:

```python
# RSSI to distance formula (in logs)
Distance ≈ 10^((TxPower - RSSI) / (10 * PathLoss))

Example:
TxPower: 20 dBm
RSSI: -35 dBm
PathLoss: 3.5
Distance ≈ 10^((20-(-35))/(10*3.5)) ≈ 7.4 meters
```

**Method:**
1. Note RSSI values from multiple locations
2. Triangulate attacker position
3. Search area with strongest signal

### Capture Evidence

```bash
# Run with detailed logging
sudo python3 deauth_detector.py | tee -a evidence.txt

# Capture packets simultaneously
sudo tcpdump -i wlan0mon -w attack.pcap &
sudo python3 deauth_detector.py
```

**Open in Wireshark:**
```bash
wireshark attack.pcap
# Filter: wlan.fc.type_subtype == 0x000c
```

### Test Detection

**Simulate legitimate:**
```bash
# Your router naturally deauths clients
# Should show high legitimacy scores
```

**Test with attack tool (ethical testing only):**
```bash
# On test network you own
sudo aireplay-ng --deauth 10 -a [ROUTER_MAC] wlan1mon

# Should detect:
# - Low legitimacy score
# - Timing anomalies
# - Possible RSSI jumps
```

## Troubleshooting

### No Deauths Detected

**Causes:**
- Wrong channel
- No attacks occurring
- Interface issues

**Solutions:**
```bash
# Verify channel
iwconfig wlan0mon

# Test packet capture
sudo tcpdump -i wlan0mon -c 100

# Check channel hopping
# Watch output for channel changes
```

### Too Many False Positives

**Solutions:**
1. Add router to whitelist
2. Increase legitimacy threshold (60-70)
3. Adjust RSSI threshold (25-30)
4. Increase timing CV threshold (1.0)

### Missing Attacks

**Solutions:**
1. Lower legitimacy threshold (40-45)
2. Add more monitored channels
3. Reduce channel dwell time
4. Use dedicated channel if known

## Best Practices

1. **Know Your Network**
   - Add routers to whitelist
   - Note normal disconnect patterns
   - Baseline legitimacy scores

2. **Monitor Continuously**
   - Run during vulnerable times
   - Log all events
   - Review periodically

3. **Verify Alerts**
   - Check legitimacy scores
   - Look for red flag patterns
   - Correlate with user reports

4. **Document Evidence**
   - Keep logs
   - Capture packets when suspicious
   - Note timestamps and patterns

5. **Physical Security**
   - Use detection to locate attackers
   - Report to authorities if needed
   - Improve network security

## Related Resources

- [Configuration Reference](configuration.md)
- [Troubleshooting Guide](troubleshooting.md)
- [API Reference](api-reference.md)
- [Architecture Overview](architecture.md)
