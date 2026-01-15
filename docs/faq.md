# Frequently Asked Questions (FAQ)

Common questions about the WiFi Security Monitor toolkit.

## General Questions

### What is this tool for?

The WiFi Security Monitor is a toolkit with two main purposes:
1. **Security**: Detect WiFi deauthentication attacks on your network
2. **Monitoring**: Track all devices connected to your network, identify IoT devices, and detect suspicious activity

### Is this legal?

**Yes, when used responsibly:**
- ✓ Monitoring your own network
- ✓ Networks you have permission to monitor
- ✓ Security research in controlled environments

**Illegal uses:**
- ✗ Monitoring networks without authorization
- ✗ Using to launch attacks
- ✗ Interfering with others' networks

**Check your local laws** - WiFi regulations vary by country.

### Do I need special hardware?

**Yes**, you need:
- A WiFi adapter that supports **monitor mode**
- Not all adapters support this
- Recommended: Alfa AWUS036NHA, TP-Link TL-WN722N v1, Alfa AWUS036ACH
- Budget: $15-60 USD

Your built-in laptop WiFi usually won't work.

### What operating systems are supported?

- ✓ **Linux** (primary support) - Ubuntu, Debian, Raspberry Pi OS, Arch, Fedora
- ⚠️ **macOS** - Limited, monitor mode support varies
- ✗ **Windows** - Not supported (no native monitor mode)

### Can I run this on a Raspberry Pi?

**Yes!** The Raspberry Pi is actually an excellent platform:
- Low power consumption (run 24/7)
- Small form factor (hide easily)
- Good Linux support
- USB ports for WiFi adapters

Tested on Raspberry Pi 3, 4, and Zero W (with USB adapter).

## Installation Questions

### Where do I get the example config files?

They're included in the repository:
```bash
cp config.example.json config.json
cp monitor_config.example.json monitor_config.json
```

If missing, see the [Configuration Reference](configuration.md) for templates.

### Why does Scapy need root/sudo?

Scapy needs to:
- Create raw sockets
- Put interface in monitor mode
- Capture all WiFi frames

These operations require root privileges in Linux.

### Can I run without sudo?

Not easily. You would need to:
1. Give Python capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`
2. Set interface to monitor mode as root first
3. Change ownership of interface

**Not recommended** - just use `sudo`.

### Does this work on Kali Linux?

**Yes**, perfectly! Kali Linux includes:
- Scapy pre-installed
- WiFi tools (aircrack-ng suite)
- Compatible drivers for most adapters

Kali is actually ideal for this tool.

## Hardware Questions

### How do I know if my adapter supports monitor mode?

```bash
# Method 1: Check with iw
iw list | grep monitor

# Method 2: Try enabling it
sudo airmon-ng start wlan0

# Method 3: Google your adapter + "monitor mode"
```

### What chipsets are best?

**Excellent:**
- Atheros AR9271 (AWUS036NHA)
- Ralink RT3070/RT5370
- MediaTek MT7612U (AWUS036ACH)

**Good:**
- Realtek RTL8812AU (with proper driver)
- Ralink RT2800

**Avoid:**
- Broadcom (poor Linux support)
- Most built-in laptop WiFi
- Cheap no-name adapters

### Can I use two adapters simultaneously?

**Yes!** This is actually recommended:
```bash
# Terminal 1
sudo python3 deauth_detector.py  # Uses wlan0mon

# Terminal 2  
sudo python3 network_monitor.py  # Uses wlan1mon
```

Just configure each tool with different interfaces.

### Why 2.4GHz vs 5GHz?

**2.4GHz:**
- Longer range
- Better wall penetration
- More congested (more devices)
- Channels 1-14

**5GHz:**
- Faster speeds
- Less interference
- Shorter range
- Many more channels

**Recommendation:** Monitor both if you have dual-band router.

## Deauth Detector Questions

### What is a deauth attack?

A **deauthentication attack** is when someone sends spoofed WiFi management frames to:
1. Disconnect devices from network
2. Force reconnection (capture handshake for password cracking)
3. Cause denial of service

Tools like `aireplay-ng` and `mdk4` are used to perform these attacks.

### How does detection work without hardware MAC?

Most WiFi adapters **don't expose** the true transmitter MAC in monitor mode. So we use **behavioral fingerprinting**:

- **Timing patterns** - Attacks show irregular timing
- **RSSI tracking** - Spoofed frames show signal jumps
- **Sequence numbers** - Attacks have abnormal sequences
- **Transmission rates** - Attacks use unusual rates

This multi-factor analysis identifies attacks even when MACs are spoofed.

### What's a "legitimacy score"?

A percentage (0-100%) indicating how likely a deauth frame is from a legitimate router vs an attacker:

- **80-100%**: Probably legitimate router activity
- **50-80%**: Unknown/uncertain
- **0-50%**: Probably attack/spoofed

Based on behavioral analysis.

### Why do I see deauths from my own router?

**Normal!** Routers legitimately send deauth frames when:
- Client is idle too long
- Client tries to roam to better AP
- Client has incorrect password
- Router is rebooting

These should show **high legitimacy scores** (70%+).

### Can I prevent deauth attacks?

**Not with this tool.** This is a detection/monitoring tool only.

**To prevent deauth attacks:**
- Use 802.11w (Protected Management Frames) - router and devices must support
- WPA3 (includes management frame protection)
- Physical security (find and remove attacker)

Most consumer routers don't support protection yet.

### What should I do if I detect an attack?

1. **Verify it's real** - Check legitimacy score and red flags
2. **Document** - Save logs, timestamps, patterns
3. **Locate attacker** - Use RSSI to estimate distance/direction
4. **Report** - Contact authorities if in public space/business
5. **Improve security** - Enable 802.11w if available, use WPA3

## Network Monitor Questions

### Why track devices on my network?

**Security reasons:**
- Detect unauthorized access
- Find unknown IoT devices
- Audit what's connected
- Identify security cameras

**Network management:**
- See what's using bandwidth
- Track device connections
- Identify problematic devices

### What is an IoT device?

**Internet of Things** devices - Internet-connected appliances:
- Smart home devices (bulbs, plugs, thermostats)
- Security cameras
- Voice assistants (Alexa, Google Home)
- Smart TVs
- ESP32/ESP8266 maker boards

**Why care?** Many IoT devices have poor security.

### Why does it say "Unknown Manufacturer"?

**Reasons:**
1. **Random MAC** - Privacy feature on modern phones
2. **Unregistered OUI** - Manufacturer didn't register their MAC prefix
3. **Locally administered MAC** - Custom/spoofed MAC
4. **Database outdated** - Very new manufacturer

This is often **intentional privacy protection**.

### What does "Belongs Here" mean?

A device that has connected:
- Multiple times (default: 3+)
- For significant duration (default: 1+ hour)

Automatically marked as "regular" device. Configurable threshold.

### Can I see device hostnames?

**Sometimes.** The monitor captures hostnames from:
- DHCP requests
- mDNS broadcasts
- DNS queries

Not all devices broadcast hostnames. IoT devices often don't.

### Does this show passwords or browsing history?

**No.** The tool only captures:
- MAC addresses
- Signal strength
- Management frames (connection requests)
- Device manufacturers

All actual data is encrypted. We don't decrypt anything.

## Configuration Questions

### What channels should I monitor?

**Depends on goal:**

**Quick scan:**
```json
"channels": [1, 6, 11]  // 2.4GHz non-overlapping
```

**Your network only:**
```json
"channels": [6]  // Replace with your router's channel
```

**Comprehensive:**
```json
"channels": [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
```

**Find your router's channel:**
```bash
iwlist wlan0 scan | grep -E "Channel|ESSID"
```

### Should I whitelist my router?

**Yes**, to reduce false positives:
```json
"whitelist_macs": ["your:router:mac:here"]
```

This adds +20% to legitimacy score for frames from your router.

### What's a good legitimacy threshold?

**Depends on environment:**

- **60-70%**: Strict (home network, few neighbors)
- **50-60%**: Balanced (recommended for most)
- **40-50%**: Permissive (apartment, lots of WiFi traffic)

Lower threshold = more alerts but catches subtle attacks.

### How do I find MAC addresses?

**Your router:**
- Check router label/bottom
- Router admin interface
- `iwconfig` while connected (shows "Access Point:")

**Your devices:**
```bash
# Linux
ip link show
ifconfig

# The "ether" or "HWaddr" value
```

## Performance Questions

### How much CPU/RAM does it use?

**Typical:**
- CPU: 5-15% on Raspberry Pi 4, <5% on desktop
- RAM: 50-100 MB

**Increases with:**
- More channels monitored
- High packet rate environments
- Verbose logging

**Very lightweight** for continuous monitoring.

### Can I run this 24/7?

**Yes!** Designed for continuous operation:
- Low resource usage
- Automatic database saves
- Log rotation (you should implement)
- Stable memory usage

Perfect for Raspberry Pi headless operation.

### Does channel hopping miss events?

**Yes, potentially.** While on channel 6, you miss events on channel 11.

**Mitigations:**
- Monitor fewer channels
- Increase dwell time
- Use single channel if you know your network
- Use multiple adapters

**In practice:** With 1.5s dwell time, you see most events.

### Will this slow down my internet?

**No.** The tool only **listens** (passive monitoring). It doesn't:
- Send any packets (except channel switching commands)
- Connect to networks
- Use internet bandwidth
- Interfere with WiFi signals

Completely passive observation.

## Technical Questions

### What's the difference between deauth and disassoc?

Both disconnect clients but technically different:

**Deauthentication:**
- Severs authentication
- Requires re-authentication
- Reason codes: Class 3 frame, STA leaving, etc.

**Disassociation:**
- Breaks association only
- Faster to reconnect
- Less severe

**For attacks:** Both are used interchangeably. This tool detects both.

### What are RadioTap headers?

**RadioTap** is a standard for capture metadata:
- Signal strength (RSSI)
- Transmission rate
- Channel
- Antenna info
- Timestamp

The tool uses RadioTap to extract frame metadata for analysis.

### Why behavioral analysis instead of simple MAC filtering?

**Problem:** MAC addresses are easily spoofed. Attackers impersonate routers.

**Solution:** Analyze behavior that's hard to fake:
- Timing consistency
- Signal characteristics
- Sequence patterns
- Rate selection

**Result:** Detect attacks even with spoofed MACs.

### What's RSSI and how do you calculate distance?

**RSSI** = Received Signal Strength Indicator (in dBm)

**Distance estimation:**
```
Distance (meters) ≈ 10^((TxPower - RSSI) / (10 * PathLoss))
```

Where:
- TxPower: 20 dBm (typical router)
- RSSI: Measured signal strength
- PathLoss: 3.5 (home environment)

**Accuracy:** ±30-50% (walls, interference affect it)

### What Python version do I need?

**Minimum:** Python 3.7

**Recommended:** Python 3.8+

**Check yours:**
```bash
python3 --version
```

**Why 3.7+:** Uses f-strings, type hints, newer stdlib features.

## Comparison Questions

### How is this different from Wireshark?

**Wireshark:**
- General packet analyzer
- Manual analysis required
- GUI-based
- Captures everything

**This tool:**
- Specialized for WiFi security
- Automatic threat detection
- CLI-based
- Filtered, analyzed output

**Use Wireshark** for deep packet inspection. **Use this** for automated security monitoring.

### How is this different from aircrack-ng?

**aircrack-ng:**
- WiFi auditing suite
- Active attacks (deauth, handshake capture)
- Password cracking
- Network penetration

**This tool:**
- Defensive monitoring only
- Detects attacks on your network
- No attacking capabilities
- Network device tracking

**aircrack is for attacking**, **this is for defending**.

### Can I use this with Kismet/Wireshark simultaneously?

**Yes**, but:
- Only one program can control the interface at once
- They'll fight over channel control
- Consider using separate adapters

**Better:**
- Use this for active monitoring
- Export data for analysis in other tools

## Privacy & Ethics

### Is it ethical to monitor WiFi?

**Depends:**

✓ **Ethical:**
- Your own network
- Networks with permission
- Security research (responsible disclosure)

✗ **Unethical:**
- Neighbors' networks without permission
- Public networks (without authorization)
- Selling or sharing collected data

**Remember:** Capture only metadata (MACs, signal strength), not content.

### What data is collected?

**Collected:**
- MAC addresses
- Signal strength
- Timestamps
- Manufacturers (from MAC)
- Connection patterns

**NOT collected:**
- Passwords
- Web traffic
- Personal data
- Decrypted content
- Usernames

### Should I tell people I'm monitoring?

**Good practice:**
- Inform household members
- Post notice in business/public space
- Get consent if monitoring others

**Legal requirement in some places.**

### Can devices detect this monitoring?

**No.** Monitor mode is **passive** - just listening. Devices can't tell they're being observed.

**Unlike:**
- Network scans (active probing)
- Man-in-the-middle attacks (visible)
- Deauth attacks (disconnects obvious)

## Troubleshooting Questions

See the detailed [Troubleshooting Guide](troubleshooting.md) for comprehensive help.

### Quick fixes for common issues?

```bash
# No packets captured
sudo airmon-ng check kill  # Kill interfering processes
sudo airmon-ng start wlan0

# Permission denied
sudo python3 deauth_detector.py  # Always use sudo

# Config errors
python3 -m json.tool config.json  # Validate JSON

# Interface not found
iwconfig  # Check actual interface name
```

### Where are the logs?

**Default locations:**
- Deauth detector: `attacker_evidence.log`
- Network monitor: `network_monitor.log`
- Device database: `data/device_database.json`

**Configurable** in `config.json` and `monitor_config.json`.

## Advanced Questions

### Can I add custom detection algorithms?

**Yes!** The code is modular. Add your own detection methods:

```python
def custom_detection(frame, metadata):
    """Your custom analysis"""
    if suspicious_pattern(frame):
        return True, 85  # suspicious, confidence%
    return False, 0
```

See [API Reference](api-reference.md) for details.

### Can I export data to other tools?

**Yes:**

```bash
# CSV export
echo "MAC,Manufacturer,Type,Time" > export.csv
cat data/device_database.json | jq -r '.[] | [.mac, .manufacturer, .device_type, .total_connection_time] | @csv' >> export.csv

# JSON for web dashboard
cp data/device_database.json /var/www/dashboard/data.json

# Syslog integration
# Add logging handlers to send to syslog
```

### Can I run this as a service?

**Yes:**

```bash
# Create systemd service: /etc/systemd/system/wifi-monitor.service
[Unit]
Description=WiFi Security Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/wifi-security-monitor
ExecStart=/usr/bin/python3 /path/to/deauth_detector.py
Restart=always

[Install]
WantedBy=multi-user.target

# Enable and start
sudo systemctl enable wifi-monitor
sudo systemctl start wifi-monitor
```

### How do I integrate with home automation?

**Example: Home Assistant**

```python
# Send MQTT messages on events
import paho.mqtt.client as mqtt

client = mqtt.Client()
client.connect("homeassistant.local", 1883)

# On suspicious deauth:
client.publish("home/security/wifi", 
               json.dumps({"alert": "deauth_attack", "mac": mac}))
```

## Still Have Questions?

- Check the [Documentation Index](index.md)
- Read the [Troubleshooting Guide](troubleshooting.md)
- See [Configuration Reference](configuration.md)
- Open a GitHub Issue
- Review the code comments in Python files

---

**Didn't find your question? Open an issue and we'll add it to the FAQ!**
