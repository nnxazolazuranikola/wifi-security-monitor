#!/usr/bin/env python3
"""
WiFi Network Device Monitor
Tracks all devices, detects new devices, identifies manufacturers and device types
"""

import sys
import time
import threading
import subprocess
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp, Dot11Elt
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.l2 import Ether

# Load configuration
CONFIG_FILE = 'monitor_config.json'
if not os.path.exists(CONFIG_FILE):
    print(f"❌ Error: {CONFIG_FILE} not found!")
    print("Please create monitor_config.json - see monitor_config.example.json")
    sys.exit(1)

try:
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
except json.JSONDecodeError as e:
    print(f"❌ Error parsing {CONFIG_FILE}: {e}")
    sys.exit(1)

# Load settings
interface = config['network']['interface']
HOSTNAME_INTERFACE = "wlan0"  # Interface for hostname capture (managed mode)
CHANNELS = config['network']['channels']
DWELL_TIME = config['network']['channel_dwell_time']
KNOWN_DEVICES = [mac.lower() for mac in config['network']['known_devices']]
ALERT_ON_NEW = config['alerts']['alert_on_new_device']
ALERT_ON_IOT = config['alerts']['alert_on_iot_device']
LOG_FILE = config['output']['log_file']

# Your router BSSIDs - only track devices communicating with these
MY_ROUTERS = [mac.lower() for mac in config['network']['known_devices']]

# Device tracking
devices = {}
current_channel = CHANNELS[0]
session_start = datetime.now()
previous_active_devices = set()  # Track for offline detection
random_mac_activity = []  # Track random MAC probes for attack detection

# Persistent device database
DEVICE_DB_FILE = 'data/device_database.json'
db_lock = threading.Lock()  # Thread-safe database access

def load_device_database():
    """Load persistent device database"""
    if os.path.exists(DEVICE_DB_FILE):
        try:
            with open(DEVICE_DB_FILE, 'r') as f:
                db = json.load(f)
                print(f"[STARTUP] Loaded {len(db)} devices from database")
                # Convert datetime strings back to datetime objects
                for mac in db:
                    db[mac]['first_ever_seen'] = datetime.fromisoformat(db[mac]['first_ever_seen'])
                    db[mac]['last_ever_seen'] = datetime.fromisoformat(db[mac]['last_ever_seen'])
                return db
        except Exception as e:
            print(f"[!] Warning: Could not load device database: {e}")
            return {}
    return {}

def save_device_database(db):
    """Save persistent device database"""
    try:
        # Ensure data directory exists
        os.makedirs(os.path.dirname(DEVICE_DB_FILE), exist_ok=True)
        
        # Convert datetime objects to strings for JSON
        db_serializable = {}
        for mac, data in db.items():
            # Copy all fields including optional ones like 'nickname' and 'hostname'
            db_serializable[mac] = {}
            for key, value in data.items():
                if key == 'first_ever_seen' or key == 'last_ever_seen':
                    db_serializable[mac][key] = value.isoformat()
                else:
                    db_serializable[mac][key] = value
        
        with open(DEVICE_DB_FILE, 'w') as f:
            json.dump(db_serializable, f, indent=2)
            
    except Exception as e:
        print(f"[!] Warning: Could not save device database: {e}")
        import traceback
        traceback.print_exc()

# Load existing device database
device_database = load_device_database()

# Debug: Show loaded hostnames at startup
if device_database:
    devices_with_hostnames = [(mac, data.get('hostname', '')) for mac, data in device_database.items() if 'hostname' in data and data['hostname']]
    if devices_with_hostnames:
        print(f"[STARTUP] Loaded {len(devices_with_hostnames)} devices with hostnames:")
        for mac, hostname in devices_with_hostnames:
            print(f"  - {mac}: {hostname}")

# Expanded manufacturer database
MANUFACTURERS = {
    # Espressif (ESP32/ESP8266)
    '24-0A-C4': 'Espressif (ESP32/ESP8266)',
    '28-56-2F': 'Espressif (ESP32/ESP8266)',
    '30-AE-A4': 'Espressif (ESP32/ESP8266)',
    '7C-9E-BD': 'Espressif (ESP32/ESP8266)',
    '94-B9-7E': 'Espressif (ESP32/ESP8266)',
    'A4-CF-12': 'Espressif (ESP32/ESP8266)',
    '3C-71-BF': 'Espressif (ESP32/ESP8266)',
    
    # Cameras
    '00-12-12': 'Hikvision Camera',
    '44-19-B6': 'Hikvision Camera',
    '54-C4-15': 'Hikvision Camera',
    '00-0F-7C': 'Dahua Camera',
    '08-60-6E': 'Dahua Camera',
    '2C-AA-8E': 'Wyze Camera',
    '00-00-F0': 'Samsung SmartCam',
    '00-1D-D3': 'Foscam Camera',
    
    # Raspberry Pi
    'DC-A6-32': 'Raspberry Pi Foundation',
    'B8-27-EB': 'Raspberry Pi Foundation',
    '28-CD-C1': 'Raspberry Pi Foundation',
    'E4-5F-01': 'Raspberry Pi Trading',
    '2C-CF-67': 'Raspberry Pi Foundation',
    
    # Smart Home/IoT
    '00-17-88': 'Philips Hue',
    'EC-FA-BC': 'Philips Hue',
    '98-F0-7B': 'Ring Doorbell',
    'A0-20-A6': 'Nest/Google',
    '18-B4-30': 'Nest/Google',
    '64-16-66': 'Amazon Echo/Alexa',
    'F0-D2-F1': 'Amazon Echo/Alexa',
    '50-F5-DA': 'Amazon Fire TV',
    'FC-A6-67': 'Amazon Devices',
    '34-D2-70': 'Sonos Speaker',
    '00-0E-58': 'Sonos Speaker',
    '5C-AA-FD': 'Xiaomi IoT',
    '34-CE-00': 'Xiaomi IoT',
    '78-11-DC': 'Xiaomi IoT',
    
    # Phones/Tablets
    'D4-9D-C0': 'Samsung Electronics',
    'E0-D5-5E': 'Apple iPhone/iPad',
    'AC-87-A3': 'Apple iPhone/iPad',
    '98-3B-8F': 'Intel (Laptop WiFi)',
    'AC-DE-48': 'Intel (Laptop WiFi)',
    
    # Routers
    'F8-9B-6E': 'Nokia Router',
    '28-87-BA': 'TP-Link Router',
    '9C-A2-F4': 'TP-Link Router',
    '80-2A-A8': 'Ubiquiti Networks',
    'B8-8A-60': 'MikroTik Router',
    '00-0C-43': 'Ralink Router',
    
    # Common WiFi Adapters
    '00-C0-CA': 'Alfa Network Adapter',
    '00-11-09': 'Ralink WiFi Adapter',
}

# Device type classification
IOT_KEYWORDS = ['ESP', 'Camera', 'Hue', 'Ring', 'Nest', 'Echo', 'Alexa', 
                'Sonos', 'Xiaomi IoT', 'SmartCam', 'Foscam', 'Hikvision', 'Dahua', 'Wyze']

def get_manufacturer(mac):
    """Get manufacturer from MAC OUI with enhanced database"""
    if not mac or mac == "unknown":
        return "Unknown"
    
    oui = mac[:8].upper().replace(':', '-')
    
    # Check for locally administered MAC
    first_byte = int(mac[:2], 16)
    is_local = bool(first_byte & 0x02)
    
    manufacturer = MANUFACTURERS.get(oui, f'Unknown ({oui})')
    
    if is_local:
        manufacturer += " [RANDOMIZED MAC]"
    
    return manufacturer

def classify_device(manufacturer):
    """Classify device type based on manufacturer"""
    for keyword in IOT_KEYWORDS:
        if keyword.lower() in manufacturer.lower():
            if 'ESP' in keyword:
                return "🔧 DIY/IoT Device"
            elif 'Camera' in keyword or any(x in manufacturer for x in ['Hikvision', 'Dahua', 'Wyze', 'Foscam']):
                return "📷 Security Camera"
            elif any(x in manufacturer for x in ['Hue', 'Ring', 'Nest', 'Echo', 'Alexa', 'Sonos', 'Xiaomi']):
                return "🏠 Smart Home Device"
    
    if 'Raspberry Pi' in manufacturer:
        return "🥧 Raspberry Pi"
    elif 'Router' in manufacturer or 'Ubiquiti' in manufacturer or 'MikroTik' in manufacturer:
        return "📡 Router/AP"
    elif 'Apple' in manufacturer:
        return "📱 Apple Device"
    elif 'Samsung' in manufacturer:
        return "📱 Samsung Device"
    elif 'Intel' in manufacturer:
        return "💻 Laptop/PC"
    elif 'RANDOMIZED' in manufacturer:
        return "🔀 Device (Random MAC)"
    else:
        return "❓ Unknown Device"

def estimate_distance(rssi):
    """Estimate distance from RSSI"""
    if rssi is None:
        return "Unknown"
    try:
        TX_POWER = 17
        PATH_LOSS = 3.5
        distance = 10 ** ((TX_POWER - rssi) / (10 * PATH_LOSS))
        
        if distance < 1:
            return "< 1m"
        elif distance < 5:
            return f"~{distance:.1f}m"
        elif distance < 20:
            return f"~{distance:.0f}m"
        else:
            return f">{distance:.0f}m"
    except:
        return "Unknown"

def get_device_display_name(mac):
    """Get device display name (hostname, nickname, or MAC)"""
    with db_lock:
        if mac in device_database:
            # Prefer real hostname if available
            if 'hostname' in device_database[mac] and device_database[mac]['hostname']:
                return f"{device_database[mac]['hostname']} ({mac})"
            # Fall back to nickname
            if 'nickname' in device_database[mac] and device_database[mac]['nickname']:
                return f"{device_database[mac]['nickname']} ({mac})"
        return mac







def generate_nickname(mac, manufacturer, device_type):
    """Generate automatic nickname for device"""
    # Remove emoji and "Device" suffix from device_type for cleaner names
    clean_type = device_type.replace('🔧', '').replace('📷', '').replace('🏠', '')
    clean_type = clean_type.replace('🥧', '').replace('📡', '').replace('📱', '')
    clean_type = clean_type.replace('💻', '').replace('🔀', '').replace('❓', '').strip()
    
    # Extract meaningful manufacturer name
    if 'Raspberry Pi' in manufacturer:
        return 'Raspberry Pi'
    elif 'Nokia Router' in manufacturer:
        return 'Nokia Router'
    elif 'TP-Link' in manufacturer:
        return 'TP-Link Router'
    elif 'Espressif' in manufacturer or 'ESP32' in manufacturer or 'ESP8266' in manufacturer:
        return 'ESP Device'
    elif 'Hikvision' in manufacturer:
        return 'Hikvision Camera'
    elif 'Dahua' in manufacturer:
        return 'Dahua Camera'
    elif 'Wyze' in manufacturer:
        return 'Wyze Camera'
    elif 'Apple' in manufacturer:
        return 'Apple Device'
    elif 'Samsung' in manufacturer:
        return 'Samsung Device'
    elif 'Intel' in manufacturer:
        return 'Laptop/PC'
    elif 'Xiaomi' in manufacturer:
        return 'Xiaomi Device'
    elif 'Ring' in manufacturer:
        return 'Ring Doorbell'
    elif 'Nest' in manufacturer or 'Google' in manufacturer:
        return 'Nest/Google Device'
    elif 'Amazon' in manufacturer or 'Echo' in manufacturer or 'Alexa' in manufacturer:
        return 'Amazon Device'
    elif 'Sonos' in manufacturer:
        return 'Sonos Speaker'
    elif 'Philips Hue' in manufacturer:
        return 'Philips Hue'
    elif 'RANDOMIZED' in manufacturer:
        return f'Random MAC Device'
    elif 'Unknown' not in manufacturer:
        # Use manufacturer name if it's not unknown
        clean_mfr = manufacturer.split('(')[0].strip()
        return clean_mfr
    else:
        # Fall back to device type
        if clean_type and clean_type != 'Unknown Device':
            return clean_type
        # Last resort: use last 4 chars of MAC
        return f'Device {mac[-8:]}'

def track_device(mac, rssi, pkt_type, frame_subtype=None):
    """Track device activity and metadata"""
    now = datetime.now()
    
    # Track random MAC activity for attack detection
    first_byte = int(mac[:2], 16)
    is_local = bool(first_byte & 0x02)
    if is_local:
        random_mac_activity.append((now, mac, rssi))
        # Keep last 5 minutes of random MAC activity
        cutoff = now - timedelta(minutes=5)
        random_mac_activity[:] = [(t, m, r) for t, m, r in random_mac_activity if t > cutoff]
        
        # Check for suspicious burst: >20 different random MACs in 1 minute
        one_min_ago = now - timedelta(minutes=1)
        recent_random = [(t, m, r) for t, m, r in random_mac_activity if t > one_min_ago]
        unique_macs = len(set(m for t, m, r in recent_random))
        if unique_macs > 20:
            print(f"\n⚠️  WARNING: Suspicious random MAC burst detected!")
            print(f"   {unique_macs} different random MACs in last minute")
            print(f"   Could indicate: wardriving, reconnaissance, or attack attempt\n")
        
        # Skip tracking if it's a random MAC with <50 total packets (reduce noise)
        if mac in device_database and device_database[mac]['total_packets'] < 50:
            return
    
    # Update persistent database with thread safety
    with db_lock:
        # Initialize only missing fields (preserves hostname/nickname if already set)
        if mac not in device_database:
            device_database[mac] = {}
        
        if 'first_ever_seen' not in device_database[mac]:
            device_database[mac]['first_ever_seen'] = now
        if 'connection_count' not in device_database[mac]:
            device_database[mac]['connection_count'] = 0
        if 'total_packets' not in device_database[mac]:
            device_database[mac]['total_packets'] = 0
        if 'total_connection_time' not in device_database[mac]:
            device_database[mac]['total_connection_time'] = 0
        if 'bytes_sent' not in device_database[mac]:
            device_database[mac]['bytes_sent'] = 0
        if 'bytes_received' not in device_database[mac]:
            device_database[mac]['bytes_received'] = 0
        
        # Update counters (hostname and nickname are NEVER modified here)
        device_database[mac]['last_ever_seen'] = now
        device_database[mac]['total_packets'] += 1
        device_database[mac]['connection_count'] += 1
    
    # Track current session
    if mac not in devices:
        manufacturer = get_manufacturer(mac)
        device_type = classify_device(manufacturer)
        is_known = mac.lower() in KNOWN_DEVICES
        is_iot = any(keyword in device_type for keyword in ['🔧', '📷', '🏠'])
        
        # Determine if device "belongs" based on history
        belongs = False
        history_note = ""
        if mac in device_database:
            total_time = device_database[mac]['total_connection_time']
            connections = device_database[mac]['connection_count']
            days_known = (now - device_database[mac]['first_ever_seen']).days
            
            # Device "belongs" if: seen multiple times OR connected for >1 hour total OR known for >7 days
            if connections > 5 or total_time > 3600 or days_known > 7:
                belongs = True
                history_note = f"Regular device ({connections} connections, {total_time//60}min total)"
            else:
                history_note = f"Occasional ({connections} connections, {total_time//60}min total)"
        else:
            history_note = "First time seen"
        
        devices[mac] = {
            'mac': mac,
            'manufacturer': manufacturer,
            'device_type': device_type,
            'first_seen': now,
            'last_seen': now,
            'session_start': now,
            'rssi_values': [],
            'packet_count': 0,
            'is_known': is_known,
            'is_new': True,
            'is_iot': is_iot,
            'belongs': belongs,
            'history_note': history_note,
            'frame_types': defaultdict(int),
            'channels_seen': set(),
            'bytes_sent': 0,
            'bytes_received': 0,
            'data_history': []  # [(timestamp, bytes, direction)]
        }
        
        # Update connection count and nickname with proper locking
        with db_lock:
            if mac in device_database:
                device_database[mac]['connection_count'] = device_database[mac].get('connection_count', 0) + 1
            
            # Auto-generate nickname ONLY if device doesn't have one
            if 'nickname' not in device_database[mac] or not device_database[mac]['nickname']:
                nickname = generate_nickname(mac, manufacturer, device_type)
                device_database[mac]['nickname'] = nickname
                print(f"✅ Auto-named device: {nickname} ({mac})")
                save_device_database(device_database)
        
        # Alert on new device (not in database or doesn't belong)
        if ALERT_ON_NEW and not is_known and not belongs:
            print_new_device_alert(devices[mac])
        
        # Alert on IoT device
        if ALERT_ON_IOT and is_iot and not is_known:
            print_iot_alert(devices[mac])
    
    device = devices[mac]
    device['last_seen'] = now
    device['packet_count'] += 1
    device['frame_types'][pkt_type] += 1
    device['channels_seen'].add(current_channel)
    
    if rssi is not None:
        device['rssi_values'].append(rssi)
        # Keep last 50 RSSI values
        if len(device['rssi_values']) > 50:
            device['rssi_values'] = device['rssi_values'][-50:]

def print_new_device_alert(device):
    """Print alert for new device"""
    print("\n" + "🆕 " + "="*88)
    print(f"NEW DEVICE DETECTED - {device['first_seen'].strftime('%H:%M:%S')}")
    print("="*90)
    print(f"  MAC Address:       {device['mac']}")
    print(f"  Manufacturer:      {device['manufacturer']}")
    print(f"  Device Type:       {device['device_type']}")
    print(f"  History:           {device['history_note']}")
    print(f"  Belongs Here:      {'✅ YES' if device['belongs'] else '⚠️  UNKNOWN/SUSPICIOUS'}")
    if device['rssi_values']:
        rssi = device['rssi_values'][-1]
        print(f"  Signal Strength:   {rssi} dBm")
        print(f"  Est. Distance:     {estimate_distance(rssi)}")
    print("="*90 + "\n")

def print_iot_alert(device):
    """Print alert for IoT device"""
    print("\n" + "⚠️  " + "="*88)
    print(f"IoT DEVICE DETECTED - {device['first_seen'].strftime('%H:%M:%S')}")
    print("="*90)
    print(f"  MAC Address:       {device['mac']}")
    print(f"  Manufacturer:      {device['manufacturer']}")
    print(f"  Device Type:       {device['device_type']}")
    if 'ESP' in device['device_type']:
        print(f"  ⚠️  WARNING:        ESP32/ESP8266 - Could be DIY device")
    elif '📷' in device['device_type']:
        print(f"  ℹ️  NOTE:           Security camera detected")
    print("="*90 + "\n")

def channel_hopper():
    """Hop between channels"""
    global current_channel
    while True:
        for channel in CHANNELS:
            try:
                subprocess.run(
                    ['iw', 'dev', interface, 'set', 'channel', str(channel)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
                current_channel = channel
                time.sleep(DWELL_TIME)
            except Exception:
                pass

def hostname_sniffer():
    """Continuously sniff wlan0 for DHCP/mDNS hostnames"""
    print(f"[*] Starting continuous hostname capture on {HOSTNAME_INTERFACE}...")
    
    def hostname_packet_handler(pkt):
        try:
            src_mac = None
            hostname = None
            
            # Get source MAC
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src.lower()
            
            if not src_mac or src_mac.startswith('ff:ff:'):
                return
            
            # Extract from DHCP
            if pkt.haslayer(DHCP):
                for option in pkt[DHCP].options:
                    if isinstance(option, tuple) and option[0] == 'hostname':
                        hostname = option[1]
                        if isinstance(hostname, bytes):
                            hostname = hostname.decode('utf-8', errors='ignore')
                        hostname = hostname.strip()
                        break
            
            # Extract from mDNS
            if not hostname and pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qd and dns.qd.qname:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode('utf-8', errors='ignore')
                    if '.local' in qname:
                        hostname = qname.replace('.local.', '').replace('.local', '').strip()
            
            # Update database if we found a hostname (validate it's not empty/garbage)
            if hostname and src_mac and len(hostname) > 0 and not hostname.startswith('_'):
                # Additional validation: hostname should be reasonable
                if len(hostname) > 50 or any(c in hostname for c in ['\x00', '\n', '\r', '\t']):
                    return  # Skip garbage hostnames
                
                with db_lock:
                    # Initialize entry if needed (preserve ALL existing fields)
                    if src_mac not in device_database:
                        device_database[src_mac] = {
                            'first_ever_seen': datetime.now(),
                            'last_ever_seen': datetime.now(),
                            'total_connection_time': 0,
                            'connection_count': 0,
                            'total_packets': 0,
                            'bytes_sent': 0,
                            'bytes_received': 0
                        }
                    
                    # Only update if we don't have a hostname yet (never overwrite existing valid hostname)
                    current_hostname = device_database[src_mac].get('hostname', '')
                    if not current_hostname:
                        device_database[src_mac]['hostname'] = hostname
                        print(f"\n🔍 Hostname discovered: {hostname} ({src_mac})")
                        save_device_database(device_database)
        
        except:
            pass
    
    try:
        sniff(iface=HOSTNAME_INTERFACE, prn=hostname_packet_handler, store=0)
    except Exception as e:
        print(f"[!] Hostname sniffer error: {e}")

def packet_handler(pkt):
    """Process captured packets - only from OUR network"""
    if not pkt.haslayer(Dot11):
        return
    
    # Filter: Only process packets involving OUR routers
    # addr3 is usually the BSSID (router MAC)
    bssid = pkt.addr3.lower() if pkt.addr3 else None
    addr1 = pkt.addr1.lower() if pkt.addr1 else None
    addr2 = pkt.addr2.lower() if pkt.addr2 else None
    
    # Check if packet involves our network
    involves_our_network = False
    if bssid in MY_ROUTERS or addr1 in MY_ROUTERS or addr2 in MY_ROUTERS:
        involves_our_network = True
    
    if not involves_our_network:
        return  # Ignore packets from other networks
    
    # Get RSSI and packet length
    rssi = None
    if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
        rssi = pkt[RadioTap].dBm_AntSignal
    
    pkt_len = len(pkt)
    
    # Track different address types with data direction
    addresses_data = []  # [(mac, direction, bytes)]
    frame_type = "Unknown"
    
    # Skip multicast/broadcast addresses
    def is_multicast(mac):
        if not mac:
            return True
        first_byte = int(mac[:2], 16)
        return bool(first_byte & 0x01) or mac == 'ff:ff:ff:ff:ff:ff'
    
    if pkt.type == 0:  # Management frames
        frame_type = "Management"
        if pkt.addr2 and not is_multicast(pkt.addr2) and pkt.addr2 not in MY_ROUTERS:
            addresses_data.append((pkt.addr2.lower(), 'sent', pkt_len))
        if pkt.addr1 and not is_multicast(pkt.addr1) and pkt.addr1 not in MY_ROUTERS:
            addresses_data.append((pkt.addr1.lower(), 'received', pkt_len))
    
    elif pkt.type == 1:  # Control frames
        frame_type = "Control"
        if pkt.addr2 and not is_multicast(pkt.addr2) and pkt.addr2 not in MY_ROUTERS:
            addresses_data.append((pkt.addr2.lower(), 'sent', pkt_len))
    
    elif pkt.type == 2:  # Data frames
        frame_type = "Data"
        # addr2 is source (sender)
        if pkt.addr2 and not is_multicast(pkt.addr2) and pkt.addr2 not in MY_ROUTERS:
            addresses_data.append((pkt.addr2.lower(), 'sent', pkt_len))
        # addr1 is destination (receiver)
        if pkt.addr1 and not is_multicast(pkt.addr1) and pkt.addr1 not in MY_ROUTERS:
            addresses_data.append((pkt.addr1.lower(), 'received', pkt_len))
    
    # Track devices with data transfer
    for addr, direction, byte_count in addresses_data:
        track_device(addr, rssi, frame_type, pkt.subtype if hasattr(pkt, 'subtype') else None)
        
        # Update data transfer
        if addr in devices:
            now = datetime.now()
            devices[addr]['data_history'].append((now, byte_count, direction))
            
            # Update totals
            if direction == 'sent':
                devices[addr]['bytes_sent'] += byte_count
                if addr in device_database:
                    with db_lock:
                        device_database[addr]['bytes_sent'] = device_database[addr].get('bytes_sent', 0) + byte_count
            else:
                devices[addr]['bytes_received'] += byte_count
                if addr in device_database:
                    with db_lock:
                        device_database[addr]['bytes_received'] = device_database[addr].get('bytes_received', 0) + byte_count
            
            # Keep only last 5 seconds of data history
            cutoff = now - timedelta(seconds=5)
            devices[addr]['data_history'] = [(t, b, d) for t, b, d in devices[addr]['data_history'] if t > cutoff]

def print_summary():
    """Print periodic summary of devices"""
    global previous_active_devices
    
    while True:
        time.sleep(30)  # Print summary every 30 seconds
        
        now = datetime.now()
        active_devices = [d for d in devices.values() if (now - d['last_seen']).seconds < 60]
        current_active_macs = {d['mac'] for d in active_devices}
        
        # Detect offline devices
        offline_devices = previous_active_devices - current_active_macs
        if offline_devices:
            for mac in offline_devices:
                print(f"\n📴 Device went offline: {get_device_display_name(mac)}")
        
        # Update connection times for active devices
        with db_lock:
            for device in devices.values():
                session_time = (device['last_seen'] - device['session_start']).seconds
                mac = device['mac']
                if mac in device_database:
                    # Update total connection time (never modify hostname/nickname)
                    old_total = device_database[mac].get('total_connection_time', 0)
                    device_database[mac]['total_connection_time'] = old_total + session_time
                    device['session_start'] = device['last_seen']  # Reset for next period
            
            # Save database periodically
            save_device_database(device_database)
        
        # Show random MAC probe stats
        five_min_ago = now - timedelta(minutes=5)
        recent_random = [(t, m, r) for t, m, r in random_mac_activity if t > five_min_ago]
        unique_random_macs = len(set(m for t, m, r in recent_random))
        print(f"Random MAC Probes:  {unique_random_macs} unique (last 5min)")
        
        # Update previous active devices for next iteration
        previous_active_devices = current_active_macs
        
        print("\n" + "="*90)
        print(f"NETWORK DEVICE SUMMARY - {now.strftime('%H:%M:%S')}")
        print("="*90)
        print(f"Session Devices:    {len(devices)}")
        print(f"Active (last 60s):  {len(active_devices)}")
        print(f"Known Devices:      {sum(1 for d in devices.values() if d['is_known'])}")
        print(f"Belongs Here:       {sum(1 for d in devices.values() if d.get('belongs', False))}")
        print(f"Suspicious:         {sum(1 for d in devices.values() if not d.get('belongs', False) and not d['is_known'])}")
        print(f"IoT Devices:        {sum(1 for d in devices.values() if d['is_iot'])}")
        print(f"Total in Database:  {len(device_database)}")
        print("="*90)
        
        if active_devices:
            print("\nACTIVE DEVICES:")
            print("-"*140)
            print(f"{'STATUS':12} | {'DEVICE NAME':35} | {'SIGNAL':8} | {'DATA (5s)':15} | {'TOTAL DATA':20} | {'DEVICE TYPE':25}")
            print("-"*140)
            
            # Filter out random MAC spam (< 50 packets)
            filtered_devices = []
            for device in active_devices:
                mac = device['mac']
                if mac in device_database:
                    if device_database[mac]['total_packets'] < 50:
                        first_byte = int(mac[:2], 16)
                        is_local = bool(first_byte & 0x02)
                        if is_local:
                            continue  # Skip random MAC spam
                filtered_devices.append(device)
            
            for device in sorted(filtered_devices, key=lambda x: x['last_seen'], reverse=True):
                if device['is_known']:
                    status = "✓ KNOWN"
                elif device.get('belongs', False):
                    status = "✓ REGULAR"
                else:
                    status = "⚠ SUSPICIOUS"
                
                avg_rssi = sum(device['rssi_values'][-5:]) / len(device['rssi_values'][-5:]) if device['rssi_values'] else None
                rssi_str = f"{avg_rssi:.0f} dBm" if avg_rssi else "N/A"
                
                # Calculate 5-second transfer rate
                now = datetime.now()
                cutoff = now - timedelta(seconds=5)
                recent_bytes = sum(b for t, b, d in device.get('data_history', []) if t > cutoff)
                rate_str = f"{recent_bytes/1024:.1f} KB/s" if recent_bytes > 0 else "0 KB/s"
                
                # Total data
                total_sent = device.get('bytes_sent', 0)
                total_recv = device.get('bytes_received', 0)
                total_mb = (total_sent + total_recv) / (1024 * 1024)
                total_str = f"↑{total_sent/1024:.0f}KB ↓{total_recv/1024:.0f}KB"
                
                # Get display name (nickname or MAC)
                display_name = get_device_display_name(device['mac'])[:35]
                
                print(f"  {status:12} | {display_name:35} | {rssi_str:8} | {rate_str:15} | {total_str:20} | {device['device_type']:25}")
        
        print("\n")

# Main
print("="*90)
print("WiFi Network Device Monitor v1.0")
print("="*90)
print(f"Interface:     {interface} (monitor mode)")
print(f"Channels:      {', '.join(map(str, CHANNELS))}")
print(f"Known Devices: {len(KNOWN_DEVICES)}")
print(f"Channels:      {', '.join(map(str, CHANNELS))}")
print(f"Known Devices: {len(KNOWN_DEVICES)}")
print(f"\nMonitoring:")
print(f"  ✓ All network devices (any frame type)")
print(f"  ✓ Device manufacturer identification")
print(f"  ✓ IoT device detection (ESP32, cameras, smart home)")
print(f"  ✓ Signal strength tracking")
print(f"  ✓ New device alerts")
print(f"  ✓ Continuous hostname capture (DHCP/mDNS)")
print(f"\n💡 Tip: Hostnames are captured automatically as devices communicate")
print(f"\nAlerts:")
print(f"  New Devices:   {'Enabled' if ALERT_ON_NEW else 'Disabled'}")
print(f"  IoT Devices:   {'Enabled' if ALERT_ON_IOT else 'Disabled'}")
print(f"\nStarting monitor...")
print("="*90 + "\n")

# Start hostname sniffer
hostname_thread = threading.Thread(target=hostname_sniffer, daemon=True)
hostname_thread.start()

# Start channel hopping
hopper_thread = threading.Thread(target=channel_hopper, daemon=True)
hopper_thread.start()

# Start summary printer
summary_thread = threading.Thread(target=print_summary, daemon=True)
summary_thread.start()

try:
    sniff(iface=interface, prn=packet_handler, store=0)
except KeyboardInterrupt:
    print("\n" + "="*90)
    print("FINAL DEVICE SUMMARY")
    print("="*90)
    
    # Save database before exit
    now = datetime.now()
    with db_lock:
        for device in devices.values():
            session_time = (device['last_seen'] - device['session_start']).seconds
            if device['mac'] in device_database:
                old_total = device_database[device['mac']].get('total_connection_time', 0)
                device_database[device['mac']]['total_connection_time'] = old_total + session_time
        
        save_device_database(device_database)
    print("\n✅ Device database saved")
    
    print(f"\nSession Duration: {(datetime.now() - session_start).seconds}s")
    print(f"Total Devices Seen: {len(devices)}\n")
    
    # Group by type
    by_type = defaultdict(list)
    for device in devices.values():
        by_type[device['device_type']].append(device)
    
    for device_type in sorted(by_type.keys()):
        print(f"\n{device_type} ({len(by_type[device_type])}):")
        print("-"*90)
        for device in sorted(by_type[device_type], key=lambda x: x['packet_count'], reverse=True):
            status = "✓" if device['is_known'] else "⚠"
            avg_rssi = sum(device['rssi_values']) / len(device['rssi_values']) if device['rssi_values'] else None
            rssi_str = f"{avg_rssi:.0f} dBm" if avg_rssi else "N/A"
            duration = (device['last_seen'] - device['first_seen']).seconds
            
            print(f"  {status} {device['mac']:17} | {rssi_str:8} | Packets: {device['packet_count']:5} | Active: {duration}s")
            print(f"     {device['manufacturer']}")
    
    print(f"\n{'='*90}")
    print("Shutting down...")
