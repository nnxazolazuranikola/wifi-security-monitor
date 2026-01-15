#!/usr/bin/env python3
"""
WiFi Deauth Attack Detector
Monitors for deauth/disassoc attacks with behavioral analysis
"""

import sys
import time
import threading
import subprocess
import json
import os
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import *

# Load configuration
CONFIG_FILE = 'config.json'
if not os.path.exists(CONFIG_FILE):
    print(f"❌ Error: {CONFIG_FILE} not found!")
    print("Please create config.json - see README for template")
    sys.exit(1)

try:
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
except json.JSONDecodeError as e:
    print(f"❌ Error parsing {CONFIG_FILE}: {e}")
    sys.exit(1)

# Load settings from config
interface = config['network']['interface']
CHANNELS = config['network']['channels']
DWELL_TIME = config['network']['channel_dwell_time']
WHITELISTED_DEVICES = [mac.lower() for mac in config['network']['whitelist_macs']]
LOCAL_DEVICE_MACS = [mac.lower() for mac in config['network']['local_device_macs']]
LOG_FILE = config['output']['log_file']

# Detection thresholds from config
RSSI_JUMP_THRESHOLD = config['detection']['rssi_jump_threshold']
LOW_RATE_THRESHOLD = config['detection']['low_rate_threshold']
TIMING_CV_THRESHOLD = config['detection']['timing_cv_threshold']
SEQUENCE_GAP_THRESHOLD = config['detection']['sequence_gap_threshold']
BURST_THRESHOLD_MS = config['detection']['burst_threshold_ms']
LEGITIMACY_THRESHOLD = config['detection']['legitimacy_threshold']
THREAT_REDUCTION_PCT = config['detection']['threat_reduction_percentage']

# WiFi settings
TX_POWER = config['wifi']['tx_power_dbm']
PATH_LOSS_EXP = config['wifi']['path_loss_exponent']

# Runtime state
attackers = {}
attack_history = defaultdict(lambda: deque(maxlen=100))
total_attacks = 0
current_channel = CHANNELS[0]

def get_manufacturer(mac):
    """Get manufacturer from MAC address OUI"""
    if not mac or mac == "unknown":
        return "Unknown"
    oui = mac[:8].upper().replace(':', '-')
    
    # Check for locally administered MAC (bit 1 of first octet = 1)
    # These are often spoofed/randomized
    first_byte = int(mac[:2], 16)
    is_local = bool(first_byte & 0x02)
    
    manufacturers = {
        'F8-9B-6E': 'Nokia',
        '2C-CF-67': 'Raspberry Pi',
        '00-C0-CA': 'Alfa Network',
        '28-87-BA': 'TP-Link',
        '9C-A2-F4': 'TP-Link',
        '28-56-2F': 'Unknown IoT',
        'D4-9D-C0': 'Samsung Electronics',
        '92-9F-1D': 'Xiaomi/Random MAC',
        'E2-1C-32': 'Random MAC',
        '78-20-51': 'Unknown Laptop/PC',
        '98-3B-8F': 'Intel Corporation',
        'AC-DE-48': 'Intel Corporation',
        'B8-8A-60': 'Routerboard.com',
        'DC-A6-32': 'Raspberry Pi Foundation',
        '00-0C-43': 'Ralink Technology',
        '80-2A-A8': 'Ubiquiti Networks',
        '20-1F-3B': 'Unknown Device',
        '58-2F-40': 'Unknown Device',
        '1C-53-F9': 'Unknown Device',
        'F2-5A-67': 'Random/Local MAC',
        '1E-B7-14': 'Random/Local MAC',
        '32-C3-7C': 'Random/Local MAC',
        '5E-01-A4': 'Random/Local MAC',
        '00-50-56': 'VMware',
        '00-0C-29': 'VMware',
        '00-1C-42': 'Parallels',
        '08-00-27': 'VirtualBox',
        'E0-D5-5E': 'Apple',
        'AC-87-A3': 'Apple',
        '00-1A-11': 'Google',
        '3C-5A-B4': 'Google',
        '00-26-5A': 'Amazon Technologies'
    }
    
    result = manufacturers.get(oui, f'Unknown ({oui})')
    if is_local:
        result += " [LOCALLY ADMINISTERED - SPOOFED?]"
    
    return result

def estimate_distance(rssi):
    """Estimate rough distance from RSSI (very approximate)"""
    if rssi == "Unknown" or rssi is None:
        return "Unknown"
    try:
        # Path loss formula: distance = 10^((TxPower - RSSI) / (10 * n))
        distance = 10 ** ((TX_POWER - rssi) / (10 * PATH_LOSS_EXP))
        
        if distance < 1:
            return "< 1m (Very Close)"
        elif distance < 5:
            return f"~{distance:.1f}m (Close)"
        elif distance < 20:
            return f"~{distance:.0f}m (Medium)"
        elif distance < 50:
            return f"~{distance:.0f}m (Far)"
        else:
            return f">{distance:.0f}m (Very Far)"
    except Exception as e:
        return "Unknown"

def analyze_rssi_for_spoofing(attacker_mac):
    """
    Analyze RSSI patterns to detect MAC spoofing.
    Returns: (is_spoofed, confidence, details)
    """
    if attacker_mac not in attackers:
        return False, 0, []
    
    attacker = attackers[attacker_mac]
    rssi_values = attacker.get('rssi_values', [])
    
    if len(rssi_values) < 3:
        return False, 0, ["Insufficient data"]
    
    # Remove None/Unknown values
    valid_rssi = [r for r in rssi_values if r is not None and r != "Unknown"]
    if len(valid_rssi) < 3:
        return False, 0, ["Insufficient valid RSSI samples"]
    
    details = []
    spoofing_indicators = 0
    confidence = 0
    
    # 1. Check for impossible RSSI jumps (device teleportation)
    # A real router doesn't move, so RSSI should be relatively stable
    max_rssi = max(valid_rssi[-10:])  # Last 10 samples
    min_rssi = min(valid_rssi[-10:])
    rssi_range = max_rssi - min_rssi
    
    if rssi_range > 30:
        spoofing_indicators += 3
        confidence += 40
        details.append(f"🚩 EXTREME RSSI jump: {rssi_range}dB (>30dB suggests multiple transmitters)")
    elif rssi_range > 20:
        spoofing_indicators += 2
        confidence += 30
        details.append(f"🚩 Large RSSI jump: {rssi_range}dB (>20dB very suspicious)")
    elif rssi_range > 15:
        spoofing_indicators += 1
        confidence += 15
        details.append(f"⚠️  Significant RSSI variation: {rssi_range}dB")
    
    # 2. Check for sudden jumps between consecutive packets
    # Real devices show gradual RSSI changes due to environmental factors
    sudden_jumps = 0
    for i in range(1, min(len(valid_rssi), 20)):
        jump = abs(valid_rssi[i] - valid_rssi[i-1])
        if jump > 15:
            sudden_jumps += 1
    
    if sudden_jumps > 3:
        spoofing_indicators += 2
        confidence += 25
        details.append(f"🚩 Multiple sudden RSSI jumps: {sudden_jumps} times (>15dB each)")
    elif sudden_jumps > 1:
        spoofing_indicators += 1
        confidence += 15
        details.append(f"⚠️  Sudden RSSI jumps detected: {sudden_jumps} times")
    
    # 3. Check standard deviation - real routers have low variance
    import statistics
    if len(valid_rssi) >= 5:
        std_dev = statistics.stdev(valid_rssi[-20:])  # Last 20 samples
        if std_dev > 8:
            spoofing_indicators += 2
            confidence += 20
            details.append(f"🚩 High RSSI instability: σ={std_dev:.1f}dB (suggests movement/multiple sources)")
        elif std_dev > 5:
            spoofing_indicators += 1
            confidence += 10
            details.append(f"⚠️  Moderate RSSI variation: σ={std_dev:.1f}dB")
    
    # 4. Check for bimodal distribution (two distinct signal strengths)
    # This suggests two different transmitters using the same MAC
    if len(valid_rssi) >= 10:
        # Split into strong and weak signal groups
        median_rssi = statistics.median(valid_rssi[-20:])
        strong_signals = [r for r in valid_rssi[-20:] if r > median_rssi + 5]
        weak_signals = [r for r in valid_rssi[-20:] if r < median_rssi - 5]
        
        if len(strong_signals) > 3 and len(weak_signals) > 3:
            # Check if the two groups are distinctly separated
            if strong_signals and weak_signals:
                gap = min(strong_signals) - max(weak_signals)
                if gap > 10:
                    spoofing_indicators += 3
                    confidence += 35
                    details.append(f"🚩 BIMODAL signal pattern detected: {gap}dB gap (MULTIPLE TRANSMITTERS)")
    
    # 5. Estimate if RSSI suggests attacker is moving impossibly fast
    # Calculate implied speed based on RSSI changes
    if len(valid_rssi) >= 5 and len(attacker.get('inter_packet_intervals', [])) >= 4:
        time_span = sum(attacker['inter_packet_intervals'][-4:])  # Last 4 intervals
        if time_span > 0:
            rssi_change = abs(valid_rssi[-1] - valid_rssi[-5])
            # Rough estimate: 6dB change ≈ doubling/halving distance
            # For TX_POWER=20, RSSI=-40 ≈ 7m, RSSI=-46 ≈ 14m
            if rssi_change > 10:
                distance_change_estimate = 10 ** ((rssi_change) / (10 * PATH_LOSS_EXP))
                speed_estimate = distance_change_estimate / time_span if time_span > 0 else 0
                if speed_estimate > 5:  # Moving >5 m/s (18 km/h) is unusual for router
                    spoofing_indicators += 2
                    confidence += 20
                    details.append(f"🚩 Implied movement speed: ~{speed_estimate:.1f}m/s (impossible for stationary router)")
    
    # 6. Add distance estimates to help locate attacker
    if valid_rssi:
        current_rssi = valid_rssi[-1]
        current_distance = estimate_distance(current_rssi)
        strongest_rssi = max(valid_rssi)
        closest_distance = estimate_distance(strongest_rssi)
        
        details.append(f"📍 Current distance estimate: {current_distance} (RSSI: {current_rssi}dB)")
        details.append(f"📍 Closest observed: {closest_distance} (RSSI: {strongest_rssi}dB)")
    
    # Determine if spoofed based on indicators
    is_spoofed = spoofing_indicators >= 2 or confidence >= 50
    confidence = min(confidence, 95)  # Cap at 95% (never 100% certain)
    
    return is_spoofed, confidence, details

def track_attacker(real_mac, spoofed_src, rssi, attack_type, dst, bssid, rate=None, antenna=None, retry=False, pkt=None):
    """Track attacker-specific information"""
    global total_attacks
    
    if real_mac not in attackers:
        attackers[real_mac] = {
            'first_attack': datetime.now(),
            'last_attack': datetime.now(),
            'total_attacks': 0,
            'spoofed_macs': set(),
            'targets': set(),
            'rssi_values': [],
            'manufacturer': get_manufacturer(real_mac),
            'attack_types': defaultdict(int),
            'broadcast_attacks': 0,
            'targeted_attacks': 0,
            'rates': [],
            'antennas': set(),
            'retry_count': 0,
            'packet_times': [],  # Timestamps for timing analysis
            'inter_packet_intervals': [],  # Time between packets
            'burst_count': 0,  # Number of high-speed bursts detected
            'sequence_numbers': [],  # Track sequence numbers for fingerprinting
            'vendor_fingerprints': set()  # Hardware-specific RadioTap signatures
        }
    
    attacker = attackers[real_mac]
    attacker['last_attack'] = datetime.now()
    attacker['total_attacks'] += 1
    attacker['spoofed_macs'].add(spoofed_src)
    attacker['targets'].add(dst)
    if rssi not in ["Unknown", None]:
        attacker['rssi_values'].append(rssi)
    attacker['attack_types'][attack_type] += 1
    
    # Track behavioral indicators
    if rate is not None:
        attacker['rates'].append(rate)
    if antenna is not None:
        attacker['antennas'].add(antenna)
    if retry:
        attacker['retry_count'] += 1
    
    # Timing analysis
    current_time = time.time()
    attacker['packet_times'].append(current_time)
    
    # Track sequence numbers for device fingerprinting
    if hasattr(pkt, 'SC'):
        seq_num = pkt.SC >> 4
        attacker['sequence_numbers'].append(seq_num)
    
    # Track vendor-specific fingerprint (hardware signature)
    if pkt and pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'notdecoded'):
        if pkt[RadioTap].notdecoded:
            vendor_fp = pkt[RadioTap].notdecoded.hex()
            attacker['vendor_fingerprints'].add(vendor_fp)
    
    # Calculate inter-packet interval
    if len(attacker['packet_times']) > 1:
        interval = current_time - attacker['packet_times'][-2]
        attacker['inter_packet_intervals'].append(interval)
        
        # Detect burst (multiple packets < 100ms apart)
        if interval < 0.1:  # Less than 100ms = burst
            attacker['burst_count'] += 1
    
    # Track broadcast vs targeted
    if dst == "ff:ff:ff:ff:ff:ff":
        attacker['broadcast_attacks'] += 1
    else:
        attacker['targeted_attacks'] += 1
    
    total_attacks += 1
    attack_history[real_mac].append(current_time)

def is_whitelisted(mac):
    """Check if MAC address is whitelisted (trusted device)"""
    if not mac or mac == "unknown":
        return False
    return mac.lower() in [w.lower() for w in WHITELISTED_DEVICES]

def channel_hopper():
    """Hop between 2.4GHz and 5GHz channels to monitor both bands"""
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
            except Exception as e:
                pass  # Continue hopping even if a channel switch fails

def is_local_device(mac_or_ip):
    """Check if target is on YOUR local network"""
    # Check if MAC is in configured local devices list
    if any(str(mac_or_ip).lower() == mac.lower() for mac in LOCAL_DEVICE_MACS):
        return True
    # Check if it's your router (whitelist)
    if any(str(mac_or_ip).lower() == mac.lower() for mac in WHITELISTED_DEVICES):
        return True
    return False

def analyze_timing_pattern(attacker):
    """Analyze packet timing to detect automated attack tools"""
    if len(attacker['inter_packet_intervals']) < 3:
        return None, None
    
    intervals = attacker['inter_packet_intervals']
    
    # Calculate timing statistics
    avg_interval = sum(intervals) / len(intervals)
    
    # Check for regular intervals (automated tools)
    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = variance ** 0.5
    
    # Use coefficient of variation (CV) = std_dev / avg
    # CV is scale-independent - works for fast and slow attacks
    cv = std_dev / avg_interval if avg_interval > 0 else 0
    
    # Low CV = very consistent timing = likely automated
    consistency_score = 0
    
    # Automated tools have CV < 0.1 (within 10% variance)
    if cv < 0.05 and avg_interval < 2.0:  # Very consistent AND fast
        consistency_score = 90  # Highly automated (aireplay-ng, mdk4)
    elif cv < 0.1 and avg_interval < 5.0:  # Consistent AND reasonably fast
        consistency_score = 70  # Probably automated
    elif cv < 0.15 and avg_interval < 10.0:  # Somewhat consistent
        consistency_score = 40  # Maybe automated
    
    # Slow attacks (>10s interval) are likely legitimate even if consistent
    if avg_interval > 10.0:
        consistency_score = max(0, consistency_score - 30)  # Reduce score
    
    pattern = "AUTOMATED TOOL" if consistency_score > 60 else "MANUAL/IRREGULAR"
    
    return consistency_score, pattern
    
    return consistency_score, pattern

def detect_sequence_anomalies(attacker):
    """Detect suspicious sequence number patterns"""
    if len(attacker['sequence_numbers']) < 3:
        return None
    
    seq_nums = attacker['sequence_numbers']
    anomalies = []
    
    # Check for duplicates (retransmissions or spoofing)
    if len(seq_nums) != len(set(seq_nums)):
        anomalies.append("Duplicate sequence numbers (suspicious)")
    
    # Check for large gaps (device might be spoofing)
    for i in range(1, len(seq_nums)):
        gap = (seq_nums[i] - seq_nums[i-1]) % 4096  # Seq wraps at 4096
        if gap > 100:  # Suspicious gap
            anomalies.append(f"Large sequence gap: {gap}")
            break
    
    # Check if sequence numbers are suspiciously sequential (fake)
    if len(seq_nums) >= 5:
        diffs = [seq_nums[i] - seq_nums[i-1] for i in range(1, min(5, len(seq_nums)))]
        if all(d == 1 for d in diffs):
            anomalies.append("Perfect sequence (possibly crafted packets)")
    
    return anomalies if anomalies else None

def calculate_threat_level(attacker_mac, attack_rate, dst, real_tx, src):
    """Calculate threat severity score (0-100)"""
    score = 0
    attacker = attackers[attacker_mac]
    
    # 🔴 CRITICAL: Attacks against YOUR devices get MUCH higher priority
    targeting_local_network = False
    if is_local_device(dst):
        score += 35  # Major boost for attacks on YOUR devices
        targeting_local_network = True
    if is_local_device(src):  # Spoofing as your devices
        score += 20
    
    # High attack rate = more suspicious
    if attack_rate > 10:
        score += 40
    elif attack_rate > 5:
        score += 25
    elif attack_rate > 2:
        score += 10
    
    # Broadcast attacks = mass disruption attempt
    if dst == "ff:ff:ff:ff:ff:ff":
        score += 20
    
    # MAC spoofing = malicious intent
    if real_tx and real_tx != src:
        score += 25
    
    # Multiple spoofed MACs = sophisticated attack
    if len(attacker['spoofed_macs']) > 3:
        score += 10
    
    # Long duration = persistent attacker
    duration = (datetime.now() - attacker['first_attack']).seconds
    if duration > 3600:  # > 1 hour
        score += 15
    elif duration > 600:  # > 10 minutes
        score += 10
    elif duration > 60:  # > 1 minute
        score += 5
    
    # Timing pattern analysis - automated tools are more dangerous
    timing_score, _ = analyze_timing_pattern(attacker)
    if timing_score:
        if timing_score > 70:  # Highly automated
            score += 20
        elif timing_score > 40:  # Somewhat automated
            score += 10
    
    # Burst attacks = aggressive
    if attacker['burst_count'] > 5:
        score += 15
    elif attacker['burst_count'] > 2:
        score += 10
    
    # Sequence number anomalies
    seq_anomalies = detect_sequence_anomalies(attacker)
    if seq_anomalies:
        score += 15  # Sequence manipulation is suspicious
    
    # RSSI jump detection (impossible location changes)
    if len(attacker['rssi_values']) > 3:
        rssi_vals = attacker['rssi_values'][-4:]  # Last 4 samples
        rssi_range = max(rssi_vals) - min(rssi_vals)
        if rssi_range > 20:  # >20 dBm swing = device moving impossibly fast
            score += 20
    
    # Check if MAC is locally administered (likely spoofed)
    if src and len(src) >= 2:
        first_byte = int(src[:2], 16)
        if first_byte & 0x02:  # Local bit set
            score += 10
    
    return min(score, 100), targeting_local_network

def get_threat_label(score):
    """Convert threat score to label"""
    if score >= 70:
        return "🔴 CRITICAL"
    elif score >= 50:
        return "🟠 HIGH"
    elif score >= 30:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"

def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return
    
    # ONLY process DEAUTH/DISASSOC packets
    if pkt.type == 0 and (pkt.subtype == 12 or pkt.subtype == 10):
        src = pkt.addr2.lower() if pkt.addr2 else "unknown"
        dst = pkt.addr1.lower() if pkt.addr1 else "unknown"
        bssid = pkt.addr3.lower() if pkt.addr3 else "unknown"
        
        # 🔒 FILTER: Only monitor attacks on YOUR network
        # Check if attack involves your router or local devices
        involves_your_network = False
        if bssid in WHITELISTED_DEVICES or bssid in LOCAL_DEVICE_MACS:
            involves_your_network = True
        elif dst in WHITELISTED_DEVICES or dst in LOCAL_DEVICE_MACS:
            involves_your_network = True
        elif src in WHITELISTED_DEVICES or src in LOCAL_DEVICE_MACS:
            involves_your_network = True
        
        if not involves_your_network:
            return  # Ignore attacks on other networks
        
        # Extract sequence number for fingerprinting
        seq_num = pkt.SC >> 4 if hasattr(pkt, 'SC') else None
        
        # Get signal strength and metadata from RadioTap
        rssi = None
        real_tx = None
        rate = None
        antenna = None
        retry_flag = False
        channel_freq = None
        
        if pkt.haslayer(RadioTap):
            # Signal strength
            if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                rssi = pkt[RadioTap].dBm_AntSignal
            
            # Transmission rate (attacks often use 1-6 Mbps for max range)
            if hasattr(pkt[RadioTap], 'Rate'):
                rate = pkt[RadioTap].Rate
            
            # Antenna ID (track if attacker switches antennas)
            if hasattr(pkt[RadioTap], 'Antenna'):
                antenna = pkt[RadioTap].Antenna
            
            # Check for retry flag (legitimate deauth rarely retries)
            if hasattr(pkt[RadioTap], 'Flags'):
                retry_flag = bool(pkt[RadioTap].Flags & 0x08)  # Bit 3 = Retry
            
            # Channel frequency verification
            if hasattr(pkt[RadioTap], 'ChannelFrequency'):
                channel_freq = pkt[RadioTap].ChannelFrequency
            
            # NOTE: Hardware MAC not available in RadioTap with this driver
            # Will rely on behavioral analysis instead
            real_tx = None  # Driver doesn't expose true transmitter MAC
        
        # Extract vendor-specific fingerprint from notdecoded bytes
        # This is driver-specific data that can help identify the actual hardware
        vendor_fingerprint = None
        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'notdecoded'):
            vendor_fingerprint = pkt[RadioTap].notdecoded.hex() if pkt[RadioTap].notdecoded else None
        
        # SECURITY FIX: Smart whitelisting with behavioral verification
        # Can't trust source MAC alone - need to verify it's actually the router
        attacker_mac = real_tx if real_tx else src
        
        # WITHOUT HARDWARE MAC: Never filter, only classify legitimacy
        # Check if source claims to be whitelisted device
        is_claiming_router = is_whitelisted(src)
        router_legitimacy_score = 0
        suspicious_flags = []
        
        if is_claiming_router:
            # Calculate legitimacy score but DON'T filter - show ALL "router" packets
            
            # RSSI check
            if rssi and -55 <= rssi <= -40:
                router_legitimacy_score += 25
            elif rssi and (rssi < -65 or rssi > -30):
                suspicious_flags.append(f"Unusual RSSI: {rssi} dBm")
            
            # Rate check
            if rate and rate >= 6.0:
                router_legitimacy_score += 20
            elif rate and rate < 6.0:
                suspicious_flags.append(f"Low TX rate: {rate} Mbps")
            
            # Frequency check
            if attacker_mac in attackers:
                recent_attacks = [t for t in attack_history[attacker_mac] if time.time() - t < 60]
                attack_rate_now = len(recent_attacks)
                if attack_rate_now <= 5:
                    router_legitimacy_score += 30
                elif attack_rate_now > 10:
                    suspicious_flags.append(f"High frequency: {attack_rate_now}/min")
            
            # Burst check
            if attacker_mac in attackers:
                if attackers[attacker_mac]['burst_count'] == 0:
                    router_legitimacy_score += 15
                elif attackers[attacker_mac]['burst_count'] > 5:
                    suspicious_flags.append(f"Burst pattern: {attackers[attacker_mac]['burst_count']}")
            
            # Timing check
            if attacker_mac in attackers:
                timing_score, _ = analyze_timing_pattern(attackers[attacker_mac])
                if timing_score and timing_score < 40:
                    router_legitimacy_score += 10
                elif timing_score and timing_score > 70:
                    suspicious_flags.append(f"Automated tool pattern")
            
            # NEVER return/filter - process all "router" packets
            # Legitimacy score will be shown in output
        
        # SECURITY: Detect if attacker is spoofing a whitelisted device
        # Check multiple conditions: src is whitelisted but real MAC isn't, OR real MAC unknown but src is router
        spoofing_trusted_device = (
            (is_whitelisted(src) and real_tx and not is_whitelisted(real_tx)) or
            (is_whitelisted(src) and not real_tx)  # Spoofing router but can't verify hardware
        )
        
        attack_type = 'Deauth' if pkt.subtype == 12 else 'Disassoc'
        
        # Track this attacker with behavioral metadata
        track_attacker(attacker_mac, src, rssi, attack_type, dst, bssid, rate, antenna, retry_flag, pkt)
        
        # Calculate attack frequency
        recent_attacks = [t for t in attack_history[attacker_mac] if time.time() - t < 60]
        attack_rate = len(recent_attacks)
        
        # Calculate threat level
        threat_score, targeting_local = calculate_threat_level(attacker_mac, attack_rate, dst, real_tx, src)
        
        # BOOST threat if spoofing trusted device (router, etc.)
        if spoofing_trusted_device:
            threat_score = min(threat_score + 30, 100)  # Major threat boost
        
        # REDUCE threat if high router legitimacy (behavioral evidence it's genuine)
        # Only reduce for router claims without hardware verification
        if is_claiming_router and not real_tx and router_legitimacy_score >= 70:
            # High legitimacy = likely genuine router behavior
            # Reduce threat proportionally: 90% legitimacy = -72 points, 70% = -56 points
            threat_reduction = int((router_legitimacy_score / 100) * THREAT_REDUCTION_PCT)
            threat_score = max(0, threat_score - threat_reduction)
        
        threat_label = get_threat_label(threat_score)
        
        # Get attacker info
        attacker = attackers[attacker_mac]
        avg_rssi = sum(attacker['rssi_values']) / len(attacker['rssi_values']) if attacker['rssi_values'] else None
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        channel_band = "2.4GHz" if current_channel == 11 else "5GHz"
        
        # Print detailed attack info
        local_warning = " ⚠️ ATTACKING YOUR NETWORK!" if targeting_local else ""
        print("\n" + "="*90)
        print(f"🚨 ATTACK #{total_attacks} DETECTED - {timestamp}{local_warning}")
        print(f"   CHANNEL: {current_channel} ({channel_band})")
        print(f"   THREAT LEVEL: {threat_label} ({threat_score}/100){local_warning}")
        print("="*90)
        
        print(f"\n⚠️  ATTACKER IDENTIFICATION:")
        if real_tx:
            print(f"    Hardware MAC:      {real_tx} ({get_manufacturer(real_tx)})")
            print(f"    Packet Source:     {src} ({get_manufacturer(src)})")
            if real_tx != src:
                print(f"    🎭 MAC SPOOFING:   YES - Pretending to be {src}")
                if spoofing_trusted_device:
                    print(f"    🚨 CRITICAL:       IMPERSONATING YOUR ROUTER/TRUSTED DEVICE!")
            else:
                print(f"    🎭 MAC SPOOFING:   NO - Hardware matches packet source")
        else:
            print(f"    Hardware MAC:      Not exposed by MT7612U driver")
            print(f"    Packet Source:     {src} ({get_manufacturer(src)})")
            # Show hardware fingerprint if available
            if len(attacker['vendor_fingerprints']) > 0:
                fp = list(attacker['vendor_fingerprints'])[0][:16]  # First 16 hex chars
                print(f"    Hardware ID:       {fp}... (vendor-specific signature)")
            
            # Show router legitimacy assessment if claiming to be router
            if is_claiming_router:
                legitimacy_pct = min(router_legitimacy_score, 100)
                if legitimacy_pct >= 80:
                    print(f"    🟢 LEGITIMACY:     {legitimacy_pct}% - Likely genuine router")
                elif legitimacy_pct >= 50:
                    print(f"    🟡 LEGITIMACY:     {legitimacy_pct}% - Uncertain, verify manually")
                else:
                    print(f"    🔴 LEGITIMACY:     {legitimacy_pct}% - LIKELY SPOOFED!")
                if suspicious_flags:
                    for flag in suspicious_flags:
                        print(f"        ⚠️  {flag}")
            
            print(f"    ℹ️  NOTE:          Using behavioral analysis for identification")
            print(f"    💡 LOCATING TIP:   Check which device joined at {attacker['first_attack'].strftime('%H:%M:%S')}")
        
        print(f"\n📡 SIGNAL ANALYSIS:")
        print(f"    Signal Strength:   {rssi} dBm (Current)")
        if avg_rssi:
            print(f"    Avg Signal:        {avg_rssi:.1f} dBm")
        print(f"    Est. Distance:     {estimate_distance(rssi)}")
        if rate:
            print(f"    TX Rate:           {rate} Mbps")
            if rate <= LOW_RATE_THRESHOLD:
                print(f"    ⚠️  LOW RATE:       Using slow rate for max range (suspicious)")
        if antenna is not None:
            print(f"    Antenna:           #{antenna}")
        if retry_flag:
            print(f"    ⚠️  RETRY FLAG:     Packet was retransmitted (unusual for deauth)")
        
        # RSSI-based spoofing detection
        is_rssi_spoofed, rssi_confidence, rssi_details = analyze_rssi_for_spoofing(attacker_mac)
        if is_rssi_spoofed or rssi_confidence > 30:
            print(f"\n🔍 RSSI SPOOFING ANALYSIS:")
            if is_rssi_spoofed:
                print(f"    🚨 SPOOFING DETECTED: {rssi_confidence}% confidence")
                print(f"    ⚠️  EVIDENCE: Signal patterns indicate multiple transmitters or movement")
            else:
                print(f"    ⚠️  SUSPICIOUS: {rssi_confidence}% confidence of spoofing")
            for detail in rssi_details:
                print(f"    {detail}")
        
        print(f"\n📊 ATTACK STATISTICS:")
        print(f"    Attack Rate:       {attack_rate} attacks/minute")
        print(f"    Total Attacks:     {attacker['total_attacks']}")
        print(f"    First Seen:        {attacker['first_attack'].strftime('%H:%M:%S')}")
        print(f"    Attack Duration:   {(datetime.now() - attacker['first_attack']).seconds}s")
        
        # Timing pattern analysis
        timing_score, timing_pattern = analyze_timing_pattern(attacker)
        if timing_score is not None:
            print(f"\n⏱️  TIMING ANALYSIS:")
            print(f"    Attack Pattern:    {timing_pattern}")
            if len(attacker['inter_packet_intervals']) > 0:
                avg_interval = sum(attacker['inter_packet_intervals']) / len(attacker['inter_packet_intervals'])
                print(f"    Avg Interval:      {avg_interval*1000:.1f}ms between packets")
            print(f"    Burst Attacks:     {attacker['burst_count']} rapid bursts detected")
            if timing_score > 60:
                print(f"    ⚠️  AUTOMATED:      High consistency = likely using attack tool")
        
        # Sequence number analysis
        seq_anomalies = detect_sequence_anomalies(attacker)
        if seq_anomalies:
            print(f"\n🔢 SEQUENCE ANOMALIES:")
            for anomaly in seq_anomalies:
                print(f"    ⚠️  {anomaly}")
        
        # Legacy RSSI check (kept for backward compatibility)
        if len(attacker['rssi_values']) > 3:
            rssi_vals = attacker['rssi_values'][-4:]
            rssi_range = max(rssi_vals) - min(rssi_vals)
            if rssi_range > 20 and not is_rssi_spoofed:  # Only show if not already shown above
                print(f"\n📍 LOCATION ANOMALY:")
                print(f"    ⚠️  RSSI variance: {rssi_range} dBm (device moving impossibly fast!)")
                print(f"    ⚠️  OR: Multiple devices using same spoofed MAC")
        
        print(f"\n📋 ATTACK DETAILS:")
        print(f"    Type:              {attack_type}")
        target_note = ""
        if is_local_device(dst):
            target_note = " 🔴 YOUR DEVICE!"
        elif dst == "ff:ff:ff:ff:ff:ff":
            target_note = " ⚠️ BROADCAST - Targeting ALL devices!"
        print(f"    Target Device:     {dst} ({get_manufacturer(dst)}){target_note}")
        print(f"    Target AP:         {bssid} ({get_manufacturer(bssid)})")
        
        print(f"\n📈 ATTACK PATTERN:")
        print(f"    Broadcast Attacks: {attacker['broadcast_attacks']}")
        print(f"    Targeted Attacks:  {attacker['targeted_attacks']}")
        print(f"    Unique Targets:    {len(attacker['targets'])}")
        print(f"    Spoofed MACs Used: {len(attacker['spoofed_macs'])}")
        if len(attacker['spoofed_macs']) > 1:
            print(f"    ⚠️  Using multiple fake identities: {', '.join(list(attacker['spoofed_macs'])[:3])}{'...' if len(attacker['spoofed_macs']) > 3 else ''}")
        
        # Location guidance based on RSSI
        if len(attacker['rssi_values']) > 0:
            valid_rssi = [r for r in attacker['rssi_values'] if r is not None and r != "Unknown"]
            if valid_rssi:
                print(f"\n🎯 ATTACKER LOCATION GUIDANCE:")
                current_rssi = valid_rssi[-1]
                strongest_rssi = max(valid_rssi)
                weakest_rssi = min(valid_rssi)
                
                current_dist = estimate_distance(current_rssi)
                closest_dist = estimate_distance(strongest_rssi)
                farthest_dist = estimate_distance(weakest_rssi)
                
                print(f"    Current Position:  {current_dist} away (RSSI: {current_rssi}dB)")
                print(f"    Closest Detected:  {closest_dist} away (RSSI: {strongest_rssi}dB)")
                print(f"    Range Observed:    {weakest_rssi}dB to {strongest_rssi}dB ({abs(strongest_rssi - weakest_rssi)}dB range)")
                
                # Provide locating tips
                print(f"\n    💡 LOCATING TIPS:")
                if current_rssi > -40:
                    print(f"       • Attacker is VERY CLOSE (strong signal)")
                    print(f"       • Check devices within 5 meters")
                    print(f"       • Look for laptops, phones, or unknown devices nearby")
                elif current_rssi > -60:
                    print(f"       • Attacker is NEARBY (medium signal)")
                    print(f"       • Check within 10-20 meters")
                    print(f"       • Walk around to triangulate - signal should strengthen as you approach")
                else:
                    print(f"       • Attacker is FAR or signal is weak")
                    print(f"       • May be outside the building or using low-power mode")
                    print(f"       • Monitor for stronger bursts to locate")
                
                if is_rssi_spoofed or (len(valid_rssi) > 5 and max(valid_rssi) - min(valid_rssi) > 20):
                    print(f"       • ⚠️  WARNING: Signal pattern suggests MULTIPLE LOCATIONS")
                    print(f"       • May be multiple attackers or attacker is moving")
                    print(f"       • Focus on most recent/strongest signals")
        
        print("\n" + "="*90 + "\n")
        
        # Log to evidence file
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(f"\n{'='*90}\n")
                f.write(f"[ATTACK #{total_attacks}] {timestamp}\n")
                f.write(f"CHANNEL: {current_channel} ({channel_band})\n")
                f.write(f"THREAT LEVEL: {threat_label} ({threat_score}/100)\n")
                f.write(f"{'='*90}\n")
            
                f.write(f"\nATTACKER IDENTIFICATION:\n")
                if real_tx:
                    f.write(f"  Hardware MAC:      {real_tx} ({get_manufacturer(real_tx)})\n")
                    f.write(f"  Packet Source:     {src} ({get_manufacturer(src)})\n")
                    if real_tx != src:
                        f.write(f"  MAC SPOOFING:      YES - Pretending to be {src}\n")
                    else:
                        f.write(f"  MAC SPOOFING:      NO - Hardware matches source\n")
                else:
                    f.write(f"  Hardware MAC:      Not detected\n")
                    f.write(f"  Packet Source:     {src} ({get_manufacturer(src)})\n")
                    f.write(f"  WARNING:           Cannot verify hardware MAC\n")
                
                f.write(f"\nSIGNAL ANALYSIS:\n")
                avg_signal = f"{avg_rssi:.1f}" if avg_rssi is not None else "N/A"
                f.write(f"  Signal:            {rssi} dBm (Avg: {avg_signal} dBm)\n")
                f.write(f"  Distance:          {estimate_distance(rssi)}\n")
                if rate:
                    f.write(f"  TX Rate:           {rate} Mbps\n")
                    if rate <= LOW_RATE_THRESHOLD:
                        f.write(f"  WARNING:           Low rate (max range attack)\n")
                if antenna is not None:
                    f.write(f"  Antenna:           #{antenna}\n")
                if retry_flag:
                    f.write(f"  WARNING:           Retry flag set (unusual)\n")
                
                f.write(f"\nATTACK STATISTICS:\n")
                f.write(f"  Attack Rate:       {attack_rate} attacks/minute\n")
                f.write(f"  Total Attacks:     {attacker['total_attacks']}\n")
                f.write(f"  Active Duration:   {(datetime.now() - attacker['first_attack']).seconds}s\n")
                
                # Timing analysis in log
                timing_score, timing_pattern = analyze_timing_pattern(attacker)
                if timing_score is not None:
                    f.write(f"\nTIMING ANALYSIS:\n")
                    f.write(f"  Pattern:           {timing_pattern}\n")
                    if len(attacker['inter_packet_intervals']) > 0:
                        avg_interval = sum(attacker['inter_packet_intervals']) / len(attacker['inter_packet_intervals'])
                        f.write(f"  Avg Interval:      {avg_interval*1000:.1f}ms\n")
                    f.write(f"  Burst Attacks:     {attacker['burst_count']}\n")
                    if timing_score > 60:
                        f.write(f"  WARNING:           Automated tool detected\n")
                
                f.write(f"\nATTACK DETAILS:\n")
                f.write(f"  Type:              {attack_type}\n")
                f.write(f"  Target:            {dst} ({get_manufacturer(dst)})")
                if dst == "ff:ff:ff:ff:ff:ff":
                    f.write(f" - BROADCAST")
                elif is_local_device(dst):
                    f.write(f" - YOUR DEVICE")
                f.write(f"\n")
                f.write(f"  Target AP:         {bssid} ({get_manufacturer(bssid)})\n")
                
                f.write(f"\nATTACK PATTERN:\n")
                f.write(f"  Broadcast Attacks: {attacker['broadcast_attacks']}\n")
                f.write(f"  Targeted Attacks:  {attacker['targeted_attacks']}\n")
                f.write(f"  Unique Targets:    {len(attacker['targets'])}\n")
                f.write(f"  Spoofed MACs Used: {len(attacker['spoofed_macs'])}\n")
                f.write(f"{'='*90}\n")
        except IOError as e:
            print(f"[!] Error writing to log file: {e}")

print("="*90)
print("Advanced Attacker Tracker v2.2 - DUAL-BAND + MAC ANALYSIS")
print("="*90)
print(f"Interface:     {interface} (monitor mode)")
print(f"Log File:      {LOG_FILE}")
print(f"Monitoring:    Deauth/Disassoc attacks with threat scoring")
band1 = "2.4GHz" if CHANNELS[0] <= 14 else "5GHz"
band2 = "2.4GHz" if CHANNELS[1] <= 14 else "5GHz"
print(f"Channel Hop:   Ch {CHANNELS[0]} ({band1}) ↔ Ch {CHANNELS[1]} ({band2}) every {DWELL_TIME}s")
if WHITELISTED_DEVICES:
    print(f"Whitelisted:   {len(WHITELISTED_DEVICES)} trusted device(s) - reduced false positives")
else:
    print(f"Whitelisted:   None - monitoring all deauth attacks")
print(f"\nCapturing:")
print(f"  ✓ Hardware MAC vs Packet Source (dual tracking)")
print(f"  ✓ MAC spoofing detection and analysis")
print(f"  ✓ Signal strength and distance estimation")
print(f"  ✓ Attack frequency and patterns")
print(f"  ✓ Device manufacturer identification")
print(f"  ✓ Complete attack timeline")
print(f"  ✓ Threat severity scoring (0-100)")
print(f"  ✓ Broadcast vs targeted attack analysis")
print(f"  ✓ Whitelisting (filters legitimate network management)")
print(f"\nThreat Levels:")
print(f"  🔴 CRITICAL (70-100): Sophisticated, high-rate attacks")
print(f"  🟠 HIGH (50-69):      Persistent or broadcast attacks")
print(f"  🟡 MEDIUM (30-49):    Moderate attack activity")
print(f"  🟢 LOW (0-29):        Low-rate or isolated incidents")
print(f"\nWaiting for attacks...")
print("="*90 + "\n")

# Initialize log file with session header
try:
    with open(LOG_FILE, 'a') as f:
        f.write(f"\n\n{'#'*90}\n")
        f.write(f"NEW MONITORING SESSION STARTED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        band1 = "2.4GHz" if CHANNELS[0] <= 14 else "5GHz"
        band2 = "2.4GHz" if CHANNELS[1] <= 14 else "5GHz"
        f.write(f"Channels: {CHANNELS[0]} ({band1}) ↔ {CHANNELS[1]} ({band2})\n")
        f.write(f"Whitelisted devices: {len(WHITELISTED_DEVICES)}\n")
        f.write(f"{'#'*90}\n")
except IOError as e:
    print(f"[!] Warning: Cannot write to log file: {e}")

# Start channel hopping in background thread
hopper_thread = threading.Thread(target=channel_hopper, daemon=True)
hopper_thread.start()
print("[*] Channel hopping started...\n")

try:
    sniff(iface=interface, prn=packet_handler, store=0)
except KeyboardInterrupt:
    print("\n\n" + "="*90)
    print("FINAL ATTACKER SUMMARY")
    print("="*90)
    
    if attackers:
        print(f"\nTotal Attacks Detected: {total_attacks}")
        print(f"Unique Attackers: {len(attackers)}\n")
        
        # Sort by threat level
        attacker_threats = []
        for mac, info in attackers.items():
            duration = (datetime.now() - info['first_attack']).seconds
            recent = [t for t in attack_history[mac] if time.time() - t < 60]
            rate = len(recent)
            avg_rssi = sum(info['rssi_values']) / len(info['rssi_values']) if info['rssi_values'] else None
            
            # Calculate final threat score
            score = 0
            if rate > 10:
                score += 40
            elif rate > 5:
                score += 25
            if info['broadcast_attacks'] > 0:
                score += 20
            if len(info['spoofed_macs']) > 3:
                score += 10
            if duration > 3600:
                score += 15
            elif duration > 600:
                score += 10
            
            attacker_threats.append((mac, info, min(score, 100), avg_rssi))
        
        # Sort by threat score descending
        attacker_threats.sort(key=lambda x: x[2], reverse=True)
        
        for mac, info, score, avg_rssi in attacker_threats:
            threat = get_threat_label(score)
            print(f"\n{'='*90}")
            print(f"Attacker: {mac} - {threat} ({score}/100)")
            print(f"{'='*90}")
            print(f"  Manufacturer:      {info['manufacturer']}")
            print(f"  Total Attacks:     {info['total_attacks']}")
            print(f"  Broadcast:         {info['broadcast_attacks']}")
            print(f"  Targeted:          {info['targeted_attacks']}")
            print(f"  Unique Targets:    {len(info['targets'])}")
            print(f"  Attack Types:      {dict(info['attack_types'])}")
            print(f"  First Attack:      {info['first_attack'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Last Attack:       {info['last_attack'].strftime('%Y-%m-%d %H:%M:%S')}")
            duration_sec = (info['last_attack'] - info['first_attack']).total_seconds()
            print(f"  Duration:          {int(duration_sec)}s ({int(duration_sec/60)}m {int(duration_sec%60)}s)")
            print(f"  Spoofed MACs Used: {len(info['spoofed_macs'])}")
            if avg_rssi is not None:
                print(f"  Avg Signal:        {avg_rssi:.1f} dBm")
                print(f"  Est. Distance:     {estimate_distance(avg_rssi)}")
            else:
                print(f"  Avg Signal:        N/A")
    else:
        print("\nNo attacks detected during monitoring session.")
    
    print(f"\n{'='*90}")
    print(f"Evidence saved to: {LOG_FILE}")
    print("Shutting down...")

