# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0] - 2025-12-22

### Changed
- Renamed `scanner.py` to `deauth_detector.py` for clarity
- Updated all documentation to reflect new script name

### Added
- Random MAC address probe detection and filtering
- Suspicious burst detection (alerts when >20 unique random MACs seen in 1 minute)
- ESP32 manufacturer OUI (28-56-2F) added to device database
- Improved IoT device identification

### Fixed
- UnboundLocalError in network monitor's print_summary function
- Hostname persistence verification (cleaned up excessive debug logging)

## [2.0.0] - 2025-12-22

### Major Update - WiFi Security Monitor Suite

#### Project Renamed
- Renamed from `wifi-deauth-detector` to `wifi-security-monitor`
- Now includes two complementary security tools

#### New Tool: Network Device Monitor
- Track all devices on your network
- Persistent device database with connection time tracking
- IoT device detection (ESP32, cameras, smart home)
- "Belongs here" detection for regular devices
- Suspicious device alerts
- Connection statistics and history

#### Deauth Detector Improvements
- Fixed hardcoded log path bug (now uses config)
- Dynamic channel band detection
- Better empty whitelist messaging

## [1.0.0] - 2025-12-21

### Initial Release - Deauth Attack Detector

#### Features
- Dual-band WiFi monitoring (2.4GHz & 5GHz)
- Deauth/Disassoc attack detection
- Behavioral analysis for MAC spoofing detection
  - Timing pattern analysis (coefficient of variation)
  - RSSI variance tracking
  - Sequence number anomaly detection
  - Rate analysis
- Router legitimacy scoring (0-100%)
- Smart threat scoring with legitimacy integration
- Vendor fingerprint extraction from RadioTap headers
- Comprehensive forensic logging
- JSON configuration file support
- Distance estimation from RSSI

#### Technical Details
- Works with any monitor mode capable WiFi adapter
- Handles hardware MAC limitations gracefully
- Multi-factor behavioral fingerprinting
- Configurable detection thresholds
- Channel hopping with configurable dwell time

#### Known Limitations
- Hardware MAC addresses not available on most adapters (MT7612U, etc.)
- 5GHz monitoring requires dual-band adapter
- Requires root/sudo for monitor mode access
- False positives possible with aggressive legitimate router behavior
