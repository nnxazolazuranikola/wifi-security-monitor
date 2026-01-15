#!/bin/bash
#
# WiFi Deauth Detector - Auto Launcher
# Automatically sets up monitor mode and starts detection
#

# Configuration
MONITOR_INTERFACE="wlan1"      # USB adapter for monitoring
MONITOR_INTERFACE_MON="wlan1mon"
MANAGED_INTERFACE="wlan0"      # Built-in WiFi (stays connected)
SCRIPT_DIR="/home/wifi-deauth-detector"
REQUIRED_DEVICES=2             # Minimum devices to stay on network
CHECK_INTERVAL=60              # Seconds between device checks

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================================="
echo "  WiFi Deauth Detector - Auto Launcher"
echo "=================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root (sudo)${NC}"
    exit 1
fi

# Check if USB adapter exists
if ! iw dev | grep -q "$MONITOR_INTERFACE"; then
    echo -e "${YELLOW}⚠️  $MONITOR_INTERFACE not found. Checking for existing monitor interface...${NC}"
    if iw dev | grep -q "$MONITOR_INTERFACE_MON"; then
        echo -e "${GREEN}✓ $MONITOR_INTERFACE_MON already exists${NC}"
    else
        echo -e "${RED}❌ No USB WiFi adapter found. Please connect one.${NC}"
        echo "Available interfaces:"
        iw dev
        exit 1
    fi
fi

# Function to setup monitor mode
setup_monitor_mode() {
    echo -e "\n${YELLOW}Setting up monitor mode...${NC}"
    
    # Check if already in monitor mode
    if iw dev | grep -q "$MONITOR_INTERFACE_MON"; then
        echo -e "${GREEN}✓ $MONITOR_INTERFACE_MON already active${NC}"
        return 0
    fi
    
    # DON'T kill NetworkManager - we want wlan0 to stay connected!
    # Just put wlan1 into monitor mode directly
    echo "Setting up monitor mode on $MONITOR_INTERFACE (keeping wlan0 connected)..."
    
    # Method 1: Use airmon-ng without killing processes
    airmon-ng start "$MONITOR_INTERFACE" > /dev/null 2>&1
    
    # Verify
    sleep 2
    if iw dev | grep -q "$MONITOR_INTERFACE_MON"; then
        echo -e "${GREEN}✓ Monitor mode enabled on $MONITOR_INTERFACE_MON${NC}"
        return 0
    else
        # Try alternative method
        echo "Trying alternative method..."
        ip link set "$MONITOR_INTERFACE" down 2>/dev/null
        iw dev "$MONITOR_INTERFACE" set type monitor 2>/dev/null
        ip link set "$MONITOR_INTERFACE" up 2>/dev/null
        
        if iw dev "$MONITOR_INTERFACE" info 2>/dev/null | grep -q "type monitor"; then
            echo -e "${GREEN}✓ Monitor mode enabled on $MONITOR_INTERFACE${NC}"
            # Update config to use wlan1 instead of wlan1mon
            sed -i 's/"interface": "wlan1mon"/"interface": "wlan1"/' "$SCRIPT_DIR/config.json"
            sed -i 's/"interface": "wlan1mon"/"interface": "wlan1"/' "$SCRIPT_DIR/monitor_config.json"
            return 0
        fi
        
        echo -e "${RED}❌ Failed to enable monitor mode${NC}"
        return 1
    fi
}

# Function to restore managed mode (cleanup)
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    airmon-ng stop "$MONITOR_INTERFACE_MON" > /dev/null 2>&1
    # Restart network manager
    systemctl restart NetworkManager 2>/dev/null || systemctl restart dhcpcd 2>/dev/null
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Trap Ctrl+C for cleanup
trap cleanup EXIT

# Setup monitor mode
if ! setup_monitor_mode; then
    echo -e "${RED}❌ Cannot start without monitor mode${NC}"
    exit 1
fi

# Ensure managed interface stays connected
echo -e "\n${YELLOW}Ensuring $MANAGED_INTERFACE stays connected...${NC}"
if ip link show "$MANAGED_INTERFACE" | grep -q "state UP"; then
    echo -e "${GREEN}✓ $MANAGED_INTERFACE is connected${NC}"
else
    echo -e "${YELLOW}⚠️  $MANAGED_INTERFACE may be down. Attempting to bring up...${NC}"
    ip link set "$MANAGED_INTERFACE" up 2>/dev/null
    # Reconnect to WiFi (may need adjustment for your setup)
    wpa_cli -i "$MANAGED_INTERFACE" reconnect 2>/dev/null
fi

# Show interface status
echo -e "\n${GREEN}Interface Status:${NC}"
echo "Monitor: $(iw dev | grep -A1 "$MONITOR_INTERFACE_MON\|$MONITOR_INTERFACE" | head -2)"
echo "Managed: $MANAGED_INTERFACE (your network connection)"

# Change to script directory
cd "$SCRIPT_DIR"

# Start the detector
echo -e "\n${GREEN}=================================================="
echo "  Starting Deauth Detector..."
echo "==================================================${NC}\n"

python3 deauth_detector.py
