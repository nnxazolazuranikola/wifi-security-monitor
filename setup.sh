#!/bin/bash
# Quick setup script for WiFi Deauth Detector

echo "🔧 WiFi Deauth Detector - Setup"
echo "================================"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "⚠️  Please run as normal user (will ask for sudo when needed)"
    exit 1
fi

# Check Python
echo "Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Install with: sudo apt install python3"
    exit 1
fi
echo "✅ Python 3 found"

# Install dependencies
echo ""
echo "Installing dependencies..."
pip3 install -r requirements.txt --user || {
    echo "⚠️  pip3 install failed. Trying with sudo..."
    sudo pip3 install -r requirements.txt
}

# Create config if doesn't exist
if [ ! -f "config.json" ]; then
    echo ""
    echo "📝 Creating config.json from example..."
    cp config.example.json config.json
    echo "⚠️  IMPORTANT: Edit config.json with your settings:"
    echo "   - interface: Your monitor mode interface (e.g., wlan1)"
    echo "   - channels: Channels to monitor"
    echo "   - whitelist_macs: Your router's MAC addresses"
    echo "   - local_device_macs: Your devices to protect"
    echo ""
    read -p "Press Enter to edit config now (or Ctrl+C to do it later)..."
    ${EDITOR:-nano} config.json
fi

# Check for wireless tools
echo ""
echo "Checking wireless tools..."
if ! command -v iwconfig &> /dev/null; then
    echo "⚠️  wireless-tools not found. Install with:"
    echo "   sudo apt install wireless-tools"
fi

if ! command -v airmon-ng &> /dev/null; then
    echo "⚠️  aircrack-ng not found. Install with:"
    echo "   sudo apt install aircrack-ng"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Put your WiFi adapter in monitor mode:"
echo "   sudo airmon-ng start wlan0"
echo ""
echo "2. Update config.json with the monitor interface name"
echo ""
echo "3. Run the scanner:"
echo "   sudo python3 deauth_detector.py"
echo ""
