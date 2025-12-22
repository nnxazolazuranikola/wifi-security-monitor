#!/usr/bin/env python3
"""Quick config validation test"""

import json
import sys

try:
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    print("✅ Config loaded successfully")
    print(f"   Interface: {config['network']['interface']}")
    print(f"   Channels: {config['network']['channels']}")
    print(f"   Whitelist: {len(config['network']['whitelist_macs'])} MACs")
    print(f"   Local devices: {len(config['network']['local_device_macs'])} MACs")
    
    # Validate required fields
    required = [
        ('network', 'interface'),
        ('network', 'channels'),
        ('network', 'whitelist_macs'),
        ('detection', 'legitimacy_threshold'),
        ('output', 'log_file')
    ]
    
    missing = []
    for section, key in required:
        if section not in config or key not in config[section]:
            missing.append(f"{section}.{key}")
    
    if missing:
        print(f"\n❌ Missing required fields: {', '.join(missing)}")
        sys.exit(1)
    
    print("\n✅ All required fields present")
    
except FileNotFoundError:
    print("❌ config.json not found")
    print("   Copy config.example.json to config.json and edit it")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"❌ Invalid JSON in config.json: {e}")
    sys.exit(1)
