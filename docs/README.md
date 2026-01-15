# Documentation

Comprehensive documentation for the WiFi Security Monitor toolkit.

## Quick Navigation

### Getting Started
- **[Index](index.md)** - Documentation overview and quick links
- **[Getting Started Guide](getting-started.md)** - Installation and setup
- **[FAQ](faq.md)** - Frequently asked questions

### User Guides
- **[Deauth Detector Guide](deauth-detector.md)** - Complete guide for attack detection
- **[Network Monitor Guide](network-monitor.md)** - Device tracking and monitoring
- **[Configuration Reference](configuration.md)** - All configuration options explained

### Technical Documentation
- **[Architecture Overview](architecture.md)** - System design and internals
- **[API Reference](api-reference.md)** - Code documentation and extension points

### Help & Support
- **[Troubleshooting Guide](troubleshooting.md)** - Common issues and solutions
- **[FAQ](faq.md)** - Questions and answers

## Documentation Structure

```
docs/
├── README.md                  # This file
├── index.md                   # Documentation hub
├── getting-started.md         # Installation & setup
├── architecture.md            # Technical design
├── deauth-detector.md         # Deauth detector usage
├── network-monitor.md         # Network monitor usage
├── configuration.md           # Config reference
├── api-reference.md           # Code API docs
├── troubleshooting.md         # Problem solving
└── faq.md                     # Q&A
```

## What's Documented

### Installation & Setup
- System requirements
- Hardware compatibility
- Software installation
- Configuration setup
- First run walkthrough

### Feature Guides
- Deauthentication attack detection
- Network device monitoring
- IoT device identification
- Connection tracking
- Alert configuration

### Configuration
- All configuration options
- Default values and ranges
- Tuning recommendations
- Common scenarios
- Best practices

### Technical Details
- System architecture
- Data flow diagrams
- Threading model
- Performance optimizations
- Detection algorithms
- Behavioral analysis

### Code Documentation
- Function references
- Class documentation
- Data structures
- Extension points
- API usage examples
- Testing approaches

### Troubleshooting
- Common issues
- Error messages
- Diagnostic commands
- Solution procedures
- Prevention tips

## How to Use This Documentation

### For New Users
1. Start with [Getting Started Guide](getting-started.md)
2. Review [FAQ](faq.md) for common questions
3. Read the appropriate tool guide:
   - [Deauth Detector](deauth-detector.md) for security monitoring
   - [Network Monitor](network-monitor.md) for device tracking
4. Refer to [Troubleshooting](troubleshooting.md) if issues arise

### For Configuration
1. Read [Configuration Reference](configuration.md)
2. Check example configurations
3. Use [Troubleshooting](troubleshooting.md) to validate

### For Development
1. Review [Architecture Overview](architecture.md)
2. Study [API Reference](api-reference.md)
3. Check source code comments
4. Refer to extension examples

### For Problem Solving
1. Check [Troubleshooting Guide](troubleshooting.md)
2. Review [FAQ](faq.md)
3. Run diagnostic commands
4. Check GitHub Issues

## Documentation Conventions

### Code Examples
All code examples are tested and functional. Copy-paste should work.

```bash
# Shell commands shown with $ or sudo
sudo python3 deauth_detector.py
```

```python
# Python code examples are complete
def example_function():
    return "works"
```

```json
// JSON examples may include comments for clarity
// Remove comments before use
{
  "key": "value"  // Explanation
}
```

### File Paths
- **Relative paths** assume you're in project root
- **Absolute paths** shown for system files
- Links to files: [config.json](../config.json)

### Emphasis
- **Bold** - Important terms, file names
- *Italic* - Emphasis
- `Code` - Commands, code, file names
- > Blockquote - Notes and warnings

### Status Indicators
- ✓ Supported/Recommended
- ✗ Not supported/Not recommended
- ⚠️ Warning/Caution
- 🚩 Red flag/Issue

## Contributing to Documentation

Found an error or want to improve the docs?

1. **Typos/Errors**: Open an issue or PR
2. **Missing Info**: Request in GitHub Issues
3. **New Guides**: Propose in Discussions
4. **Examples**: Share working code

### Documentation Style
- Clear and concise
- Include examples
- Step-by-step instructions
- Explain the "why" not just "how"
- Test all code examples
- Link between related docs

## Offline Access

All documentation is in Markdown format for offline reading:

```bash
# Read in terminal
cat docs/getting-started.md | less

# Convert to HTML
markdown docs/index.md > docs.html

# Convert to PDF
pandoc docs/index.md -o docs.pdf

# Generate all docs as website
mkdocs build  # If using MkDocs
```

## Documentation Updates

This documentation is version-controlled with the code:
- Updated with each release
- Versioned with git tags
- Changelog in CHANGELOG.md
- Documentation for specific versions available in git history

## Quick Reference Card

### Essential Commands
```bash
# Start deauth detector
sudo python3 deauth_detector.py

# Start network monitor
sudo python3 network_monitor.py

# Enable monitor mode
sudo airmon-ng start wlan0

# Validate configuration
python3 test_config.py
```

### Essential Files
- `config.json` - Deauth detector config
- `monitor_config.json` - Network monitor config
- `attacker_evidence.log` - Deauth detector logs
- `data/device_database.json` - Device tracking database

### Essential Concepts
- **Monitor mode** - WiFi adapter captures all frames
- **Deauth attack** - Malicious disconnection frames
- **Legitimacy score** - 0-100% likelihood of legitimate traffic
- **IoT device** - Internet-connected smart device
- **MAC address** - Unique device identifier

## Additional Resources

### External Links
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [IEEE 802.11 Standard](https://standards.ieee.org/standard/802_11-2020.html)
- [WiFi Alliance](https://www.wi-fi.org/)

### Related Tools
- **aircrack-ng** - WiFi auditing suite
- **Wireshark** - Packet analyzer
- **Kismet** - WiFi detector/sniffer
- **Bettercap** - Network attack framework

### Learning Resources
- WiFi security basics
- 802.11 frame types
- Deauthentication attacks
- Network monitoring principles
- Python Scapy tutorials

## Support

Need help?
- 📖 Read the docs (you're doing it!)
- ❓ Check [FAQ](faq.md)
- 🔧 See [Troubleshooting](troubleshooting.md)
- 🐛 [GitHub Issues](https://github.com/YOUR_USERNAME/wifi-security-monitor/issues)
- 💬 [GitHub Discussions](https://github.com/YOUR_USERNAME/wifi-security-monitor/discussions)

## License

Documentation is licensed under [Creative Commons BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

Code is licensed under [Apache License 2.0](../LICENSE).

---

**Last Updated**: December 27, 2025
**Documentation Version**: 1.0
**Compatible with**: WiFi Security Monitor v1.0+
