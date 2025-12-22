# Contributing to WiFi Deauth Detector

Thank you for considering contributing! This project benefits from community input.

## How to Contribute

### Reporting Bugs
- Use GitHub Issues
- Include your OS, Python version, WiFi adapter model
- Provide config.json (remove sensitive MACs)
- Include relevant log output
- Steps to reproduce

### Suggesting Features
- Check existing issues first
- Clearly describe the use case
- Explain why it would be useful
- Consider implementation complexity

### Code Contributions

#### Setup Development Environment
```bash
git clone https://github.com/YOUR_USERNAME/wifi-security-monitor.git
cd wifi-security-monitor
pip3 install -r requirements.txt
```

#### Testing Your Changes
1. Test on multiple WiFi adapters if possible
2. Verify config.json compatibility
3. Run syntax check: `python3 -m py_compile deauth_detector.py`
4. Test with actual network traffic
5. Check for false positives/negatives

#### Code Style
- Follow PEP 8 for Python
- Use descriptive variable names
- Comment complex logic
- Keep functions focused and short
- Add docstrings for new functions

#### Pull Request Process
1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly
5. Update CHANGELOG.md
6. Update README.md if needed
7. Commit with clear messages
8. Push to your fork
9. Create Pull Request with description

### Adding WiFi Adapter Support
If you test with a new adapter:
1. Document the chipset and model
2. Note any special requirements
3. Update README with compatibility info
4. Share any quirks or limitations

### Improving Detection
If you improve the behavioral analysis:
- Document the technique
- Provide test cases
- Explain threshold choices
- Consider false positive impact

## Questions?
Open a GitHub Discussion for questions or ideas.

## Code of Conduct
- Be respectful and constructive
- Welcome newcomers
- Focus on technical merit
- No harassment or discrimination

---

**Thank you for helping make WiFi security better!**
