# NetPenTool

A comprehensive network penetration testing framework designed for authorized security assessments and vulnerability research.

## Overview

NetPenTool provides security professionals with a robust set of utilities for conducting authorized network security assessments. The framework focuses on common attack vectors including ARP manipulation, DHCP exploitation, and credential testing.

## Core Features

### Network Layer Attacks
- **ARP Spoofing**: Advanced ARP table manipulation with stealth capabilities
- **DHCP Exploitation**: DHCP starvation and rogue server deployment
- **Network Discovery**: Comprehensive host and service enumeration

### Authentication Testing
- **Credential Brute Force**: Multi-protocol password testing (SSH, FTP, HTTP, etc.)
- **Dictionary Attacks**: Optimized wordlist-based authentication bypass
- **Custom Payload Generation**: Dynamic password list creation

### Security Controls
- **Whitelist Protection**: IP-based exclusion system
- **Rate Limiting**: Configurable attack throttling
- **Stealth Mode**: Traffic obfuscation and evasion techniques

### Logging & Reporting
- **Comprehensive Logging**: Detailed attack progression tracking
- **JSON Output**: Structured result export
- **Real-time Monitoring**: Live attack status updates

## Project Structure

```
netpentool/
├── src/
│   ├── core/           # Attack modules
│   │   ├── arp.py      # ARP spoofing implementation
│   │   ├── dhcp.py     # DHCP attack vectors
│   │   └── bruteforce.py # Authentication testing
│   └── utils/          # Support utilities
│       ├── network.py  # Network operations
│       ├── logger.py   # Logging framework
│       └── config.py   # Configuration management
├── config/             # Configuration files
├── data/              # Wordlists and targets
├── logs/              # Attack logs
└── scripts/           # Standalone tools
```

## Requirements

- Python 3.8+
- Administrative privileges (for raw socket operations)
- Target network authorization

### Dependencies

```bash
pip install -r requirements.txt
```

## Quick Start

### ARP Spoofing
```bash
python -m src.core.arp --target 192.168.1.100 --gateway 192.168.1.1
```

### DHCP Starvation
```bash
python -m src.core.dhcp --interface eth0 --mode starve
```

### Credential Testing
```bash
python -m src.core.bruteforce --target 192.168.1.100 --service ssh --wordlist data/passwords.txt
```

## Configuration

Edit `config/config.json` to customize:
- Default network interfaces
- Logging preferences
- Attack parameters
- Whitelist entries

## Legal Notice

⚠️ **IMPORTANT**: This tool is intended solely for authorized security testing and educational purposes. Users must:

- Obtain explicit written permission before testing any network
- Comply with all applicable laws and regulations
- Use responsibly within the scope of authorized assessments
- Not employ for malicious activities or unauthorized access

Unauthorized use of this software may violate local, state, and federal laws. Users assume full responsibility for lawful and ethical usage.

## Contributing

Contributions are welcome for:
- New attack modules
- Performance optimizations
- Documentation improvements
- Bug fixes and security enhancements

## License

MIT License - See LICENSE file for details.

---

*Developed for cybersecurity professionals and researchers*