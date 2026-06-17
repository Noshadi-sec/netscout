# netscout

A lightweight Python toolkit for network reconnaissance and service discovery. Built for security researchers and network engineers.

## Features

- **TCP port scanning** — single ports and ranges
- **DNS resolution** — forward and reverse lookups
- **Banner grabbing** — identify running services
- **Concurrent scanning** — multi-threaded for speed
- **JSON output** — machine-readable results

## Installation

```bash
git clone https://github.com/Noshadi-sec/netscout.git
cd netscout
pip install -r requirements.txt
```

## Quick Start

```python
from netscout.scanner import scan_port, scan_range
from netscout.resolver import resolve, reverse_lookup

# Check if SSH is open
if scan_port("192.168.1.1", 22):
    print("SSH is open")

# Scan common ports
open_ports = scan_range("192.168.1.1", 1, 1024)
print(f"Open ports: {open_ports}")

# Resolve hostname
ip = resolve("example.com")
print(f"IP: {ip}")
```

## CLI Usage

```bash
python -m netscout scan 192.168.1.1 --ports 1-1024
python -m netscout resolve example.com
```

## Disclaimer

This tool is intended for authorized network testing and security research only.

## License

MIT
