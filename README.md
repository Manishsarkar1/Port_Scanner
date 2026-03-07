# ScanForge (From Scratch)

Pure-Python port scanning framework without using `nmap` binary or nmap wrappers.

## Features
- Modular scanner framework structure (easy to extend)
- TCP connect scan engine
- TCP SYN scan engine (`--scan-type syn`)
- Target parsing: single IP, hostname, comma lists, CIDR
- Port parsing: single values and ranges
- Parallel scanning with configurable worker count
- Optional banner grabbing
- Service/version probing (`--version-detect`) for common protocols
- Optional JSON output

## Quick Start
1. Install Python 3.10+
2. (Optional for SYN mode) install scapy: `pip install scapy`
3. Run:

```bash
python main.py -t 127.0.0.1 -p 1-1024
```

## Examples
```bash
# Connect scan (default)
python main.py -t scanme.nmap.org -p 22,80,443,3306,5432

# SYN scan (typically requires admin/root privileges)
python main.py -t 192.168.1.10 -p 1-1024 --scan-type syn

# Detect service versions on open ports
python main.py -t 192.168.1.10 -p 21,22,25,80,110,143,3306,5432,6379 --version-detect

# SYN + version detect + JSON output
python main.py -t 192.168.1.10 -p 22,80,443 --scan-type syn --version-detect --json-out reports/scan.json
```

## Version Detection Coverage (Current)
- SSH, HTTP, FTP, SMTP, POP3, IMAP, Redis, MySQL, PostgreSQL (best-effort probes)

## Next Extensions
- UDP scan engine
- OS fingerprinting module
- Service/version detection plugins
- NSE-like scripting subsystem

## Legal
Only scan systems you own or have explicit written permission to test.
