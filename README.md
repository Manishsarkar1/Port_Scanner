# ScanForge (From Scratch)

Pure-Python port scanning framework without using `nmap` binary or nmap wrappers.

## Features
- Modular scanner framework structure (easy to extend)
- TCP connect scan engine
- Target parsing: single IP, hostname, comma lists, CIDR
- Port parsing: single values and ranges
- Parallel scanning with configurable worker count
- Optional banner grabbing
- Service/version probing (`--version-detect`) for common protocols
- Optional JSON output

## Quick Start
1. Install Python 3.10+
2. Run:

```bash
python main.py -t 127.0.0.1 -p 1-1024
```

## Examples
```bash
# Scan top common ports
python main.py -t scanme.nmap.org -p 22,80,443,3306,5432

# Detect service versions
python main.py -t 192.168.1.10 -p 21,22,25,80,110,143,3306,5432,6379 --version-detect

# Show closed ports too + save JSON
python main.py -t 192.168.1.0/28 -p 1-200 --show-closed --json-out reports/scan.json
```

## Version Detection Coverage (Current)
- SSH, HTTP, FTP, SMTP, POP3, IMAP, Redis, MySQL, PostgreSQL (best-effort probes)

## Next Extensions
- SYN scan engine using raw sockets
- UDP scan engine
- OS fingerprinting module
- Service/version detection plugins
- NSE-like scripting subsystem

## Legal
Only scan systems you own or have explicit written permission to test.
