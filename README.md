# ScanForge (From Scratch)

Pure-Python port scanning framework without using `nmap` binary or nmap wrappers.

## Features
- Modular scanner framework structure (easy to extend)
- TCP connect scan engine
- Target parsing: single IP, hostname, comma lists, CIDR
- Port parsing: single values and ranges
- Parallel scanning with configurable worker count
- Optional banner grabbing
- Optional JSON output

## Quick Start
1. Install Python 3.10+
2. Run:

```bash
python main.py -t 127.0.0.1 -p 1-1024
```

## Examples
```bash
# Scan top common web/db ports on one host
python main.py -t scanme.nmap.org -p 22,80,443,3306,5432

# Scan CIDR and show closed ports too
python main.py -t 192.168.1.0/28 -p 1-200 --show-closed

# Grab banners and save JSON report
python main.py -t 10.0.0.15 -p 21,22,25,80 --banner --json-out reports/scan.json
```

## Next Extensions
- SYN scan engine using raw sockets
- UDP scan engine
- OS fingerprinting module
- Service/version detection plugins
- NSE-like scripting subsystem

## Legal
Only scan systems you own or have explicit written permission to test.
