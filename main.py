import argparse
import json
from collections import defaultdict
from pathlib import Path

from scanner_framework.engine import ConnectScanEngine
from scanner_framework.models import ScanResult
from scanner_framework.parsers import parse_ports, parse_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanforge",
        description="From-scratch Python port scanner framework (no nmap dependency).",
    )
    parser.add_argument("-t", "--targets", required=True, help="Comma list: IP, hostname, or CIDR.")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports expression, e.g. 22,80,443,8000-8100")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--workers", type=int, default=200, help="Parallel worker count")
    parser.add_argument("--show-closed", action="store_true", help="Include closed/filtered results")
    parser.add_argument("--banner", action="store_true", help="Try grabbing banner from open ports")
    parser.add_argument("--json-out", type=Path, help="Write JSON report to this file path")
    return parser


def print_report(results: list[ScanResult]) -> None:
    grouped: dict[str, list[ScanResult]] = defaultdict(list)
    for item in results:
        grouped[item.target].append(item)

    for target in sorted(grouped):
        print(f"\nTarget: {target}")
        for row in sorted(grouped[target], key=lambda r: r.port):
            if row.state == "unresolved":
                print("  [!] unresolved hostname")
                continue
            service = row.service if row.service else "unknown"
            banner = f" | banner={row.banner}" if row.banner else ""
            latency = f"{row.latency_ms}ms" if row.latency_ms is not None else "-"
            print(f"  {row.port:>5}/tcp  {row.state:<8}  service={service:<12} latency={latency}{banner}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    targets = parse_targets(args.targets)
    ports = parse_ports(args.ports)

    engine = ConnectScanEngine(
        targets=targets,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
        grab_banner=args.banner,
        include_closed=args.show_closed,
    )
    results = engine.run()
    print_report(results)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps([item.to_dict() for item in results], indent=2),
            encoding="utf-8",
        )
        print(f"\nSaved report to: {args.json_out}")


if __name__ == "__main__":
    main()
