import ipaddress
from typing import Iterable


def parse_targets(raw: str, cidr_host_limit: int = 4096) -> list[str]:
    """Parse comma-separated targets (IP, hostname, CIDR) into a flat target list."""
    targets: list[str] = []
    seen: set[str] = set()

    for chunk in raw.split(","):
        token = chunk.strip()
        if not token:
            continue

        if "/" in token:
            network = ipaddress.ip_network(token, strict=False)
            hosts = list(network.hosts())
            if len(hosts) > cidr_host_limit:
                raise ValueError(
                    f"CIDR range '{token}' is too large ({len(hosts)} hosts). "
                    f"Use at most {cidr_host_limit} hosts."
                )
            for host in hosts:
                value = str(host)
                if value not in seen:
                    seen.add(value)
                    targets.append(value)
            continue

        if token not in seen:
            seen.add(token)
            targets.append(token)

    if not targets:
        raise ValueError("No valid targets were provided.")

    return targets


def _parse_port_token(token: str) -> Iterable[int]:
    if "-" in token:
        left, right = token.split("-", 1)
        start = int(left.strip())
        end = int(right.strip())
        if start > end:
            start, end = end, start
        for value in range(start, end + 1):
            yield value
        return

    yield int(token.strip())


def parse_ports(raw: str) -> list[int]:
    """Parse a port expression like '22,80,443,8000-8100'."""
    ports: set[int] = set()

    for chunk in raw.split(","):
        token = chunk.strip()
        if not token:
            continue
        for value in _parse_port_token(token):
            if value < 1 or value > 65535:
                raise ValueError(f"Invalid port {value}; valid range is 1-65535.")
            ports.add(value)

    if not ports:
        raise ValueError("No valid ports were provided.")

    return sorted(ports)
