import re
import socket
from typing import Callable


def _safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip()


def _recv_once(ip: str, port: int, timeout: float, payload: bytes | None = None) -> str | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            data = sock.recv(2048)
            if not data:
                return None
            return _safe_decode(data)
    except OSError:
        return None


def _probe_ssh(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    banner = _recv_once(ip, port, timeout)
    if not banner:
        return None, None
    line = banner.splitlines()[0]
    if line.startswith("SSH-"):
        return "ssh", line
    return None, line


def _probe_http(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    req = b"GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: scanforge\r\n\r\n"
    resp = _recv_once(ip, port, timeout, req)
    if not resp:
        return None, None

    # Extract Server header when available; fall back to status line.
    server_match = re.search(r"^Server:\s*(.+)$", resp, flags=re.IGNORECASE | re.MULTILINE)
    status_line = resp.splitlines()[0] if resp.splitlines() else None
    if server_match:
        return "http", server_match.group(1).strip()
    return "http", status_line


def _probe_ftp(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    banner = _recv_once(ip, port, timeout)
    if not banner:
        return None, None
    line = banner.splitlines()[0]
    if line.startswith("220"):
        return "ftp", line
    return None, line


def _probe_smtp(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    banner = _recv_once(ip, port, timeout)
    if not banner:
        return None, None
    line = banner.splitlines()[0]
    if line.startswith("220"):
        return "smtp", line
    return None, line


def _probe_pop3(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    banner = _recv_once(ip, port, timeout)
    if not banner:
        return None, None
    line = banner.splitlines()[0]
    if line.startswith("+OK"):
        return "pop3", line
    return None, line


def _probe_imap(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    banner = _recv_once(ip, port, timeout)
    if not banner:
        return None, None
    line = banner.splitlines()[0]
    if "IMAP" in line.upper():
        return "imap", line
    return None, line


def _probe_redis(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    resp = _recv_once(ip, port, timeout, b"*1\r\n$4\r\nPING\r\n")
    if not resp:
        return None, None
    line = resp.splitlines()[0] if resp.splitlines() else resp
    if line.startswith("+PONG") or "redis" in line.lower() or "-NOAUTH" in line:
        return "redis", line
    return None, line


def _probe_mysql(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(512)
            if len(data) < 6:
                return None, None
            # MySQL handshake: byte 4 is protocol version, then null-terminated version string.
            if data[4] in (9, 10):
                start = 5
                end = data.find(b"\x00", start)
                if end > start:
                    version = _safe_decode(data[start:end])
                    return "mysql", version
    except OSError:
        return None, None
    return None, None


def _probe_postgres(ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    # SSLRequest packet; PostgreSQL usually answers with 'S' or 'N'.
    payload = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            data = sock.recv(64)
            if data in (b"S", b"N"):
                return "postgresql", "PostgreSQL (SSL response)"
    except OSError:
        return None, None
    return None, None


PROBES_BY_PORT: dict[int, list[Callable[[str, int, float], tuple[str | None, str | None]]]] = {
    21: [_probe_ftp],
    22: [_probe_ssh],
    25: [_probe_smtp],
    80: [_probe_http],
    110: [_probe_pop3],
    143: [_probe_imap],
    443: [_probe_http],
    587: [_probe_smtp],
    993: [_probe_imap],
    995: [_probe_pop3],
    3306: [_probe_mysql],
    5432: [_probe_postgres],
    6379: [_probe_redis],
    8080: [_probe_http],
    8443: [_probe_http],
}

FALLBACK_PROBES: list[Callable[[str, int, float], tuple[str | None, str | None]]] = [
    _probe_ssh,
    _probe_http,
    _probe_ftp,
    _probe_smtp,
    _probe_pop3,
    _probe_imap,
    _probe_redis,
]


def detect_service_version(
    ip: str,
    port: int,
    timeout: float,
    service_hint: str | None = None,
) -> tuple[str | None, str | None]:
    probes = PROBES_BY_PORT.get(port, []) + FALLBACK_PROBES

    for probe in probes:
        detected_service, version = probe(ip, port, timeout)
        if detected_service or version:
            if service_hint and not detected_service:
                detected_service = service_hint
            return detected_service, version

    return service_hint, None
