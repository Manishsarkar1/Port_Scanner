import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner_framework.models import ScanResult
from scanner_framework.services import COMMON_TCP_SERVICES
from scanner_framework.versioning import detect_service_version


class ConnectScanEngine:
    def __init__(
        self,
        targets: list[str],
        ports: list[int],
        timeout: float = 1.0,
        workers: int = 200,
        grab_banner: bool = False,
        detect_version: bool = False,
        include_closed: bool = False,
    ) -> None:
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.grab_banner = grab_banner
        self.detect_version = detect_version
        self.include_closed = include_closed

    @staticmethod
    def _resolve_target(target: str) -> str | None:
        try:
            return socket.gethostbyname(target)
        except OSError:
            return None

    def _banner(self, ip: str, port: int) -> str | None:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                try:
                    s.sendall(b"\r\n")
                except OSError:
                    return None
                data = s.recv(256)
                if not data:
                    return None
                return data.decode("utf-8", errors="replace").strip()
        except OSError:
            return None

    def _scan_one(self, target: str, ip: str, port: int) -> ScanResult:
        start = time.perf_counter()
        state = "closed"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                code = sock.connect_ex((ip, port))
                if code == 0:
                    state = "open"
        except OSError:
            state = "filtered"

        latency = (time.perf_counter() - start) * 1000
        service = COMMON_TCP_SERVICES.get(port)
        banner = None
        version = None

        if state == "open" and self.detect_version:
            detected_service, detected_version = detect_service_version(
                ip=ip,
                port=port,
                timeout=self.timeout,
                service_hint=service,
            )
            service = detected_service or service
            version = detected_version
            banner = detected_version if self.grab_banner else None
        elif state == "open" and self.grab_banner:
            banner = self._banner(ip, port)

        return ScanResult(
            target=target,
            ip=ip,
            port=port,
            state=state,
            service=service,
            version=version,
            banner=banner,
            latency_ms=round(latency, 2),
        )

    def run(self) -> list[ScanResult]:
        resolved: list[tuple[str, str]] = []
        for target in self.targets:
            ip = self._resolve_target(target)
            if ip:
                resolved.append((target, ip))
            else:
                resolved.append((target, "unresolved"))

        results: list[ScanResult] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            future_map = {}
            for target, ip in resolved:
                if ip == "unresolved":
                    results.append(
                        ScanResult(
                            target=target,
                            ip=ip,
                            port=0,
                            state="unresolved",
                            service=None,
                            version=None,
                            banner=None,
                            latency_ms=None,
                        )
                    )
                    continue
                for port in self.ports:
                    future = pool.submit(self._scan_one, target, ip, port)
                    future_map[future] = (target, port)

            for future in as_completed(future_map):
                result = future.result()
                if self.include_closed or result.state == "open":
                    results.append(result)

        return sorted(results, key=lambda r: (r.target, r.port))
