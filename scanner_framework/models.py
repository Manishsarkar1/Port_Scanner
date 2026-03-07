from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class ScanResult:
    target: str
    ip: str
    port: int
    state: str
    service: str | None = None
    banner: str | None = None
    latency_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
