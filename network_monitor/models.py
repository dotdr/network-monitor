from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Host:
    id: int
    address: str
    port: int
    enabled: bool = True


@dataclass(frozen=True)
class ProbeResult:
    success: bool
    latency_ms: float | None
    method: str
    detail: str
    checked_at: datetime


@dataclass(frozen=True)
class Sample:
    id: int
    host_id: int
    address: str
    port: int
    success: bool
    latency_ms: float | None
    method: str
    detail: str
    checked_at: datetime


@dataclass(frozen=True)
class HostSummary:
    address: str
    port: int
    samples: int
    successes: int
    loss_percent: float
    average_ms: float | None
    minimum_ms: float | None
    maximum_ms: float | None
