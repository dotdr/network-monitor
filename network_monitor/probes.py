import math
import platform
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone

from .models import Host, ProbeResult


def _icmp_command(address: str, timeout_seconds: float) -> list[str] | None:
    executable = shutil.which("ping")
    if executable is None:
        return None

    timeout_ms = max(1, math.ceil(timeout_seconds * 1000))
    if platform.system().lower() == "windows":
        return [executable, "-n", "1", "-w", str(timeout_ms), address]
    if platform.system().lower() == "darwin":
        return [executable, "-c", "1", "-W", str(timeout_ms), address]
    return [
        executable,
        "-n",
        "-c",
        "1",
        "-W",
        str(max(1, math.ceil(timeout_seconds))),
        address,
    ]


def _icmp_probe(address: str, timeout_seconds: float) -> tuple[bool, float | None, str]:
    command = _icmp_command(address, timeout_seconds)
    if command is None:
        return False, None, "ping command is not available"

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds + 1,
            check=False,
            creationflags=(
                subprocess.CREATE_NO_WINDOW
                if platform.system().lower() == "windows"
                else 0
            ),
        )
    except subprocess.TimeoutExpired:
        return False, None, "ICMP probe timed out"
    except OSError as error:
        return False, None, f"ICMP probe could not run: {error}"

    elapsed_ms = (time.perf_counter() - started) * 1000
    if completed.returncode == 0:
        return True, elapsed_ms, "ICMP reply received"
    return False, None, "no ICMP reply"


def _tcp_probe(host: Host, timeout_seconds: float) -> tuple[bool, float | None, str]:
    started = time.perf_counter()
    try:
        with socket.create_connection(
            (host.address, host.port), timeout=timeout_seconds
        ):
            elapsed_ms = (time.perf_counter() - started) * 1000
        return True, elapsed_ms, f"TCP connection to port {host.port} succeeded"
    except OSError as error:
        return False, None, f"TCP connection to port {host.port} failed: {error}"


def probe_host(
    host: Host, mode: str = "auto", timeout_seconds: float = 1.0
) -> ProbeResult:
    """Probe a host using ICMP, TCP, or ICMP with a TCP fallback."""
    if mode not in {"auto", "icmp", "tcp"}:
        raise ValueError(f"Unsupported probe mode: {mode}")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    checked_at = datetime.now(timezone.utc)
    if mode == "tcp":
        success, latency, detail = _tcp_probe(host, timeout_seconds)
        return ProbeResult(success, latency, "TCP", detail, checked_at)

    success, latency, detail = _icmp_probe(host.address, timeout_seconds)
    if success:
        return ProbeResult(True, latency, "ICMP", detail, checked_at)
    if mode == "icmp":
        return ProbeResult(False, None, "ICMP", detail, checked_at)

    tcp_success, tcp_latency, tcp_detail = _tcp_probe(host, timeout_seconds)
    if tcp_success:
        return ProbeResult(
            True,
            tcp_latency,
            "TCP fallback",
            f"{detail}; {tcp_detail}",
            checked_at,
        )
    return ProbeResult(
        False,
        None,
        "ICMP + TCP",
        f"{detail}; {tcp_detail}",
        checked_at,
    )
