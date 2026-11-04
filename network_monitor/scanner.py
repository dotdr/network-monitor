import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from socket import gethostbyaddr

from .probes import _icmp_probe

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
MAX_SCAN_HOSTS = 254


@dataclass(frozen=True)
class ScanResult:
    address: str
    latency_ms: float


def parse_scan_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as error:
        raise ValueError("Enter a valid IPv4 network in CIDR notation.") from error
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only private IPv4 networks can be scanned.")
    if not any(network.subnet_of(private) for private in PRIVATE_NETWORKS):
        raise ValueError("Scans are limited to RFC 1918 private IPv4 networks.")
    host_count = network.num_addresses - (
        2 if network.prefixlen <= 30 else 0
    )
    if host_count > MAX_SCAN_HOSTS:
        raise ValueError(
            f"The network has {host_count} usable addresses; the limit is "
            f"{MAX_SCAN_HOSTS} per scan."
        )
    return network


def reverse_lookup(address: str) -> str:
    """Return a PTR hostname for an IP address or raise a lookup error."""
    parsed = ipaddress.ip_address(address.strip())
    hostname, _aliases, _addresses = gethostbyaddr(str(parsed))
    return hostname.rstrip(".")


def scan_network(
    value: str, timeout_seconds: float = 0.6, max_workers: int = 16
) -> list[ScanResult]:
    """Discover ICMP-responsive hosts in a bounded private IPv4 network."""
    network = parse_scan_network(value)
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero.")
    if not 1 <= max_workers <= 32:
        raise ValueError("max_workers must be between 1 and 32.")

    addresses = [str(address) for address in network.hosts()]
    results: list[ScanResult] = []
    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(addresses) or 1),
        thread_name_prefix="network-scan",
    ) as executor:
        pending = {
            executor.submit(_icmp_probe, address, timeout_seconds): address
            for address in addresses
        }
        for future in as_completed(pending):
            address = pending[future]
            success, latency_ms, _detail = future.result()
            if success and latency_ms is not None:
                results.append(ScanResult(address, latency_ms))
    return sorted(results, key=lambda result: ipaddress.ip_address(result.address))

