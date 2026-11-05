import ctypes
import os
import platform
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .models import Host, ProbeResult

ICMP_ECHO_REPLY_STATUS_SUCCESS = 0
ICMPV4_ECHO_REQUEST = 8
ICMPV4_ECHO_REPLY = 0
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129


class _IpOptionInformation(ctypes.Structure):
    _fields_ = [
        ("ttl", ctypes.c_ubyte),
        ("tos", ctypes.c_ubyte),
        ("flags", ctypes.c_ushort),
        ("options_size", ctypes.c_ubyte),
        ("options_data", ctypes.c_void_p),
    ]


class _IcmpEchoReply(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
        ("round_trip_time", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
        ("data_size", ctypes.c_ushort),
        ("reserved", ctypes.c_ushort),
        ("options", _IpOptionInformation),
    ]


def _windows_icmp_probe(address: str, timeout_seconds: float) -> tuple[bool, float | None, str]:
    try:
        target = socket.getaddrinfo(
            address, None, family=socket.AF_INET, type=socket.SOCK_DGRAM
        )[0][4][0]
        destination = ctypes.c_uint32.from_buffer_copy(
            socket.inet_aton(target)
        ).value
        ip_helper = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    except (OSError, socket.gaierror) as error:
        return False, None, f"Could not resolve IPv4 address: {error}"

    ip_helper.IcmpCreateFile.restype = ctypes.c_void_p
    ip_helper.IcmpSendEcho.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    ip_helper.IcmpSendEcho.restype = ctypes.c_uint32
    ip_helper.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    ip_helper.IcmpCloseHandle.restype = ctypes.c_int

    handle = ip_helper.IcmpCreateFile()
    if handle in (None, ctypes.c_void_p(-1).value):
        error_code = ctypes.get_last_error()
        return False, None, f"Could not create ICMP handle (Windows error {error_code})"

    payload = b"network-monitor"
    request_data = ctypes.create_string_buffer(payload)
    reply_size = ctypes.sizeof(_IcmpEchoReply) + len(payload) + 8
    reply_buffer = ctypes.create_string_buffer(reply_size)
    timeout_ms = max(1, int(timeout_seconds * 1000))
    started = time.perf_counter()
    try:
        reply_count = ip_helper.IcmpSendEcho(
            handle,
            destination,
            request_data,
            len(payload),
            None,
            reply_buffer,
            reply_size,
            timeout_ms,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        if not reply_count:
            error_code = ctypes.get_last_error()
            return False, None, f"No ICMP reply (Windows error {error_code})"
        reply = ctypes.cast(
            reply_buffer, ctypes.POINTER(_IcmpEchoReply)
        ).contents
        if reply.status != ICMP_ECHO_REPLY_STATUS_SUCCESS:
            return False, None, f"ICMP reply status {reply.status}"
        return True, elapsed_ms, "ICMP reply received"
    finally:
        ip_helper.IcmpCloseHandle(handle)


def _icmp_checksum(packet: bytes) -> int:
    if len(packet) % 2:
        packet += b"\x00"
    words = struct.unpack(f"!{len(packet) // 2}H", packet)
    checksum = sum(words)
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return (~checksum) & 0xFFFF


def _socket_icmp_probe(
    family: int,
    destination: tuple[Any, ...],
    timeout_seconds: float,
) -> tuple[bool, float | None, str]:
    protocol = socket.IPPROTO_ICMP if family == socket.AF_INET else socket.IPPROTO_ICMPV6
    request_type = (
        ICMPV4_ECHO_REQUEST if family == socket.AF_INET else ICMPV6_ECHO_REQUEST
    )
    reply_type = (
        ICMPV4_ECHO_REPLY if family == socket.AF_INET else ICMPV6_ECHO_REPLY
    )
    identifier = (os.getpid() ^ threading.get_ident()) & 0xFFFF
    sequence = int(time.monotonic() * 1000) & 0xFFFF
    payload = b"network-monitor"
    header = struct.pack("!BBHHH", request_type, 0, 0, identifier, sequence)
    if family == socket.AF_INET:
        checksum = _icmp_checksum(header + payload)
        header = struct.pack(
            "!BBHHH", request_type, 0, checksum, identifier, sequence
        )
    packet = header + payload

    try:
        with socket.socket(family, socket.SOCK_RAW, protocol) as probe_socket:
            probe_socket.settimeout(timeout_seconds)
            started = time.perf_counter()
            probe_socket.sendto(packet, destination)
            while True:
                response, _sender = probe_socket.recvfrom(1024)
                offset = 0
                if family == socket.AF_INET:
                    offset = (response[0] & 0x0F) * 4
                if len(response) < offset + 8:
                    continue
                response_type, _code, _checksum, response_id, response_sequence = (
                    struct.unpack_from("!BBHHH", response, offset)
                )
                if (
                    response_type == reply_type
                    and response_id == identifier
                    and response_sequence == sequence
                ):
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    return True, elapsed_ms, "ICMP reply received"
    except socket.timeout:
        return False, None, "ICMP probe timed out"
    except OSError as error:
        return False, None, f"Python ICMP probe failed: {error}"


def _icmp_probe(address: str, timeout_seconds: float) -> tuple[bool, float | None, str]:
    if platform.system().lower() == "windows":
        success, latency_ms, detail = _windows_icmp_probe(address, timeout_seconds)
        if success or not detail.startswith("Could not resolve IPv4 address"):
            return success, latency_ms, detail
        try:
            destinations = socket.getaddrinfo(
                address, None, family=socket.AF_INET6, type=socket.SOCK_DGRAM
            )
        except socket.gaierror:
            return success, latency_ms, detail
        for family, _socket_type, _protocol, _canonical_name, destination in destinations:
            success, latency_ms, detail = _socket_icmp_probe(
                family, destination, timeout_seconds
            )
            if success:
                return success, latency_ms, detail
        return success, latency_ms, detail

    try:
        destinations = socket.getaddrinfo(
            address, None, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM
        )
    except socket.gaierror as error:
        return False, None, f"Could not resolve address: {error}"

    last_detail = "No ICMP-compatible address was found"
    for family, _socket_type, _protocol, _canonical_name, destination in destinations:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        success, latency_ms, detail = _socket_icmp_probe(
            family, destination, timeout_seconds
        )
        if success:
            return success, latency_ms, detail
        last_detail = detail
    return False, None, last_detail


def _tcp_probe(host: Host, timeout_seconds: float) -> tuple[bool, float | None, str]:
    try:
        destinations = socket.getaddrinfo(
            host.address, host.port, type=socket.SOCK_STREAM
        )
    except OSError as error:
        return False, None, f"TCP connection to port {host.port} failed: {error}"

    last_error: OSError | None = None
    for family, socket_type, protocol, _canonical_name, destination in destinations:
        try:
            with socket.socket(family, socket_type, protocol) as probe_socket:
                probe_socket.settimeout(timeout_seconds)
                started = time.perf_counter()
                probe_socket.connect(destination)
                elapsed_ms = (time.perf_counter() - started) * 1000
        except OSError as error:
            last_error = error
            continue
        return True, elapsed_ms, f"TCP connection to port {host.port} succeeded"
    detail = str(last_error) if last_error else "no TCP address was resolved"
    return False, None, f"TCP connection to port {host.port} failed: {detail}"


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
