"""TCP/UDP port scanning utilities."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the given TCP port is open on host."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_range(host: str, start: int, end: int, timeout: float = 1.0) -> list[int]:
    """Scan a range of ports and return the open ones."""
    open_ports = []
    for port in range(start, end + 1):
        if scan_port(host, port, timeout):
            open_ports.append(port)
    return open_ports


def scan_range_concurrent(
    host: str,
    start: int,
    end: int,
    timeout: float = 1.0,
    max_workers: int = 10,
    show_progress: bool = True,
    rate_limit: float = 0.0,
) -> list[int]:
    """Scan a range of ports concurrently using ThreadPoolExecutor.
    
    Args:
        host: Target hostname or IP address
        start: Starting port number
        end: Ending port number (inclusive)
        timeout: Connection timeout in seconds
        max_workers: Number of concurrent workers
        show_progress: Whether to show progress bar
        rate_limit: Delay in seconds between port scans (0.0 = no limit)
    
    Returns:
        Sorted list of open ports
    """
    open_ports = []
    ports = list(range(start, end + 1))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for port in ports:
            future = executor.submit(scan_port, host, port, timeout)
            futures[future] = port
            if rate_limit > 0:
                time.sleep(rate_limit)

        iterator = futures
        if HAS_TQDM and show_progress:
            iterator = tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Scanning TCP ports",
                unit="port",
            )
        else:
            iterator = as_completed(futures)

        for future in iterator:
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    return sorted(open_ports)


def scan_udp_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the given UDP port is open on host.
    
    Note: UDP scanning is unreliable as ICMP filters may prevent responses.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (host, port))
            sock.recvfrom(1024)
            return True
    except (socket.timeout, OSError):
        return False


def scan_udp_range(
    host: str,
    start: int,
    end: int,
    timeout: float = 1.0,
    max_workers: int = 10,
    show_progress: bool = True,
) -> list[int]:
    """Scan a range of UDP ports concurrently using ThreadPoolExecutor.
    
    Args:
        host: Target hostname or IP address
        start: Starting port number
        end: Ending port number (inclusive)
        timeout: Connection timeout in seconds
        max_workers: Number of concurrent workers
        show_progress: Whether to show progress bar
    
    Returns:
        Sorted list of open UDP ports
    """
    open_ports = []
    ports = list(range(start, end + 1))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for port in ports:
            future = executor.submit(scan_udp_port, host, port, timeout)
            futures[future] = port

        iterator = futures
        if HAS_TQDM and show_progress:
            iterator = tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Scanning UDP ports",
                unit="port",
            )
        else:
            iterator = as_completed(futures)

        for future in iterator:
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    return sorted(open_ports)
