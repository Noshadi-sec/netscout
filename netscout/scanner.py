"""TCP port scanning utilities."""

import socket
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
) -> list[int]:
    """Scan a range of ports concurrently using ThreadPoolExecutor."""
    open_ports = []
    ports = list(range(start, end + 1))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }

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


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt to grab the service banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner if banner else None
    except Exception:
        return None


def grab_banner_concurrent(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    max_workers: int = 10,
    show_progress: bool = True,
) -> dict[int, Optional[str]]:
    """Grab banners from multiple ports concurrently."""
    banners = {}

    if not ports:
        return banners

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(grab_banner, host, port, timeout): port
            for port in ports
        }

        iterator = futures
        if HAS_TQDM and show_progress:
            iterator = tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Grabbing banners",
                unit="port",
            )
        else:
            iterator = as_completed(futures)

        for future in iterator:
            port = futures[future]
            try:
                banner = future.result()
                if banner:
                    banners[port] = banner
            except Exception:
                pass

    return banners


def scan_udp_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if the given UDP port is open or responds on host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"", (host, port))
            try:
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                # Timeout may indicate filtered or open port
                return False
    except (OSError, socket.error):
        return False


def scan_udp_range(
    host: str,
    start: int,
    end: int,
    timeout: float = 2.0,
) -> list[int]:
    """Scan a range of UDP ports and return responsive ones."""
    open_ports = []
    for port in range(start, end + 1):
        if scan_udp_port(host, port, timeout):
            open_ports.append(port)
    return open_ports


def scan_udp_range_concurrent(
    host: str,
    start: int,
    end: int,
    timeout: float = 2.0,
    max_workers: int = 10,
    show_progress: bool = True,
) -> list[int]:
    """Scan a range of UDP ports concurrently using ThreadPoolExecutor."""
    open_ports = []
    ports = list(range(start, end + 1))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_udp_port, host, port, timeout): port
            for port in ports
        }

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
