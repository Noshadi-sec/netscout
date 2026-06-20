"""TCP port scanning utilities."""

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
    rate_limit: float = 0.0,
) -> dict[int, Optional[str]]:
    """Grab banners from multiple ports concurrently.
    
    Args:
        host: Target hostname or IP address
        ports: List of ports to grab banners from
        timeout: Connection timeout in seconds
        max_workers: Number of concurrent workers
        show_progress: Whether to show progress bar
        rate_limit: Delay in seconds between banner grabs (0.0 = no limit)
    
    Returns:
        Dictionary mapping port numbers to banner strings
    """
    banners = {}

    if not ports:
        return banners

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for port in ports:
            future = executor.submit(grab_banner, host, port, timeout)
            futures[future] = port
            if rate_limit > 0:
                time.sleep(rate_limit)

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
    rate_limit: float = 0.0,
) -> list[int]:
    """Scan a range of UDP ports concurrently using ThreadPoolExecutor.
    
    Args:
        host: Target hostname or IP address
        start: Starting port number
        end: Ending port number (inclusive)
        timeout: Connection timeout in seconds
        max_workers: Number of concurrent workers
        show_progress: Whether to show progress bar
        rate_limit: Delay in seconds between port scans (0.0 = no limit)
    
    Returns:
        Sorted list of responsive ports
    """
    open_ports = []
    ports = list(range(start, end + 1))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for port in ports:
            future = executor.submit(scan_udp_port, host, port, timeout)
            futures[future] = port
            if rate_limit > 0:
                time.sleep(rate_limit)

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


def get_ttl(host: str, timeout: float = 2.0) -> Optional[int]:
    """Get the TTL value from ICMP echo response.
    
    Args:
        host: Target hostname or IP address
        timeout: Timeout in seconds
    
    Returns:
        TTL value if reachable, None otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
            sock.settimeout(timeout)
            sock.sendto(b"\x08\x00\x00\x00\x00\x00\x00\x00", (host, 0))
            data, _ = sock.recvfrom(1024)
            # Extract TTL from IP header (field at offset 8, 1 byte)
            ttl = data[8]
            return ttl
    except (OSError, socket.error, PermissionError):
        return None


def fingerprint_os(ttl: int) -> str:
    """Guess the operating system based on TTL value.
    
    Common defaults:
    - Windows: 128
    - Linux/Unix: 64
    - Cisco/Network devices: 255
    
    Args:
        ttl: TTL value from ping response
    
    Returns:
        Estimated OS name
    """
    if ttl >= 200:
        return "Cisco/Network Device"
    elif ttl >= 100:
        return "Windows"
    elif ttl >= 50:
        return "Linux/Unix"
    else:
        return "Unknown"


def analyze_http_headers(host: str, port: int = 80, timeout: float = 2.0) -> dict[str, str]:
    """Analyze HTTP headers from a web service.
    
    Args:
        host: Target hostname or IP address
        port: HTTP port (default: 80)
        timeout: Connection timeout in seconds
    
    Returns:
        Dictionary mapping header names to values
    """
    headers = {}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        
        response_text = response.decode("utf-8", errors="ignore")
        lines = response_text.split("\r\n")
        
        # Parse status line
        if lines:
            headers["Status"] = lines[0]
        
        # Parse headers
        for line in lines[1:]:
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key] = value
            elif line == "":
                break
        
        return headers
    except Exception:
        return {}
