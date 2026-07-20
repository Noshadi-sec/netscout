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


def _validate_timeout(timeout: float, name: str = "timeout") -> None:
    """Validate that timeout is a positive number.
    
    Args:
        timeout: Timeout value to validate
        name: Name of parameter for error messages
    
    Raises:
        ValueError: If timeout is not positive
    """
    if timeout <= 0:
        raise ValueError(f"{name} must be positive, got {timeout}")


def _validate_port(port: int, name: str = "port") -> None:
    """Validate that port is in valid range (1-65535).
    
    Args:
        port: Port number to validate
        name: Name of parameter for error messages
    
    Raises:
        ValueError: If port is outside valid range
        TypeError: If port is not an integer
    """
    if not isinstance(port, int):
        raise TypeError(f"{name} must be an integer, got {type(port).__name__}")
    if port < 1 or port > 65535:
        raise ValueError(f"{name} must be in range 1-65535, got {port}")


def _validate_host(host: str, name: str = "host") -> None:
    """Validate that host is a non-empty string.
    
    Args:
        host: Hostname or IP address to validate
        name: Name of parameter for error messages
    
    Raises:
        TypeError: If host is not a string
        ValueError: If host is an empty string
    """
    if not isinstance(host, str):
        raise TypeError(f"{name} must be a string, got {type(host).__name__}")
    if not host:
        raise ValueError(f"{name} cannot be empty")


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the given TCP port is open on host.
    
    Args:
        host: Target hostname or IP address
        port: Port number (1-65535)
        timeout: Connection timeout in seconds
    
    Returns:
        True if port is open, False otherwise
    
    Raises:
        ValueError: If port is invalid
        TypeError: If port is not an integer
    """
    _validate_host(host)
    _validate_timeout(timeout)
    _validate_port(port)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_range(host: str, start: int, end: int, timeout: float = 1.0) -> list[int]:
    """Scan a range of ports and return the open ones.
    
    Args:
        host: Target hostname or IP address
        start: Starting port number
        end: Ending port number (inclusive)
        timeout: Connection timeout in seconds
    
    Returns:
        List of open ports
    
    Raises:
        ValueError: If ports are invalid
        TypeError: If ports are not integers
    """
    _validate_host(host)
    _validate_timeout(timeout)
    _validate_port(start, "start port")
    _validate_port(end, "end port")
    if start > end:
        raise ValueError(f"start port {start} cannot be greater than end port {end}")
    
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
    
    Raises:
        ValueError: If timeout, ports, or rate_limit are invalid
        TypeError: If ports are not integers
    """
    _validate_host(host)
    _validate_timeout(timeout)
    _validate_port(start, "start port")
    _validate_port(end, "end port")
    if start > end:
        raise ValueError(f"start port {start} cannot be greater than end port {end}")
    if rate_limit < 0:
        raise ValueError(f"rate_limit must be non-negative, got {rate_limit}")
    
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
    
    Args:
        host: Target hostname or IP address
        port: Port number (1-65535)
        timeout: Connection timeout in seconds
    
    Returns:
        True if port is open, False otherwise
    
    Raises:
        ValueError: If port is invalid
        TypeError: If port is not an integer
    """
    _validate_host(host)
    _validate_timeout(timeout)
    _validate_port(port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (host, port))
            sock.recvfrom(1024)
            return True
    except (socket.timeout, OSError):
        return False


def scan_udp_range(host: str, start: int, end: int, timeout: float = 1.0) -> list[int]:
    """Scan a range of UDP ports and return the open ones.
    
    Args:
        host: Target hostname or IP address
        start: Starting port number
        end: Ending port number (inclusive)
        timeout: Connection timeout in seconds
    
    Returns:
        List of open ports
    
    Raises:
        ValueError: If ports are invalid
        TypeError: If ports are not integers
    """
    _validate_host(host)
    _validate_timeout(timeout)
    _validate_port(start, "start port")
    _validate_port(end, "end port")
    if start > end:
        raise ValueError(f"start port {start} cannot be greater than end port {end}")
    
    open_ports = []
    for port in range(start, end + 1):
        if scan_udp_port(host, port, timeout):
            open_ports.append(port)
    return open_ports


def scan_udp_range_concurrent(
    host: str,
    start: int,
    end: int,
    timeout: float = 1.0,
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
        Sorted list of open ports
    
    Raises:
        ValueError: If timeout, ports, or rate_limit are invalid
        TypeError: If ports are not integers
    """
    _validate_host(host)
    _validate_timeout(timeout)
    _validate_port(start, "start port")
    _validate_port(end, "end port")
    if start > end:
        raise ValueError(f"start port {start} cannot be greater than end port {end}")
    if rate_limit < 0:
        raise ValueError(f"rate_limit must be non-negative, got {rate_limit}")
    
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


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt to grab the service banner from an open port.
    
    Tries multiple approaches: first a simple socket read for immediate responses,
    then HTTP-style probes for web services.
    
    Args:
        host: Target hostname or IP address
        port: Port number to grab banner from
        timeout: Connection timeout in seconds
    
    Returns:
        Banner string, or None if unable to retrieve
    
    Raises:
        ValueError: If timeout or port are invalid
        TypeError: If port is not an integer
    """
    _validate_host(host)
    _validate_timeout(timeout)
    _validate_port(port)
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        
        # First try: read raw response (for services that immediately send banners)
        try:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                return banner
        except (socket.timeout, OSError):
            pass
        
        # Second try: send HTTP-style request
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                return banner
        except (socket.timeout, OSError):
            pass
        
        return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def grab_banner_concurrent(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    max_workers: int = 10,
    show_progress: bool = True,
    rate_limit: float = 0.0,
) -> dict[int, Optional[str]]:
    """Grab service banners from multiple ports concurrently.
    
    Args:
        host: Target hostname or IP address
        ports: List of port numbers to grab banners from
        timeout: Connection timeout in seconds
        max_workers: Number of concurrent workers
        show_progress: Whether to show progress bar
        rate_limit: Delay in seconds between banner grabs (0.0 = no limit)
    
    Returns:
        Dictionary mapping port numbers to their banners (or None)
    
    Raises:
        ValueError: If timeout or rate_limit are invalid
    """
    _validate_host(host)
    _validate_timeout(timeout)
    if rate_limit < 0:
        raise ValueError(f"rate_limit must be non-negative, got {rate_limit}")
    
    banners = {}

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
                banners[port] = banner
            except Exception:
                banners[port] = None

    return banners


def get_ttl(host: str, timeout: float = 2.0) -> Optional[int]:
    """Get TTL value from ICMP echo reply (requires root/admin).
    
    Args:
        host: Target hostname or IP address
        timeout: ICMP timeout in seconds
    
    Returns:
        TTL value as integer, or None if unable to retrieve
    
    Raises:
        ValueError: If timeout is not positive
    """
    _validate_host(host)
    _validate_timeout(timeout)
    try:
        # Use ICMP echo (ping) to get TTL
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"\x08\x00\x00\x00\x00\x00\x00\x00", (host, 0))
            data, _ = sock.recvfrom(1024)
            # Extract TTL from IP header (byte 8)
            ttl = data[8]
            return ttl
    except (OSError, socket.timeout, PermissionError):
        return None


def fingerprint_os(ttl: int) -> str:
    """Estimate operating system based on TTL value.
    
    Args:
        ttl: Time To Live value from ICMP echo reply
    
    Returns:
        Estimated OS name
    
    Raises:
        TypeError: If ttl is not an integer
    """
    if not isinstance(ttl, int):
        raise TypeError(f"ttl must be an integer, got {type(ttl).__name__}")
    if ttl >= 200:
        return "Linux/Unix"
    elif ttl >= 100:
        return "Windows"
    elif ttl >= 50:
        return "Cisco/Network Device"
    else:
        return "Unknown"


def analyze_http_headers(host: str, port: int = 80, timeout: float = 2.0) -> Optional[dict[str, str]]:
    """Analyze HTTP headers from a web service.
    
    Args:
        host: Target hostname or IP address
        port: HTTP port (default: 80)
        timeout: Connection timeout in seconds
    
    Returns:
        Dictionary of HTTP headers, or None if unable to retrieve
    
    Raises:
        ValueError: If timeout or port are invalid
        TypeError: If port is not an integer
    """
    _validate_host(host)
    _validate_timeout(timeout)
    _validate_port(port)
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        
        # Send HTTP GET request
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        # Parse headers from response
        response_str = response.decode("utf-8", errors="ignore")
        lines = response_str.split("\r\n")
        
        headers = {}
        for line in lines[1:]:  # Skip status line
            if not line:
                break
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        
        return headers if headers else None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
