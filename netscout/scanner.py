"""TCP port scanning utilities."""

import socket
from typing import Optional


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


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt to grab the service banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner if banner else None
    except Exception:
        return None
