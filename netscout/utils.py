"""Utility helpers for netscout."""

import ipaddress
from typing import Iterator, Tuple


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def port_to_service(port: int) -> str:
    """Return the common service name for a well-known port."""
    return COMMON_PORTS.get(port, "unknown")


def validate_port_range(port_spec: str) -> Tuple[int, int]:
    """Parse and validate a port range specification.
    
    Args:
        port_spec: Port range like '1-1024' or single/comma-separated ports '22,80,443'
    
    Returns:
        Tuple of (start_port, end_port)
    
    Raises:
        ValueError: If port specification is invalid or ports out of range
    """
    if "-" in port_spec:
        parts = port_spec.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid port range '{port_spec}' (use format: start-end)")
        try:
            start, end = int(parts[0].strip()), int(parts[1].strip())
        except ValueError:
            raise ValueError(f"Invalid port range '{port_spec}' (ports must be integers)")
    else:
        # Single port or comma-separated list
        try:
            ports = [int(p.strip()) for p in port_spec.split(",")]
            if not ports:
                raise ValueError("Port list cannot be empty")
            start, end = min(ports), max(ports)
        except ValueError as e:
            raise ValueError(f"Invalid port specification '{port_spec}' (ports must be integers)")
    
    # Validate port ranges
    if start < 1 or start > 65535:
        raise ValueError(f"Start port {start} out of valid range (1-65535)")
    if end < 1 or end > 65535:
        raise ValueError(f"End port {end} out of valid range (1-65535)")
    if start > end:
        raise ValueError(f"Start port {start} is greater than end port {end}")
    
    return start, end


def expand_cidr(cidr: str) -> Iterator[str]:
    """Yield all host IP addresses in a CIDR block."""
    network = ipaddress.ip_network(cidr, strict=False)
    for host in network.hosts():
        yield str(host)


def is_valid_ip(address: str) -> bool:
    """Return True if address is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False