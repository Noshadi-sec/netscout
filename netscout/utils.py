"""Utility helpers for netscout."""

import ipaddress
from typing import Iterator


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
