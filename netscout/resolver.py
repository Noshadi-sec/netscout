"""DNS resolution utilities."""

import socket
from typing import Optional


def resolve(hostname: str) -> Optional[str]:
    """Resolve a hostname to its IPv4 address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def resolve_all(hostname: str) -> list[str]:
    """Return all IP addresses associated with a hostname."""
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def reverse_lookup(ip: str) -> Optional[str]:
    """Perform a reverse DNS lookup on an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
