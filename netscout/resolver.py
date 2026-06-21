"""DNS resolution utilities."""

import socket
from typing import Optional


def resolve(hostname: str, timeout: float = 3.0) -> Optional[str]:
    """Resolve a hostname to its IPv4 address.
    
    Args:
        hostname: Hostname to resolve
        timeout: Resolution timeout in seconds (default: 3.0)
    
    Returns:
        IPv4 address as string, or None if resolution fails
    """
    try:
        # Set socket timeout before resolution
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyname(hostname)
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (socket.gaierror, socket.timeout):
        return None


def resolve_all(hostname: str, timeout: float = 3.0) -> list[str]:
    """Return all IP addresses associated with a hostname.
    
    Args:
        hostname: Hostname to resolve
        timeout: Resolution timeout in seconds (default: 3.0)
    
    Returns:
        List of IP addresses, or empty list if resolution fails
    """
    try:
        # Set socket timeout before resolution
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            results = socket.getaddrinfo(hostname, None)
            return list({r[4][0] for r in results})
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (socket.gaierror, socket.timeout):
        return []


def reverse_lookup(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Perform a reverse DNS lookup on an IP address.
    
    Args:
        ip: IP address to look up
        timeout: Lookup timeout in seconds (default: 3.0)
    
    Returns:
        Hostname as string, or None if lookup fails
    """
    try:
        # Set socket timeout before lookup
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyaddr(ip)[0]
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (socket.herror, socket.timeout):
        return None
