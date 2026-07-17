"""DNS resolution utilities."""

import socket
from contextlib import contextmanager
from typing import Generator, Optional


@contextmanager
def _socket_timeout(timeout: float) -> Generator[None, None, None]:
    """Context manager to temporarily set socket timeout.
    
    Args:
        timeout: Timeout in seconds to apply
    
    Yields:
        None
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        yield
    finally:
        socket.setdefaulttimeout(old_timeout)


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


def resolve(hostname: str, timeout: float = 3.0) -> Optional[str]:
    """Resolve a hostname to its IPv4 address.
    
    Args:
        hostname: Hostname to resolve
        timeout: Resolution timeout in seconds (default: 3.0)
    
    Returns:
        IPv4 address as string, or None if resolution fails
    
    Raises:
        ValueError: If timeout is not positive
    """
    _validate_timeout(timeout)
    try:
        with _socket_timeout(timeout):
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if results:
                return results[0][4][0]
            return None
    except (socket.gaierror, socket.timeout, OSError):
        return None


def resolve_all(hostname: str, timeout: float = 3.0) -> list[str]:
    """Return all IP addresses associated with a hostname.
    
    Args:
        hostname: Hostname to resolve
        timeout: Resolution timeout in seconds (default: 3.0)
    
    Returns:
        List of IP addresses, or empty list if resolution fails
    
    Raises:
        ValueError: If timeout is not positive
    """
    _validate_timeout(timeout)
    try:
        with _socket_timeout(timeout):
            results = socket.getaddrinfo(hostname, None)
            return list({r[4][0] for r in results})
    except (socket.gaierror, socket.timeout, OSError):
        return []


def reverse_lookup(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Perform a reverse DNS lookup on an IP address.
    
    Args:
        ip: IP address to look up
        timeout: Lookup timeout in seconds (default: 3.0)
    
    Returns:
        Hostname as string, or None if lookup fails
    
    Raises:
        ValueError: If timeout is not positive
    """
    _validate_timeout(timeout)
    try:
        with _socket_timeout(timeout):
            return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout, OSError):
        return None
