"""Utility helpers for netscout."""

import ipaddress
from typing import Iterator, Tuple


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
    # Additional common services
    1433: "MSSQL", 3128: "Squid", 5900: "VNC", 5984: "CouchDB",
    6389: "Memcached", 7001: "Cassandra", 8000: "HTTP-Alt",
    8001: "HTTP-Alt", 8008: "HTTP", 8888: "HTTP-Alt",
    9000: "PHP-FPM", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 27015: "Steam", 50000: "SAP",
    # Uncommon but important
    135: "RPC", 139: "NetBIOS", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 636: "LDAPS", 873: "Rsync", 993: "IMAPS",
    995: "POP3S", 1521: "Oracle", 2049: "NFS", 3690: "SVN",
    4369: "EPMD", 5060: "SIP", 5061: "SIP-TLS", 5432: "PostgreSQL",
}


def port_to_service(port: int) -> str:
    """Return the common service name for a well-known port.
    
    Args:
        port: Port number to look up
    
    Returns:
        Service name string, or 'unknown' if not recognized
    """
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
    """Yield all host IP addresses in a CIDR block.
    
    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24')
    
    Yields:
        IP address strings
    
    Raises:
        ValueError: If CIDR notation is invalid
    """
    network = ipaddress.ip_network(cidr, strict=False)
    for host in network.hosts():
        yield str(host)


def is_valid_ip(address: str) -> bool:
    """Return True if address is a valid IPv4 or IPv6 address.
    
    Args:
        address: IP address string to validate
    
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
