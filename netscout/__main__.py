"""CLI entry point for netscout."""

import argparse
import sys
from netscout.scanner import (
    scan_port,
    scan_range_concurrent,
    scan_udp_port,
    scan_udp_range_concurrent,
)
from netscout.resolver import resolve, reverse_lookup, resolve_all
from netscout.utils import port_to_service, is_valid_ip


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="netscout",
        description="Lightweight network reconnaissance and service discovery toolkit.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan TCP ports on a host")
    scan_parser.add_argument("host", help="Target hostname or IP address")
    scan_parser.add_argument(
        "--ports",
        default="1-1024",
        help="Port range to scan (e.g., 1-1024 or 22,80,443)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of concurrent workers (default: 10)",
    )
    scan_parser.add_argument(
        "--protocol",
        choices=["tcp", "udp"],
        default="tcp",
        help="Protocol to scan (default: tcp)",
    )

    # Resolve subcommand
    resolve_parser = subparsers.add_parser("resolve", help="Resolve hostname to IP")
    resolve_parser.add_argument("hostname", help="Hostname to resolve")
    resolve_parser.add_argument(
        "--all",
        action="store_true",
        help="Show all IP addresses associated with hostname",
    )

    # Reverse lookup subcommand
    reverse_parser = subparsers.add_parser("reverse", help="Reverse DNS lookup")
    reverse_parser.add_argument("ip", help="IP address to look up")

    args = parser.parse_args()

    if args.command == "scan":
        _handle_scan(args)
    elif args.command == "resolve":
        _handle_resolve(args)
    elif args.command == "reverse":
        _handle_reverse(args)
    else:
        parser.print_help()
        sys.exit(1)


def _handle_scan(args):
    """Handle the scan subcommand."""
    host = args.host

    # Validate host
    if not is_valid_ip(host):
        resolved = resolve(host)
        if not resolved:
            print(f"Error: Could not resolve {host}", file=sys.stderr)
            sys.exit(1)
        host = resolved
        print(f"Resolved {args.host} to {host}")

    # Parse port specification
    if "-" in args.ports:
        parts = args.ports.split("-")
        if len(parts) != 2:
            print(f"Error: Invalid port range {args.ports}", file=sys.stderr)
            sys.exit(1)
        try:
            start, end = int(parts[0]), int(parts[1])
        except ValueError:
            print(f"Error: Invalid port range {args.ports}", file=sys.stderr)
            sys.exit(1)
    else:
        # Single port or comma-separated list
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
            start, end = min(ports), max(ports)
        except ValueError:
            print(f"Error: Invalid port specification {args.ports}", file=sys.stderr)
            sys.exit(1)

    protocol = getattr(args, "protocol", "tcp")
    print(f"Scanning {host} {protocol.upper()} ports {start}-{end}...")

    if protocol == "udp":
        open_ports = scan_udp_range_concurrent(
            host,
            start,
            end,
            timeout=args.timeout,
            max_workers=args.workers,
        )
    else:
        open_ports = scan_range_concurrent(
            host,
            start,
            end,
            timeout=args.timeout,
            max_workers=args.workers,
        )

    if open_ports:
        print(f"\nOpen {protocol.upper()} ports on {host}:")
        for port in open_ports:
            service = port_to_service(port)
            print(f"  {port:5d} - {service}")
    else:
        print(f"No open {protocol.upper()} ports found on {host} in range {start}-{end}")


def _handle_resolve(args):
    """Handle the resolve subcommand."""
    hostname = args.hostname

    if args.all:
        ips = resolve_all(hostname)
        if ips:
            print(f"IP addresses for {hostname}:")
            for ip in ips:
                print(f"  {ip}")
        else:
            print(f"Error: Could not resolve {hostname}", file=sys.stderr)
            sys.exit(1)
    else:
        ip = resolve(hostname)
        if ip:
            print(f"{hostname} -> {ip}")
        else:
            print(f"Error: Could not resolve {hostname}", file=sys.stderr)
            sys.exit(1)


def _handle_reverse(args):
    """Handle the reverse subcommand."""
    ip = args.ip

    if not is_valid_ip(ip):
        print(f"Error: {ip} is not a valid IP address", file=sys.stderr)
        sys.exit(1)

    hostname = reverse_lookup(ip)
    if hostname:
        print(f"{ip} -> {hostname}")
    else:
        print(f"No reverse DNS record found for {ip}")


if __name__ == "__main__":
    main()
