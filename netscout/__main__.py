"""CLI entry point for netscout."""

import argparse
import sys
import json
from netscout import __version__
from netscout.scanner import (
    scan_port,
    scan_range_concurrent,
    scan_udp_port,
    scan_udp_range_concurrent,
    grab_banner_concurrent,
    get_ttl,
    fingerprint_os,
    analyze_http_headers,
)
from netscout.resolver import resolve, reverse_lookup, resolve_all
from netscout.utils import port_to_service, is_valid_ip, validate_port_range


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="netscout",
        description="Lightweight network reconnaissance and service discovery toolkit.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"netscout {__version__}",
        help="Show version information and exit",
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
        "--rate-limit",
        type=float,
        default=0.0,
        help="Delay in seconds between port scans to avoid detection (default: 0.0)",
    )
    scan_parser.add_argument(
        "--protocol",
        choices=["tcp", "udp"],
        default="tcp",
        help="Protocol to scan (default: tcp)",
    )
    scan_parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Save output to file (optional)",
    )
    scan_parser.add_argument(
        "--banners",
        action="store_true",
        help="Attempt to grab service banners from open ports (TCP only)",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress bars",
    )
    scan_parser.add_argument(
        "--dns-timeout",
        type=float,
        default=3.0,
        help="DNS resolution timeout in seconds (default: 3.0)",
    )

    # Resolve subcommand
    resolve_parser = subparsers.add_parser("resolve", help="Resolve hostname to IP")
    resolve_parser.add_argument("hostname", help="Hostname to resolve")
    resolve_parser.add_argument(
        "--all",
        action="store_true",
        help="Show all IP addresses associated with hostname",
    )
    resolve_parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="DNS resolution timeout in seconds (default: 3.0)",
    )
    resolve_parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Save output to file (optional)",
    )

    # Reverse lookup subcommand
    reverse_parser = subparsers.add_parser("reverse", help="Reverse DNS lookup")
    reverse_parser.add_argument("ip", help="IP address to look up")
    reverse_parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="DNS lookup timeout in seconds (default: 3.0)",
    )
    reverse_parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Save output to file (optional)",
    )

    # Fingerprint subcommand
    fingerprint_parser = subparsers.add_parser(
        "fingerprint",
        help="Fingerprint OS based on TTL value",
    )
    fingerprint_parser.add_argument(
        "host",
        help="Target hostname or IP address",
    )
    fingerprint_parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="ICMP timeout in seconds (default: 2.0)",
    )
    fingerprint_parser.add_argument(
        "--dns-timeout",
        type=float,
        default=3.0,
        help="DNS resolution timeout in seconds (default: 3.0)",
    )
    fingerprint_parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Save output to file (optional)",
    )

    # HTTP header analysis subcommand
    http_parser = subparsers.add_parser(
        "http",
        help="Analyze HTTP headers from a web service",
    )
    http_parser.add_argument(
        "host",
        help="Target hostname or IP address",
    )
    http_parser.add_argument(
        "--port",
        type=int,
        default=80,
        help="HTTP port (default: 80)",
    )
    http_parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Connection timeout in seconds (default: 2.0)",
    )
    http_parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    http_parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Save output to file (optional)",
    )
    http_parser.add_argument(
        "--dns-timeout",
        type=float,
        default=3.0,
        help="DNS resolution timeout in seconds (default: 3.0)",
    )

    args = parser.parse_args()

    if args.command == "scan":
        _handle_scan(args)
    elif args.command == "resolve":
        _handle_resolve(args)
    elif args.command == "reverse":
        _handle_reverse(args)
    elif args.command == "fingerprint":
        _handle_fingerprint(args)
    elif args.command == "http":
        _handle_http(args)
    else:
        parser.print_help()
        sys.exit(1)


def _write_output(output: str, output_file: str = None) -> None:
    """Write output to stdout or file.
    
    Args:
        output: Output string to write
        output_file: Optional file path to write to (None for stdout)
    
    Raises:
        IOError: If unable to write to file
    """
    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(output)
            print(f"Output saved to {output_file}", file=sys.stderr)
        except IOError as e:
            print(f"Error: Could not write to {output_file}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output)


def _handle_scan(args):
    """Handle the scan subcommand."""
    host = args.host
    dns_timeout = getattr(args, "dns_timeout", 3.0)

    # Validate host
    if not is_valid_ip(host):
        resolved = resolve(host, timeout=dns_timeout)
        if not resolved:
            print(f"Error: Could not resolve {host}", file=sys.stderr)
            sys.exit(1)
        host = resolved
        if getattr(args, "output", "text") == "text" and not getattr(args, "output_file"):
            print(f"Resolved {args.host} to {host}")

    # Parse port specification
    try:
        start, end = validate_port_range(args.ports)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    protocol = getattr(args, "protocol", "tcp")
    output_format = getattr(args, "output", "text")
    output_file = getattr(args, "output_file", None)
    grab_banners = getattr(args, "banners", False)
    quiet = getattr(args, "quiet", False)
    rate_limit = getattr(args, "rate_limit", 0.0)
    show_progress = output_format == "text" and not quiet and not output_file
    
    if show_progress:
        print(f"Scanning {host} {protocol.upper()} ports {start}-{end}...")

    if protocol == "udp":
        open_ports = scan_udp_range_concurrent(
            host,
            start,
            end,
            timeout=args.timeout,
            max_workers=args.workers,
            show_progress=show_progress,
            rate_limit=rate_limit,
        )
        banners_dict = {}
    else:
        open_ports = scan_range_concurrent(
            host,
            start,
            end,
            timeout=args.timeout,
            max_workers=args.workers,
            show_progress=show_progress,
            rate_limit=rate_limit,
        )
        # Grab banners if requested and protocol is TCP
        if grab_banners and open_ports:
            banners_dict = grab_banner_concurrent(
                host,
                open_ports,
                timeout=args.timeout,
                max_workers=args.workers,
                show_progress=show_progress,
                rate_limit=rate_limit,
            )
        else:
            banners_dict = {}

    if output_format == "json":
        result = {
            "host": host,
            "protocol": protocol,
            "ports_scanned": f"{start}-{end}",
            "open_ports": [
                {
                    "port": port,
                    "service": port_to_service(port),
                    "banner": banners_dict.get(port) if banners_dict else None
                }
                for port in open_ports
            ]
        }
        output = json.dumps(result, indent=2)
    else:
        if open_ports:
            lines = [f"Open {protocol.upper()} ports on {host}:"]
            for port in open_ports:
                service = port_to_service(port)
                if banners_dict and port in banners_dict:
                    lines.append(f"  {port:5d} - {service}")
                    lines.append(f"           Banner: {banners_dict[port][:60]}...")
                else:
                    lines.append(f"  {port:5d} - {service}")
            output = "\n".join(lines)
        else:
            output = f"No open {protocol.upper()} ports found on {host} in range {start}-{end}"

    _write_output(output, output_file)


def _handle_resolve(args):
    """Handle the resolve subcommand."""
    hostname = args.hostname
    timeout = getattr(args, "timeout", 3.0)
    output_file = getattr(args, "output_file", None)

    if args.all:
        ips = resolve_all(hostname, timeout=timeout)
        if ips:
            lines = [f"IP addresses for {hostname}:"]
            lines.extend([f"  {ip}" for ip in ips])
            output = "\n".join(lines)
        else:
            print(f"Error: Could not resolve {hostname}", file=sys.stderr)
            sys.exit(1)
    else:
        ip = resolve(hostname, timeout=timeout)
        if ip:
            output = f"{hostname} -> {ip}"
        else:
            print(f"Error: Could not resolve {hostname}", file=sys.stderr)
            sys.exit(1)

    _write_output(output, output_file)


def _handle_reverse(args):
    """Handle the reverse subcommand."""
    ip = args.ip
    timeout = getattr(args, "timeout", 3.0)
    output_file = getattr(args, "output_file", None)

    if not is_valid_ip(ip):
        print(f"Error: {ip} is not a valid IP address", file=sys.stderr)
        sys.exit(1)

    hostname = reverse_lookup(ip, timeout=timeout)
    if hostname:
        output = f"{ip} -> {hostname}"
    else:
        output = f"No reverse DNS record found for {ip}"

    _write_output(output, output_file)


def _handle_fingerprint(args):
    """Handle the fingerprint subcommand."""
    host = args.host
    dns_timeout = getattr(args, "dns_timeout", 3.0)
    output_file = getattr(args, "output_file", None)

    # Validate host
    if not is_valid_ip(host):
        resolved = resolve(host, timeout=dns_timeout)
        if not resolved:
            print(f"Error: Could not resolve {host}", file=sys.stderr)
            sys.exit(1)
        host = resolved
        if not output_file:
            print(f"Resolved {args.host} to {host}")

    if not output_file:
        print(f"Attempting OS fingerprinting for {host}...")
    ttl = get_ttl(host, timeout=args.timeout)

    if ttl is not None:
        os_guess = fingerprint_os(ttl)
        lines = [f"TTL: {ttl}", f"Estimated OS: {os_guess}"]
        output = "\n".join(lines)
        _write_output(output, output_file)
    else:
        print(
            f"Error: Could not retrieve TTL from {host}",
            "(requires root/admin or ICMP may be filtered)",
            file=sys.stderr,
        )
        sys.exit(1)


def _handle_http(args):
    """Handle the http subcommand."""
    host = args.host
    dns_timeout = getattr(args, "dns_timeout", 3.0)
    output_format = getattr(args, "output", "text")
    output_file = getattr(args, "output_file", None)

    # Validate host
    if not is_valid_ip(host):
        resolved = resolve(host, timeout=dns_timeout)
        if not resolved:
            print(f"Error: Could not resolve {host}", file=sys.stderr)
            sys.exit(1)
        host = resolved
        if output_format == "text" and not output_file:
            print(f"Resolved {args.host} to {host}")

    if not output_file:
        print(f"Analyzing HTTP headers from {host}:{args.port}...")
    headers = analyze_http_headers(host, port=args.port, timeout=args.timeout)

    if not headers:
        print(f"Error: Could not retrieve headers from {host}:{args.port}", file=sys.stderr)
        sys.exit(1)

    if output_format == "json":
        output = json.dumps(headers, indent=2)
    else:
        lines = [f"HTTP Headers from {host}:{args.port}:"]
        lines.extend([f"  {key}: {value}" for key, value in headers.items()])
        output = "\n".join(lines)

    _write_output(output, output_file)


if __name__ == "__main__":
    main()
