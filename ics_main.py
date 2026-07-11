#!/usr/bin/env python3
"""
ICS Security Scanner - Main Orchestrator
Runs all OT/ICS security checks and generates reports
"""

import argparse
import sys
import os
from typing import Dict, Any, List, Optional

# Import all check functions
from . import ALL_CHECKS
from .ics_report_generator import ICSReportGenerator, create_report, save_report


# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------

DEFAULT_PORTS = [502, 102, 20000, 44818, 47808, 4840, 2404]


# -----------------------------------------------------------------
# Core Scanning Functions
# -----------------------------------------------------------------

def run_checks(
    target: str,
    port: Optional[int] = None,
    checks: Optional[List[str]] = None,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """
    Run selected checks against a target

    Args:
        target: IP address or URL
        port: Specific port (optional, will scan common ports if not specified)
        checks: List of check names to run (None = run all)
        verbose: Print progress to console

    Returns:
        List of result dictionaries
    """
    results = []

    # Determine which checks to run
    if checks is None:
        check_names = list(ALL_CHECKS.keys())
    else:
        check_names = [c for c in checks if c in ALL_CHECKS]

    if verbose:
        print(f"\n[+] Starting ICS scan against: {target}")
        print(f"[+] Running {len(check_names)} checks: {', '.join(check_names)}\n")

    # Check if target is a URL (for web checks) or IP (for OT checks)
    is_url = target.startswith(("http://", "https://"))

    for i, check_name in enumerate(check_names, 1):
        check_func = ALL_CHECKS[check_name]

        if verbose:
            print(f"[{i}/{len(check_names)}] Running: {check_name}...", end=" ", flush=True)

        try:
            # Determine how to call the check function
            if is_url:
                # Web-style check (takes URL as first arg)
                result = check_func(target)
            else:
                # OT-style check (takes IP and optional port)
                if port:
                    result = check_func(target, port)
                else:
                    result = check_func(target)

            results.append(result)

            if verbose:
                status = result.get("status", "unknown")
                severity = result.get("severity", "low")
                print(f"done ({status}/{severity})")

        except Exception as e:
            error_result = {
                "name": check_name,
                "status": "error",
                "severity": "high",
                "details": str(e),
                "recommendation": "Check the target configuration and try again."
            }
            results.append(error_result)

            if verbose:
                print(f"ERROR: {str(e)}")

    return results


def scan_network(
    network: str,
    ports: Optional[List[int]] = None,
    checks: Optional[List[str]] = None,
    verbose: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Scan a network range for OT/ICS devices

    Args:
        network: Network in CIDR notation (e.g., 192.168.1.0/24)
        ports: List of ports to check
        checks: List of check names to run
        verbose: Print progress

    Returns:
        Dict mapping IP -> list of results
    """
    # Parse network
    try:
        import ipaddress
        net = ipaddress.ip_network(network, strict=False)
        ips = [str(ip) for ip in net.hosts()]
    except ImportError:
        # Fallback for Python < 3.3
        import netaddr
        net = netaddr.IPNetwork(network)
        ips = [str(ip) for ip in net]

    if verbose:
        print(f"\n[+] Scanning network: {network} ({len(ips)} hosts)")

    all_results = {}

    for ip in ips:
        if verbose:
            print(f"\n[*] Scanning {ip}...")

        # Check if device is alive (port scan)
        alive = False
        check_ports = ports or DEFAULT_PORTS

        for p in check_ports:
            if test_port(ip, p):
                alive = True
                if verbose:
                    print(f"    Found OT/ICS device on port {p}")
                break

        if alive:
            results = run_checks(ip, None, checks, verbose=False)
            all_results[ip] = results
        else:
            if verbose:
                print("    No OT/ICS devices found")

    return all_results


def test_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Test if a port is open on a target IP"""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


# -----------------------------------------------------------------
# Main CLI
# -----------------------------------------------------------------

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="ICS Security Scanner - OT/ICS Security Assessment Suite",
        epilog="""
Examples:
  ics_main.py -t 192.168.1.100            # Scan a single IP
  ics_main.py -t 192.168.1.100 -p 502     # Scan a specific port
  ics_main.py -t https://device.local     # Scan a web interface
  ics_main.py -n 192.168.1.0/24           # Scan a network range
  ics_main.py -t 192.168.1.100 -c device  # Run only device check
  ics_main.py -t 192.168.1.100 -f json -o report.json
        """
    )

    # Target options (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--target",
        help="Target IP address or URL (e.g., 192.168.1.100, https://device.local)"
    )
    target_group.add_argument(
        "-n", "--network",
        help="Network range in CIDR notation (e.g., 192.168.1.0/24)"
    )

    # Port options
    parser.add_argument(
        "-p", "--port",
        type=int,
        help="Target port (default: scan common OT ports 502, 102, etc.)"
    )

    # Check selection
    parser.add_argument(
        "-c", "--checks",
        nargs="+",
        choices=list(ALL_CHECKS.keys()),
        help="Specific checks to run (default: all)"
    )

    # Output options
    parser.add_argument(
        "-f", "--format",
        choices=["console", "json", "markdown", "html"],
        default="console",
        help="Output format (default: console)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: stdout)"
    )

    # Other options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available checks and exit"
    )

    return parser.parse_args()


def list_checks():
    """Print all available checks"""
    print("\nAvailable ICS Security Checks:")
    print("-" * 40)
    for i, name in enumerate(sorted(ALL_CHECKS.keys()), 1):
        # Try to get a description by calling the check's docstring
        func = ALL_CHECKS[name]
        doc = func.__doc__ or "No description"
        description = doc.strip().split("\n")[0] if doc else "No description"
        print(f"{i:3}. {name}")
        print(f"     {description[:70]}{'...' if len(description) > 70 else ''}")
    print("-" * 40)
    print(f"Total: {len(ALL_CHECKS)} checks")


def main():
    """Main entry point"""
    args = parse_arguments()

    # List checks if requested
    if args.list_checks:
        list_checks()
        return 0

    # Network scan mode
    if args.network:
        print(f"[+] Network scan mode: {args.network}")

        results = scan_network(
            args.network,
            ports=[args.port] if args.port else None,
            checks=args.checks,
            verbose=args.verbose
        )

        # Flatten results into a single list for reporting
        flattened_results = []
        for ip, ip_results in results.items():
            for result in ip_results:
                if result:
                    # Add IP to the result
                    result_copy = result.copy()
                    result_copy["_target"] = ip
                    flattened_results.append(result_copy)

        if not flattened_results:
            print("\n[!] No OT/ICS devices found in network")
            return 0

        report_target = f"Network: {args.network} ({len(results)} hosts)"
        generator = ICSReportGenerator(report_target)

        # Group results by severity
        for result in flattened_results:
            generator.add_result(result)
        generator.finish()

        if args.format == "console":
            output = generator.to_console()
        elif args.format == "json":
            output = generator.to_json()
        elif args.format == "markdown":
            output = generator.to_markdown()
        elif args.format == "html":
            output = generator.to_html()
        else:
            output = generator.to_console()

        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"\n[+] Report saved to: {args.output}")
        else:
            print(output)

        return 0

    # Single target mode
    results = run_checks(
        args.target,
        port=args.port,
        checks=args.checks,
        verbose=args.verbose
    )

    # Generate report
    if args.format == "console":
        output = create_report(args.target, results, "console")
    elif args.format == "json":
        output = create_report(args.target, results, "json")
    elif args.format == "markdown":
        output = create_report(args.target, results, "markdown")
    elif args.format == "html":
        output = create_report(args.target, results, "html")
    else:
        output = create_report(args.target, results, "console")

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"\n[+] Report saved to: {args.output}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())