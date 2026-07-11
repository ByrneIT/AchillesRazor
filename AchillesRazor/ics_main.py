#!/usr/bin/env python3
"""
AchillesRazor - Main Orchestrator
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

SCAN_TYPE_ALIASES = {
    "all": None,
    "device": "device",
    "security": "security",
    "policy": "policy",
    "exposure": "exposure",
    "dns-discover": "dns_discovery",
    "dns_discovery": "dns_discovery",
    "dns-sec": "dns_security",
    "dns_security": "dns_security",
    "probe": "discovery_probe",
    "protocol-sec": "protocol_security",
    "protocol_security": "protocol_security",
    "protocol-enforce": "protocol_enforcement",
    "protocol_enforcement": "protocol_enforcement",
    "redirect": "redirect_chain",
    "redirect_chain": "redirect_chain",
    "encryption": "encryption",
    "mixed-mode": "mixed_mode",
    "mixed_mode": "mixed_mode",
    "func-perm": "function_permission",
    "function_permission": "function_permission",
    "source-restrict": "source_restriction",
    "source_restriction": "source_restriction",
    "protocol-type": "protocol_type_enforcement",
    "protocol_type_enforcement": "protocol_type_enforcement",
    "interface-access": "interface_access",
    "interface_access": "interface_access",
}

VALID_SCAN_TYPES = sorted(set(SCAN_TYPE_ALIASES.keys()) | set(ALL_CHECKS.keys()))


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

def resolve_scan_type(scan_type: Optional[str]) -> Optional[List[str]]:
    """Resolve a CLI scan type name to the internal check key."""
    if not scan_type:
        return None

    normalized = scan_type.strip().lower()
    resolved_name = SCAN_TYPE_ALIASES.get(normalized)
    if resolved_name is None:
        return None
    return [resolved_name] if resolved_name else None


def detect_output_format(output_path: Optional[str], override_format: Optional[str] = None) -> str:
    """Choose an output format from the CLI override or the output filename."""
    if override_format:
        return override_format

    if not output_path or output_path == "-":
        return "console"

    extension = os.path.splitext(output_path)[1].lower()
    if extension == ".json":
        return "json"
    if extension == ".md":
        return "markdown"
    if extension == ".html":
        return "html"
    return "console"


def list_checks() -> None:
    """Print all supported scan type names and aliases."""
    print("\nAvailable scan types:")
    print("-" * 40)
    for scan_type in sorted(VALID_SCAN_TYPES):
        if scan_type in SCAN_TYPE_ALIASES and SCAN_TYPE_ALIASES[scan_type] is not None:
            print(f"  - {scan_type} -> {SCAN_TYPE_ALIASES[scan_type]}")
        else:
            print(f"  - {scan_type}")
    print("-" * 40)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AchillesRazor - OT/ICS Security Assessment Suite",
        epilog="""
Examples:
  achillesrazor 192.168.1.100
  achillesrazor 192.168.1.100 --type security -o report.json
  achillesrazor 192.168.1.0/24 --type exposure -o report.md
        """
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target IP address, hostname, URL, or CIDR network"
    )
    parser.add_argument(
        "--type",
        dest="scan_type",
        choices=VALID_SCAN_TYPES,
        help="Scan type to run (default: all checks)"
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        help="Output file path or '-' for stdout"
    )
    parser.add_argument(
        "--format",
        choices=["console", "json", "markdown", "html"],
        help="Optional output format override"
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Target port (default: scan common OT ports 502, 102, etc.)"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output during scans"
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available scan types and exit"
    )

    args = parser.parse_args()
    if not args.list_checks and not args.target:
        parser.error("the following arguments are required: target")
    return args


def main():
    """Main entry point"""
    args = parse_arguments()

    if args.list_checks:
        list_checks()
        return 0

    target = args.target
    output_path = args.output
    output_format = detect_output_format(output_path, args.format)
    checks = resolve_scan_type(args.scan_type)

    if "/" in target and not target.startswith(("http://", "https://")):
        print(f"[+] Network scan mode: {target}")

        results = scan_network(
            target,
            ports=[args.port] if args.port else None,
            checks=checks,
            verbose=args.verbose,
        )

        flattened_results = []
        for ip, ip_results in results.items():
            for result in ip_results:
                if result:
                    result_copy = result.copy()
                    result_copy["_target"] = ip
                    flattened_results.append(result_copy)

        if not flattened_results:
            print("\n[!] No OT/ICS devices found in network")
            return 0

        report_target = f"Network: {target} ({len(results)} hosts)"
        generator = ICSReportGenerator(report_target)

        for result in flattened_results:
            generator.add_result(result)
        generator.finish()

        if output_format == "console":
            output = generator.to_console()
        elif output_format == "json":
            output = generator.to_json()
        elif output_format == "markdown":
            output = generator.to_markdown()
        else:
            output = generator.to_html()

        if output_path and output_path != "-":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"\n[+] Report saved to: {output_path}")
        else:
            print(output)

        return 0

    results = run_checks(
        target,
        port=args.port,
        checks=checks,
        verbose=args.verbose,
    )

    if output_format == "console":
        output = create_report(target, results, "console")
    elif output_format == "json":
        output = create_report(target, results, "json")
    elif output_format == "markdown":
        output = create_report(target, results, "markdown")
    else:
        output = create_report(target, results, "html")

    if output_path and output_path != "-":
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"\n[+] Report saved to: {output_path}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())