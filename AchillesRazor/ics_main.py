#!/usr/bin/env python3
"""
AchillesRazor - Main Orchestrator
Runs all OT/ICS security checks and generates reports
"""

import argparse
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Dict, Any, List, Optional

# Import all check functions
from . import ALL_CHECKS, __version__
from .ics_banner import print_banner
from .ics_report_generator import ICSReportGenerator, create_report, save_report


# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------

DEFAULT_PORTS = [502, 102, 20000, 44818, 47808, 4840, 2404]

# Hard ceiling on any single check, regardless of what timeouts it sets
# internally. This is a safety net, not the primary defense - individual
# checks should still time out their own sockets/DNS queries well before
# this fires.
CHECK_TIMEOUT_SECONDS = 60

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

    print(f"\n[+] Starting ICS scan against: {target}", flush=True)
    print(f"[+] Running {len(check_names)} check(s) - this can take a few minutes...", flush=True)
    if verbose:
        print(f"    Checks: {', '.join(check_names)}\n", flush=True)

    # Check if target is a URL (for web checks) or IP (for OT checks)
    is_url = target.startswith(("http://", "https://"))

    # Not used as a context manager: shutdown() on exit would block waiting
    # for any still-running (timed-out) check thread to finish, and Python
    # cannot forcibly kill a blocked thread. Letting the pool go untracked
    # means a hung check's thread is simply abandoned once its timeout fires.
    #
    # That abandonment is also why Ctrl+C is handled explicitly below instead
    # of being left to propagate as a bare KeyboardInterrupt: concurrent.futures
    # registers a process-exit hook that joins *every* thread any
    # ThreadPoolExecutor ever created, regardless of whether shutdown() was
    # called. If a check thread is blocked in a call with no effective
    # timeout, that join waits forever and the process outlives Ctrl+C. The
    # only reliable way to kill a background thread stuck in blocking I/O is
    # to bypass that hook with os._exit(), which tears the whole process down
    # at the OS level immediately.
    executor = ThreadPoolExecutor(max_workers=max(4, len(check_names) or 1))

    try:
        for i, check_name in enumerate(check_names, 1):
            check_func = ALL_CHECKS[check_name]

            # Always show per-check progress (not just under -v): a default scan
            # with no responsive OT services can take a few minutes, and with no
            # feedback at all that reads as a hang rather than normal operation.
            print(f"[{i}/{len(check_names)}] Running: {check_name}...", end=" ", flush=True)

            try:
                # Determine how to call the check function
                if is_url:
                    # Web-style check (takes URL as first arg)
                    future = executor.submit(check_func, target)
                else:
                    # OT-style check (takes IP and optional port)
                    if port:
                        future = executor.submit(check_func, target, port)
                    else:
                        future = executor.submit(check_func, target)

                try:
                    result = future.result(timeout=CHECK_TIMEOUT_SECONDS)
                except FutureTimeoutError:
                    result = {
                        "name": check_name,
                        "status": "error",
                        "severity": "medium",
                        "details": f"Check timed out after {CHECK_TIMEOUT_SECONDS}s and was skipped.",
                        "recommendation": "The target may be unreachable or filtering traffic. Re-run with --type to isolate the slow check."
                    }

                results.append(result)

                status = result.get("status", "unknown")
                severity = result.get("severity", "low")
                print(f"done ({status}/{severity})")

            except KeyboardInterrupt:
                raise

            except Exception as e:
                error_result = {
                    "name": check_name,
                    "status": "error",
                    "severity": "high",
                    "details": str(e),
                    "recommendation": "Check the target configuration and try again."
                }
                results.append(error_result)

                print(f"ERROR: {str(e)}")
    except KeyboardInterrupt:
        completed = len(results)
        print(f"\n\n[!] Scan interrupted by user. {completed}/{len(check_names)} checks completed.")
        # Hard-exit: a check thread may still be blocked in the pool with no
        # way to cancel it. os._exit() skips interpreter shutdown (and the
        # thread-join hook that would hang on it) and kills the process now.
        os._exit(130)

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

    try:
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
    except KeyboardInterrupt:
        print(f"\n\n[!] Scan interrupted by user. {len(all_results)}/{len(ips)} hosts completed.")
        os._exit(130)

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
  achillesrazor -t 192.168.1.100
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
        "-t",
        "--target",
        dest="target_flag",
        metavar="TARGET",
        help="Target IP address, hostname, URL, or CIDR network (same as the positional argument)"
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
    args.target = args.target_flag or args.target
    if not args.list_checks and not args.target:
        parser.error("the following arguments are required: target (or -t/--target)")
    return args


def main():
    """Main entry point"""
    # Windows consoles frequently default to a legacy codepage (e.g. cp1252)
    # that can't encode the report's status icons (checkmarks, arrows, etc.),
    # which crashes print() with UnicodeEncodeError. Force UTF-8 on stdout so
    # console output always works, falling back gracefully if stdout doesn't
    # support reconfiguration (e.g. when piped through something unusual).
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    print_banner(version=__version__)

    args = parse_arguments()

    if args.list_checks:
        list_checks()
        return 0

    target = args.target
    output_path = args.output
    output_format = detect_output_format(output_path, args.format)
    checks = resolve_scan_type(args.scan_type)

    scan_start = time.time()

    try:
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
            generator = ICSReportGenerator(report_target, start_time=scan_start)

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
            output = create_report(target, results, "console", start_time=scan_start)
        elif output_format == "json":
            output = create_report(target, results, "json", start_time=scan_start)
        elif output_format == "markdown":
            output = create_report(target, results, "markdown", start_time=scan_start)
        else:
            output = create_report(target, results, "html", start_time=scan_start)

        if output_path and output_path != "-":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"\n[+] Report saved to: {output_path}")
        else:
            print(output)

        return 0

    except KeyboardInterrupt:
        # run_checks()/scan_network() already handle their own interrupts and
        # os._exit() directly (see their comments for why). This is a
        # safety net for interrupts landing outside those calls, e.g. during
        # report generation or the output file write.
        print("\n\n[!] Scan interrupted by user.")
        os._exit(130)


if __name__ == "__main__":
    sys.exit(main())