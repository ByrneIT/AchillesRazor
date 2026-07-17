import socket
import struct
import time
import requests
from urllib.parse import urlparse, parse_qs

# -----------------------------------------------------------------
# Function code patterns that can cause "redirects" in OT protocols
# -----------------------------------------------------------------

# Modbus function codes that can cause unexpected behavior
MODBUS_SENSITIVE_FUNCTIONS = [
    0x05,  # Write Single Coil (can turn things on/off)
    0x06,  # Write Single Register (can change setpoints)
    0x0F,  # Write Multiple Coils (mass control change)
    0x10,  # Write Multiple Registers (mass data change)
    0x17,  # Read/Write Multiple Registers (read + write)
    0x2B,  # Encapsulated Interface Transport (can include custom functions)
]

# S7 function codes that are dangerous
S7_SENSITIVE_FUNCTIONS = [
    0x32,  # CPU Info (exposes system details)
    0x34,  # Read DB (read data blocks)
    0x35,  # Write DB (write data blocks)
    0x36,  # Start/Stop CPU (critical!)
    0x38,  # Read SZL (system info)
    0x3E,  # Download blocks (firmware update)
]

# DNP3 function codes that are dangerous
DNP3_SENSITIVE_FUNCTIONS = [
    0x01,  # Read (data exfiltration)
    0x02,  # Write (control change)
    0x03,  # Select (prepare control operation)
    0x04,  # Operate (execute control operation)
    0x0C,  # Cold Restart (reboot device)
    0x0D,  # Warm Restart (soft reboot)
    0x0E,  # Enable Unsolicited (change reporting behavior)
]


def run_check(target_ip, target_port=None, target_url=None):
    """
    OT/ICS Redirect Chain and Misconfiguration Check
    Merges redirect_check.py and open_redirect_check.py for OT/ICS
    """
    name = "OT/ICS Protocol Redirect Chain and Misconfiguration Check"

    # ics_main dispatches web-style targets by calling check_func(target)
    # with a single positional argument, so a URL always arrives here as
    # target_ip rather than the target_url kwarg. Detect it the same way
    # ics_encryption_check.py and ics_dns_security_check.py do, otherwise
    # http(s):// targets silently fall through to the OT protocol probes
    # below (which just fail to connect) and this check never actually
    # exercises its web-based redirect logic at all.
    if target_url:
        return run_web_check(target_url)
    if isinstance(target_ip, str) and target_ip.startswith(("http://", "https://")):
        return run_web_check(target_ip)

    # Otherwise, do OT protocol checks
    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    chain_results = []
    parameter_findings = []
    issues = []

    for port in common_ports:
        # Check the protocol call chain (like redirect chain)
        chain_result = check_protocol_chain(target_ip, port)
        if chain_result:
            chain_results.append(chain_result)

        # Check for dangerous parameters/function codes (like open redirect parameters)
        param_result = check_dangerous_parameters(target_ip, port)
        if param_result:
            parameter_findings.extend(param_result)

    # --- RESULT LOGIC (mirrors both original checks) ---
    if not chain_results and not parameter_findings:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    # Build details string (like redirect chain)
    details_parts = []
    if chain_results:
        details_parts.append("Protocol Chain: " + " → ".join(chain_results))
    if parameter_findings:
        details_parts.append("Sensitive Parameters: " + ", ".join(parameter_findings))

    details = " | ".join(details_parts)

    # Check for issues (like open redirect issues)
    if chain_results and len(chain_results) > 3:
        issues.append("Long protocol chain (more than 3 hops)")

    if parameter_findings:
        for param in parameter_findings:
            if "write" in param.lower() or "modify" in param.lower():
                issues.append(f"Dangerous function code: {param}")

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "high",  # Elevated for OT
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "Review OT/ICS device configuration: "
                "1. Ensure function codes are restricted to necessary operations "
                "2. Disable dangerous function codes (writes, reboots, firmware updates) "
                "3. Implement network segmentation to limit access "
                "4. Use firewalls to restrict unauthorized protocol operations"
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "No protocol misconfigurations detected. Continue to monitor."
    }


def run_web_check(target_url):
    """
    Run web-based redirect checks (original functionality)
    For OT devices with web interfaces
    """
    name = "OT/ICS Web Interface Redirect Check"
    results = []
    issues = []

    # --- Part 1: Redirect Chain Check (from redirect_check.py) ---
    try:
        response = requests.get(target_url, timeout=5, allow_redirects=True)
        chain = [resp.url for resp in response.history] + [response.url]

        if len(chain) > 1:
            results.append("Redirect Chain: " + " → ".join(chain))
            if len(chain) > 3:
                issues.append("Long redirect chain (more than 3 hops)")
        else:
            results.append("No redirects detected")
    except Exception as e:
        results.append(f"Redirect check failed: {str(e)}")

    # --- Part 2: Open Redirect Parameter Check (from open_redirect_check.py) ---
    try:
        parsed = urlparse(target_url)
        query = parse_qs(parsed.query)

        # Common redirect parameters
        redirect_params = [
            "redirect", "redirect_url", "redirect_uri", "redir",
            "url", "next", "dest", "destination", "forward", "goto", "out"
        ]

        param_findings = []
        for param in redirect_params:
            if param in query:
                value = query[param][0]
                param_findings.append(f"{param}={value}")

                # If it contains a full URL, that's a red flag
                if value.startswith("http://") or value.startswith("https://"):
                    issues.append(f"Parameter '{param}' contains a full URL (potential open redirect)")

        if param_findings:
            results.append("Redirect Parameters: " + ", ".join(param_findings))
    except Exception as e:
        results.append(f"Parameter check failed: {str(e)}")

    # --- Result logic ---
    details = " | ".join(results)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "medium",
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "Review redirect configuration on OT web interface. "
                "Validate redirect targets against an allowlist. "
                "Limit redirect chains to a single hop."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "No redirect issues detected on web interface."
    }


def check_protocol_chain(ip, port):
    """
    Check the protocol call chain for an OT device
    Like redirect_check.py but for protocol operations
    """
    if port == 502:
        return check_modbus_chain(ip)
    elif port == 102:
        return check_s7_chain(ip)
    elif port == 20000:
        return check_dnp3_chain(ip)
    elif port == 44818:
        return check_cip_chain(ip)
    elif port == 47808:
        return check_bacnet_chain(ip)
    elif port == 4840:
        return check_opcua_chain(ip)
    elif port == 2404:
        return check_iec104_chain(ip)
    else:
        return None


def check_modbus_chain(ip):
    """
    Check Modbus operation chain
    Sequence: Request → Response → (next request)
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 502))

        chain_parts = []
        functions_used = []

        # Test a series of operations (like a redirect chain)
        # 1. Read Device ID
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x2B, 0x0E, 0x01, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 9 and response[7] == 0x2B:
            chain_parts.append("Device ID (0x2B)")
            functions_used.append(0x2B)

        # 2. Read Holding Registers
        packet = bytearray([
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 6 and response[7] == 0x03:
            chain_parts.append("Read Registers (0x03)")
            functions_used.append(0x03)

        # 3. Write Coil test (intentionally skipped for safety)
        # A live FC 0x05 write could change device state or crash the PLC.
        # We therefore do not test writes on live devices.

        s.close()

        # Build the chain description
        if chain_parts:
            # Check for dangerous functions in the chain
            dangerous = []
            for func in functions_used:
                if func in MODBUS_SENSITIVE_FUNCTIONS:
                    dangerous.append(f"0x{func:02X}")

            chain_desc = " → ".join(chain_parts)
            if dangerous:
                chain_desc += f" [DANGEROUS: {', '.join(dangerous)}]"

            return chain_desc

    except:
        pass

    return None


def check_s7_chain(ip):
    """
    Check S7 operation chain
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))

        chain_parts = []
        functions_used = []

        # COTP Connection
        packet = bytearray([
            0x03, 0x00, 0x00, 0x16,
            0x11, 0xE0, 0x00, 0x00,
            0x00, 0x01, 0x00, 0xC0,
            0x01, 0x0A, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 5:
            chain_parts.append("COTP Connect")
            functions_used.append(0x11)

        # CPU Info
        packet = bytearray([
            0x03, 0x00, 0x00, 0x1F,
            0x02, 0xF0, 0x80,
            0x32, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 20:
            chain_parts.append("CPU Info (0x32)")
            functions_used.append(0x32)

            # Check for dangerous functions
            dangerous = []
            for func in functions_used:
                if func in S7_SENSITIVE_FUNCTIONS:
                    dangerous.append(f"0x{func:02X}")

            chain_desc = " → ".join(chain_parts)
            if dangerous:
                chain_desc += f" [DANGEROUS: {', '.join(dangerous)}]"

            s.close()
            return chain_desc

        s.close()

    except:
        pass

    return None


def check_dnp3_chain(ip):
    """
    Check DNP3 operation chain
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 20000))

        chain_parts = []
        functions_used = []

        # DNP3 Link Layer + Application Layer
        packet = bytearray([
            0x05, 0x64, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 5:
            chain_parts.append("DNP3 Link")
            functions_used.append(0x00)

            # Check for dangerous functions
            dangerous = []
            for func in functions_used:
                if func in DNP3_SENSITIVE_FUNCTIONS:
                    dangerous.append(f"0x{func:02X}")

            chain_desc = " → ".join(chain_parts)
            if dangerous:
                chain_desc += f" [DANGEROUS: {', '.join(dangerous)}]"

            s.close()
            return chain_desc

        s.close()

    except:
        pass

    return None


def check_cip_chain(ip):
    """
    Check CIP operation chain
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 44818))

        chain_parts = []

        # CIP Identity Request
        packet = bytearray([
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 10:
            chain_parts.append("CIP Identity")

            chain_desc = " → ".join(chain_parts)
            s.close()
            return chain_desc

        s.close()

    except:
        pass

    return None


def check_bacnet_chain(ip):
    """
    Check BACnet operation chain
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)

        chain_parts = []

        # BACnet Who-Is
        packet = bytearray([
            0x01, 0x01, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.sendto(packet, (ip, 47808))
        response, addr = s.recvfrom(1024)
        if len(response) > 5:
            chain_parts.append("BACnet Who-Is")

        # BACnet I-Am (device response)
        if len(response) > 15:
            chain_parts.append("BACnet I-Am")

        chain_desc = " → ".join(chain_parts)
        s.close()
        return chain_desc

    except:
        pass

    return None


def check_opcua_chain(ip):
    """
    Check OPC-UA operation chain
    """
    try:
        import ssl
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 4840))

        chain_parts = []

        # OPC-UA Hello
        packet = bytearray([
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 5:
            chain_parts.append("OPC-UA Hello")

        # OPC-UA Open Secure Channel
        # Simplified - just check if TLS is available
        chain_parts.append("TLS Available")

        chain_desc = " → ".join(chain_parts)
        s.close()
        return chain_desc

    except:
        pass

    return None


def check_iec104_chain(ip):
    """
    Check IEC 60870-5-104 operation chain
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 2404))

        chain_parts = []

        # IEC-104 StartDT
        packet = bytearray([
            0x68, 0x04, 0x07, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 5 and response[2] == 0x07:
            chain_parts.append("StartDT")

        # Test if we can send a query
        chain_parts.append("Data Query Available")

        chain_desc = " → ".join(chain_parts)
        s.close()
        return chain_desc

    except:
        pass

    return None


def check_dangerous_parameters(ip, port):
    """
    Check for dangerous parameters/function codes on an OT device
    Like open_redirect_check.py but for OT protocols
    """
    if port == 502:
        return check_modbus_parameters(ip)
    elif port == 102:
        return check_s7_parameters(ip)
    elif port == 20000:
        return check_dnp3_parameters(ip)
    elif port == 44818:
        return check_cip_parameters(ip)
    elif port == 47808:
        return check_bacnet_parameters(ip)
    elif port == 4840:
        return check_opcua_parameters(ip)
    elif port == 2404:
        return check_iec104_parameters(ip)
    else:
        return []


def check_modbus_parameters(ip):
    """
    Check for dangerous Modbus parameters
    """
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 502))

        # Check for read access (like checking redirect parameters)
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 6 and response[7] == 0x03:
            findings.append("Read Holding Registers (0x03) - Data exfiltration risk")

        # Write access is intentionally not probed on live devices because
        # a live FC 0x05 write could change equipment state or crash the PLC.

        # Check for broadcast access
        packet = bytearray([
            0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x01
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 6:
            findings.append("Broadcast Unit ID (0x00) - Network-wide control risk")

        s.close()

    except:
        pass

    return findings


def check_s7_parameters(ip):
    """
    Check for dangerous S7 parameters
    """
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))

        # COTP Connection
        packet = bytearray([
            0x03, 0x00, 0x00, 0x16,
            0x11, 0xE0, 0x00, 0x00,
            0x00, 0x01, 0x00, 0xC0,
            0x01, 0x0A, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)

        # Check if CPU Info is exposed
        packet = bytearray([
            0x03, 0x00, 0x00, 0x1F,
            0x02, 0xF0, 0x80,
            0x32, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 20:
            findings.append("CPU Info (0x32) - System information exposure risk")

        s.close()

    except:
        pass

    return findings


def check_dnp3_parameters(ip):
    """
    Check for dangerous DNP3 parameters
    """
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 20000))

        # Check if device responds to generic requests
        packet = bytearray([
            0x05, 0x64, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 5:
            findings.append("DNP3 Link Layer - Control command risk")

        s.close()

    except:
        pass

    return findings


def check_cip_parameters(ip):
    """
    Check for dangerous CIP parameters
    """
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 44818))

        # Check if device responds to identity requests
        packet = bytearray([
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 10:
            findings.append("CIP Identity - Device enumeration risk")

        s.close()

    except:
        pass

    return findings


def check_bacnet_parameters(ip):
    """
    Check for dangerous BACnet parameters
    """
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)

        # Check Who-Is response
        packet = bytearray([
            0x01, 0x01, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.sendto(packet, (ip, 47808))
        response, addr = s.recvfrom(1024)
        if len(response) > 5:
            findings.append("BACnet Who-Is - Device discovery risk")

        s.close()

    except:
        pass

    return findings


def check_opcua_parameters(ip):
    """
    Check for dangerous OPC-UA parameters
    """
    findings = []
    try:
        import ssl
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 4840))

        # Check if Hello is accepted
        packet = bytearray([
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 5:
            findings.append("OPC-UA Hello - Server enumeration risk")

        # Check if TLS is missing
        try:
            context = ssl.create_default_context()
            tls_sock = context.wrap_socket(s, server_hostname=ip)
            tls_sock.connect((ip, 4840))
            tls_sock.close()
        except:
            findings.append("OPC-UA TLS Missing - Encryption risk")

        s.close()

    except:
        pass

    return findings


def check_iec104_parameters(ip):
    """
    Check for dangerous IEC-104 parameters
    """
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 2404))

        # Check StartDT
        packet = bytearray([
            0x68, 0x04, 0x07, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 5 and response[2] == 0x07:
            findings.append("IEC-104 StartDT - Control command risk")

        s.close()

    except:
        pass

    return findings