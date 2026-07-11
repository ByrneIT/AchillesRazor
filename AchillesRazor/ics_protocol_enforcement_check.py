import socket
import time


def _port_open(ip, port, timeout=2, udp=False):
    """Return True when a TCP/UDP port is reachable on the target."""
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (ip, port))
            try:
                sock.recvfrom(1024)
            except socket.timeout:
                sock.close()
                return False
            sock.close()
            return True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def run_check(target_ip, target_port=None):
    """
    OT/ICS Protocol Enforcement Check
    Parallels hsts_check.py but for industrial protocol security enforcement
    """
    name = "OT/ICS Protocol Enforcement Check"

    # If no port provided, probe common ICS ports
    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    results = []
    devices_checked = 0

    for port in common_ports:
        result = check_protocol_enforcement(target_ip, port)
        if result:
            devices_checked += 1
            results.append(result)

    # --- RESULT LOGIC (mirrors your HSTS logic) ---
    if not results:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    # Check if any device has encryption enforcement
    enforcement_found = False
    issues = []
    details_list = []

    for result in results:
        details_list.append(f"{result['protocol']}: {result['enforcement_status']}")
        if result.get('issues'):
            issues.extend(result['issues'])
        if result.get('enforcement_found'):
            enforcement_found = True

    details = " | ".join(details_list)

    # --- HSTS-style classification ---
    if not enforcement_found:
        return {
            "name": name,
            "status": "warn",
            "severity": "high",  # Elevated because OT has physical impact
            "details": details + " | No encryption enforcement detected",
            "recommendation": (
                "OT/ICS devices must enforce secure protocol usage. "
                "Enable TLS/encryption where supported. Use network segmentation to "
                "compensate for devices that don't support encryption. "
                "Configure devices to reject plaintext connections."
            )
        }

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "medium",
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "Strengthen protocol enforcement: verify all devices are configured "
                "to require encryption. Consider adding network-level enforcement "
                "with firewalls or IPSEC."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details + " | Protocol enforcement appears configured",
        "recommendation": "Protocol enforcement is configured. Continue to monitor for new devices."
    }


def check_protocol_enforcement(ip, port):
    """
    Check if an OT/ICS device enforces secure protocol usage
    """
    if port == 502:
        return check_modbus_enforcement(ip)
    elif port == 102:
        return check_s7_enforcement(ip)
    elif port == 20000:
        return check_dnp3_enforcement(ip)
    elif port == 44818:
        return check_cip_enforcement(ip)
    elif port == 47808:
        return check_bacnet_enforcement(ip)
    elif port == 4840:
        return check_opcua_enforcement(ip)
    elif port == 2404:
        return check_iec104_enforcement(ip)
    else:
        return None


def check_modbus_enforcement(ip):
    """
    Check if Modbus enforces secure connections
    Modbus/TLS (port 802) is the secure variant, but rarely used
    """
    if not _port_open(ip, 502) and not _port_open(ip, 802):
        return None

    result = {
        "protocol": "Modbus",
        "port": 502,
        "enforcement_status": "Plaintext only",
        "enforcement_found": False,
        "issues": []
    }

    # Check if plaintext Modbus is open (port 502)
    plaintext_open = test_port(ip, 502)
    if plaintext_open:
        # Check if Modbus/TLS is also available (port 802)
        tls_open = test_port(ip, 802)

        if tls_open:
            # Check if plaintext is still accepted (HSTS violation equivalent)
            if plaintext_open:
                result["enforcement_status"] = "Plaintext accepted (TLS available but not enforced)"
                result["issues"].append("Plaintext Modbus accepted despite TLS availability")
                result["enforcement_found"] = False
            else:
                result["enforcement_status"] = "TLS enforced (plaintext rejected)"
                result["enforcement_found"] = True
        else:
            result["enforcement_status"] = "Plaintext only (no TLS support)"
            result["issues"].append("No TLS support available")
            result["enforcement_found"] = False
    else:
        # Port not open - maybe TLS only
        result["enforcement_status"] = "Port 502 not open (possibly TLS only)"
        result["enforcement_found"] = False

    return result


def check_s7_enforcement(ip):
    """
    Check if Siemens S7 enforces secure connections
    S7-1200/1500 support TLS on port 102
    """
    if not _port_open(ip, 102) and not test_tls_port(ip, 102):
        return None

    result = {
        "protocol": "S7",
        "port": 102,
        "enforcement_status": "Unknown",
        "enforcement_found": False,
        "issues": []
    }

    # Check if standard S7 is open (port 102)
    standard_open = test_port(ip, 102)

    if standard_open:
        # Check if TLS is supported (S7 with TLS)
        tls_open = test_tls_port(ip, 102)

        if tls_open:
            # Check if plaintext is still accepted (HSTS violation equivalent)
            # This requires deeper inspection - simplified check
            result["enforcement_status"] = "TLS available, plaintext may be accepted"
            result["issues"].append("Plaintext S7 may be accepted despite TLS availability")
            result["enforcement_found"] = False
        else:
            result["enforcement_status"] = "Plaintext S7 only"
            result["issues"].append("No TLS support detected")
            result["enforcement_found"] = False
    else:
        # Port not open on standard port - check if it's TLS-only
        tls_open = test_tls_port(ip, 102)
        if tls_open:
            result["enforcement_status"] = "TLS only (plaintext rejected)"
            result["enforcement_found"] = True
        else:
            result["enforcement_status"] = "No S7 service detected"

    return result


def check_dnp3_enforcement(ip):
    """
    Check if DNP3 enforces secure connections
    DNP3 has a security extension but rarely used
    """
    if not _port_open(ip, 20000):
        return None

    result = {
        "protocol": "DNP3",
        "port": 20000,
        "enforcement_status": "Unknown",
        "enforcement_found": False,
        "issues": []
    }

    # Check if standard DNP3 is open
    standard_open = test_port(ip, 20000)

    if standard_open:
        # DNP3 has an optional secure authentication extension
        # This requires deeper protocol inspection
        result["enforcement_status"] = "Plaintext DNP3 (auth extension may be available)"
        result["issues"].append("DNP3 Secure Authentication not detected")
        result["enforcement_found"] = False
    else:
        result["enforcement_status"] = "DNP3 port not open"

    return result


def check_cip_enforcement(ip):
    """
    Check if CIP/EtherNet/IP enforces secure connections
    CIP Security (CIP-S) is the secure variant
    """
    if not _port_open(ip, 44818):
        return None

    result = {
        "protocol": "CIP",
        "port": 44818,
        "enforcement_status": "Unknown",
        "enforcement_found": False,
        "issues": []
    }

    # Check if standard CIP is open
    standard_open = test_port(ip, 44818)

    if standard_open:
        # CIP Security (CIP-S) is rarely implemented
        result["enforcement_status"] = "Plaintext CIP only"
        result["issues"].append("CIP Security (CIP-S) not detected")
        result["enforcement_found"] = False
    else:
        result["enforcement_status"] = "CIP port not open"

    return result


def check_bacnet_enforcement(ip):
    """
    Check if BACnet enforces secure connections
    BACnet/SC is the secure variant (TLS)
    """
    if not _port_open(ip, 47808, udp=True):
        return None

    result = {
        "protocol": "BACnet",
        "port": 47808,
        "enforcement_status": "Unknown",
        "enforcement_found": False,
        "issues": []
    }

    # Check if standard BACnet is open (UDP)
    standard_open = test_port(ip, 47808, udp=True)

    if standard_open:
        # Check if BACnet/SC (TLS) is available on port 47808 or similar
        tls_open = test_tls_port(ip, 47808)
        if tls_open:
            result["enforcement_status"] = "Plaintext BACnet available (TLS may also be available)"
            result["issues"].append("Plaintext BACnet accepted")
            result["enforcement_found"] = False
        else:
            result["enforcement_status"] = "Plaintext BACnet only"
            result["issues"].append("No TLS support detected")
            result["enforcement_found"] = False
    else:
        result["enforcement_status"] = "BACnet port not open"

    return result


def check_opcua_enforcement(ip):
    """
    Check if OPC-UA enforces secure connections
    OPC-UA has built-in security and can enforce encryption/signing
    """
    if not _port_open(ip, 4840):
        return None

    result = {
        "protocol": "OPC-UA",
        "port": 4840,
        "enforcement_status": "Unknown",
        "enforcement_found": False,
        "issues": []
    }

    # Check if OPC-UA is open
    standard_open = test_port(ip, 4840)

    if standard_open:
        # Check if security is enforced
        security_enforced = check_opcua_security_enforced(ip)

        if security_enforced:
            result["enforcement_status"] = "Security enforced (encryption/authentication required)"
            result["enforcement_found"] = True
        else:
            result["enforcement_status"] = "OPC-UA available with security disabled"
            result["issues"].append("Security not enforced (plaintext allowed)")
            result["enforcement_found"] = False
    else:
        result["enforcement_status"] = "OPC-UA port not open"

    return result


def check_iec104_enforcement(ip):
    """
    Check if IEC 60870-5-104 enforces secure connections
    """
    if not _port_open(ip, 2404):
        return None

    result = {
        "protocol": "IEC-104",
        "port": 2404,
        "enforcement_status": "Unknown",
        "enforcement_found": False,
        "issues": []
    }

    # Check if standard IEC-104 is open
    standard_open = test_port(ip, 2404)

    if standard_open:
        # IEC-104 has no native security
        result["enforcement_status"] = "Plaintext only"
        result["issues"].append("No native security in IEC-104")
        result["enforcement_found"] = False
    else:
        result["enforcement_status"] = "IEC-104 port not open"

    return result


# -----------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------

def test_port(ip, port, timeout=2, udp=False):
    """Test if a port is open"""
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (ip, port))
            # UDP is connectionless - this is a simple test
            sock.close()
            return True
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
    except:
        return False


def test_tls_port(ip, port, timeout=2):
    """
    Test if a port supports TLS
    This attempts a TLS handshake
    """
    try:
        import ssl
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Try to wrap with TLS
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname=ip)
        tls_sock.connect((ip, port))
        tls_sock.close()
        return True
    except:
        return False


def check_opcua_security_enforced(ip):
    """
    Check if OPC-UA enforces security
    This is a simplified check - full OPC-UA would require handshake
    """
    try:
        import ssl
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        # Try to connect with TLS - if it works, security is enabled
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname=ip)
        tls_sock.connect((ip, 4840))
        tls_sock.close()
        return True
    except:
        return False