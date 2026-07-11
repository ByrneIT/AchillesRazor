import socket
import time

def run_check(target_ip, target_port=None):
    """
    OT/ICS Mixed Mode Check
    Parallels mixed_content_check.py - checks if encrypted devices also allow plaintext
    """
    name = "OT/ICS Mixed Mode Check"

    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    issues = []
    findings = []
    devices_found = 0

    for port in common_ports:
        result = check_mixed_mode(target_ip, port)
        if result:
            devices_found += 1
            findings.append(result)
            if result.get('issues'):
                for issue in result['issues']:
                    issues.append(f"[{result['protocol']}] {issue}")

    # --- RESULT LOGIC (mirrors your mixed_content logic) ---
    if not findings:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    details_parts = []
    for result in findings:
        status = result.get('mode_status', 'Unknown')
        details_parts.append(f"{result['protocol']}: {status}")

    details = " | ".join(details_parts)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "high",  # Elevated for OT
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "Mixed mode detected: devices that support encryption also accept plaintext. "
                "Configure devices to reject plaintext connections. "
                "Use network segmentation to prevent downgrade attacks."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "No mixed mode issues detected."
    }


def check_mixed_mode(ip, port):
    """
    Check if an OT device supports both encrypted and plaintext modes
    """
    if port == 502:
        return check_modbus_mixed(ip)
    elif port == 102:
        return check_s7_mixed(ip)
    elif port == 20000:
        return check_dnp3_mixed(ip)
    elif port == 44818:
        return check_cip_mixed(ip)
    elif port == 47808:
        return check_bacnet_mixed(ip)
    elif port == 4840:
        return check_opcua_mixed(ip)
    elif port == 2404:
        return check_iec104_mixed(ip)
    else:
        return None


def check_modbus_mixed(ip):
    """
    Check if Modbus supports both plaintext and TLS
    """
    result = {
        "protocol": "Modbus",
        "mode_status": "Unknown",
        "issues": []
    }

    # Check plaintext (port 502)
    plaintext = test_port(ip, 502)

    # Check TLS (port 802)
    tls = test_tls_port(ip, 802)

    if tls and plaintext:
        result["mode_status"] = "Mixed mode (plaintext + TLS)"
        result["issues"].append("Plaintext Modbus accepted even though TLS is available")
    elif tls:
        result["mode_status"] = "TLS only (secure)"
    elif plaintext:
        result["mode_status"] = "Plaintext only"
    else:
        result["mode_status"] = "No Modbus service detected"

    return result


def check_s7_mixed(ip):
    """
    Check if S7 supports both plaintext and TLS
    """
    result = {
        "protocol": "S7",
        "mode_status": "Unknown",
        "issues": []
    }

    # Check plaintext (port 102)
    plaintext = test_port(ip, 102)

    # Check TLS (port 102 with TLS)
    tls = test_tls_port(ip, 102)

    if tls and plaintext:
        result["mode_status"] = "Mixed mode (plaintext + TLS)"
        result["issues"].append("Plaintext S7 accepted even though TLS is available")
    elif tls:
        result["mode_status"] = "TLS only (secure)"
    elif plaintext:
        result["mode_status"] = "Plaintext only"
    else:
        result["mode_status"] = "No S7 service detected"

    return result


def check_dnp3_mixed(ip):
    """
    Check if DNP3 supports mixed modes (DNP3 has optional secure auth)
    """
    result = {
        "protocol": "DNP3",
        "mode_status": "Unknown",
        "issues": []
    }

    # Check plaintext (port 20000)
    plaintext = test_port(ip, 20000)

    # DNP3 Secure Auth doesn't use a different port - it's a function code extension
    if plaintext:
        # We can't easily test if Secure Auth is enabled
        result["mode_status"] = "Plaintext (Secure Auth may or may not be enabled)"
        result["issues"].append("DNP3 Secure Auth status unknown")
    else:
        result["mode_status"] = "No DNP3 service detected"

    return result


def check_cip_mixed(ip):
    """
    Check if CIP supports mixed modes
    """
    result = {
        "protocol": "CIP",
        "mode_status": "Unknown",
        "issues": []
    }

    # CIP Security (CIP-S) on port 44818
    plaintext = test_port(ip, 44818)

    if plaintext:
        result["mode_status"] = "Plaintext (CIP-S may or may not be available)"
        result["issues"].append("CIP Security status unknown")
    else:
        result["mode_status"] = "No CIP service detected"

    return result


def check_bacnet_mixed(ip):
    """
    Check if BACnet supports mixed modes
    """
    result = {
        "protocol": "BACnet",
        "mode_status": "Unknown",
        "issues": []
    }

    # BACnet/SC (TLS) on port 47808
    plaintext = test_port(ip, 47808, udp=True)
    tls = test_tls_port(ip, 47808)

    if tls and plaintext:
        result["mode_status"] = "Mixed mode (plaintext + BACnet/SC)"
        result["issues"].append("Plaintext BACnet accepted even though TLS is available")
    elif tls:
        result["mode_status"] = "BACnet/SC only (secure)"
    elif plaintext:
        result["mode_status"] = "Plaintext only"
    else:
        result["mode_status"] = "No BACnet service detected"

    return result


def check_opcua_mixed(ip):
    """
    Check if OPC-UA supports mixed modes
    """
    result = {
        "protocol": "OPC-UA",
        "mode_status": "Unknown",
        "issues": []
    }

    # OPC-UA on port 4840
    plaintext = test_port(ip, 4840)
    tls = test_tls_port(ip, 4840)

    if tls and plaintext:
        result["mode_status"] = "Mixed mode (plaintext + TLS)"
        result["issues"].append("Plaintext OPC-UA accepted even though TLS is available")
    elif tls:
        result["mode_status"] = "TLS only (secure)"
    elif plaintext:
        result["mode_status"] = "Plaintext only"
        result["issues"].append("OPC-UA security disabled")
    else:
        result["mode_status"] = "No OPC-UA service detected"

    return result


def check_iec104_mixed(ip):
    """
    Check if IEC-104 supports mixed modes
    """
    result = {
        "protocol": "IEC-104",
        "mode_status": "Unknown",
        "issues": []
    }

    # IEC-104 on port 2404
    plaintext = test_port(ip, 2404)

    if plaintext:
        result["mode_status"] = "Plaintext only"
        result["issues"].append("No native security in IEC-104")
    else:
        result["mode_status"] = "No IEC-104 service detected"

    return result


def test_port(ip, port, timeout=2, udp=False):
    """Test if a port is open"""
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (ip, port))
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
    """Test if a port supports TLS"""
    try:
        import ssl
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname=ip)
        tls_sock.connect((ip, port))
        tls_sock.close()
        return True
    except:
        return False