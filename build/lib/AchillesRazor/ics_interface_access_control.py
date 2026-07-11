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
    OT/ICS Interface Access Control Check
    Parallels x_frame_options_check.py - checks if device interfaces have access controls
    """
    name = "OT/ICS Interface Access Control Check"

    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    findings = []
    issues = []
    devices_found = 0

    for port in common_ports:
        result = check_interface_access(target_ip, port)
        if result:
            devices_found += 1
            findings.append(result)
            if result.get('issues'):
                for issue in result['issues']:
                    issues.append(f"[{result['protocol']}] {issue}")

    # --- RESULT LOGIC (mirrors your x_frame_options logic) ---
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
        status = result.get('access_status', 'Unknown')
        if result.get('access_method'):
            status += f" (Access: {result['access_method']})"
        details_parts.append(f"{result['protocol']}: {status}")

    details = " | ".join(details_parts)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "high",
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "OT/ICS device interfaces should have strong access controls. "
                "Require authentication for all management interfaces. "
                "Use network segmentation and firewalls to limit who can access OT devices."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "Interface access controls appear appropriately configured."
    }


def check_interface_access(ip, port):
    """
    Check if an OT/ICS device has interface access controls
    """
    if port == 502:
        return check_modbus_access(ip)
    elif port == 102:
        return check_s7_access(ip)
    elif port == 20000:
        return check_dnp3_access(ip)
    elif port == 44818:
        return check_cip_access(ip)
    elif port == 47808:
        return check_bacnet_access(ip)
    elif port == 4840:
        return check_opcua_access(ip)
    elif port == 2404:
        return check_iec104_access(ip)
    else:
        return None


def check_modbus_access(ip):
    """
    Check Modbus access controls
    """
    if not _port_open(ip, 502):
        return None

    result = {
        "protocol": "Modbus",
        "access_status": "Unknown",
        "access_method": None,
        "issues": []
    }

    # Modbus has no native authentication
    if test_port(ip, 502):
        result["access_status"] = "No access control"
        result["access_method"] = "None"
        result["issues"].append("Modbus has no native authentication")
    else:
        result["access_status"] = "No response"

    return result


def check_s7_access(ip):
    """
    Check S7 access controls
    """
    if not _port_open(ip, 102):
        return None

    result = {
        "protocol": "S7",
        "access_status": "Unknown",
        "access_method": None,
        "issues": []
    }

    if test_port(ip, 102):
        # Check if device responds to basic queries
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, 102))

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
            s.close()

            if len(response) > 5:
                result["access_status"] = "Accessible (may or may not have password)"
                result["access_method"] = "Password (unknown if set)"
                result["issues"].append("S7 access protection status unknown")
            else:
                result["access_status"] = "Access restricted"
                result["access_method"] = "Password"
        except:
            result["access_status"] = "Connection failed"
    else:
        result["access_status"] = "No response"

    return result


def check_dnp3_access(ip):
    """
    Check DNP3 access controls
    """
    if not _port_open(ip, 20000):
        return None

    result = {
        "protocol": "DNP3",
        "access_status": "Unknown",
        "access_method": None,
        "issues": []
    }

    if test_port(ip, 20000):
        result["access_status"] = "Accessible (Secure Auth status unknown)"
        result["access_method"] = "Optional Secure Auth"
        result["issues"].append("DNP3 Secure Auth status unknown")
    else:
        result["access_status"] = "No response"

    return result


def check_cip_access(ip):
    """
    Check CIP access controls
    """
    if not _port_open(ip, 44818):
        return None

    result = {
        "protocol": "CIP",
        "access_status": "Unknown",
        "access_method": None,
        "issues": []
    }

    if test_port(ip, 44818):
        result["access_status"] = "Accessible (limited access control)"
        result["access_method"] = "None/Unknown"
        result["issues"].append("CIP has limited access control")
    else:
        result["access_status"] = "No response"

    return result


def check_bacnet_access(ip):
    """
    Check BACnet access controls
    """
    if not _port_open(ip, 47808, udp=True):
        return None

    result = {
        "protocol": "BACnet",
        "access_status": "Unknown",
        "access_method": None,
        "issues": []
    }

    if test_port(ip, 47808, udp=True):
        result["access_status"] = "Accessible (no native access control)"
        result["access_method"] = "None"
        result["issues"].append("BACnet has no native access control")
    else:
        result["access_status"] = "No response"

    return result


def check_opcua_access(ip):
    """
    Check OPC-UA access controls
    """
    if not _port_open(ip, 4840):
        return None

    result = {
        "protocol": "OPC-UA",
        "access_status": "Unknown",
        "access_method": None,
        "issues": []
    }

    if test_port(ip, 4840):
        # Check if anonymous access is allowed
        try:
            import ssl
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)

            context = ssl.create_default_context()
            tls_sock = context.wrap_socket(sock, server_hostname=ip)
            tls_sock.connect((ip, 4840))
            tls_sock.close()

            result["access_status"] = "Accessible (TLS available)"
            result["access_method"] = "TLS + optional auth"
            # Anonymous check requires deeper inspection
            result["issues"].append("OPC-UA anonymous access status unknown")
        except:
            result["access_status"] = "Accessible (TLS may be available)"
            result["access_method"] = "Unknown"
    else:
        result["access_status"] = "No response"

    return result


def check_iec104_access(ip):
    """
    Check IEC-104 access controls
    """
    if not _port_open(ip, 2404):
        return None

    result = {
        "protocol": "IEC-104",
        "access_status": "Unknown",
        "access_method": None,
        "issues": []
    }

    if test_port(ip, 2404):
        result["access_status"] = "Accessible (no native access control)"
        result["access_method"] = "None"
        result["issues"].append("IEC-104 has no native access control")
    else:
        result["access_status"] = "No response"

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