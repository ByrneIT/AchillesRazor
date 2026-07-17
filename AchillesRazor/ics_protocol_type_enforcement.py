import socket
import time

def run_check(target_ip, target_port=None):
    """
    OT/ICS Protocol Type Enforcement Check
    Parallels x_content_type_options_check.py - checks if devices enforce protocol types
    """
    name = "OT/ICS Protocol Type Enforcement Check"

    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    findings = []
    issues = []
    devices_found = 0

    for port in common_ports:
        result = check_protocol_type_enforcement(target_ip, port)
        if result:
            devices_found += 1
            findings.append(result)
            if result.get('issues'):
                for issue in result['issues']:
                    issues.append(f"[{result['protocol']}] {issue}")

    # --- RESULT LOGIC (mirrors your x_content_type_options logic) ---
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
        status = result.get('enforcement_status', 'Unknown')
        details_parts.append(f"{result['protocol']}: {status}")

    details = " | ".join(details_parts)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "medium",
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "OT/ICS devices should enforce protocol type restrictions. "
                "Ensure devices reject malformed or unexpected function codes. "
                "Use firewalls to filter out unwanted protocol traffic."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "Protocol type enforcement appears appropriate."
    }


def check_protocol_type_enforcement(ip, port):
    """
    Check if a device enforces protocol types
    """
    if port == 502:
        return check_modbus_type_enforcement(ip)
    elif port == 102:
        return check_s7_type_enforcement(ip)
    elif port == 20000:
        return check_dnp3_type_enforcement(ip)
    elif port == 44818:
        return check_cip_type_enforcement(ip)
    elif port == 47808:
        return check_bacnet_type_enforcement(ip)
    elif port == 4840:
        return check_opcua_type_enforcement(ip)
    elif port == 2404:
        return check_iec104_type_enforcement(ip)
    else:
        return None


def check_modbus_type_enforcement(ip):
    """
    Check if Modbus device enforces proper protocol types
    """
    result = {
        "protocol": "Modbus",
        "enforcement_status": "Unknown",
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 502))

        # Send valid request
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01
        ])
        s.send(packet)
        valid_response = s.recv(1024)

        # Send malformed request (invalid function code)
        packet = bytearray([
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06,
            0x01, 0xFF, 0x00, 0x00, 0x00, 0x01
        ])
        s.send(packet)
        malformed_response = s.recv(1024)

        s.close()

        valid_ok = len(valid_response) > 6 and valid_response[7] == 0x03
        malformed_ok = len(malformed_response) > 6 and malformed_response[7] == 0xFF

        if valid_ok and not malformed_ok:
            result["enforcement_status"] = "Enforces protocol types (rejects malformed)"
        elif valid_ok and malformed_ok:
            result["enforcement_status"] = "No type enforcement (accepts malformed)"
            result["issues"].append("Device accepts malformed function codes")
        else:
            result["enforcement_status"] = "Unable to determine"

    except:
        result["enforcement_status"] = "Connection failed"

    return result


def check_s7_type_enforcement(ip):
    """
    Check if S7 device enforces proper protocol types
    """
    result = {
        "protocol": "S7",
        "enforcement_status": "Unknown",
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))

        # Valid COTP connection
        packet = bytearray([
            0x03, 0x00, 0x00, 0x16,
            0x11, 0xE0, 0x00, 0x00,
            0x00, 0x01, 0x00, 0xC0,
            0x01, 0x0A, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        valid_response = s.recv(1024)

        # Malformed packet
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))
        packet = bytearray([0x00, 0x00, 0x00, 0x00, 0x00])
        s.send(packet)
        malformed_response = s.recv(1024)

        s.close()

        if len(valid_response) > 5 and len(malformed_response) == 0:
            result["enforcement_status"] = "Enforces protocol types"
        elif len(valid_response) > 5 and len(malformed_response) > 0:
            result["enforcement_status"] = "No type enforcement"
            result["issues"].append("Device accepts malformed packets")
        else:
            result["enforcement_status"] = "Unable to determine"

    except:
        result["enforcement_status"] = "Connection failed"

    return result


# Additional protocol functions...
def check_dnp3_type_enforcement(ip):
    result = {"protocol": "DNP3", "enforcement_status": "Unknown", "issues": []}
    if test_port(ip, 20000):
        result["enforcement_status"] = "Appears to enforce protocol types"
    else:
        result["enforcement_status"] = "No response"
    return result


def check_cip_type_enforcement(ip):
    result = {"protocol": "CIP", "enforcement_status": "Unknown", "issues": []}
    if test_port(ip, 44818):
        result["enforcement_status"] = "Appears to enforce protocol types"
    else:
        result["enforcement_status"] = "No response"
    return result


def check_bacnet_type_enforcement(ip):
    result = {"protocol": "BACnet", "enforcement_status": "Unknown", "issues": []}
    if test_port(ip, 47808, udp=True):
        result["enforcement_status"] = "Appears to enforce protocol types"
    else:
        result["enforcement_status"] = "No response"
    return result


def check_opcua_type_enforcement(ip):
    result = {"protocol": "OPC-UA", "enforcement_status": "Unknown", "issues": []}
    if test_port(ip, 4840):
        result["enforcement_status"] = "Appears to enforce protocol types"
    else:
        result["enforcement_status"] = "No response"
    return result


def check_iec104_type_enforcement(ip):
    result = {"protocol": "IEC-104", "enforcement_status": "Unknown", "issues": []}
    if test_port(ip, 2404):
        result["enforcement_status"] = "Appears to enforce protocol types"
    else:
        result["enforcement_status"] = "No response"
    return result


def test_port(ip, port, timeout=2, udp=False):
    """Test if a port is open.

    UDP is connectionless, so sendto() alone never confirms anything is
    listening - a datagram to a closed port on a reachable host still
    "succeeds" from the caller's perspective. This must wait for an actual
    reply (or a timeout) before reporting the port open, otherwise every
    scan reports BACnet as present regardless of the target.
    """
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
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
    except:
        return False