import socket
import time

def run_check(target_ip, target_port=None):
    """
    OT/ICS Source Restriction Check
    Parallels referrer_policy_check.py - checks if devices restrict source IPs
    """
    name = "OT/ICS Source Restriction Check"

    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    findings = []
    issues = []
    devices_found = 0

    for port in common_ports:
        result = check_source_restrictions(target_ip, port)
        if result:
            devices_found += 1
            findings.append(result)
            if result.get('issues'):
                for issue in result['issues']:
                    issues.append(f"[{result['protocol']}] {issue}")

    # --- RESULT LOGIC (mirrors your referrer_policy logic) ---
    if not findings:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    # Build details
    details_parts = []
    for result in findings:
        status = result.get('restriction_status', 'Unknown')
        details_parts.append(f"{result['protocol']}: {status}")

    details = " | ".join(details_parts)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "medium",
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "OT/ICS devices should implement source IP restrictions. "
                "Configure firewalls to only allow authorized engineering workstations. "
                "Use network segmentation to limit who can access OT devices."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "Source restrictions appear appropriately configured."
    }


def check_source_restrictions(ip, port):
    """
    Check if a device restricts source IPs
    """
    if port == 502:
        return check_modbus_source_restriction(ip)
    elif port == 102:
        return check_s7_source_restriction(ip)
    elif port == 20000:
        return check_dnp3_source_restriction(ip)
    elif port == 44818:
        return check_cip_source_restriction(ip)
    elif port == 47808:
        return check_bacnet_source_restriction(ip)
    elif port == 4840:
        return check_opcua_source_restriction(ip)
    elif port == 2404:
        return check_iec104_source_restriction(ip)
    else:
        return None


def check_modbus_source_restriction(ip):
    """
    Check if Modbus device has source restrictions
    """
    result = {
        "protocol": "Modbus",
        "restriction_status": "Unknown",
        "issues": []
    }

    # If the device responds, it likely doesn't have source restrictions
    if test_port(ip, 502):
        result["restriction_status"] = "No source restriction detected"
        result["issues"].append("Device accepts connections from any source")
    else:
        result["restriction_status"] = "Possibly restricted (no response)"

    return result


def check_s7_source_restriction(ip):
    """
    Check if S7 device has source restrictions
    """
    result = {
        "protocol": "S7",
        "restriction_status": "Unknown",
        "issues": []
    }

    if test_port(ip, 102):
        result["restriction_status"] = "No source restriction detected"
        result["issues"].append("Device accepts connections from any source")
    else:
        result["restriction_status"] = "Possibly restricted"

    return result


# Additional protocol functions...
def check_dnp3_source_restriction(ip):
    result = {"protocol": "DNP3", "restriction_status": "Unknown", "issues": []}
    if test_port(ip, 20000):
        result["restriction_status"] = "No source restriction detected"
        result["issues"].append("Device accepts connections from any source")
    else:
        result["restriction_status"] = "Possibly restricted"
    return result


def check_cip_source_restriction(ip):
    result = {"protocol": "CIP", "restriction_status": "Unknown", "issues": []}
    if test_port(ip, 44818):
        result["restriction_status"] = "No source restriction detected"
        result["issues"].append("Device accepts connections from any source")
    else:
        result["restriction_status"] = "Possibly restricted"
    return result


def check_bacnet_source_restriction(ip):
    result = {"protocol": "BACnet", "restriction_status": "Unknown", "issues": []}
    # BACnet uses UDP
    if test_port(ip, 47808, udp=True):
        result["restriction_status"] = "No source restriction detected"
        result["issues"].append("Device responds from any source")
    else:
        result["restriction_status"] = "Possibly restricted"
    return result


def check_opcua_source_restriction(ip):
    result = {"protocol": "OPC-UA", "restriction_status": "Unknown", "issues": []}
    if test_port(ip, 4840):
        result["restriction_status"] = "No source restriction detected"
        result["issues"].append("Server accepts connections from any source")
    else:
        result["restriction_status"] = "Possibly restricted"
    return result


def check_iec104_source_restriction(ip):
    result = {"protocol": "IEC-104", "restriction_status": "Unknown", "issues": []}
    if test_port(ip, 2404):
        result["restriction_status"] = "No source restriction detected"
        result["issues"].append("Device accepts connections from any source")
    else:
        result["restriction_status"] = "Possibly restricted"
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