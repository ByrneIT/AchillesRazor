import socket
import time

def run_check(target_ip, target_port=None):
    """
    OT/ICS Function Permission Check
    Parallels permissions_policy_check.py - checks what protocol functions are allowed
    """
    name = "OT/ICS Function Permission Check"

    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    issues = []
    findings = []
    devices_found = 0

    for port in common_ports:
        result = check_function_permissions(target_ip, port)
        if result:
            devices_found += 1
            findings.append(result)
            if result.get('issues'):
                for issue in result['issues']:
                    issues.append(f"[{result['protocol']}] {issue}")

    # --- RESULT LOGIC (mirrors your permissions_policy logic) ---
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
        status = result.get('permission_status', 'Unknown')
        if result.get('allowed_functions'):
            status += f" (Allowed: {', '.join(result['allowed_functions'][:3])})"
        details_parts.append(f"{result['protocol']}: {status}")

    details = " | ".join(details_parts)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "high",
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "Restrict OT/ICS device functions to only what is necessary. "
                "Disable dangerous function codes (writes, reboots, firmware updates). "
                "Use network segmentation to limit who can execute privileged functions."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "Function permissions appear appropriately configured."
    }


def check_function_permissions(ip, port):
    """
    Check what protocol functions a device allows
    """
    if port == 502:
        return check_modbus_permissions(ip)
    elif port == 102:
        return check_s7_permissions(ip)
    elif port == 20000:
        return check_dnp3_permissions(ip)
    elif port == 44818:
        return check_cip_permissions(ip)
    elif port == 47808:
        return check_bacnet_permissions(ip)
    elif port == 4840:
        return check_opcua_permissions(ip)
    elif port == 2404:
        return check_iec104_permissions(ip)
    else:
        return None


def check_modbus_permissions(ip):
    """
    Check Modbus function permissions
    """
    result = {
        "protocol": "Modbus",
        "permission_status": "Unknown",
        "allowed_functions": [],
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 502))

        # Test read function (0x03)
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01
        ])
        s.send(packet)
        response = s.recv(1024)
        if len(response) > 6 and response[7] == 0x03:
            result["allowed_functions"].append("Read (0x03)")
        else:
            result["issues"].append("Read function may be restricted")

        # Write function (0x05) is intentionally not probed on live devices
        # because a full write could crash the PLC or change its state.
        result["issues"].append("Write function not tested live for safety")

        s.close()

        if result["allowed_functions"]:
            result["permission_status"] = "Functions allowed (read-only probe; write test skipped for safety)"
        else:
            result["permission_status"] = "No functions allowed (restricted)"
            result["issues"].append("No detectable functions allowed - verify configuration")

    except:
        result["permission_status"] = "Connection failed"

    return result


def check_s7_permissions(ip):
    """
    Check Siemens S7 function permissions
    """
    result = {
        "protocol": "S7",
        "permission_status": "Unknown",
        "allowed_functions": [],
        "issues": []
    }

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

        if len(response) > 5:
            result["allowed_functions"].append("COTP Connect")

            # CPU Info request
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
                result["allowed_functions"].append("CPU Info (0x32)")
                result["issues"].append("CPU Info exposed (information disclosure)")
            else:
                result["issues"].append("CPU Info may be restricted")

        s.close()

        if result["allowed_functions"]:
            result["permission_status"] = "Functions allowed"
        else:
            result["permission_status"] = "No functions allowed"

    except:
        result["permission_status"] = "Connection failed"

    return result


def check_dnp3_permissions(ip):
    """
    Check DNP3 function permissions
    """
    result = {
        "protocol": "DNP3",
        "permission_status": "Unknown",
        "allowed_functions": [],
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 20000))

        # DNP3 Link Layer
        packet = bytearray([
            0x05, 0x64, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)

        if len(response) > 5:
            result["allowed_functions"].append("Link Layer")
            result["permission_status"] = "Functions allowed"
        else:
            result["permission_status"] = "No response"

        s.close()

    except:
        result["permission_status"] = "Connection failed"

    return result


# Additional protocol functions removed for brevity...
def check_cip_permissions(ip):
    result = {"protocol": "CIP", "permission_status": "Not implemented", "allowed_functions": [], "issues": []}
    return result


def check_bacnet_permissions(ip):
    result = {"protocol": "BACnet", "permission_status": "Not implemented", "allowed_functions": [], "issues": []}
    return result


def check_opcua_permissions(ip):
    result = {"protocol": "OPC-UA", "permission_status": "Not implemented", "allowed_functions": [], "issues": []}
    return result


def check_iec104_permissions(ip):
    result = {"protocol": "IEC-104", "permission_status": "Not implemented", "allowed_functions": [], "issues": []}
    return result