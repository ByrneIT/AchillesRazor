import socket
import time

def run_check(target_ip, target_port=None):
    """
    OT/ICS Discovery Probe Check
    Parallels sitemap_robots_check.py but for industrial device discovery
    """
    name = "OT/ICS Discovery Probe Check"

    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    findings = []
    issues = []
    devices_found = 0

    for port in common_ports:
        result = check_discovery_probes(target_ip, port)
        if result:
            devices_found += 1
            findings.append(result)
            if result.get('issues'):
                for issue in result['issues']:
                    issues.append(f"[{result['protocol']}] {issue}")

    # --- RESULT LOGIC (mirrors your sitemap_robots logic) ---
    if not findings:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    # Build details string
    details_parts = []
    for result in findings:
        status = result.get('discovery_status', 'Unknown')
        if result.get('device_info'):
            status += f" (Info: {result['device_info'][:50]})"
        details_parts.append(f"{result['protocol']}: {status}")

    details = " | ".join(details_parts)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "medium",
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "OT/ICS device discovery issues detected. "
                "Consider disabling unnecessary discovery probes (Device ID, CPU Info). "
                "Use network segmentation to restrict who can query device information."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "OT/ICS device discovery probes appear appropriately configured."
    }


def check_discovery_probes(ip, port):
    """
    Check what discovery probes an OT/ICS device allows
    """
    if port == 502:
        return check_modbus_discovery(ip)
    elif port == 102:
        return check_s7_discovery(ip)
    elif port == 20000:
        return check_dnp3_discovery(ip)
    elif port == 44818:
        return check_cip_discovery(ip)
    elif port == 47808:
        return check_bacnet_discovery(ip)
    elif port == 4840:
        return check_opcua_discovery(ip)
    elif port == 2404:
        return check_iec104_discovery(ip)
    else:
        return None


def check_modbus_discovery(ip):
    """
    Check Modbus discovery probes
    Equivalent to checking robots.txt and sitemap.xml
    """
    result = {
        "protocol": "Modbus",
        "port": 502,
        "discovery_status": "Unknown",
        "device_info": None,
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 502))

        # --- Probe 1: Read Device ID (like sitemap.xml - intentional exposure) ---
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x2B, 0x0E, 0x01, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)

        if len(response) > 9 and response[7] == 0x2B:
            result["discovery_status"] = "Device ID exposed"
            # Extract device info if present
            if len(response) > 12:
                result["device_info"] = response[12:].hex()[:20]
        else:
            result["discovery_status"] = "Device ID not exposed"
            result["issues"].append("Device ID not accessible (good for security)")

        s.close()

    except:
        result["discovery_status"] = "Connection failed"

    return result


def check_s7_discovery(ip):
    """
    Check Siemens S7 discovery probes
    """
    result = {
        "protocol": "S7",
        "port": 102,
        "discovery_status": "Unknown",
        "device_info": None,
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
                result["discovery_status"] = "CPU Info exposed"
                result["device_info"] = response[20:40].hex()[:20]
            else:
                result["discovery_status"] = "CPU Info protected"
                result["issues"].append("CPU Info not accessible (good for security)")

        s.close()

    except:
        result["discovery_status"] = "Connection failed"

    return result


def check_dnp3_discovery(ip):
    """
    Check DNP3 discovery probes
    """
    result = {
        "protocol": "DNP3",
        "port": 20000,
        "discovery_status": "Unknown",
        "device_info": None,
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 20000))

        # DNP3 Link Layer probe
        packet = bytearray([
            0x05, 0x64, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)

        if len(response) > 5:
            result["discovery_status"] = "DNP3 device responds"
            result["device_info"] = response[4:8].hex()
        else:
            result["discovery_status"] = "No response to probe"

        s.close()

    except:
        result["discovery_status"] = "Connection failed"

    return result


def check_cip_discovery(ip):
    """
    Check CIP discovery probes
    """
    result = {
        "protocol": "CIP",
        "port": 44818,
        "discovery_status": "Unknown",
        "device_info": None,
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 44818))

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
            result["discovery_status"] = "CIP identity exposed"
            result["device_info"] = response[8:16].hex()
        else:
            result["discovery_status"] = "No identity response"

        s.close()

    except:
        result["discovery_status"] = "Connection failed"

    return result


def check_bacnet_discovery(ip):
    """
    Check BACnet discovery probes
    """
    result = {
        "protocol": "BACnet",
        "port": 47808,
        "discovery_status": "Unknown",
        "device_info": None,
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)

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
            result["discovery_status"] = "BACnet device responds"
            result["device_info"] = response[4:8].hex()
        else:
            result["discovery_status"] = "No response to Who-Is"

        s.close()

    except:
        result["discovery_status"] = "No response"

    return result


def check_opcua_discovery(ip):
    """
    Check OPC-UA discovery probes
    """
    result = {
        "protocol": "OPC-UA",
        "port": 4840,
        "discovery_status": "Unknown",
        "device_info": None,
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 4840))

        # OPC-UA Hello
        packet = bytearray([
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)

        if len(response) > 5:
            result["discovery_status"] = "OPC-UA server responds"
            result["device_info"] = response[4:8].hex()
        else:
            result["discovery_status"] = "No hello response"

        s.close()

    except:
        result["discovery_status"] = "Connection failed"

    return result


def check_iec104_discovery(ip):
    """
    Check IEC 60870-5-104 discovery probes
    """
    result = {
        "protocol": "IEC-104",
        "port": 2404,
        "discovery_status": "Unknown",
        "device_info": None,
        "issues": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 2404))

        # StartDT
        packet = bytearray([
            0x68, 0x04, 0x07, 0x00,
            0x00, 0x00
        ])
        s.send(packet)
        response = s.recv(1024)

        if len(response) > 5 and response[2] == 0x07:
            result["discovery_status"] = "IEC-104 device responds"
        else:
            result["discovery_status"] = "No response to StartDT"

        s.close()

    except:
        result["discovery_status"] = "Connection failed"

    return result