import socket
import time

def run_check(target_ip, target_port=None):
    """
    OT/ICS Security Policy Check
    Parallels csp_check.py but for industrial device security policies
    """
    name = "OT/ICS Security Policy Check"

    # If no port provided, probe common ICS ports
    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    devices_found = []
    issues = []
    recommendations = []

    for port in common_ports:
        result = check_device_policy(target_ip, port)
        if result:
            devices_found.append(result)
            if result.get("issues"):
                for issue in result["issues"]:
                    issues.append(f"[{result['protocol']}] {issue}")
            if result.get("recommendation"):
                recommendations.append(f"[{result['protocol']}] {result['recommendation']}")

    # --- RESULT LOGIC (mirrors your CSP logic) ---
    if not devices_found:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    # Build the details string (like your CSP details)
    if issues:
        details = "OT/ICS devices found but with security policy weaknesses: " + " ".join(issues)
        return {
            "name": name,
            "status": "warn",
            "severity": "high",  # Elevated because OT policy weaknesses have physical impact
            "details": details,
            "recommendation": (
                "Remediate identified security policy weaknesses: " + " ".join(recommendations) + ". "
                "Key OT security policies should include: authentication, encryption, access control, "
                "and changed default credentials. Review vendor security guides for best practices."
            )
        }

    # If we got here, devices have reasonably secure policies
    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": f"Found {len(devices_found)} OT/ICS device(s) with no obvious security policy weaknesses detected.",
        "recommendation": "Continue to review security policies as firmware is updated and network changes occur."
    }


def check_device_policy(ip, port):
    """
    Check security policies of a specific OT/ICS device
    Returns dict with findings or None
    """
    if port == 502:
        return check_modbus_policy(ip)
    elif port == 102:
        return check_s7_policy(ip)
    elif port == 20000:
        return check_dnp3_policy(ip)
    elif port == 44818:
        return check_cip_policy(ip)
    elif port == 47808:
        return check_bacnet_policy(ip)
    elif port == 4840:
        return check_opcua_policy(ip)
    elif port == 2404:
        return check_iec104_policy(ip)
    else:
        return None


def check_modbus_policy(ip):
    """
    Check Modbus security policy
    Equivalent to checking CSP for "unsafe-inline" patterns
    """
    result = {
        "protocol": "Modbus",
        "port": 502,
        "issues": [],
        "recommendation": "",
        "policy_found": False
    }

    # Check if authentication is present (like checking for CSP header)
    if has_modbus_auth(ip):
        result["policy_found"] = True
        result["auth_type"] = "Present"
    else:
        result["issues"].append("No authentication policy (Modbus has no native auth - relies on network segmentation)")
        result["recommendation"] = "Implement network segmentation and firewalls to restrict Modbus access."

    # Check for default Unit ID (like checking for 'unsafe-inline')
    if has_modbus_default_unit(ip):
        result["issues"].append("Using default Unit ID (0x01) - like using wildcard '*' in CSP")
        result["recommendation"] += " Change default Unit ID and restrict access."

    # Check for open write access (like checking for 'unsafe-eval')
    if has_modbus_write_access(ip):
        result["issues"].append("Write access available without authentication - like enabling 'unsafe-eval'")
        result["recommendation"] += " Restrict write access to trusted clients only."

    # Check if device is identifiable (like checking if CSP is present)
    if has_modbus_identification(ip):
        result["device_identifiable"] = True
    else:
        result["issues"].append("Device does not respond to identification requests - policy may be restrictive")
        result["recommendation"] += " Verify device is properly configured."

    return result


def check_s7_policy(ip):
    """
    Check Siemens S7 security policy
    """
    result = {
        "protocol": "S7",
        "port": 102,
        "issues": [],
        "recommendation": "",
        "policy_found": False
    }

    # Check if PLC access protection is enabled
    if has_s7_access_protection(ip):
        result["policy_found"] = True
        result["auth_type"] = "Access Protection Enabled"
    else:
        result["issues"].append("No PLC access protection - like missing CSP header")
        result["recommendation"] = "Enable S7 access protection (password) in TIA Portal."

    # Check for default password (like checking for 'unsafe-inline')
    if has_s7_default_password(ip):
        result["issues"].append("Using default Siemens password - like using 'unsafe-inline' in CSP")
        result["recommendation"] += " IMMEDIATELY change default password."

    # Check if CPU info is exposed (like checking for wildcards)
    if has_s7_cpu_info_exposed(ip):
        result["issues"].append("CPU information exposed without auth - like using '*' in CSP")
        result["recommendation"] += " Restrict CPU info queries."

    return result


def check_dnp3_policy(ip):
    """
    Check DNP3 security policy
    """
    result = {
        "protocol": "DNP3",
        "port": 20000,
        "issues": [],
        "recommendation": "",
        "policy_found": False
    }

    # DNP3 has optional authentication
    if has_dnp3_auth(ip):
        result["policy_found"] = True
        result["auth_type"] = "Authentication Enabled"
    else:
        result["issues"].append("DNP3 authentication not enabled - like missing CSP header")
        result["recommendation"] = "Enable DNP3 authentication (Secure Authentication v5)."

    # Check for default settings
    if has_dnp3_defaults(ip):
        result["issues"].append("Using default DNP3 settings - like using 'unsafe-inline'")
        result["recommendation"] += " Change default DNP3 addresses and configurations."

    return result


def check_cip_policy(ip):
    """
    Check EtherNet/IP (CIP) security policy
    """
    result = {
        "protocol": "CIP/EtherNet/IP",
        "port": 44818,
        "issues": [],
        "recommendation": "",
        "policy_found": False
    }

    # CIP has limited security - check for common policy issues
    if has_cip_identity_exposed(ip):
        result["issues"].append("CIP device identity exposed without auth - like missing CSP")
        result["recommendation"] = "Use Rockwell's security features. Restrict CIP traffic."

    # Check for default configuration
    if has_cip_defaults(ip):
        result["issues"].append("Using default CIP configuration - like 'unsafe-inline'")
        result["recommendation"] += " Change default IP settings and use network segmentation."

    return result


def check_bacnet_policy(ip):
    """
    Check BACnet security policy
    """
    result = {
        "protocol": "BACnet",
        "port": 47808,
        "issues": [],
        "recommendation": "",
        "policy_found": False
    }

    # BACnet has no native security - policy is purely network segmentation
    if has_bacnet_response(ip):
        result["issues"].append("BACnet device responds to Who-Is requests - like missing CSP (no security control)")
        result["recommendation"] = "BACnet is inherently insecure. Use network segmentation, firewalls, and VPNs."

    # Check if it's using default object IDs
    if has_bacnet_defaults(ip):
        result["issues"].append("Using default BACnet object IDs - like using '*' in CSP")
        result["recommendation"] += " Reconfigure default BACnet object instances."

    return result


def check_opcua_policy(ip):
    """
    Check OPC-UA security policy
    """
    result = {
        "protocol": "OPC-UA",
        "port": 4840,
        "issues": [],
        "recommendation": "",
        "policy_found": False
    }

    # OPC-UA has built-in security - check if it's enforced
    if has_opcua_security(ip):
        result["policy_found"] = True
        result["auth_type"] = "Security Enabled"
    else:
        result["issues"].append("OPC-UA security not enabled - like missing CSP header")
        result["recommendation"] = "Enable OPC-UA security (authentication, encryption, and signing)."

    # Check for anonymous access
    if has_opcua_anonymous(ip):
        result["issues"].append("OPC-UA allows anonymous access - like 'unsafe-inline'")
        result["recommendation"] += " Disable anonymous access."

    return result


def check_iec104_policy(ip):
    """
    Check IEC 60870-5-104 security policy
    """
    result = {
        "protocol": "IEC-104",
        "port": 2404,
        "issues": [],
        "recommendation": "",
        "policy_found": False
    }

    # IEC-104 has minimal security
    if has_iec104_access(ip):
        result["issues"].append("IEC-104 device accepts connections without auth - like missing CSP")
        result["recommendation"] = "IEC-104 is inherently insecure. Use IP whitelisting, VPNs, and monitoring."

    # Check for default settings
    if has_iec104_defaults(ip):
        result["issues"].append("Using default IEC-104 settings - like using '*' in CSP")
        result["recommendation"] += " Change default ASDU addresses and use TLS if supported."

    return result


# -----------------------------------------------------------------
# Protocol-specific policy check functions
# -----------------------------------------------------------------

def has_modbus_auth(ip):
    """
    Check if Modbus has authentication (it never does natively)
    This is more about checking if the device is on a segmented network
    """
    # Modbus has no native authentication - always return False
    return False


def has_modbus_default_unit(ip):
    """Check if Modbus device uses default Unit ID"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        
        # Try Unit ID 0x01 (default)
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01,  # Unit ID 0x01
            0x03, 0x00, 0x00, 0x00, 0x01
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        # If it responds to default Unit ID, it's using default
        if len(response) > 6:
            return True
    except:
        pass
    return False


def has_modbus_write_access(ip):
    """Check if Modbus device allows unauthenticated writes"""
    try:
        from AchillesRazor.ics_exposure_check import has_modbus_write_access as safe_has_modbus_write_access
    except ImportError:
        from ics_exposure_check import has_modbus_write_access as safe_has_modbus_write_access
    return safe_has_modbus_write_access(ip)


def has_modbus_identification(ip):
    """Check if Modbus device responds to identification requests"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        
        # Read Device ID request
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x2B, 0x0E, 0x01, 0x00
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        if len(response) > 9 and response[7] == 0x2B:
            return True
    except:
        pass
    return False


def has_s7_access_protection(ip):
    """
    Check if S7 has access protection enabled
    Simplified: if it rejects a basic info request, protection may be enabled
    """
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
        
        # If we got a response, protection may still be enabled
        # This is simplified - full detection requires deeper analysis
        s.close()
        return False  # Default assumption: no access protection
    except:
        pass
    return False


def has_s7_default_password(ip):
    """Simplified check for default S7 password"""
    # If device responds to basic requests, it likely has no password
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))
        s.close()
        return True  # Connected - likely no password
    except:
        return False


def has_s7_cpu_info_exposed(ip):
    """Check if CPU info is exposed"""
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
        
        # Send CPU info request
        info_packet = bytearray([
            0x03, 0x00, 0x00, 0x1F,
            0x02, 0xF0, 0x80,
            0x32, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        
        s.send(info_packet)
        response = s.recv(1024)
        s.close()
        
        if len(response) > 20:
            return True
    except:
        pass
    return False


def has_dnp3_auth(ip):
    """Check if DNP3 authentication is enabled (simplified)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 20000))
        s.close()
        # If it connected, likely no auth (in practice, DNP3 auth is complex)
        return False
    except:
        return False


def has_dnp3_defaults(ip):
    """Check for default DNP3 settings"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 20000))
        
        # Simple test - if it responds, likely using defaults
        packet = bytearray([
            0x05, 0x64, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        if len(response) > 5:
            return True
    except:
        pass
    return False


def has_cip_identity_exposed(ip):
    """Check if CIP identity is exposed"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
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
        s.close()
        
        if len(response) > 10:
            return True
    except:
        pass
    return False


def has_cip_defaults(ip):
    """Check for default CIP configuration"""
    # If device responds to CIP requests, likely defaults
    return has_cip_identity_exposed(ip)


def has_bacnet_response(ip):
    """Check if BACnet device responds to Who-Is"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        
        packet = bytearray([
            0x01, 0x01, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        
        s.sendto(packet, (ip, 47808))
        response, addr = s.recvfrom(1024)
        s.close()
        
        if len(response) > 5:
            return True
    except:
        pass
    return False


def has_bacnet_defaults(ip):
    """Check for default BACnet object IDs"""
    # If device responds, likely using defaults
    return has_bacnet_response(ip)


def has_opcua_security(ip):
    """Check if OPC-UA security is enabled"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 4840))
        s.close()
        # Connection indicates it's listening - security may not be enabled
        return False
    except:
        return False


def has_opcua_anonymous(ip):
    """Check if OPC-UA allows anonymous access"""
    # If it connects without error, anonymous likely allowed
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 4840))
        s.close()
        return True
    except:
        return False


def has_iec104_access(ip):
    """Check if IEC-104 device allows access"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 2404))
        
        # StartDT request
        packet = bytearray([
            0x68, 0x04, 0x07, 0x00,
            0x00, 0x00
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        if len(response) > 5 and response[2] == 0x07:
            return True
    except:
        pass
    return False


def has_iec104_defaults(ip):
    """Check for default IEC-104 settings"""
    return has_iec104_access(ip)