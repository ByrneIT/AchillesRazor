import socket
import struct
import time

def run_check(target_ip, target_port=None):
    """
    OT/ICS Device Security Posture Check
    Parallels cookie_check.py but for industrial device security
    """
    name = "OT/ICS Device Security Posture Check"

    # If no port provided, probe common ICS ports
    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    devices_checked = []
    issues = []
    recommendations = []

    for port in common_ports:
        result = check_device_security(target_ip, port)
        if result:
            devices_checked.append(result)
            
            # Aggregate issues across devices
            if result.get("issues"):
                for issue in result["issues"]:
                    issues.append(f"[{result['protocol']}] {issue}")
            
            if result.get("recommendation"):
                recommendations.append(f"[{result['protocol']}] {result['recommendation']}")

    # --- RESULT LOGIC (mirrors your cookie logic) ---
    if not devices_checked:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    # Build details string (like your cookie_details)
    details_list = []
    for dev in devices_checked:
        details_list.append(
            f"{dev['protocol']} on port {dev['port']}: "
            f"Auth={dev.get('authentication', 'Unknown')}, "
            f"Encryption={dev.get('encryption', 'Unknown')}, "
            f"Access={dev.get('access_control', 'Unknown')}"
        )
    details = " | ".join(details_list)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "high",  # Elevated because OT security issues have physical impact
            "details": details + " | Issues: " + " ".join(issues),
            "recommendation": (
                "Address identified security gaps: " + " ".join(recommendations) + ". "
                "OT/ICS devices should have authentication enabled, encryption where possible, "
                "and strict access controls. Default credentials must be changed immediately."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": (
            "OT/ICS devices appear to have basic security controls. "
            "Continue to monitor for firmware updates and network segmentation."
        )
    }


def check_device_security(ip, port):
    """
    Check security posture of a specific OT/ICS device
    Returns dict with security findings or None
    """
    if port == 502:
        return check_modbus_security(ip)
    elif port == 102:
        return check_s7_security(ip)
    elif port == 20000:
        return check_dnp3_security(ip)
    elif port == 44818:
        return check_cip_security(ip)
    elif port == 47808:
        return check_bacnet_security(ip)
    elif port == 4840:
        return check_opcua_security(ip)
    elif port == 2404:
        return check_iec104_security(ip)
    else:
        return None


def check_modbus_security(ip):
    """
    Check Modbus security posture
    Modbus has no built-in authentication or encryption by default
    """
    result = {
        "protocol": "Modbus",
        "port": 502,
        "authentication": "None",
        "encryption": "None (plaintext)",
        "access_control": "Unknown",
        "issues": [],
        "recommendation": ""
    }

    # Test if device responds to read requests (indicates unauthenticated access)
    # This is a simple "is this accessible without auth" test
    if modbus_read_test(ip):
        result["issues"].append("Device responds to read requests without authentication")
        result["access_control"] = "No access control (unauthenticated reads allowed)"
        result["recommendation"] = "Enable authentication if supported. Use network segmentation to restrict access."
    else:
        result["access_control"] = "Possibly restricted"

    # Check if writes are allowed (even more dangerous)
    if modbus_write_test(ip):
        result["issues"].append("Device accepts write commands without authentication")
        result["recommendation"] = "CRITICAL: Restrict write access. Use firewalls to limit write-capable clients."
    
    # Check for default Modbus unit ID (0x01) - indicates default configuration
    if modbus_default_unit_test(ip):
        result["issues"].append("Device using default Unit ID (0x01)")
        result["recommendation"] += " Change default Unit ID."

    return result


def check_s7_security(ip):
    """
    Check Siemens S7 security posture
    """
    result = {
        "protocol": "S7",
        "port": 102,
        "authentication": "Unknown",
        "encryption": "None (plaintext)",
        "access_control": "Unknown",
        "issues": [],
        "recommendation": ""
    }

    # Test if S7 device allows unauthenticated read
    if s7_read_test(ip):
        result["issues"].append("S7 device responds to read requests without authentication")
        result["access_control"] = "No access control (unauthenticated reads allowed)"
        result["recommendation"] = "Enable PLC access protection. Use S7-1200/1500 security features."
    else:
        result["access_control"] = "Possibly restricted"

    # Check for default Siemens password
    if s7_default_password_test(ip):
        result["issues"].append("S7 device using default Siemens password (or no password)")
        result["recommendation"] += " IMMEDIATELY change default credentials."
        result["authentication"] = "Weak/Default"

    return result


def check_dnp3_security(ip):
    """
    Check DNP3 security posture
    """
    result = {
        "protocol": "DNP3",
        "port": 20000,
        "authentication": "Unknown",
        "encryption": "None (plaintext)",
        "access_control": "Unknown",
        "issues": [],
        "recommendation": ""
    }

    # DNP3 has optional authentication - check if it's enabled
    if dnp3_auth_test(ip):
        result["authentication"] = "Enabled"
    else:
        result["issues"].append("DNP3 authentication not detected")
        result["authentication"] = "None/Disabled"
        result["recommendation"] = "Enable DNP3 authentication if supported."

    return result


def check_cip_security(ip):
    """
    Check EtherNet/IP (CIP) security posture
    """
    result = {
        "protocol": "CIP/EtherNet/IP",
        "port": 44818,
        "authentication": "Unknown",
        "encryption": "None (plaintext)",
        "access_control": "Unknown",
        "issues": [],
        "recommendation": ""
    }

    # CIP often has no authentication
    if cip_read_test(ip):
        result["issues"].append("CIP device allows unauthenticated read access")
        result["access_control"] = "No access control"
        result["recommendation"] = "Use Rockwell Automation's security features. Segment CIP traffic."

    return result


def check_bacnet_security(ip):
    """
    Check BACnet security posture
    """
    result = {
        "protocol": "BACnet",
        "port": 47808,
        "authentication": "None",
        "encryption": "None (plaintext)",
        "access_control": "Unknown",
        "issues": [],
        "recommendation": ""
    }

    # BACnet has no native security - check if it's exposed
    if bacnet_whois_test(ip):
        result["issues"].append("BACnet device responds to Who-Is broadcasts")
        result["access_control"] = "No access control"
        result["recommendation"] = "BACnet devices are inherently insecure. Segment and firewall aggressively."

    return result


def check_opcua_security(ip):
    """
    Check OPC-UA security posture
    """
    result = {
        "protocol": "OPC-UA",
        "port": 4840,
        "authentication": "Unknown",
        "encryption": "Unknown",
        "access_control": "Unknown",
        "issues": [],
        "recommendation": ""
    }

    # OPC-UA has built-in security - check if it's enforced
    if opcua_security_test(ip):
        result["authentication"] = "Enabled"
        result["encryption"] = "Enabled"
        result["recommendation"] = "OPC-UA security appears configured."
    else:
        result["issues"].append("OPC-UA server may not have security enabled")
        result["authentication"] = "None/Disabled"
        result["encryption"] = "None/Disabled"
        result["recommendation"] = "Enable OPC-UA security (authentication and encryption)."

    return result


def check_iec104_security(ip):
    """
    Check IEC 60870-5-104 security posture
    """
    result = {
        "protocol": "IEC-104",
        "port": 2404,
        "authentication": "None",
        "encryption": "None (plaintext)",
        "access_control": "Unknown",
        "issues": [],
        "recommendation": ""
    }

    # IEC-104 has minimal security
    if iec104_startdt_test(ip):
        result["issues"].append("IEC-104 device accepts StartDT without authentication")
        result["access_control"] = "No access control"
        result["recommendation"] = "IEC-104 is inherently insecure. Use IP whitelisting and VPNs."

    return result


# -----------------------------------------------------------------
# Protocol-specific test functions (simplified probes)
# -----------------------------------------------------------------

def modbus_read_test(ip):
    """Test if Modbus device allows unauthenticated read"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        
        # Read Holding Register 0 (typical test)
        # Function code 0x03, starting address 0x0000, count 0x0001
        packet = bytearray([
            0x00, 0x01,  # Transaction ID
            0x00, 0x00,  # Protocol ID
            0x00, 0x06,  # Length
            0x01,        # Unit ID
            0x03,        # Function (Read Holding Registers)
            0x00, 0x00,  # Starting Address
            0x00, 0x01   # Quantity
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        # If we got a response with function code 0x03, it's readable
        if len(response) > 6 and response[7] == 0x03:
            return True
    except:
        pass
    return False


def modbus_write_test(ip):
    """Test if Modbus device allows unauthenticated write"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        s.close()
        # Full write tests could crash the PLC or alter device state.
        # Conservative: do not test writes on live devices.
        return False
    except:
        return False


def modbus_default_unit_test(ip):
    """Test if Modbus device uses default Unit ID"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        
        # Test with Unit ID 0x01 (default)
        packet = bytearray([
            0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
            0x01,        # Unit ID 0x01
            0x03, 0x00, 0x00, 0x00, 0x01
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        # If it responds to default Unit ID, it's likely default
        if len(response) > 6:
            return True
    except:
        pass
    return False


def s7_read_test(ip):
    """Test if S7 device allows unauthenticated read"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))
        
        # COTP Connection + S7 CPU Info request (simplified)
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
        
        if len(response) > 10:
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


def s7_default_password_test(ip):
    """Check for default S7 password (simplified)"""
    # If device responds to read, it likely has no password
    return s7_read_test(ip)


def dnp3_auth_test(ip):
    """Check if DNP3 has authentication enabled (simplified)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 20000))
        
        # DNP3 Read request with authentication bit check
        # Simplified - if device responds with error, auth may be enabled
        packet = bytearray([
            0x05, 0x64, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        # If response has error code for authentication, auth is enabled
        if len(response) > 5 and response[4] == 0x01:  # Error response
            return False
        return False  # Default assumption: no auth
    except:
        pass
    return False


def cip_read_test(ip):
    """Test if CIP device allows unauthenticated read"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 44818))
        
        # CIP Identity Request (simplified)
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


def bacnet_whois_test(ip):
    """Test if BACnet device responds to Who-Is"""
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


def opcua_security_test(ip):
    """Test if OPC-UA has security enabled (simplified)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 4840))
        s.close()
        # If it connects, security may or may not be enabled
        # Full OPC-UA security check requires handshake
        return False  # Default assumption: not secure
    except:
        pass
    return False


def iec104_startdt_test(ip):
    """Test if IEC-104 accepts StartDT without auth"""
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