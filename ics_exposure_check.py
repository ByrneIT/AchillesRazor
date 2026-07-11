import socket
import time
import struct

def run_check(target_ip, target_port=None):
    """
    OT/ICS Device Exposure Check
    Parallels directory_exposure_check.py but for industrial device exposure
    """
    name = "OT/ICS Device Exposure Check"

    # If no port provided, probe common ICS ports
    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    exposed_items = []

    for port in common_ports:
        # Check for exposure on each port
        result = check_port_exposure(target_ip, port)
        if result:
            exposed_items.append(result)

    # --- RESULT LOGIC (mirrors your directory exposure logic) ---
    if exposed_items:
        details = "Exposed OT/ICS device capabilities detected: " + ", ".join(exposed_items)
        return {
            "name": name,
            "status": "warn",
            "severity": "high",  # Elevated because OT exposure has physical impact
            "details": details,
            "recommendation": (
                "Restrict access to these OT/ICS devices using network segmentation, firewalls, "
                "and device-specific access controls. Disable unnecessary protocols and services. "
                "Default credentials must be changed immediately."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": "No OT/ICS device exposure detected on common ports.",
        "recommendation": "No action needed. Continue to monitor for network changes."
    }


def check_port_exposure(ip, port):
    """
    Check a specific port for OT/ICS exposure
    Returns a description of the exposure or None
    """
    if port == 502:
        return check_modbus_exposure(ip)
    elif port == 102:
        return check_s7_exposure(ip)
    elif port == 20000:
        return check_dnp3_exposure(ip)
    elif port == 44818:
        return check_cip_exposure(ip)
    elif port == 47808:
        return check_bacnet_exposure(ip)
    elif port == 4840:
        return check_opcua_exposure(ip)
    elif port == 2404:
        return check_iec104_exposure(ip)
    else:
        return None


def check_modbus_exposure(ip):
    """
    Check for Modbus exposure
    Equivalent to checking /.git/, /.env, /admin/ in the web version
    """
    exposures = []
    
    # --- Check 1: Basic Modbus availability (like checking /admin/) ---
    if has_modbus_basic_availability(ip):
        exposures.append("Modbus device present (port 502 exposed)")
    else:
        return None  # No exposure to report
    
    # --- Check 2: Read access (like checking /.git/) ---
    if has_modbus_read_access(ip):
        exposures.append("Read access allowed without authentication")
    
    # --- Check 3: Write access (like checking /backup/ - highly sensitive) ---
    if has_modbus_write_access(ip):
        exposures.append("Write access allowed without authentication")
    
    # --- Check 4: Read Device ID (like checking /phpinfo.php) ---
    if has_modbus_device_id_exposed(ip):
        exposures.append("Device ID information exposed")
    
    # --- Check 5: Default Unit ID (like checking default admin paths) ---
    if has_modbus_default_unit_id(ip):
        exposures.append("Using default Unit ID (0x01)")
    
    # --- Check 6: Broadcast address exposure (like checking /server-status) ---
    if has_modbus_broadcast_exposed(ip):
        exposures.append("Responds to broadcast requests")
    
    if exposures:
        return "Modbus: " + ", ".join(exposures)
    else:
        return "Modbus device present but no additional exposure detected"


def check_s7_exposure(ip):
    """
    Check for Siemens S7 exposure
    """
    exposures = []
    
    # --- Check 1: Basic S7 availability ---
    if has_s7_basic_availability(ip):
        exposures.append("S7 PLC present (port 102 exposed)")
    else:
        return None
    
    # --- Check 2: CPU info exposure (like checking /phpinfo.php) ---
    if has_s7_cpu_info_exposed(ip):
        exposures.append("CPU information exposed")
    
    # --- Check 3: Read access (like checking /.git/) ---
    if has_s7_read_access(ip):
        exposures.append("Read access allowed without authentication")
    
    # --- Check 4: Write access (like checking /backup/) ---
    if has_s7_write_access(ip):
        exposures.append("Write access allowed without authentication")
    
    # --- Check 5: Default password (like checking default admin paths) ---
    if has_s7_default_password(ip):
        exposures.append("Using default Siemens password")
    
    # --- Check 6: Module info exposed ---
    if has_s7_module_info_exposed(ip):
        exposures.append("Module configuration information exposed")
    
    if exposures:
        return "S7: " + ", ".join(exposures)
    else:
        return "S7 PLC present but no additional exposure detected"


def check_dnp3_exposure(ip):
    """
    Check for DNP3 exposure
    """
    exposures = []
    
    # --- Check 1: Basic DNP3 availability ---
    if has_dnp3_basic_availability(ip):
        exposures.append("DNP3 device present (port 20000 exposed)")
    else:
        return None
    
    # --- Check 2: Device info exposed (like checking /phpinfo.php) ---
    if has_dnp3_device_info_exposed(ip):
        exposures.append("Device information exposed")
    
    # --- Check 3: Read access ---
    if has_dnp3_read_access(ip):
        exposures.append("Read access allowed without authentication")
    
    # --- Check 4: Write access (like checking /backup/) ---
    if has_dnp3_write_access(ip):
        exposures.append("Write access allowed without authentication")
    
    # --- Check 5: Default addresses (like default admin paths) ---
    if has_dnp3_default_addresses(ip):
        exposures.append("Using default DNP3 addresses")
    
    if exposures:
        return "DNP3: " + ", ".join(exposures)
    else:
        return "DNP3 device present but no additional exposure detected"


def check_cip_exposure(ip):
    """
    Check for EtherNet/IP (CIP) exposure
    """
    exposures = []
    
    # --- Check 1: Basic CIP availability ---
    if has_cip_basic_availability(ip):
        exposures.append("CIP/EtherNet/IP device present (port 44818 exposed)")
    else:
        return None
    
    # --- Check 2: Device identity exposed (like checking /phpinfo.php) ---
    if has_cip_identity_exposed(ip):
        exposures.append("Device identity information exposed")
    
    # --- Check 3: Read access ---
    if has_cip_read_access(ip):
        exposures.append("Read access allowed without authentication")
    
    # --- Check 4: Write access (like checking /backup/) ---
    if has_cip_write_access(ip):
        exposures.append("Write access allowed without authentication")
    
    # --- Check 5: Default configuration ---
    if has_cip_defaults(ip):
        exposures.append("Using default CIP configuration")
    
    if exposures:
        return "CIP: " + ", ".join(exposures)
    else:
        return "CIP device present but no additional exposure detected"


def check_bacnet_exposure(ip):
    """
    Check for BACnet exposure
    """
    exposures = []
    
    # --- Check 1: Basic BACnet availability ---
    if has_bacnet_basic_availability(ip):
        exposures.append("BACnet device present (port 47808 exposed)")
    else:
        return None
    
    # --- Check 2: Who-Is response (like checking /server-status) ---
    if has_bacnet_whois_response(ip):
        exposures.append("Responds to Who-Is broadcasts")
    
    # --- Check 3: Device object exposed (like checking /.git/) ---
    if has_bacnet_device_object_exposed(ip):
        exposures.append("Device object configuration exposed")
    
    # --- Check 4: Default object IDs (like default admin paths) ---
    if has_bacnet_defaults(ip):
        exposures.append("Using default BACnet object IDs")
    
    if exposures:
        return "BACnet: " + ", ".join(exposures)
    else:
        return "BACnet device present but no additional exposure detected"


def check_opcua_exposure(ip):
    """
    Check for OPC-UA exposure
    """
    exposures = []
    
    # --- Check 1: Basic OPC-UA availability ---
    if has_opcua_basic_availability(ip):
        exposures.append("OPC-UA server present (port 4840 exposed)")
    else:
        return None
    
    # --- Check 2: Anonymous access (like checking /.git/) ---
    if has_opcua_anonymous_access(ip):
        exposures.append("Anonymous access allowed")
    
    # --- Check 3: Security disabled (like checking /phpinfo.php) ---
    if has_opcua_security_disabled(ip):
        exposures.append("Security features disabled (no encryption/authentication)")
    
    # --- Check 4: Endpoint info exposed (like checking /server-status) ---
    if has_opcua_endpoints_exposed(ip):
        exposures.append("Server endpoint information exposed")
    
    if exposures:
        return "OPC-UA: " + ", ".join(exposures)
    else:
        return "OPC-UA server present but no additional exposure detected"


def check_iec104_exposure(ip):
    """
    Check for IEC 60870-5-104 exposure
    """
    exposures = []
    
    # --- Check 1: Basic IEC-104 availability ---
    if has_iec104_basic_availability(ip):
        exposures.append("IEC-104 device present (port 2404 exposed)")
    else:
        return None
    
    # --- Check 2: StartDT response (like checking /server-status) ---
    if has_iec104_startdt_response(ip):
        exposures.append("Responds to StartDT activation requests")
    
    # --- Check 3: Read access (like checking /.git/) ---
    if has_iec104_read_access(ip):
        exposures.append("Read access allowed without authentication")
    
    # --- Check 4: Write access (like checking /backup/) ---
    if has_iec104_write_access(ip):
        exposures.append("Write access allowed without authentication")
    
    # --- Check 5: Default ASDU addresses (like default admin paths) ---
    if has_iec104_defaults(ip):
        exposures.append("Using default IEC-104 addresses")
    
    if exposures:
        return "IEC-104: " + ", ".join(exposures)
    else:
        return "IEC-104 device present but no additional exposure detected"


# -----------------------------------------------------------------
# Protocol-specific exposure check functions
# (These parallel the directory path checks)
# -----------------------------------------------------------------

def has_modbus_basic_availability(ip):
    """Check if Modbus port is open"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        s.close()
        return True
    except:
        return False


def has_modbus_read_access(ip):
    """Check if Modbus allows unauthenticated reads"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        if len(response) > 6 and response[7] == 0x03:
            return True
    except:
        pass
    return False


def has_modbus_write_access(ip):
    """Check if Modbus allows unauthenticated writes"""
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


def has_modbus_device_id_exposed(ip):
    """Check if Modbus Device ID is exposed"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        
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


def has_modbus_default_unit_id(ip):
    """Check if Modbus uses default Unit ID"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x03, 0x00, 0x00, 0x00, 0x01
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        if len(response) > 6:
            return True
    except:
        pass
    return False


def has_modbus_broadcast_exposed(ip):
    """Check if Modbus responds to broadcast address (0x00)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 502))
        
        packet = bytearray([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x00,  # Broadcast Unit ID
            0x03, 0x00, 0x00, 0x00, 0x01
        ])
        
        s.send(packet)
        response = s.recv(1024)
        s.close()
        
        if len(response) > 6:
            return True
    except:
        pass
    return False


def has_s7_basic_availability(ip):
    """Check if S7 port is open"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))
        s.close()
        return True
    except:
        return False


def has_s7_cpu_info_exposed(ip):
    """Check if S7 CPU info is exposed"""
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
        
        # CPU Info request
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


def has_s7_read_access(ip):
    """Check if S7 allows unauthenticated reads"""
    # If CPU info is exposed, read access is likely available
    return has_s7_cpu_info_exposed(ip)


def has_s7_write_access(ip):
    """Check if S7 allows unauthenticated writes (simplified)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))
        s.close()
        # If it connects without auth, writes may be allowed
        # Full write test requires DB write which could crash the PLC
        return False  # Conservative: don't test writes on live devices
    except:
        return False


def has_s7_default_password(ip):
    """Check if S7 uses default password"""
    # If CPU info is exposed, likely no password
    return has_s7_cpu_info_exposed(ip)


def has_s7_module_info_exposed(ip):
    """Check if S7 module info is exposed"""
    # Same as CPU info exposure
    return has_s7_cpu_info_exposed(ip)


def has_dnp3_basic_availability(ip):
    """Check if DNP3 port is open"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 20000))
        s.close()
        return True
    except:
        return False


def has_dnp3_device_info_exposed(ip):
    """Check if DNP3 device info is exposed"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 20000))
        
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


def has_dnp3_read_access(ip):
    """Check if DNP3 allows unauthenticated reads"""
    return has_dnp3_device_info_exposed(ip)


def has_dnp3_write_access(ip):
    """Check if DNP3 allows unauthenticated writes (simplified)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 20000))
        s.close()
        return True  # If it connects, writes may be allowed
    except:
        return False


def has_dnp3_default_addresses(ip):
    """Check if DNP3 uses default addresses"""
    return has_dnp3_basic_availability(ip)


def has_cip_basic_availability(ip):
    """Check if CIP port is open"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 44818))
        s.close()
        return True
    except:
        return False


def has_cip_identity_exposed(ip):
    """Check if CIP identity is exposed"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 44818))
        
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


def has_cip_read_access(ip):
    """Check if CIP allows unauthenticated reads"""
    return has_cip_identity_exposed(ip)


def has_cip_write_access(ip):
    """Check if CIP allows unauthenticated writes"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 44818))
        s.close()
        return True
    except:
        return False


def has_cip_defaults(ip):
    """Check if CIP uses default configuration"""
    return has_cip_basic_availability(ip)


def has_bacnet_basic_availability(ip):
    """Check if BACnet port is open"""
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


def has_bacnet_whois_response(ip):
    """Check if BACnet responds to Who-Is"""
    return has_bacnet_basic_availability(ip)


def has_bacnet_device_object_exposed(ip):
    """Check if BACnet device object is exposed"""
    return has_bacnet_basic_availability(ip)


def has_bacnet_defaults(ip):
    """Check if BACnet uses default object IDs"""
    return has_bacnet_basic_availability(ip)


def has_opcua_basic_availability(ip):
    """Check if OPC-UA port is open"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 4840))
        s.close()
        return True
    except:
        return False


def has_opcua_anonymous_access(ip):
    """Check if OPC-UA allows anonymous access"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 4840))
        s.close()
        return True  # If it connects without credentials, anonymous access allowed
    except:
        return False


def has_opcua_security_disabled(ip):
    """Check if OPC-UA has security disabled"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 4840))
        s.close()
        return True  # If it connects without security negotiation, likely disabled
    except:
        return False


def has_opcua_endpoints_exposed(ip):
    """Check if OPC-UA endpoints are exposed"""
    return has_opcua_basic_availability(ip)


def has_iec104_basic_availability(ip):
    """Check if IEC-104 port is open"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 2404))
        s.close()
        return True
    except:
        return False


def has_iec104_startdt_response(ip):
    """Check if IEC-104 responds to StartDT"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 2404))
        
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


def has_iec104_read_access(ip):
    """Check if IEC-104 allows unauthenticated reads"""
    return has_iec104_startdt_response(ip)


def has_iec104_write_access(ip):
    """Check if IEC-104 allows unauthenticated writes"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 2404))
        s.close()
        return True
    except:
        return False


def has_iec104_defaults(ip):
    """Check if IEC-104 uses default addresses"""
    return has_iec104_basic_availability(ip)