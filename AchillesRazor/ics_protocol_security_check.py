import socket
import struct
import time

def run_check(target_ip, target_port=None):
    """
    OT/ICS Protocol Security Fields Check
    Parallels headers_check.py but for industrial protocol security fields
    """
    name = "OT/ICS Protocol Security Check"

    # If no port provided, probe common ICS ports
    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    results = []
    devices_checked = 0

    for port in common_ports:
        result = check_protocol_security(target_ip, port)
        if result:
            devices_checked += 1
            results.append(result)

    # --- RESULT LOGIC (mirrors your headers logic) ---
    if not results:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    # Collect missing protocol security fields
    missing_fields = []
    for result in results:
        if result.get("missing_fields"):
            for field in result["missing_fields"]:
                missing_fields.append(f"[{result['protocol']}] {field}")

    # Collect weak protocol security fields
    weak_fields = []
    for result in results:
        if result.get("weak_fields"):
            for field in result["weak_fields"]:
                weak_fields.append(f"[{result['protocol']}] {field}")

    if missing_fields or weak_fields:
        details = []
        if missing_fields:
            details.append(f"Missing security fields: {', '.join(missing_fields)}")
        if weak_fields:
            details.append(f"Weak security fields: {', '.join(weak_fields)}")

        return {
            "name": name,
            "status": "warn",
            "severity": "medium",
            "details": " | ".join(details),
            "recommendation": (
                "Remediate protocol security gaps: Ensure authentication is enabled, "
                "use encrypted variants where available (Modbus/TLS, S7/TLS), "
                "restrict function codes, and enable access controls. "
                "Consider using network segmentation to compensate for protocol limitations."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": f"Checked {devices_checked} OT/ICS device(s). Protocol security fields appear adequate.",
        "recommendation": "No action needed. Continue to monitor protocol security posture."
    }


def check_protocol_security(ip, port):
    """
    Check security fields of a specific OT/ICS protocol
    Returns dict with findings or None
    """
    if port == 502:
        return check_modbus_security_fields(ip)
    elif port == 102:
        return check_s7_security_fields(ip)
    elif port == 20000:
        return check_dnp3_security_fields(ip)
    elif port == 44818:
        return check_cip_security_fields(ip)
    elif port == 47808:
        return check_bacnet_security_fields(ip)
    elif port == 4840:
        return check_opcua_security_fields(ip)
    elif port == 2404:
        return check_iec104_security_fields(ip)
    else:
        return None


def check_modbus_security_fields(ip):
    """
    Check Modbus protocol security fields
    Equivalent to checking HTTP security headers
    """
    result = {
        "protocol": "Modbus",
        "port": 502,
        "missing_fields": [],
        "weak_fields": []
    }

    # Connect to the device
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 502))

        # --- Check 1: Is authentication present? (like checking HSTS) ---
        # Modbus has no native authentication - this is always "missing"
        result["missing_fields"].append("Authentication (Modbus has no native auth)")

        # --- Check 2: Is encryption present? (like checking CSP) ---
        # Modbus has no native encryption - this is always "missing"
        result["missing_fields"].append("Encryption (Modbus is plaintext)")

        # --- Check 3: Is Unit ID default? (like checking X-Frame-Options) ---
        if has_modbus_default_unit_id(ip):
            result["weak_fields"].append("Default Unit ID (0x01)")

        # --- Check 4: Are writes protected? (like checking X-Content-Type-Options) ---
        if has_modbus_write_access(ip):
            result["weak_fields"].append("Write access unprotected")

        # --- Check 5: Is device identification restricted? (like checking Referrer-Policy) ---
        if has_modbus_device_id_exposed(ip):
            result["missing_fields"].append("Device ID exposed (no access control)")

        s.close()

        # If no issues found, mark it as "secure" (though Modbus is inherently insecure)
        if not result["missing_fields"] and not result["weak_fields"]:
            result["status"] = "pass"

    except:
        return None

    return result


def check_s7_security_fields(ip):
    """
    Check Siemens S7 protocol security fields
    """
    result = {
        "protocol": "S7",
        "port": 102,
        "missing_fields": [],
        "weak_fields": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 102))

        # --- Check 1: Is access protection enabled? (like HSTS) ---
        if has_s7_access_protection(ip):
            # Access protection present
            pass
        else:
            result["missing_fields"].append("Access protection (no password)")

        # --- Check 2: Is encryption used? (like CSP) ---
        # S7-1200/1500 support TLS - check if it's used
        if has_s7_encryption(ip):
            # Encryption present
            pass
        else:
            result["missing_fields"].append("Encryption (plaintext S7)")

        # --- Check 3: Is CPU info protected? (like X-Frame-Options) ---
        if has_s7_cpu_info_exposed(ip):
            result["weak_fields"].append("CPU information exposed")

        # --- Check 4: Are writes protected? (like X-Content-Type-Options) ---
        if has_s7_write_access(ip):
            result["weak_fields"].append("Write access unprotected")

        # --- Check 5: Is module info protected? (like Referrer-Policy) ---
        if has_s7_module_info_exposed(ip):
            result["weak_fields"].append("Module configuration exposed")

        s.close()

    except:
        return None

    return result


def check_dnp3_security_fields(ip):
    """
    Check DNP3 protocol security fields
    """
    result = {
        "protocol": "DNP3",
        "port": 20000,
        "missing_fields": [],
        "weak_fields": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 20000))

        # --- Check 1: Is authentication enabled? (like HSTS) ---
        if has_dnp3_auth(ip):
            # Authentication present
            pass
        else:
            result["missing_fields"].append("Authentication (DNP3 Secure Auth not enabled)")

        # --- Check 2: Is encryption used? (like CSP) ---
        # DNP3 has no native encryption
        result["missing_fields"].append("Encryption (DNP3 is plaintext)")

        # --- Check 3: Is device info protected? (like X-Frame-Options) ---
        if has_dnp3_device_info_exposed(ip):
            result["weak_fields"].append("Device information exposed")

        # --- Check 4: Are writes protected? (like X-Content-Type-Options) ---
        if has_dnp3_write_access(ip):
            result["weak_fields"].append("Write access unprotected")

        # --- Check 5: Are default addresses used? (like Referrer-Policy) ---
        if has_dnp3_default_addresses(ip):
            result["weak_fields"].append("Default DNP3 addresses")

        s.close()

    except:
        return None

    return result


def check_cip_security_fields(ip):
    """
    Check CIP/EtherNet/IP protocol security fields
    """
    result = {
        "protocol": "CIP",
        "port": 44818,
        "missing_fields": [],
        "weak_fields": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 44818))

        # --- Check 1: Is authentication enabled? (like HSTS) ---
        # CIP has no native authentication
        result["missing_fields"].append("Authentication (CIP has no native auth)")

        # --- Check 2: Is encryption used? (like CSP) ---
        # CIP has no native encryption
        result["missing_fields"].append("Encryption (CIP is plaintext)")

        # --- Check 3: Is device identity protected? (like X-Frame-Options) ---
        if has_cip_identity_exposed(ip):
            result["weak_fields"].append("Device identity exposed")

        # --- Check 4: Are writes protected? (like X-Content-Type-Options) ---
        if has_cip_write_access(ip):
            result["weak_fields"].append("Write access unprotected")

        # --- Check 5: Is default config used? (like Referrer-Policy) ---
        if has_cip_defaults(ip):
            result["weak_fields"].append("Default CIP configuration")

        s.close()

    except:
        return None

    return result


def check_bacnet_security_fields(ip):
    """
    Check BACnet protocol security fields
    """
    result = {
        "protocol": "BACnet",
        "port": 47808,
        "missing_fields": [],
        "weak_fields": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)

        # --- Check 1: Is authentication enabled? (like HSTS) ---
        # BACnet has no native authentication
        result["missing_fields"].append("Authentication (BACnet has no native auth)")

        # --- Check 2: Is encryption used? (like CSP) ---
        # BACnet has no native encryption
        result["missing_fields"].append("Encryption (BACnet is plaintext)")

        # --- Check 3: Is device info protected? (like X-Frame-Options) ---
        if has_bacnet_response(ip):
            result["weak_fields"].append("Device information exposed (Who-Is responses)")

        # --- Check 4: Is device object protected? (like X-Content-Type-Options) ---
        if has_bacnet_device_object_exposed(ip):
            result["weak_fields"].append("Device object configuration exposed")

        s.close()

    except:
        return None

    return result


def check_opcua_security_fields(ip):
    """
    Check OPC-UA protocol security fields
    """
    result = {
        "protocol": "OPC-UA",
        "port": 4840,
        "missing_fields": [],
        "weak_fields": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 4840))

        # --- Check 1: Is security enabled? (like HSTS) ---
        if has_opcua_security(ip):
            # Security present
            pass
        else:
            result["missing_fields"].append("Security (encryption/authentication not enforced)")

        # --- Check 2: Is anonymous access restricted? (like CSP) ---
        if has_opcua_anonymous_access(ip):
            result["weak_fields"].append("Anonymous access allowed")

        # --- Check 3: Is endpoints info protected? (like X-Frame-Options) ---
        if has_opcua_endpoints_exposed(ip):
            result["weak_fields"].append("Endpoint information exposed")

        # --- Check 4: Is signing required? (like X-Content-Type-Options) ---
        if has_opcua_signing_disabled(ip):
            result["missing_fields"].append("Message signing disabled")

        s.close()

    except:
        return None

    return result


def check_iec104_security_fields(ip):
    """
    Check IEC 60870-5-104 protocol security fields
    """
    result = {
        "protocol": "IEC-104",
        "port": 2404,
        "missing_fields": [],
        "weak_fields": []
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 2404))

        # --- Check 1: Is authentication enabled? (like HSTS) ---
        # IEC-104 has no native authentication
        result["missing_fields"].append("Authentication (IEC-104 has no native auth)")

        # --- Check 2: Is encryption used? (like CSP) ---
        # IEC-104 has no native encryption
        result["missing_fields"].append("Encryption (IEC-104 is plaintext)")

        # --- Check 3: Is access protected? (like X-Frame-Options) ---
        if has_iec104_access(ip):
            result["weak_fields"].append("Access not restricted (StartDT accepted)")

        # --- Check 4: Are writes protected? (like X-Content-Type-Options) ---
        if has_iec104_write_access(ip):
            result["weak_fields"].append("Write access unprotected")

        s.close()

    except:
        return None

    return result


# -----------------------------------------------------------------
# Protocol-specific test functions (reused from other files)
# -----------------------------------------------------------------

# These functions are reused from the other mutated files
# For brevity, I'm referencing them here - they are already defined

def has_modbus_default_unit_id(ip):
    from ics_exposure_check import has_modbus_default_unit_id
    return has_modbus_default_unit_id(ip)

def has_modbus_write_access(ip):
    try:
        from AchillesRazor.ics_exposure_check import has_modbus_write_access
    except ImportError:
        from ics_exposure_check import has_modbus_write_access
    return has_modbus_write_access(ip)

def has_modbus_device_id_exposed(ip):
    from ics_exposure_check import has_modbus_device_id_exposed
    return has_modbus_device_id_exposed(ip)

def has_s7_access_protection(ip):
    from ics_policy_check import has_s7_access_protection
    return has_s7_access_protection(ip)

def has_s7_encryption(ip):
    # Simplified: check if S7 uses TLS on port 102 (TLS is rare)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 102))
        s.close()
        # If it connects on port 102, it's likely plaintext S7
        return False
    except:
        return True

def has_s7_cpu_info_exposed(ip):
    from ics_exposure_check import has_s7_cpu_info_exposed
    return has_s7_cpu_info_exposed(ip)

def has_s7_write_access(ip):
    from ics_exposure_check import has_s7_write_access
    return has_s7_write_access(ip)

def has_s7_module_info_exposed(ip):
    from ics_exposure_check import has_s7_module_info_exposed
    return has_s7_module_info_exposed(ip)

def has_dnp3_auth(ip):
    from ics_policy_check import has_dnp3_auth
    return has_dnp3_auth(ip)

def has_dnp3_device_info_exposed(ip):
    from ics_exposure_check import has_dnp3_device_info_exposed
    return has_dnp3_device_info_exposed(ip)

def has_dnp3_write_access(ip):
    from ics_exposure_check import has_dnp3_write_access
    return has_dnp3_write_access(ip)

def has_dnp3_default_addresses(ip):
    from ics_exposure_check import has_dnp3_default_addresses
    return has_dnp3_default_addresses(ip)

def has_cip_identity_exposed(ip):
    from ics_exposure_check import has_cip_identity_exposed
    return has_cip_identity_exposed(ip)

def has_cip_write_access(ip):
    from ics_exposure_check import has_cip_write_access
    return has_cip_write_access(ip)

def has_cip_defaults(ip):
    from ics_exposure_check import has_cip_defaults
    return has_cip_defaults(ip)

def has_bacnet_response(ip):
    from ics_exposure_check import has_bacnet_response
    return has_bacnet_response(ip)

def has_bacnet_device_object_exposed(ip):
    from ics_exposure_check import has_bacnet_device_object_exposed
    return has_bacnet_device_object_exposed(ip)

def has_opcua_security(ip):
    from ics_policy_check import has_opcua_security
    return has_opcua_security(ip)

def has_opcua_anonymous_access(ip):
    from ics_exposure_check import has_opcua_anonymous_access
    return has_opcua_anonymous_access(ip)

def has_opcua_endpoints_exposed(ip):
    from ics_exposure_check import has_opcua_endpoints_exposed
    return has_opcua_endpoints_exposed(ip)

def has_opcua_signing_disabled(ip):
    # Simplified: if security is disabled, signing is also disabled
    return not has_opcua_security(ip)

def has_iec104_access(ip):
    from ics_policy_check import has_iec104_access
    return has_iec104_access(ip)

def has_iec104_write_access(ip):
    from ics_exposure_check import has_iec104_write_access
    return has_iec104_write_access(ip)

def check_s7_access_protection(ip):
    from ics_policy_check import check_s7_policy
    result = check_s7_policy(ip)
    return result.get("auth_type") == "Access Protection Enabled"