import ssl
import socket
from datetime import datetime
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

# -----------------------------------------------------------------
# OT/ICS Protocol Encryption Check
# Merges ssl_check.py (certificate validation) and tls_check.py (TLS version/cipher)
# -----------------------------------------------------------------

def run_check(target_ip_or_url, target_port=None, protocol="auto"):
    """
    OT/ICS Encryption Check - Merged SSL/TLS Validation

    Can check:
    1. Web interfaces (HTTPS) - certificate expiry + TLS version/cipher
    2. OT/ICS devices with TLS support - certificate + TLS strength
    3. OT/ICS devices without TLS - reports lack of encryption

    Parallels ssl_check.py and tls_check.py merged into one
    """
    name = "OT/ICS Encryption and TLS Security Check"

    # Check if input is a URL (web interface)
    if target_ip_or_url.startswith(("http://", "https://")):
        return run_web_check(target_ip_or_url)
    else:
        return run_ot_check(target_ip_or_url, target_port, protocol)


def run_web_check(target_url):
    """
    Web interface encryption check
    Original ssl_check.py + tls_check.py merged for web interfaces
    """
    name = "Web Interface SSL/TLS Check"
    hostname = target_url.replace("https://", "").replace("http://", "").split("/")[0]
    port = 443

    if ":" in hostname:
        hostname, port_str = hostname.split(":", 1)
        port = int(port_str)

    results = []
    issues = []
    recommendation_parts = []

    try:
        # --- Part 1: Certificate Check (from ssl_check.py) ---
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

        # Certificate expiry
        expires = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days

        if days_left < 0:
            issues.append(f"Certificate expired {abs(days_left)} days ago")
            recommendation_parts.append("Renew the SSL certificate immediately")
        elif days_left < 30:
            issues.append(f"Certificate expires in {days_left} days")
            recommendation_parts.append("Renew the certificate soon")
        else:
            results.append(f"Certificate valid ({days_left} days remaining)")

        # --- Part 2: TLS Version Check (from tls_check.py) ---
        if tls_version in ("TLSv1.2", "TLSv1.3"):
            results.append(f"TLS version: {tls_version} (modern)")
        elif tls_version in ("TLSv1", "TLSv1.1"):
            issues.append(f"Outdated TLS version: {tls_version}")
            recommendation_parts.append("Disable TLS 1.0/1.1, enforce TLS 1.2+")
        elif tls_version is None:
            issues.append("Unable to determine TLS version")
            recommendation_parts.append("Check server TLS configuration")
        else:
            issues.append(f"Insecure protocol: {tls_version}")
            recommendation_parts.append("Disable legacy SSL/TLS versions, enforce TLS 1.2+")

        # --- Part 3: Cipher Check (from tls_check.py) ---
        cipher_name = cipher[0] if cipher else "Unknown"
        bits = cipher[2] if cipher else "Unknown"
        results.append(f"Cipher: {cipher_name} ({bits} bits)")

        # Check for weak ciphers
        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
        for weak in weak_ciphers:
            if weak in cipher_name:
                issues.append(f"Weak cipher detected: {cipher_name}")
                recommendation_parts.append("Disable weak ciphers (RC4, DES, 3DES, NULL)")
                break

        # --- Result logic ---
        details = " | ".join(results)

        if issues:
            return {
                "name": name,
                "status": "warn",
                "severity": "medium" if days_left > 0 else "high",
                "details": details + " | Issues: " + ", ".join(issues),
                "recommendation": (
                    "Encryption issues detected: " + ". ".join(recommendation_parts) + ". "
                    "Recommended configuration: TLS 1.2+ with strong ciphers, "
                    "certificate valid for >30 days."
                )
            }

        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": details,
            "recommendation": "SSL/TLS configuration appears secure."
        }

    except Exception as e:
        return {
            "name": name,
            "status": "error",
            "severity": "high",
            "details": str(e),
            "recommendation": "Unable to verify SSL/TLS configuration. Check server availability."
        }


def run_ot_check(target_ip, target_port=None, protocol="auto"):
    """
    OT/ICS device encryption check
    Checks for TLS/encryption support on OT protocols
    """
    name = "OT/ICS Device Encryption Check"

    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    results = []
    issues = []
    devices_found = 0

    for port in common_ports:
        result = check_ot_encryption(target_ip, port)
        if result:
            devices_found += 1
            results.append(result)

            if result.get('issues'):
                for issue in result['issues']:
                    issues.append(f"[{result['protocol']}] {issue}")

    # --- Result logic ---
    if not results:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No OT/ICS devices detected on common ports.",
            "recommendation": "No action needed."
        }

    details_parts = []
    for result in results:
        status_text = result.get('encryption_status', 'Unknown')
        if result.get('tls_version'):
            status_text += f" (TLS: {result['tls_version']})"
        details_parts.append(f"{result['protocol']}: {status_text}")

    details = " | ".join(details_parts)

    if issues:
        return {
            "name": name,
            "status": "warn",
            "severity": "high",  # Elevated for OT
            "details": details + " | Issues: " + ", ".join(issues),
            "recommendation": (
                "OT/ICS encryption gaps detected. "
                "For devices without TLS: implement network segmentation and VPNs. "
                "For devices with weak TLS: upgrade to TLS 1.2+. "
                "Consider using dedicated security gateways for legacy devices."
            )
        }

    return {
        "name": name,
        "status": "pass",
        "severity": "low",
        "details": details,
        "recommendation": "OT/ICS device encryption appears configured where available."
    }


def check_ot_encryption(ip, port):
    """
    Check if an OT/ICS device supports TLS/encryption
    """
    if port == 502:
        return check_modbus_encryption(ip)
    elif port == 102:
        return check_s7_encryption(ip)
    elif port == 20000:
        return check_dnp3_encryption(ip)
    elif port == 44818:
        return check_cip_encryption(ip)
    elif port == 47808:
        return check_bacnet_encryption(ip)
    elif port == 4840:
        return check_opcua_encryption(ip)
    elif port == 2404:
        return check_iec104_encryption(ip)
    else:
        return None


def check_modbus_encryption(ip):
    """
    Check Modbus encryption support
    Modbus/TLS (port 802) is the secure variant
    """
    if not _port_open(ip, 502):
        return None

    result = {
        "protocol": "Modbus",
        "port": 502,
        "encryption_status": "None",
        "tls_version": None,
        "issues": []
    }

    # Check if plaintext Modbus is open (port 502)
    if test_port(ip, 502):
        # Check if Modbus/TLS is available (port 802)
        tls_info = test_tls_port(ip, 802, check_cert=True)

        if tls_info:
            result["encryption_status"] = "Modbus/TLS available"
            if tls_info.get('tls_version'):
                result["tls_version"] = tls_info['tls_version']
            # Check if plaintext is still accepted
            if test_port(ip, 502):
                result["issues"].append("Plaintext Modbus still accepted (TLS available)")
        else:
            result["encryption_status"] = "Plaintext only"
            result["issues"].append("No TLS support (Modbus plaintext)")

    return result


def check_s7_encryption(ip):
    """
    Check Siemens S7 encryption support
    S7-1200/1500 support TLS on port 102
    """
    if not _port_open(ip, 102):
        return None

    result = {
        "protocol": "S7",
        "port": 102,
        "encryption_status": "None",
        "tls_version": None,
        "issues": []
    }

    # Check if plaintext S7 is open
    if test_port(ip, 102):
        # Check if TLS is supported on port 102
        tls_info = test_tls_port(ip, 102, check_cert=True)

        if tls_info:
            result["encryption_status"] = "TLS available"
            if tls_info.get('tls_version'):
                result["tls_version"] = tls_info['tls_version']
            # Check if plaintext is still accepted
            result["issues"].append("Plaintext S7 may be accepted (TLS available)")
        else:
            result["encryption_status"] = "Plaintext only"
            result["issues"].append("No TLS support (plaintext S7)")

    return result


def check_dnp3_encryption(ip):
    """
    Check DNP3 encryption support
    DNP3 has optional authentication but no native encryption
    """
    if not _port_open(ip, 20000):
        return None

    result = {
        "protocol": "DNP3",
        "port": 20000,
        "encryption_status": "None",
        "tls_version": None,
        "issues": []
    }

    if test_port(ip, 20000):
        # DNP3 has no native encryption
        result["encryption_status"] = "Plaintext only"
        result["issues"].append("No encryption in DNP3 (uses plaintext)")

    return result


def check_cip_encryption(ip):
    """
    Check CIP/EtherNet/IP encryption support
    CIP Security (CIP-S) is the secure variant
    """
    if not _port_open(ip, 44818):
        return None

    result = {
        "protocol": "CIP",
        "port": 44818,
        "encryption_status": "None",
        "tls_version": None,
        "issues": []
    }

    if test_port(ip, 44818):
        # CIP has limited encryption support
        result["encryption_status"] = "Plaintext only"
        result["issues"].append("No encryption in CIP (uses plaintext)")

    return result


def check_bacnet_encryption(ip):
    """
    Check BACnet encryption support
    BACnet/SC is the secure variant (TLS)
    """
    if not _port_open(ip, 47808, udp=True):
        return None

    result = {
        "protocol": "BACnet",
        "port": 47808,
        "encryption_status": "None",
        "tls_version": None,
        "issues": []
    }

    # BACnet is UDP-based
    if test_port(ip, 47808, udp=True):
        # Check if BACnet/SC (TLS) is available
        tls_info = test_tls_port(ip, 47808, check_cert=True)

        if tls_info:
            result["encryption_status"] = "BACnet/SC available"
            if tls_info.get('tls_version'):
                result["tls_version"] = tls_info['tls_version']
            result["issues"].append("Plaintext BACnet may be accepted")
        else:
            result["encryption_status"] = "Plaintext only"
            result["issues"].append("No encryption in BACnet (uses plaintext)")

    return result


def check_opcua_encryption(ip):
    """
    Check OPC-UA encryption support
    OPC-UA has built-in security with TLS
    """
    if not _port_open(ip, 4840):
        return None

    result = {
        "protocol": "OPC-UA",
        "port": 4840,
        "encryption_status": "None",
        "tls_version": None,
        "issues": []
    }

    if test_port(ip, 4840):
        # OPC-UA typically supports TLS
        tls_info = test_tls_port(ip, 4840, check_cert=True)

        if tls_info:
            result["encryption_status"] = "TLS available"
            if tls_info.get('tls_version'):
                result["tls_version"] = tls_info['tls_version']
            # Check if security is enforced (requires deeper inspection)
        else:
            result["encryption_status"] = "TLS not detected"
            result["issues"].append("OPC-UA security may be disabled")

    return result


def check_iec104_encryption(ip):
    """
    Check IEC 60870-5-104 encryption support
    No native encryption
    """
    if not _port_open(ip, 2404):
        return None

    result = {
        "protocol": "IEC-104",
        "port": 2404,
        "encryption_status": "None",
        "tls_version": None,
        "issues": []
    }

    if test_port(ip, 2404):
        # IEC-104 has no native encryption
        result["encryption_status"] = "Plaintext only"
        result["issues"].append("No encryption in IEC-104 (uses plaintext)")

    return result


# -----------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------

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


def test_tls_port(ip, port, timeout=2, check_cert=False):
    """
    Test if a port supports TLS and optionally check certificate
    Returns dict with TLS info or None
    """
    try:
        context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            tls_sock = context.wrap_socket(sock, server_hostname=ip)
            tls_sock.connect((ip, port))

            result = {
                'tls_version': tls_sock.version()
            }

            if check_cert:
                cert = tls_sock.getpeercert()
                if cert:
                    result['certificate'] = cert
                    expires = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    result['days_left'] = (expires - datetime.utcnow()).days

            tls_sock.close()
            return result

        except Exception:
            return None

    except:
        return None


def test_tls_port_old(ip, port, timeout=2):
    """Legacy TLS test - kept for compatibility"""
    try:
        import ssl
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname=ip)
        tls_sock.connect((ip, port))

        version = tls_sock.version()
        cipher = tls_sock.cipher()
        tls_sock.close()

        return {
            'tls_version': version,
            'cipher': cipher
        }
    except:
        return None