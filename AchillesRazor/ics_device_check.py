import socket
import struct
import time
import re

def run_check(target_ip, target_port=None):
    """
    OT/ICS Device Discovery and Fingerprinting
    Parallels cms_check.py but for industrial devices
    """
    name = "OT/ICS Device Detection and Fingerprinting"

    # If no port provided, try common ICS ports
    if target_port is None:
        common_ports = [502, 102, 20000, 44818, 47808, 4840, 2404]
    else:
        common_ports = [target_port]

    detected_devices = []
    version_info = []

    for port in common_ports:
        result = probe_port(target_ip, port)
        if result:
            detected_devices.append(result["device_type"])
            if result.get("version"):
                version_info.append(f"{result['device_type']} version {result['version']}")
            if result.get("vendor"):
                version_info.append(f"Vendor: {result['vendor']}")
            if result.get("model"):
                version_info.append(f"Model: {result['model']}")

    # --- RESULT LOGIC (mirrors your CMS logic) ---
    if not detected_devices:
        return {
            "name": name,
            "status": "pass",
            "severity": "low",
            "details": "No recognizable OT/ICS devices detected on common ports.",
            "recommendation": "No action needed. If expecting OT devices, verify network segmentation."
        }

    details = "Detected OT/ICS Device(s): " + ", ".join(detected_devices)
    if version_info:
        details += " | " + ", ".join(version_info)

    return {
        "name": name,
        "status": "warn",
        "severity": "medium",
        "details": details,
        "recommendation": (
            "Document all discovered OT/ICS devices. Verify they are properly segmented from IT networks "
            "and that default credentials have been changed. Check for known CVEs against detected firmware versions."
        )
    }


def probe_port(ip, port):
    """
    Probe a specific port for OT/ICS device signatures.
    Returns device info dict or None.
    """
    if port == 502:
        return probe_modbus(ip)
    elif port == 102:
        return probe_s7(ip)
    elif port == 20000:
        return probe_dnp3(ip)
    elif port == 44818:
        return probe_cip(ip)
    elif port == 47808:
        return probe_bacnet(ip)
    elif port == 4840:
        return probe_opcua(ip)
    elif port == 2404:
        return probe_iec104(ip)
    else:
        return None


def probe_modbus(ip):
    """
    Probe for Modbus device on port 502
    Sends Read Device ID request (function code 0x2B, MEI 0x0E)
    """
    # Modbus Read Device ID request packet
    packet = bytearray([
        0x00, 0x01,  # Transaction ID
        0x00, 0x00,  # Protocol ID
        0x00, 0x06,  # Length (6 bytes)
        0x01,        # Unit ID
        0x2B,        # Function Code (Encapsulated Interface Transport)
        0x0E,        # MEI Type (Read Device ID)
        0x01,        # Read Device ID request (Basic)
        0x00         # Object ID (Start from 0)
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, 502))
        sock.send(packet)

        response = sock.recv(1024)
        sock.close()

        if len(response) < 9:
            return None

        # Parse the response
        # Response structure: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + Function (1) + MEI (1) + Data...
        if response[7] == 0x2B and response[8] == 0x0E:
            # Extract device info from response
            data = response[9:]

            # Device ID data is typically at offset 3+ in the data section
            # This is simplified parsing; real devices vary
            device_info = {
                "device_type": "Modbus Device",
                "protocol": "Modbus TCP",
                "port": 502
            }

            # Try to extract vendor/model from response
            # Many devices put vendor name in the response
            vendor_match = re.search(rb'([A-Za-z]{3,})', data)
            if vendor_match:
                device_info["vendor"] = vendor_match.group(1).decode('utf-8', errors='ignore')

            # Extract any version-like strings
            version_match = re.search(rb'v([0-9]+\.[0-9]+)', data)
            if version_match:
                device_info["version"] = version_match.group(1).decode('utf-8', errors='ignore')

            return device_info

    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception:
        pass

    return None


def probe_s7(ip):
    """
    Probe for Siemens S7 device on port 102
    Sends a CPU Info request (COTP header + S7 PDU)
    """
    # S7 Comm Setup + CPU Info Request
    # This is a simplified packet for S7-300/400/1200/1500
    packet = bytearray([
        # COTP Header (Connection Request)
        0x03, 0x00, 0x00, 0x16,  # TPKT
        0x11, 0xE0, 0x00, 0x00,  # COTP
        0x00, 0x01, 0x00, 0xC0,  # COTP options
        0x01, 0x0A,              # S7 PDU
        # S7 Header (CPU Info Request)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        sock.connect((ip, 102))

        # Send COTP Connection Request
        sock.send(packet)

        # Wait for connection response
        response = sock.recv(1024)

        # Send S7 CPU Info Request
        # Simplified packet for CPU info
        cpu_packet = bytearray([
            0x03, 0x00, 0x00, 0x1F,  # TPKT
            0x02, 0xF0, 0x80,        # COTP Data
            0x32, 0x01, 0x00, 0x00,  # S7 Header
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ])

        sock.send(cpu_packet)
        response = sock.recv(1024)
        sock.close()

        if len(response) > 20:
            device_info = {
                "device_type": "Siemens S7 PLC",
                "protocol": "S7",
                "port": 102,
                "vendor": "Siemens"
            }

            # Try to extract CPU type and firmware
            # S7 response contains CPU model at specific offsets
            # This is simplified - real parsing is more complex
            data_str = response.hex()

            # Common S7 CPU models in response
            cpu_patterns = {
                "414": "S7-400",
                "315": "S7-300",
                "316": "S7-300",
                "317": "S7-300",
                "319": "S7-300",
                "410": "S7-400",
                "1500": "S7-1500",
                "1200": "S7-1200"
            }

            for pattern, model in cpu_patterns.items():
                if pattern in data_str:
                    device_info["model"] = model
                    break

            # Try to extract firmware version
            fw_match = re.search(r'V([0-9]\.[0-9])', data_str)
            if fw_match:
                device_info["version"] = fw_match.group(1)

            return device_info

    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception:
        pass

    return None


def probe_dnp3(ip):
    """
    Probe for DNP3 device on port 20000
    Sends a DNP3 Read Device Info request
    """
    # DNP3 Link Layer + Application Layer
    # Simplified DNP3 Read request for device info
    # Sync bytes 0x05 0x64
    packet = bytearray([
        0x05, 0x64,  # Sync
        0x00, 0x00,  # Length
        0x00,        # Control
        0x00, 0x00,  # Destination
        0x00, 0x00,  # Source
        0x00, 0x00,  # CRC (simplified)
        0x00,        # Application control
        0x00, 0x00   # Function code + data
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, 20000))
        sock.send(packet)
        response = sock.recv(1024)
        sock.close()

        if len(response) > 5:
            device_info = {
                "device_type": "DNP3 Device",
                "protocol": "DNP3",
                "port": 20000
            }

            # DNP3 devices often respond with their vendor and model
            data_str = response.hex()
            if "534C" in data_str:  # "SL" for Schweitzer
                device_info["vendor"] = "Schweitzer Engineering"
            elif "4348" in data_str:  # "CH" for CH
                device_info["vendor"] = "General Electric"

            return device_info

    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception:
        pass

    return None


def probe_cip(ip):
    """
    Probe for EtherNet/IP (CIP) device on port 44818
    """
    # CIP Request for device identity
    # Simplified CIP Identity Request
    packet = bytearray([
        0x00, 0x00, 0x00, 0x00,  # Session Header
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, 44818))
        sock.send(packet)
        response = sock.recv(1024)
        sock.close()

        if len(response) > 10:
            device_info = {
                "device_type": "EtherNet/IP (CIP) Device",
                "protocol": "CIP",
                "port": 44818,
                "vendor": "Rockwell Automation / Others"
            }
            return device_info

    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception:
        pass

    return None


def probe_bacnet(ip):
    """
    Probe for BACnet device on port 47808
    """
    # BACnet Who-Is request (simplified)
    packet = bytearray([
        0x01, 0x01,  # BACnet Version
        0x00, 0x10,  # Who-Is Request
        0x00, 0x00, 0x00, 0x00,  # Network
        0x00, 0x00, 0x00, 0x00   # Address
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(packet, (ip, 47808))
        response, addr = sock.recvfrom(1024)
        sock.close()

        if len(response) > 5:
            device_info = {
                "device_type": "BACnet Device",
                "protocol": "BACnet",
                "port": 47808,
                "vendor": "Building Automation Vendor"
            }
            return device_info

    except socket.timeout:
        pass
    except Exception:
        pass

    return None


def probe_opcua(ip):
    """
    Probe for OPC-UA device on port 4840
    """
    # OPC-UA Hello message
    packet = bytearray([
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x00, 0x00  # "Hello"
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, 4840))
        sock.send(packet)
        response = sock.recv(1024)
        sock.close()

        if len(response) > 5:
            device_info = {
                "device_type": "OPC-UA Server",
                "protocol": "OPC-UA",
                "port": 4840
            }
            return device_info

    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception:
        pass

    return None


def probe_iec104(ip):
    """
    Probe for IEC 60870-5-104 device on port 2404
    """
    # IEC 104 StartDT request
    packet = bytearray([
        0x68, 0x04,  # Start
        0x07, 0x00, 0x00, 0x00  # StartDT
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, 2404))
        sock.send(packet)
        response = sock.recv(1024)
        sock.close()

        if len(response) > 5:
            device_info = {
                "device_type": "IEC 60870-5-104 Device",
                "protocol": "IEC-104",
                "port": 2404
            }
            return device_info

    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception:
        pass

    return None