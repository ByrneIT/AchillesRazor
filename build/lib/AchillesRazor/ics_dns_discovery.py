import dns.resolver
import dns.reversename
import socket
import re

def run_check(target_ip_or_domain, network_context=None):
    """
    OT/ICS DNS Discovery and Exposure Check
    Parallels dns_check.py but for industrial device discovery via DNS
    """
    name = "OT/ICS DNS Discovery and Exposure Check"

    # If target is a domain (like google.com), resolve it
    if not is_ip_address(target_ip_or_domain):
        results = check_domain_dns(target_ip_or_domain)
        if results.get("status") == "error":
            return results
        
        # Add OT/ICS DNS discovery
        ot_results = check_ot_dns_discovery(target_ip_or_domain)
        if ot_results:
            results["details"] += " | " + ot_results["details"]
            if ot_results.get("devices_found"):
                results["ot_devices"] = ot_results["devices_found"]
                results["status"] = "warn"
                results["severity"] = "medium"
                results["recommendation"] = (
                    "OT/ICS devices discovered via DNS. Verify these are properly documented and segregated from IT networks. "
                    "Consider using DNS-based device discovery to build an asset inventory."
                )
        return results
    
    # If target is an IP, do reverse DNS and OT network discovery
    else:
        results = check_ip_dns(target_ip_or_domain)
        if results.get("status") == "error":
            return results
        
        # Add OT/ICS discovery based on network context
        ot_results = check_ot_network_discovery(target_ip_or_domain)
        if ot_results:
            results["details"] += " | " + ot_results["details"]
            if ot_results.get("devices_found"):
                results["ot_devices"] = ot_results["devices_found"]
                results["status"] = "warn"
                results["severity"] = "medium"
                results["recommendation"] = (
                    "OT/ICS devices discovered via DNS. Verify these are properly documented and segregated from IT networks."
                )
        return results


def is_ip_address(string):
    """Check if string is an IP address"""
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(pattern.match(string))


def check_domain_dns(domain):
    """Original DNS check but with expanded record types"""
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]
    
    results = {
        "name": "OT/ICS DNS Discovery",
        "details": [],
        "status": "pass",
        "severity": "low"
    }
    
    # --- Check A records (IPv4) ---
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        ips = [rdata.address for rdata in answers]
        results["details"].append(f"A Records: {', '.join(ips)}")
    except:
        pass
    
    # --- Check AAAA records (IPv6) ---
    try:
        answers = dns.resolver.resolve(hostname, 'AAAA')
        ips = [rdata.address for rdata in answers]
        results["details"].append(f"AAAA Records: {', '.join(ips)}")
    except:
        pass
    
    # --- Check TXT records (often contain device info) ---
    try:
        answers = dns.resolver.resolve(hostname, 'TXT')
        txts = [rdata.strings[0].decode() for rdata in answers if rdata.strings]
        if txts:
            results["details"].append(f"TXT Records: {', '.join(txts[:2])}")  # Limit to first 2
    except:
        pass
    
    # --- Check CNAME records (aliases, often reveal internal naming) ---
    try:
        answers = dns.resolver.resolve(hostname, 'CNAME')
        cnames = [str(rdata.target) for rdata in answers]
        results["details"].append(f"CNAME: {', '.join(cnames)}")
    except:
        pass
    
    # --- Check MX records (mail servers, often reveal internal network names) ---
    try:
        answers = dns.resolver.resolve(hostname, 'MX')
        mx_records = [f"{rdata.exchange} (priority {rdata.preference})" for rdata in answers]
        results["details"].append(f"MX Records: {', '.join(mx_records[:2])}")
    except:
        pass
    
    # --- Check NS records (name servers, reveal infrastructure) ---
    try:
        answers = dns.resolver.resolve(hostname, 'NS')
        ns_records = [str(rdata.target) for rdata in answers]
        results["details"].append(f"NS Records: {', '.join(ns_records)}")
    except:
        pass
    
    if results["details"]:
        results["details"] = " | ".join(results["details"])
        return results
    else:
        return {
            "name": name,
            "status": "error",
            "severity": "high",
            "details": f"No DNS records found for {hostname}",
            "recommendation": "DNS resolution failed. Check domain configuration."
        }


def check_ot_dns_discovery(domain):
    """
    Check for OT/ICS-specific DNS records
    This is where the real OT discovery happens
    """
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]
    devices_found = []
    details = []
    
    # --- Check for OPC-UA discovery via DNS SRV records ---
    # OPC-UA servers often register _opcua-tcp._tcp SRV records
    try:
        answers = dns.resolver.resolve(f"_opcua-tcp._tcp.{hostname}", 'SRV')
        for rdata in answers:
            devices_found.append(f"OPC-UA Server: {rdata.target}:{rdata.port}")
            details.append(f"OPC-UA SRV Record: {rdata.target} (port {rdata.port})")
    except:
        pass
    
    # --- Check for Siemens S7 discovery via DNS ---
    # Some Siemens systems register specific records
    try:
        # Try common Siemens naming patterns
        for prefix in ["s7", "plc", "cpu", "siemens"]:
            try:
                answers = dns.resolver.resolve(f"{prefix}.{hostname}", 'A')
                ips = [rdata.address for rdata in answers]
                for ip in ips:
                    devices_found.append(f"Siemens S7 Device: {prefix}.{hostname} ({ip})")
                    details.append(f"Siemens S7 A Record: {prefix}.{hostname} -> {ip}")
            except:
                pass
    except:
        pass
    
    # --- Check for Modbus TCP devices via DNS ---
    try:
        # Many Modbus devices register with specific naming conventions
        for prefix in ["modbus", "mb", "rtu", "plc"]:
            try:
                answers = dns.resolver.resolve(f"{prefix}.{hostname}", 'A')
                ips = [rdata.address for rdata in answers]
                for ip in ips:
                    devices_found.append(f"Modbus Device: {prefix}.{hostname} ({ip})")
                    details.append(f"Modbus A Record: {prefix}.{hostname} -> {ip}")
            except:
                pass
    except:
        pass
    
    # --- Check for common OT device naming conventions ---
    # This uses known naming patterns from OT environments
    ot_patterns = [
        "plc", "rtu", "hmi", "scada", "dcs", "controller",
        "pump", "valve", "sensor", "motor", "drive", "inverter",
        "generator", "turbine", "boiler", "chiller", "compressor",
        "analyzer", "meter", "gauge", "transmitter", "actuator"
    ]
    
    # Try to resolve common OT hostnames
    for pattern in ot_patterns:
        # Try pattern.xxx.local, pattern.xxx.plant, pattern.xxx.com
        for tld in [hostname, f"plant.{hostname}", f"local.{hostname}"]:
            try:
                answers = dns.resolver.resolve(f"{pattern}.{tld}", 'A')
                ips = [rdata.address for rdata in answers]
                for ip in ips:
                    devices_found.append(f"OT Device: {pattern}.{tld} ({ip})")
                    details.append(f"OT A Record: {pattern}.{tld} -> {ip}")
            except:
                pass
    
    # --- Check for DNS zone transfers (classic OT misconfiguration) ---
    # This attempts a zone transfer (AXFR) which is often misconfigured in OT networks
    try:
        ns_answers = dns.resolver.resolve(hostname, 'NS')
        for ns in ns_answers:
            ns_server = str(ns.target).rstrip('.')
            try:
                # Use dns.query to attempt zone transfer
                import dns.query
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, hostname))
                if zone:
                    devices_found.append(f"DNS Zone Transfer available on {ns_server}")
                    details.append(f"Zone Transfer: {hostname} -> {ns_server} (exposes full network)")
            except:
                pass
    except:
        pass
    
    # --- Check for reverse DNS (reveals hostnames of devices) ---
    # This is done in the IP-based function below
    
    if devices_found:
        return {
            "devices_found": devices_found,
            "details": "OT DNS Discovery: Found " + ", ".join(devices_found[:5]) + (" and more" if len(devices_found) > 5 else "")
        }
    return None


def check_ip_dns(ip):
    """
    Check reverse DNS for an IP address
    """
    try:
        # Convert IP to reverse DNS format
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        ptr_records = [str(rdata.target) for rdata in answers]
        
        return {
            "name": "IP DNS Resolution",
            "status": "pass",
            "severity": "low",
            "details": f"Reverse DNS: {', '.join(ptr_records)}",
            "recommendation": "No action needed."
        }
    except dns.resolver.NXDOMAIN:
        return {
            "name": "IP DNS Resolution",
            "status": "warn",
            "severity": "low",
            "details": f"No reverse DNS record for {ip}",
            "recommendation": "Consider adding reverse DNS for better asset management."
        }
    except Exception as e:
        return {
            "name": "IP DNS Resolution",
            "status": "error",
            "severity": "high",
            "details": str(e),
            "recommendation": "DNS resolution failed. Check DNS configuration."
        }


def check_ot_network_discovery(ip):
    """
    Check for OT devices in the same network via DNS
    """
    # If we have an IP, we can infer the network range and scan for devices via DNS
    # This attempts to resolve common OT hostnames with the given IP's subnet
    devices_found = []
    details = []
    
    # Extract subnet from IP (assuming /24)
    try:
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
        else:
            return None
    except:
        return None
    
    # Common OT naming conventions with this subnet
    ot_patterns = [
        "plc", "rtu", "hmi", "scada", "dcs",
        "pump", "valve", "sensor", "motor"
    ]
    
    for i in range(1, 20):  # Check .1 to .20 of the subnet
        for pattern in ot_patterns:
            try:
                # Try to resolve pattern-IP (e.g., plc-10, pump-5)
                hostname = f"{pattern}-{i}"
                # This would require network context to work properly
                # We'll use a broader approach instead
            except:
                pass
    
    # Since we can't actually query DNS for arbitrary hostnames without the domain,
    # this returns None to avoid false positives
    # The real value is in the domain-based discovery above
    
    return None