"""
ICS Security Scanner - A comprehensive OT/ICS security assessment suite
"""

__version__ = "1.0.0"
__author__ = "Your Name"

from .ics_device_check import run_check as device_check
from .ics_security_check import run_check as security_check
from .ics_policy_check import run_check as policy_check
from .ics_exposure_check import run_check as exposure_check
from .ics_dns_discovery import run_check as dns_discovery
from .ics_dns_security_check import run_check as dns_security
from .ics_protocol_security_check import run_check as protocol_security
from .ics_protocol_enforcement_check import run_check as protocol_enforcement
from .ics_redirect_chain_check import run_check as redirect_chain
from .ics_encryption_check import run_check as encryption_check
from .ics_discovery_probe_check import run_check as discovery_probe
from .ics_mixed_mode_check import run_check as mixed_mode
from .ics_function_permission_check import run_check as function_permission
from .ics_source_restriction_check import run_check as source_restriction
from .ics_protocol_type_enforcement import run_check as protocol_type_enforcement
from .ics_interface_access_control import run_check as interface_access_control

# All available checks
ALL_CHECKS = {
    "device": device_check,
    "security": security_check,
    "policy": policy_check,
    "exposure": exposure_check,
    "dns_discovery": dns_discovery,
    "dns_security": dns_security,
    "protocol_security": protocol_security,
    "protocol_enforcement": protocol_enforcement,
    "redirect_chain": redirect_chain,
    "encryption": encryption_check,
    "discovery_probe": discovery_probe,
    "mixed_mode": mixed_mode,
    "function_permission": function_permission,
    "source_restriction": source_restriction,
    "protocol_type_enforcement": protocol_type_enforcement,
    "interface_access": interface_access_control,
}

__all__ = [
    "device_check",
    "security_check",
    "policy_check",
    "exposure_check",
    "dns_discovery",
    "dns_security",
    "protocol_security",
    "protocol_enforcement",
    "redirect_chain",
    "encryption_check",
    "discovery_probe",
    "mixed_mode",
    "function_permission",
    "source_restriction",
    "protocol_type_enforcement",
    "interface_access_control",
    "ALL_CHECKS",
]