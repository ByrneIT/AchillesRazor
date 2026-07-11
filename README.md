# ðŸ”’ ICS Security Scanner

**A comprehensive OT/ICS security assessment suite for industrial control systems**

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()

---

## ðŸ“‹ Overview

The ICS Security Scanner is a modular, extensible framework for assessing the security posture of industrial control systems (ICS) and operational technology (OT) environments. It provides **16 specialized security checks** covering everything from device discovery to protocol security analysis.

### Why This Tool?

- **No proprietary licensing** â€” Fully open source
- **No cloud dependencies** â€” Runs entirely offline
- **No vendor lock-in** â€” Works with Modbus, S7, DNP3, CIP, BACnet, OPC-UA, IEC-104
- **Safe scanning** â€” Built-in delays and timeouts to avoid crashing fragile OT devices
- **Professional reporting** â€” Console, JSON, Markdown, and HTML output formats

### Who Is This For?

- **OT/ICS Security Engineers** â€” Assessing industrial network security
- **Penetration Testers** â€” OT/ICS engagements
- **Security Auditors** â€” Compliance and risk assessments
- **Plant Operators** â€” Understanding their own security posture
- **Students** â€” Learning OT/ICS security concepts

---

## ðŸš€ Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ByrneIT/AchillesRazor.git
cd AchillesRazor

# Install dependencies
pip install -r requirements.txt

# Run your first scan
python -m AchillesRazor.ics_main -t 192.168.1.100
