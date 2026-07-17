

# 🔒 AchillesRazor

**A comprehensive OT/ICS security assessment suite for industrial control systems**

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)

**Created by Allen Byrne (aka *Cybershoresy*)**

---

## 📋 Overview

AchillesRazor is a modular, extensible framework for assessing the security posture of industrial control systems (ICS) and operational technology (OT) environments. It provides **16 specialized security checks** covering everything from device discovery to protocol security analysis.

### Why This Tool?

- **No proprietary licensing** — Fully open source
- **No cloud dependencies** — Runs entirely offline
- **No vendor lock-in** — Works with Modbus, S7, DNP3, CIP, BACnet, OPC-UA, IEC-104
- **Safe scanning** — Built-in delays and timeouts to avoid crashing fragile OT devices
- **Professional reporting** — Console, JSON, Markdown, and HTML output formats

### Who Is This For?

- **OT/ICS Security Engineers** — Assessing industrial network security
- **Penetration Testers** — OT/ICS engagements
- **Security Auditors** — Compliance and risk assessments
- **Plant Operators** — Understanding their own security posture
- **Students** — Learning OT/ICS security concepts

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ByrneIT/AchillesRazor.git
cd AchillesRazor

# Install (also pulls in requests + dnspython)
pip install .

# Run your first scan
achillesrazor -t 192.168.1.100
```

`pip install .` registers the `achillesrazor` command (and a short `AR` alias)
on your PATH via setuptools `console_scripts` — no need to invoke it through
`python -m`. If you'd rather not install the package, `pip install -r
requirements.txt` followed by `python -m AchillesRazor.ics_main -t
192.168.1.100` from the repo root works identically.

A default run executes all 16 checks against the target and prints a console
report. This can take a few minutes depending on how many ports the target
has open or filtered — the scan prints a starting banner immediately, and
per-check progress (`[3/16] Running: exposure... done`) as it goes.

### Usage

```
achillesrazor -t <target> [options]
```

| Flag | Description |
|------|-------------|
| `-t`, `--target` (or a bare positional target) | IP address, hostname, URL, or CIDR network (e.g. `192.168.1.0/24`) |
| `--type <type>` | Run a single check instead of all 16 (see `--list-checks` for names) |
| `-o`, `--output <path>` | Write the report to a file instead of stdout. `'-'` means stdout |
| `--format {console,json,markdown,html}` | Force an output format; otherwise inferred from the `-o` file extension |
| `--port <port>` | Check a specific port instead of the default OT port list (502, 102, 20000, 44818, 47808, 4840, 2404) |
| `-v`, `--verbose` | Also print the full list of checks being run before they start |
| `--list-checks` | List all available `--type` values and exit |

Examples:

```bash
achillesrazor -t 192.168.1.100
achillesrazor -t 192.168.1.100 --type security -o report.json
achillesrazor -t 192.168.1.0/24 --type exposure -o report.md
achillesrazor --list-checks
```

---

## Author

Created and maintained by **Allen Byrne** (aka **Cybershoresy**).