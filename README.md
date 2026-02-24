# BLUE RECCOON — Blue Team Reconnaissance & Baseline Platform

A mission-prep tool for Cyber Protection Teams operating on unfamiliar networks. Rapidly build a huntable baseline from zero knowledge of the target environment.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Standalone mode (single operator, localhost only)
python app.py --standalone

# Team server mode (multi-analyst, network accessible)
python app.py --host 0.0.0.0 --port 5000

# Access the UI
# Open http://localhost:5000
# Default passphrase: blue-reccoon-2024
```

## Running Modes

| Mode | Command | Use Case |
|------|---------|----------|
| **Standalone** | `python app.py --standalone` | Single operator on laptop |
| **Team Server** | `python app.py --host 0.0.0.0` | Multi-analyst, shared mission data |

## Features (Current Build - Phase 1 + Phase 2)

### Core Platform
- **Mission Management** — Create, track, and export missions with classification markings
- **Dual-mode deployment** — Standalone laptop or team server with real-time collaboration via Socket.IO
- **Dark SOC theme** — Optimized for low-light operations center environments
- **Authentication** — Passphrase-based auth suitable for field deployment

### Network Visualization
- **Interactive Topology Map** — D3.js force-directed graph with full zoom/pan/drag
- **Three Layout Modes:** Force / Grouped by Subnet / Hierarchical by Zone
- **Subnet Hulls** — Auto-generated convex hulls with color coding
- **Device Type Differentiation** — Diamonds for OT, circles for IT, rings for critical
- **Connection Visualization** — Color-coded (IT/OT/cross-zone), thickness by volume
- **Interactive** — Hover tooltips, click to select, search/filter, subnet focus zoom, SVG export

### Scan Engine (Phase 2 — NEW)
Full modular enumeration framework with 14 scanner modules, real-time progress via Socket.IO, background threading, and automatic DB ingestion.

**Scan Control Center UI** — Visual scan launcher with:
- Scan type selection with descriptions
- Configurable targets (IP, CIDR, ranges, comma-separated)
- Aggressiveness slider (1-5) with visual feedback
- Credential support for authenticated scans
- OT safety warnings and rate limiting controls
- Real-time progress bars and status updates
- Live discovery notifications via WebSocket

**Active Enumeration Modules:**
| Module | Description |
|--------|-------------|
| **Host Discovery** | ARP sweep + ICMP ping via nmap, arping, or native ping. Auto-infers subnets. |
| **Port Scanner** | TCP/UDP scanning with 5 aggressiveness levels. Nmap integration with socket fallback. OT ports always included. |
| **Service Detection** | Banner grabbing, version ID, TLS cert extraction. Protocol-specific probes for 20+ services. |
| **OS Detection** | Active (nmap) and passive (TTL analysis) OS fingerprinting. |
| **OT/ICS Scanner** | Protocol-aware probes for Modbus, S7comm, DNP3, EtherNet/IP, BACnet, OPC UA. Read-only operations with configurable rate limiting. Device ID extraction. |
| **SMB Enumeration** | Share/user/domain enumeration via enum4linux, smbclient, rpcclient. |
| **AD Enumeration** | Root DSE, DCs, trusts, OUs, privileged groups (Domain Admins, etc.), Kerberoastable SPNs. |
| **SNMP Enumeration** | Community string testing, sysDescr parsing for vendor/model/OS. |
| **Host Profiler** | Deep profiling via WinRM/SSH — hostname, OS, installed software. |
| **Full Active Scan** | Orchestrates all active modules sequentially: Discovery → Ports → Services → OT → SNMP. |

**Passive Modules:**
| Module | Description |
|--------|-------------|
| **Passive Capture** | Live tcpdump/tshark capture, zero packets sent. Extracts hosts and connections from observed traffic. |
| **PCAP Importer** | Import existing PCAP files. Extracts hosts, connections, passive OS fingerprints, protocol distribution. |

**Scan Engine Architecture:**
- Background threaded execution with cancellation support
- Automatic result ingestion into mission database
- Real-time progress reporting via Socket.IO WebSockets
- Subnet auto-detection and host auto-assignment
- Device type and criticality inference from scan results
- Smart deduplication (updates existing hosts instead of creating duplicates)
- Tool availability detection (graceful fallback when nmap/tshark not installed)

### Host Profiling
- Comprehensive host cards: IP, MAC, hostname, domain, OS, device type, vendor, model, firmware
- Criticality classification (Critical/High/Medium/Low) with visual indicators
- Service inventory per host with port, protocol, version, and banner data
- OT device detail tracking: device class, serial number, master/slave role, protocol
- Network connection mapping per host (inbound/outbound)

### Data Management
- **Hosts Table** — Sortable, filterable by type, criticality, subnet
- **Subnets Table** — VLAN mapping, gateway identification, host counts
- **Connections Table** — Full traffic flow inventory with byte/packet counts
- **Threat Intel** — Import threat actor profiles with MITRE ATT&CK TTP mapping and IOC lists
- **Hunt Hypotheses** — Track hunting leads with priority, MITRE mapping, and status
- **Export** — Full mission data export as JSON

### OT/ICS Support
- OT protocol identification (Modbus, DNP3, BACnet, EtherNet/IP, S7comm, OPC UA)
- OT device profiling (PLC, HMI, RTU, SCADA, Engineering Workstation, Historian)
- Firmware tracking and serial number inventory
- Master/slave relationship mapping
- Visual distinction of OT zones in topology
- Cross-zone traffic detection (IT↔OT boundary violations flagged)

## Demo Data

Click **"Load Demo Data"** on the dashboard to seed a realistic hybrid IT/OT energy sector scenario including:
- 6 subnets (Corporate IT, Server Farm, DMZ, OT Control, OT Field Devices, Management)
- 25 hosts across all zones
- Siemens S7-1500 PLCs, Allen-Bradley ControlLogix, SEL RTUs
- Domain controllers, Exchange, SCCM, WSUS
- SCADA server, Historian, HMIs running WinCC
- Realistic connection flows including suspicious cross-zone traffic
- VOLTZITE APT threat intel with MITRE ATT&CK TTPs
- Pre-generated hunt hypotheses

## Planned Features (Future Phases)

### Phase 3: Threat Intel Cross-Referencing
- ATT&CK technique mapping against discovered baseline
- Crown jewel auto-identification
- Lateral movement path analysis
- Anomaly detection from baseline
- Automated hunt hypothesis generation
- Network segmentation analysis (expected vs. actual)

### Phase 4: Advanced Analysis
- Detection-as-code rule testing against baseline
- Persistence mechanism inventory
- DNS anomaly detection (DGA, tunneling)
- Beaconing detection from traffic patterns
- Automated report generation

## Architecture

```
blue-reccoon/
├── app.py                          # Flask app, API routes, Socket.IO, DB schema
├── requirements.txt
├── modules/
│   ├── __init__.py
│   ├── scan_engine.py              # Scan orchestrator, threading, result ingestion
│   ├── base_scanner.py             # Base class: target parsing, OT detection, tool helpers
│   ├── network_discovery.py        # ARP sweep, ICMP ping, subnet detection
│   ├── port_scanner.py             # TCP/UDP port scanning (nmap + socket fallback)
│   ├── service_scanner.py          # Banner grabbing, version detection, TLS certs
│   ├── os_detector.py              # Active/passive OS fingerprinting
│   ├── ot_scanner.py               # Modbus, S7, DNP3, EtherNet/IP, BACnet, OPC UA
│   ├── smb_enumerator.py           # SMB shares, users, domain info
│   ├── ad_enumerator.py            # AD: DCs, trusts, OUs, privileged groups, SPNs
│   ├── snmp_enumerator.py          # SNMP community testing, device info
│   ├── host_profiler.py            # Deep profiling via WinRM/SSH
│   ├── full_scan.py                # Orchestrates all active modules
│   ├── passive_capture.py          # Live traffic capture (tcpdump/tshark)
│   └── pcap_importer.py            # PCAP file import and analysis
├── templates/
│   ├── login.html                  # Authentication
│   ├── dashboard.html              # Mission selection/creation
│   ├── mission.html                # Mission detail with tabbed data views
│   ├── topology.html               # Interactive D3.js network topology
│   └── scan_control.html           # Scan launcher and monitor
├── static/
│   └── css/
│       └── main.css                # Dark SOC theme
└── utils/                          # (Future) Helpers
```

## Tech Stack
- **Backend:** Flask + SQLite (WAL mode) + Flask-SocketIO
- **Frontend:** Vanilla JS + D3.js v7 for topology visualization
- **Styling:** Custom dark theme optimized for SOC environments
- **Real-time:** Socket.IO for multi-analyst collaboration
- **Zero cloud dependencies** — Runs fully offline/air-gapped

## Recommended External Tools

The scan engine gracefully degrades when tools aren't available, but for full capability install:

```bash
# Core scanning
apt install nmap           # Port scanning, OS detection, service detection
apt install tshark         # Passive capture and PCAP analysis

# SMB/AD enumeration
apt install smbclient      # SMB share enumeration
apt install ldap-utils     # LDAP/AD queries
pip install crackmapexec   # Windows host profiling

# Network discovery
apt install arping         # ARP-based host discovery
apt install net-tools      # Additional network tools

# SNMP
apt install snmp           # SNMP queries
```

Without these tools, the scanner falls back to native Python socket scanning, which covers basic host discovery and port scanning.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | Random | Flask session secret |
| `AUTH_HASH` | sha256('blue-reccoon-2024') | SHA256 hash of auth passphrase |
| `DB_PATH` | blue_reccoon.db | SQLite database path |

## Custom Passphrase

```bash
# Generate hash for your passphrase
python -c "import hashlib; print(hashlib.sha256(b'your-passphrase').hexdigest())"

# Set it
AUTH_HASH=<hash> python app.py
```
