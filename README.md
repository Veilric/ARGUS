# ARGUS — Network Observation, Diagnostics & Discovery Toolkit
**Brand:** ARGUS by Veilric  
**Version:** 1.0.0  
**License:** MIT  

ARGUS is a portable, zero-dependency network investigation assistant designed for network administrators, systems engineers, and technicians. Instead of juggling multiple terminals (`ping`, `traceroute`, `arp`, `ip route`, `dig`, `nslookup`, `netstat`) and scribbling down IP addresses, ARGUS unifies real-time telemetry observation, fault-isolation diagnostics, local subnet discovery, and incident reporting into a single high-performance binary.

---

## ⚡ Key Highlights

- **USB Flash Drive Portable**: Pure static binaries (`argus` ELF for Linux, `argus.exe` PE for Windows) with `CGO_ENABLED=0`. Zero shared runtime dependencies, no installation, and no drivers required.
- **Vertical Cyber-Telemetry Widget (TUI)**: High-contrast terminal dashboard featuring real-time hop-by-hop reachability pipelines, live latency sparklines, diagnostic health cards, and a lightweight host stats footer.
- **Dual Privilege Mode with Graceful Degradation**: Operates securely in unprivileged `[USER]` mode by default using safe OS sockets and routing tables; unlocks deep diagnostic probes (ARP conflict scans, raw ICMP) when run as `[ADMIN/ROOT]`.
- **Modular Diagnostic Rule Engine**: Independent, evidence-backed diagnostic modules that isolate:
  - Physical Link & Interface Carrier drops
  - Gateway reachability & configuration drift (MAC/ARP changes)
  - IP address conflicts and ARP anomalies
  - Double NAT detection (RFC 1918 / CGNAT multi-hop traversal)
  - Upstream ISP / WAN outages vs local DNS server failures
  - Captive portal and HTTP splash page interception
  - Path MTU & fragmentation black-hole detection
- **Evidence-Based Categorization**: Findings are strictly classified into **Confirmed Observations**, **Suspected Causes**, and **Inconclusive Findings**, accompanied by concrete measurement evidence.
- **Passive-First Subnet Discovery**: Reads kernel ARP/NDP tables with zero packets emitted; supports an on-demand gentle sweep strictly throttled to 15 pkts/sec to avoid tripping corporate IDS/IPS or switch port security.
- **One-Click Incident Reports**: Press `[E]` or run `argus --scan` to export timestamped, self-contained reports in both **Markdown (`.md`)** and **JSON (`.json`)** formats, branded **ARGUS by Veilric**.

---

## 🖥️ Interactive Controls (TUI Mode)

| Key | Action | Description |
| :--- | :--- | :--- |
| `[1]` / `[Tab]` | **Live Telemetry** | View hop-by-hop pipeline, latency sparklines, and vital signs |
| `[2]` | **Deep Diagnostics** | View modular root-cause analysis, evidence details, and remediation |
| `[3]` | **Subnet Devices** | View discovered local subnet inventory (IP, MAC, Vendor, Iface) |
| `[4]` | **Incident Logs** | View timestamped session event feed and configuration transitions |
| `[↑ / ↓]` or `[k / j]` | **Scroll Line** | Scroll content up or down line by line |
| `[PgUp / PgDn]` | **Scroll Page** | Scroll content up or down by page |
| `[Home / End]` | **Top / Bottom** | Jump immediately to the top or bottom of content |
| `Mouse Wheel` | **Wheel Scroll** | Smoothly scroll the content viewport with the mouse wheel |
| `[D]` / `[Space]` | **Run Deep Scan** | Concurrently triggers all modular diagnostic checks |
| `[S]` | **Subnet Sweep** | Runs gentle, rate-limited active discovery across local `/24` |
| `[E]` | **Export Report** | Generates timestamped Markdown & JSON reports in `./reports/` |
| `[R]` | **Refresh** | Re-detects interfaces, default gateway, and system ARP cache |
| `[Q]` / `[Ctrl+C]` | **Quit** | Restores terminal screen cleanly and flushes rotating logs |

---

## 🚀 Quick Start

### 1. Running from a USB Flash Drive

Copy the binaries and directories onto your USB drive:
```text
USB_DRIVE/
├── argus               # Run on Linux machines
├── argus.exe           # Run on Windows machines
├── reports/            # Exported incident reports (.md and .json)
└── logs/               # Rotating session event logs
```

- **Linux**:
  ```bash
  ./argus
  ```
- **Windows**:
  ```cmd
  argus.exe
  ```

### 2. Headless / Scripting Mode (`--scan`)

Execute diagnostic triage from automation scripts or without launching the interactive TUI:
```bash
./argus --scan
```
This runs the full diagnostic suite, outputs a clear summary table to standard output, and automatically exports Markdown and JSON reports to `./reports/`.

### 3. Command-Line Options

```text
Usage:
  argus [options]

Options:
  -scan               Run one-shot headless diagnostic scan without opening TUI
  -export string      Custom directory path to export incident reports
  -iface string       Override network interface name (auto-detected if omitted)
  -log-dir string     Directory for session event logs (default "./logs")
  -report-dir string  Directory for exported incident reports (default "./reports")
  -version            Display ARGUS version information
```

---

## 🛠️ Building from Source

Prerequisites: Go 1.22+

```bash
# Clone or navigate to the repository
cd ARGUS

# Compile static binaries for both Linux and Windows
./scripts/build.sh
```

Static binaries are placed in `./dist/` and the project root:
- `dist/argus` (Linux ELF 64-bit, statically linked, stripped)
- `dist/argus.exe` (Windows PE32+ executable, statically linked)

---

## 📄 Incident Report Example

Generated incident reports feature standardized executive summaries and evidence breakdowns:

```markdown
# ARGUS Network Incident & Observation Report
**Toolkit:** ARGUS by Veilric
**Timestamp:** 2026-11-02 15:03:43 PST | **Mode:** [USER]

## 1. Executive Summary & Chain of Reachability
| Component | Status | Latency | Measurement Details |
| :--- | :--- | :--- | :--- |
| **Physical Link** | ✔ ONLINE | — | Interface: `enp6s0` (02:00:00:00:00:01) |
| **Default Gateway** | ✔ ONLINE | 1.596ms | Target: `192.0.2.1` |
| **DNS Resolution** | ✔ ONLINE | 108µs | Server: `[127.0.0.53]` |
| **Internet Egress** | ✔ ONLINE | 5.914ms | Public Egress Verified |
| **Captive Portal** | CLEAN | — | State: `CLEAN` |

## 2. Evidence-Based Diagnostic Findings
### [HEALTHY] ISP WAN Outage vs DNS Server Failure Isolation
- **Classification:** `HEALTHY` (Severity: `NONE`)
- **Summary:** Internet and DNS healthy (Egress: 5ms, DNS: 7ms)
- **Evidence Backing:**
  - Raw Public IP Reachability: true (5ms via 1.1.1.1:443)
  - DNS Resolution ('one.one.one.one'): true (7ms)
  - Configured System DNS: [127.0.0.53]
```

---
*ARGUS by Veilric — Autonomous Network Observation, Diagnostics & Discovery.*
