# ARGUS — Network Observation, Diagnostics & Discovery Toolkit
**Brand:** ARGUS by Veilric  
**Version:** 1.1.0  
**License:** MIT  

ARGUS is a portable, zero-dependency network investigation assistant designed for network administrators, systems engineers, and technicians. Instead of juggling multiple terminals (`ping`, `traceroute`, `arp`, `ip route`, `dig`, `nslookup`, `netstat`, `ipconfig`, `nmcli`) and scribbling down IP addresses, ARGUS unifies real-time telemetry observation, fault-isolation diagnostics, DHCP intelligence & baseline history, local subnet discovery, and incident reporting into a single high-performance binary.

---

## ⚡ Key Highlights

- **USB Flash Drive Portable**: Pure static binaries (`argus` ELF for Linux, `argus.exe` PE for Windows) with `CGO_ENABLED=0`. Zero shared runtime dependencies, no installation, and no drivers required.
- **Vertical Cyber-Telemetry Widget (TUI)**: High-contrast terminal dashboard featuring real-time hop-by-hop reachability pipelines, live latency sparklines, diagnostic health cards, and a lightweight host stats footer.
- **DHCP Intelligence & Network Configuration History (v1.1.0)**:
  - 100% read-only local inspection (Linux NetworkManager / lease files, Windows `ipconfig /all`) with zero active broadcast packets.
  - Persistent baseline storage in lightweight local JSON (`config/baselines.json`).
  - Automated drift detection identifying unexpected DHCP server changes (e.g. secondary routers or mesh nodes like TP-Link Deco inadvertently set to Router mode instead of AP mode), gateway IP changes, subnet prefix shifts, and DNS resolver changes.
  - Strict temporal qualification: correlates configuration shifts with external outages without claiming unproven causation.
  - Explicit user baseline refresh via `[B]` in TUI or `--refresh-baseline` in CLI.
- **Dual Privilege Mode with Graceful Degradation**: Operates securely in unprivileged `[USER]` mode by default using safe OS sockets and routing tables; unlocks deep diagnostic probes (ARP conflict scans, raw ICMP) when run as `[ADMIN/ROOT]`.
- **Modular Diagnostic Rule Engine**: Independent, evidence-backed diagnostic modules that isolate:
  - Physical Link & Interface Carrier drops
  - Gateway reachability & configuration drift (MAC/ARP changes)
  - IP address conflicts and ARP anomalies
  - Double NAT detection (RFC 1918 / CGNAT multi-hop traversal)
  - Upstream ISP / WAN outages vs local DNS server failures
  - DHCP leasing anomalies, gateway shifts, and rogue/secondary DHCP server symptoms
  - Captive portal and HTTP splash page interception
  - Path MTU & fragmentation black-hole detection
- **Evidence-Based Categorization**: Findings are strictly classified into **Confirmed Observations**, **Suspected Causes**, and **Inconclusive Findings**, accompanied by concrete measurement evidence. Never invents healthy or failure classifications when metadata is unavailable.
- **Passive-First Subnet Discovery with Explicit Authorization**: Reads kernel ARP/NDP tables with zero packets emitted. Active scanning requires explicit user confirmation of the target scope, rate, and interface before any probe packets are transmitted, with responsive modal bounds adapting to compact terminal sizes and immediate cancellation support via `[C]` or `[Esc]`.
- **One-Click Incident Reports**: Press `[E]` or run `argus --scan` to export timestamped, self-contained reports in both **Markdown (`.md`)** and **JSON (`.json`)** formats, branded **ARGUS by Veilric**.

---

## 🖥️ Interactive Controls (TUI Mode)

| Key | Action | Description |
| :--- | :--- | :--- |
| `[1]` / `[Tab]` | **Live Telemetry** | View hop-by-hop pipeline, latency sparklines, and vital signs |
| `[2]` | **Deep Diagnostics** | View modular root-cause analysis, DHCP baseline cards, evidence, and remediation |
| `[3]` | **Subnet Devices** | View discovered local subnet inventory (IP, MAC, Vendor, Iface) |
| `[4]` | **Incident Logs** | View timestamped session event feed, config change alerts, and transitions |
| `[↑ / ↓]` or `[k / j]` | **Scroll Line** | Scroll content up or down line by line |
| `[PgUp / PgDn]` | **Scroll Page** | Scroll content up or down by page |
| `[Home / End]` | **Top / Bottom** | Jump immediately to the top or bottom of content |
| `Mouse Wheel` | **Wheel Scroll** | Smoothly scroll the content viewport with the mouse wheel |
| `[D]` / `[Space]` | **Run Deep Scan** | Concurrently triggers all modular diagnostic checks |
| `[B]` | **Refresh Baseline** | Explicitly establishes/updates local network configuration baseline |
| `[S]` | **Subnet Sweep** | Displays responsive authorization modal with exact target scope and rate |
| `[Enter]` / `[Y]` | **Confirm Scan** | Authorizes and launches sweep when authorization modal is open |
| `[Esc]` / `[N]` | **Cancel / Dismiss** | Dismisses authorization modal before starting, or cancels active scan |
| `[C]` | **Cancel Scan** | Immediately stops an in-flight active sweep |
| `[E]` | **Export Report** | Generates timestamped Markdown & JSON reports in `./reports/` |
| `[R]` | **Refresh** | Re-detects interfaces, default gateway, and system ARP cache |
| `[Q]` / `[Ctrl+C]` | **Quit** | Restores terminal screen cleanly, aborts any active sweep, and flushes logs |

---

## 🚀 Quick Start

### 1. Running from a USB Flash Drive

Copy the binaries and directories onto your USB drive:
```text
USB_DRIVE/
├── argus               # Run on Linux machines
├── argus.exe           # Run on Windows machines
├── config/             # Persistent network baselines (baselines.json)
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

To re-baseline an interface headlessly:
```bash
./argus --refresh-baseline
```

### 3. Command-Line Options

```text
Usage:
  argus [options]

Options:
  -scan               Run one-shot headless diagnostic scan without opening TUI
  -refresh-baseline   Update and persist current network configuration as baseline
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

## 3. DHCP Intelligence & Network Configuration History
| Parameter | Current Observation | Baseline Reference | Status |
| :--- | :--- | :--- | :--- |
| **Interface** | `enp6s0` (02:00:00:00:00:01) | `enp6s0` | Match |
| **Assignment** | DHCP | DHCP | Match |
| **Assigned IPv4** | `192.168.1.50/24` | `192.168.1.50/24` | Match |
| **Default Gateway**| `192.168.1.1` | `192.168.1.1` | Match |
| **DNS Resolvers** | `[192.168.1.1]` | `[192.168.1.1]` | Match |
| **DHCP Server** | `192.168.1.1` | `192.168.1.1` | Match |
| **Lease Expiry** | 2026-11-03 14:00:00 PST | — | Active |
```

---
*ARGUS by Veilric — Autonomous Network Observation, Diagnostics & Discovery.*
