# 🌐 Network Utils

<div align="center">

```
  ███╗   ██╗███████╗████████╗ █████╗ ██╗      █████╗ ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██╔══██╗██║
  ██╔██╗ ██║█████╗     ██║   ███████║██║     ███████║██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██║██║     ██╔══██║██║
  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗██║  ██║██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝
```

**A self-contained networking toolkit for cybersecurity students and enthusiasts**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: PEP 8](https://img.shields.io/badge/Code%20Style-PEP%208-green.svg)](https://www.python.org/dev/peps/pep-0008/)

</div>

---

## 📋 Overview

**Network Utils** is a command-line networking toolkit built with Python, designed as a portfolio project for aspiring cybersecurity professionals. It provides six essential network reconnaissance tools in a clean, modular architecture with a professional terminal interface.

This project demonstrates proficiency in:
- **Socket programming** — Raw TCP connections for port scanning and banner grabbing
- **Clean architecture** — Organized into clearly labeled sections within a single file, each tool's logic is self-contained and well-documented
- **Error handling** — Graceful degradation with informative error messages
- **Logging** — Comprehensive session logging for audit trails and debugging
- **Clean code practices** — Type hints, docstrings, PEP 8 compliance throughout

The entire toolkit lives in a single `main.py` file — zero import hassles, zero module path issues. Just clone and run. Each tool section is clearly separated and documented so the codebase remains easy to read and extend.

---

## ✨ Features

| # | Tool | Description |
|---|------|-------------|
| 1 | **Ping Host** | Check if a host is reachable via ICMP echo requests |
| 2 | **DNS Lookup** | Resolve domain names to IPs, reverse lookups, and full DNS record queries (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| 3 | **IP Information** | Display local hostname, IP addresses, and network interface details |
| 4 | **Port Scanner** | Multi-threaded TCP port scanner with configurable ports, ranges, and timeouts |
| 5 | **Banner Grabbing** | Retrieve service banners from open ports to identify software and versions |
| 6 | **Traceroute** | Display the network path (hop-by-hop) to a target host |

### Key Highlights

- **Interactive terminal menu** with colored output and intuitive navigation
- **Multi-threaded port scanning** for fast, efficient reconnaissance
- **Cross-platform support** — Works on Linux, macOS, and Windows
- **Comprehensive logging** — Every session is logged with timestamps to `logs/`
- **Graceful error handling** — No crashes on invalid input or network failures
- **Single-file architecture** — Everything in one file, just clone and run

---

## 🛠️ Installation

### Prerequisites

- **Python 3.8** or higher
- **pip** (Python package manager)
- A terminal/command-line interface

### Step-by-Step

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/network-utils.git
   cd network-utils
   ```

2. **(Optional) Install dnspython for advanced DNS features:**
   ```bash
   pip install -r requirements.txt
   ```
   > The only external dependency is `dnspython`, which enables full DNS record queries (MX, NS, TXT, etc.). The toolkit works without it using Python's built-in `socket` library as a fallback.

3. **Run the application:**
   ```bash
   python main.py
   ```

> **That's it.** No module imports to configure, no path issues. One file, one command.

### Optional System Tools

Some features rely on system utilities that may need to be installed separately:

| Tool | Linux (Debian/Ubuntu) | macOS | Windows |
|------|----------------------|-------|---------|
| `ping` | Pre-installed | Pre-installed | Pre-installed |
| `traceroute` | `sudo apt install traceroute` | Pre-installed | `tracert` (built-in) |
| `tracepath` | Pre-installed (alternative) | N/A | N/A |

---

## 🚀 Usage

### Interactive Mode (Recommended)

Launch the application and use the numbered menu to select tools:

```
$ python main.py

  ╔═══════════════════════════════════════════════════════════╗
  ║   N E T W O R K   U T I L S  v1.0.0                      ║
  ╚═══════════════════════════════════════════════════════════╝

  [1]  Ping Host
  [2]  DNS Lookup
  [3]  IP Information
  [4]  Port Scanner
  [5]  Banner Grabbing
  [6]  Traceroute
  [0]  Exit

  Select an option: _
```

### Using Tool Functions Directly (Programmatic)

All tool functions are available at the top level of `main.py`. You can import them directly:

```python
from main import ping_host, dns_lookup, get_dns_records
from main import get_local_ip, get_hostname
from main import scan_ports, scan_common_ports
from main import grab_banner, grab_banners
from main import traceroute

# Ping a host
result = ping_host("example.com", count=3)
print(result)

# Resolve DNS records
records = get_dns_records("example.com")
for rtype, values in records.items():
    print(f"{rtype}: {', '.join(values)}")

# Scan common ports on your local network device
open_ports = scan_common_ports("192.168.1.1", timeout=1.5)
for port_info in open_ports:
    print(f"Port {port_info['port']} ({port_info['service']}) is open")

# Grab a banner from SSH
banner = grab_banner("192.168.1.1", 22)
print(f"SSH Banner: {banner}")
```

### Usage Examples

**Example 1: Quick host reachability check**
```
Select an option: 1
Enter target host: google.com
Number of echo requests: 3

PING google.com (142.250.80.46) 56(84) bytes of data.
64 bytes from lax17s55-in-f14.1e100.net (142.250.80.46): icmp_seq=1 ttl=117 time=12.3 ms
64 bytes from lax17s55-in-f14.1e100.net (142.250.80.46): icmp_seq=2 ttl=117 time=11.8 ms
64 bytes from lax17s55-in-f14.1e100.net (142.250.80.46): icmp_seq=3 ttl=117 time=13.1 ms

[✓] Ping to google.com completed
```

**Example 2: DNS record enumeration**
```
Select an option: 2
Select lookup type: 3
Enter domain name: github.com

Type     Value
─────── ─────────────────────────────────────────────
A        20.205.243.166
NS       dns1.p08.nsone.net
NS       dns2.p08.nsone.net
MX       1 aspmx.l.google.com
TXT      v=spf1 include:_spf.google.com include:spf.mtasv.net ...
```

**Example 3: Port scanning with banner grabbing**
```
Select an option: 4
Enter target host: scanme.nmap.org
Select scan type: 1

[✓] Found 3 open port(s) on scanme.nmap.org:

Port       State      Service
────────── ────────── ─────────────────────────
22/tcp     open       SSH
80/tcp     open       HTTP
9929/tcp   open       Unknown

Grab banners from open ports? (y/N): y

Port       Banner
────────── ──────────────────────────────────────────
22/tcp     SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
80/tcp     HTTP/1.1 200 OK Server: nginx/1.18.0
9929/tcp   No banner available
```

**Example 4: Traceroute**
```
Select an option: 6
Enter target host: example.com
Maximum hops: 15

[✓] Traceroute to example.com — 12 hop(s):

Hop    Host                                          Latency
────── ───────────────────────────────────────────── ───────────────
1      192.168.1.1                                   1.234 ms
2      10.0.0.1                                      5.678 ms
3      *                                             timeout
...
12     93.184.216.34                                 24.567 ms
```

---

## 💻 Technologies Used

| Technology | Purpose |
|-----------|---------|
| **Python 3** | Core programming language |
| **socket** | TCP connections, DNS resolution, and network I/O |
| **subprocess** | System command execution (ping, traceroute) |
| **concurrent.futures** | Multi-threaded port scanning |
| **dnspython** | Advanced DNS record queries (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| **logging** | Session logging and audit trails |
| **ANSI escape codes** | Colored terminal output |

### Project Structure

```
network-utils/
├── main.py                 # 🎯 The entire toolkit — all tools, UI, logging
├── requirements.txt        # Optional: dnspython for advanced DNS
├── README.md               # Project documentation (this file)
├── screenshots/            # Application screenshots
└── logs/                   # Session log files (auto-generated)
```

The `main.py` file is organized into 11 clearly labeled sections:

| Section | Contents |
|---------|----------|
| 1 — ANSI Color Codes | Terminal color constants and Windows compatibility |
| 2 — Ping Module | ICMP echo reachability checks |
| 3 — DNS Lookup Module | Forward/reverse DNS and multi-record queries |
| 4 — IP Information Module | Local/remote IP and hostname details |
| 5 — Port Scanner Module | Multi-threaded TCP port scanning |
| 6 — Banner Grabber Module | Service banner retrieval |
| 7 — Traceroute Module | Network path tracing |
| 8 — Logging Configuration | File and console logging setup |
| 9 — Display Helpers | ASCII banner, menu, colored output functions |
| 10 — Menu Handlers | User interaction logic for each tool |
| 11 — Main Application Loop | Entry point and interactive loop |

### Design Decisions

- **System commands vs. raw sockets for ping/traceroute**: Using the OS-native `ping` and `traceroute` commands ensures reliability across platforms and avoids the need for root/sudo privileges. Raw socket implementations would be more "pure Python" but introduce compatibility and permission issues.

- **Threading for port scanning**: `concurrent.futures.ThreadPoolExecutor` provides a clean, Pythonic approach to parallel port scanning. The thread pool is capped at 100 workers to avoid overwhelming the target or the local system.

- **dnspython as optional dependency**: The toolkit gracefully falls back to `socket`-based resolution if `dnspython` is not installed, ensuring the DNS module always works even without the extra dependency.

- **No external framework for CLI**: The menu is built with plain Python `input()` and `print()` to keep the project dependency-free and easy to understand for beginners.

- **Single-file architecture**: All tool logic lives in one `main.py` file so anyone can clone the repo and run it immediately — no import path issues, no missing module errors, no setup complexity. Each tool is still logically separated into its own section with clear headers and documentation.

---

## 📸 Screenshots

> Screenshots will be added after the first release.

| Feature | Screenshot |
|---------|-----------|
| Main Menu | *Coming soon* |
| Ping Host | *Coming soon* |
| DNS Lookup | *Coming soon* |
| Port Scanner | *Coming soon* |
| Banner Grabbing | *Coming soon* |
| Traceroute | *Coming soon* |

---

## 🔮 Future Improvements

- [ ] **IPv6 support** — Full IPv6 compatibility across all modules
- [ ] **ASN lookup** — Display Autonomous System Number information for IPs
- [ ] **WHOIS integration** — Domain registration and ownership lookups
- [ ] **SSL/TLS certificate analysis** — Inspect certificates on HTTPS services
- [ ] **UDP port scanning** — Extend the scanner to support UDP probes
- [ ] **Output export** — Save scan results to JSON/CSV files
- [ ] **Configuration file** — User-customizable defaults and preferences
- [ ] **Rate limiting** — Configurable scan speed to avoid detection/overload
- [ ] **Nmap integration** — Optional integration with Nmap for advanced scanning
- [ ] **GUI wrapper** — Optional graphical interface using Tkinter or PyQt
- [ ] **Docker containerization** — Package the tool in a Docker image for easy deployment
- [ ] **Unit tests** — Comprehensive test suite with mocked network calls
- [ ] **CI/CD pipeline** — Automated testing and linting with GitHub Actions

---

## ⚠️ Disclaimer

This tool is developed **solely for educational purposes and authorized network testing**.

**You MUST NOT use this tool to scan, probe, or access any network, system, or device without explicit written authorization from the owner.** Unauthorized port scanning, banner grabbing, and network reconnaissance may violate local, state, national, and international laws, including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States and the Computer Misuse Act in the United Kingdom.

By using this software, you agree that:

1. You will only use it on systems you own or have explicit permission to test
2. You understand that unauthorized scanning is illegal and unethical
3. The author(s) assume **no liability** for misuse or damage caused by this tool
4. You are responsible for complying with all applicable laws in your jurisdiction

**If you are learning cybersecurity, practice on:**
- Your own home network and devices
- Intentionally vulnerable lab environments (e.g., DVWA, Metasploitable, Hack The Box)
- Platforms that explicitly authorize testing (e.g., bug bounty programs)

*With great power comes great responsibility. Use your skills to defend, not to harm.*

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with 💻 and ☕ by an aspiring cybersecurity professional**

*If this project helped you learn, consider giving it a ⭐ on GitHub!*

</div>
