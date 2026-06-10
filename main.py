#!/usr/bin/env python3
"""
Network Utils — All-in-One Networking Toolkit
==============================================

A professional networking toolkit designed for cybersecurity students
and enthusiasts. Provides an interactive terminal menu for running
network reconnaissance tools including ping, DNS lookup, IP information,
port scanning, banner grabbing, and traceroute.

This is a self-contained single-file application. All tool logic,
colored output, logging, and the interactive menu are included here
so the project runs with just: python main.py

No external modules are required — only Python 3.8+ and the optional
'dnspython' package for advanced DNS record queries.

Features:
    1. Ping Host         — Check host reachability via ICMP
    2. DNS Lookup        — Forward/reverse DNS and full record queries
    3. IP Information    — Local & remote hostname and IP details
    4. Port Scanner      — Multi-threaded TCP port scanning
    5. Banner Grabbing   — Service banner retrieval from open ports
    6. Traceroute        — Network path tracing to a target host

Usage:
    python main.py

Author: Network Utils Project
License: MIT
Disclaimer: For educational and authorized testing purposes only.
"""

import os
import sys
import platform
import subprocess
import socket
import logging
import datetime
import re
import concurrent.futures
from typing import Optional, Dict, List

# Attempt to import dnspython for advanced DNS queries (optional)
try:
    import dns.resolver
    import dns.reversename
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


# ===========================================================================
#  SECTION 1 — ANSI COLOR CODES
# ===========================================================================
# Cross-platform colored terminal output. On older Windows terminals
# that don't support ANSI, colors are automatically disabled.
# ===========================================================================

class Colors:
    """ANSI escape code constants for terminal color formatting."""

    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    # Background
    BG_RED   = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE  = "\033[44m"

    @classmethod
    def disable(cls):
        """Disable all color codes by setting them to empty strings."""
        for attr in dir(cls):
            if attr.isupper():
                setattr(cls, attr, "")


# Enable ANSI on Windows 10+ or disable colors on legacy Windows
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        Colors.disable()


# ===========================================================================
#  SECTION 2 — PING MODULE
# ===========================================================================
# Uses the system's native ping command for reliable cross-platform
# ICMP echo checks. On Linux/macOS: 'ping -c', on Windows: 'ping -n'.
# ===========================================================================

def ping_host(host: str, count: int = 4) -> Optional[str]:
    """
    Send ICMP echo requests to a target host and return the results.

    Executes the system's native ping command, captures both stdout
    and stderr, and returns the combined output. Handles common
    failure modes such as unreachable hosts, DNS resolution failures,
    and timeout conditions gracefully.

    Args:
        host: The hostname or IP address to ping (e.g., 'example.com').
        count: Number of ICMP echo request packets to send (default: 4).

    Returns:
        The ping command output as a string if successful, or None
        if the ping command fails entirely.

    Raises:
        ValueError: If the host parameter is empty or whitespace-only.
    """
    logger = logging.getLogger(__name__)

    if not host or not host.strip():
        logger.error("Ping failed: empty hostname provided")
        raise ValueError("Hostname cannot be empty or whitespace.")

    host = host.strip()
    logger.info(f"Initiating ping to {host} with {count} request(s)")

    # Build OS-appropriate ping command
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", str(count), host]
    else:
        command = ["ping", "-c", str(count), host]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        output = result.stdout

        if result.returncode == 0:
            logger.info(f"Ping to {host} completed successfully")
        else:
            error_output = result.stderr.strip()
            if error_output:
                output += f"\n{error_output}"
            logger.warning(f"Ping to {host} returned non-zero exit code: {result.returncode}")

        return output

    except subprocess.TimeoutExpired:
        logger.error(f"Ping to {host} timed out after 30 seconds")
        return None
    except FileNotFoundError:
        logger.error("Ping command not found on this system")
        return None
    except Exception as e:
        logger.error(f"Unexpected error while pinging {host}: {e}")
        return None


# ===========================================================================
#  SECTION 3 — DNS LOOKUP MODULE
# ===========================================================================
# Resolves domain names to IPs, performs reverse lookups, and queries
# multiple DNS record types. Uses dnspython when available; falls back
# to Python's built-in socket library otherwise.
# ===========================================================================

def _dns_lookup_dnspython(domain: str) -> Optional[List[str]]:
    """Resolve a domain using the dnspython library (A + AAAA records)."""
    logger = logging.getLogger(__name__)
    ip_addresses = []

    for rtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for record in answers:
                ip_addresses.append(str(record))
            logger.debug(f"Found {len(answers)} {rtype} record(s) for {domain}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            logger.debug(f"No {rtype} records found for {domain}")

    return ip_addresses if ip_addresses else None


def _dns_lookup_socket(domain: str) -> Optional[List[str]]:
    """Resolve a domain using Python's built-in socket library (fallback)."""
    logger = logging.getLogger(__name__)
    try:
        addr_info = socket.getaddrinfo(domain, None)
        ip_addresses = list(dict.fromkeys(addr[4][0] for addr in addr_info))
        logger.info(f"Resolved {domain} to {len(ip_addresses)} address(es)")
        return ip_addresses
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {domain}: {e}")
        return None


def dns_lookup(domain: str) -> Optional[List[str]]:
    """
    Resolve a domain name to its associated IP addresses.

    Queries both IPv4 (A) and IPv6 (AAAA) records when dnspython
    is available. Falls back to socket.getaddrinfo otherwise.

    Args:
        domain: The domain name to resolve (e.g., 'example.com').

    Returns:
        A list of IP address strings, or None if resolution fails.

    Raises:
        ValueError: If the domain parameter is empty.
    """
    logger = logging.getLogger(__name__)

    if not domain or not domain.strip():
        raise ValueError("Domain cannot be empty or whitespace.")

    domain = domain.strip()
    logger.info(f"Performing DNS lookup for: {domain}")

    if DNSPYTHON_AVAILABLE:
        return _dns_lookup_dnspython(domain)
    return _dns_lookup_socket(domain)


def _dns_reverse_dnspython(ip_address: str) -> Optional[str]:
    """Reverse DNS lookup using dnspython."""
    logger = logging.getLogger(__name__)
    try:
        reverse_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        hostname = str(answers[0]).rstrip(".")
        logger.info(f"Reverse lookup for {ip_address}: {hostname}")
        return hostname
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
        logger.warning(f"No reverse DNS entry for {ip_address}: {e}")
        return None


def _dns_reverse_socket(ip_address: str) -> Optional[str]:
    """Reverse DNS lookup using socket (fallback)."""
    logger = logging.getLogger(__name__)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        logger.info(f"Reverse lookup for {ip_address}: {hostname}")
        return hostname
    except (socket.herror, socket.gaierror, OSError) as e:
        logger.warning(f"Reverse DNS lookup failed for {ip_address}: {e}")
        return None


def dns_reverse_lookup(ip_address: str) -> Optional[str]:
    """
    Perform a reverse DNS lookup to find the hostname for an IP.

    Args:
        ip_address: The IP address to look up (e.g., '8.8.8.8').

    Returns:
        The resolved hostname, or None if no PTR record exists.

    Raises:
        ValueError: If the ip_address parameter is empty.
    """
    if not ip_address or not ip_address.strip():
        raise ValueError("IP address cannot be empty or whitespace.")

    ip_address = ip_address.strip()
    logging.getLogger(__name__).info(f"Performing reverse DNS lookup for: {ip_address}")

    if DNSPYTHON_AVAILABLE:
        return _dns_reverse_dnspython(ip_address)
    return _dns_reverse_socket(ip_address)


def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """
    Retrieve multiple DNS record types for a domain.

    Queries A, AAAA, MX, NS, TXT, CNAME, and SOA records using
    dnspython. If dnspython is not installed, only A/AAAA records
    are returned via the socket fallback.

    Args:
        domain: The domain name to query.

    Returns:
        A dictionary mapping record type strings to lists of values.

    Raises:
        ValueError: If the domain parameter is empty.
    """
    logger = logging.getLogger(__name__)

    if not domain or not domain.strip():
        raise ValueError("Domain cannot be empty or whitespace.")

    domain = domain.strip()
    logger.info(f"Querying DNS records for: {domain}")

    records: Dict[str, List[str]] = {}

    if DNSPYTHON_AVAILABLE:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata).rstrip(".") for rdata in answers]
                logger.debug(f"Found {len(records[rtype])} {rtype} record(s)")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                logger.debug(f"No {rtype} records found for {domain}")
    else:
        ips = _dns_lookup_socket(domain)
        if ips:
            ipv4 = [ip for ip in ips if "." in ip and ":" not in ip]
            ipv6 = [ip for ip in ips if ":" in ip]
            if ipv4:
                records["A"] = ipv4
            if ipv6:
                records["AAAA"] = ipv6

    logger.info(f"Retrieved {len(records)} record type(s) for {domain}")
    return records


# ===========================================================================
#  SECTION 4 — IP INFORMATION MODULE
# ===========================================================================
# Gathers local and remote IP address information, hostname details,
# and network interface addresses using Python's socket library.
# ===========================================================================

# Public DNS resolver used as a probe target for local IP detection
_PROBE_HOST = "8.8.8.8"
_PROBE_PORT = 80


def get_local_ip() -> Optional[str]:
    """
    Determine the local machine's preferred outbound IP address.

    Creates a UDP socket and connects it to a public DNS resolver
    (8.8.8.8). No data is sent — the connection merely lets the OS
    select the correct source IP for that destination.

    Returns:
        The local IP address as a string, or None if undetectable.
    """
    logger = logging.getLogger(__name__)
    logger.info("Detecting local IP address")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect((_PROBE_HOST, _PROBE_PORT))
            local_ip = sock.getsockname()[0]
        logger.info(f"Local IP address: {local_ip}")
        return local_ip
    except (socket.error, OSError) as e:
        logger.error(f"Failed to detect local IP: {e}")
        return None


def get_hostname() -> str:
    """
    Retrieve the local machine's hostname.

    Returns:
        The hostname string, or 'unknown' if unavailable.
    """
    logger = logging.getLogger(__name__)
    logger.info("Retrieving local hostname")
    try:
        hostname = socket.gethostname()
        logger.info(f"Local hostname: {hostname}")
        return hostname
    except Exception as e:
        logger.error(f"Failed to retrieve hostname: {e}")
        return "unknown"


def get_remote_ip_info(domain: str) -> Optional[Dict[str, str]]:
    """
    Gather IP address and hostname information for a remote host.

    Performs a forward DNS lookup and attempts to retrieve the FQDN
    and any alias hostnames.

    Args:
        domain: The domain name or IP address to look up.

    Returns:
        A dictionary with keys 'domain', 'ip', 'fqdn', 'aliases',
        or None if the domain cannot be resolved.

    Raises:
        ValueError: If the domain parameter is empty.
    """
    logger = logging.getLogger(__name__)

    if not domain or not domain.strip():
        raise ValueError("Domain cannot be empty or whitespace.")

    domain = domain.strip()
    logger.info(f"Gathering IP information for: {domain}")

    try:
        ip_address = socket.gethostbyname(domain)
        fqdn = socket.getfqdn(domain)

        info = {"domain": domain, "ip": ip_address, "fqdn": fqdn}

        try:
            _, aliases, _ = socket.gethostbyname_ex(domain)
            info["aliases"] = ", ".join(aliases) if aliases else "None"
        except Exception:
            info["aliases"] = "None"

        logger.info(f"Remote info for {domain}: IP={ip_address}, FQDN={fqdn}")
        return info

    except socket.gaierror as e:
        logger.warning(f"Cannot resolve {domain}: {e}")
        return None


def get_network_interfaces() -> List[Dict[str, str]]:
    """
    List network interface addresses on the local machine.

    Returns:
        A list of dicts with 'address' and 'family' (IPv4/IPv6) keys.
    """
    logger = logging.getLogger(__name__)
    logger.info("Enumerating network interfaces")

    interfaces = []
    hostname = get_hostname()

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        family_map = {socket.AF_INET: "IPv4", socket.AF_INET6: "IPv6"}
        seen = set()

        for addr in addr_info:
            family = family_map.get(addr[0], "Unknown")
            ip_address = addr[4][0]
            if ip_address not in seen:
                seen.add(ip_address)
                interfaces.append({"address": ip_address, "family": family})

        logger.info(f"Found {len(interfaces)} unique interface address(es)")
    except Exception as e:
        logger.error(f"Failed to enumerate interfaces: {e}")

    return interfaces


# ===========================================================================
#  SECTION 5 — PORT SCANNER MODULE
# ===========================================================================
# Multi-threaded TCP port scanner using socket programming.
# Supports user-specified ports, port ranges, and a curated list of
# common service ports. Uses concurrent.futures for parallelism.
# ===========================================================================

# Well-known ports commonly evaluated during security assessments
COMMON_PORTS = {
    20: "FTP-Data",      21: "FTP",           22: "SSH",
    23: "Telnet",        25: "SMTP",           53: "DNS",
    67: "DHCP-Server",   68: "DHCP-Client",    69: "TFTP",
    80: "HTTP",         110: "POP3",          119: "NNTP",
    123: "NTP",         143: "IMAP",          161: "SNMP",
    194: "IRC",         443: "HTTPS",         445: "SMB",
    465: "SMTPS",       514: "Syslog",        587: "SMTP-Submission",
    993: "IMAPS",       995: "POP3S",        1080: "SOCKS",
    1433: "MSSQL",     1521: "Oracle-DB",    3306: "MySQL",
    3389: "RDP",       5432: "PostgreSQL",   5900: "VNC",
    6379: "Redis",      8080: "HTTP-Alt",    8443: "HTTPS-Alt",
    8888: "HTTP-Proxy", 9090: "OpenFire",   27017: "MongoDB",
}

MAX_WORKERS = 100  # Thread pool size for concurrent scanning


def scan_port(host: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
    """
    Scan a single TCP port on a target host.

    Attempts a TCP connection (three-way handshake). If the connection
    succeeds, the port is considered open.

    Args:
        host: The hostname or IP address to scan.
        port: The TCP port number (1-65535).
        timeout: Connection timeout in seconds (default: 1.0).

    Returns:
        A dict with 'port', 'service', and 'state' if open, else None.
    """
    logger = logging.getLogger(__name__)

    if not (1 <= port <= 65535):
        logger.error(f"Invalid port number: {port}")
        return None

    service = COMMON_PORTS.get(port, "Unknown")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                logger.debug(f"Port {port} ({service}) is OPEN on {host}")
                return {"port": port, "service": service, "state": "open"}
            else:
                logger.debug(f"Port {port} is closed/filtered on {host}")
                return None

    except socket.gaierror:
        logger.error(f"Cannot resolve hostname: {host}")
        return None
    except socket.error as e:
        logger.debug(f"Socket error on port {port}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error scanning port {port}: {e}")
        return None


def scan_ports(host: str, ports: List[int], timeout: float = 1.0) -> List[Dict]:
    """
    Scan multiple TCP ports on a target host concurrently.

    Uses a thread pool to scan ports in parallel. Only open ports
    are included in the results.

    Args:
        host: The hostname or IP address to scan.
        ports: A list of port numbers to scan.
        timeout: Per-port connection timeout in seconds (default: 1.0).

    Returns:
        A sorted list of dicts with 'port', 'service', 'state' for
        open ports only.

    Raises:
        ValueError: If the host parameter is empty.
    """
    logger = logging.getLogger(__name__)

    if not host or not host.strip():
        raise ValueError("Host cannot be empty or whitespace.")

    host = host.strip()
    logger.info(f"Starting port scan on {host}: {len(ports)} port(s)")

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    logger.info(f"Scan complete: {len(open_ports)} open port(s) found on {host}")
    return open_ports


def scan_common_ports(host: str, timeout: float = 1.0) -> List[Dict]:
    """
    Scan a curated list of well-known service ports on a target host.

    Convenience function that scans the most commonly encountered
    service ports (defined in COMMON_PORTS).

    Args:
        host: The hostname or IP address to scan.
        timeout: Per-port connection timeout in seconds (default: 1.0).

    Returns:
        A sorted list of dicts for open ports.
    """
    return scan_ports(host, list(COMMON_PORTS.keys()), timeout)


def parse_port_range(port_string: str) -> List[int]:
    """
    Parse a user-provided port specification into a list of port numbers.

    Supports single ports ("80"), comma-separated ("80,443"),
    ranges ("1-1024"), and mixed ("22,80,443,8000-9000").

    Args:
        port_string: A string describing the ports to include.

    Returns:
        A sorted list of unique, valid port numbers.

    Raises:
        ValueError: If the port_string is empty or yields no valid ports.
    """
    logger = logging.getLogger(__name__)

    if not port_string or not port_string.strip():
        raise ValueError("Port specification cannot be empty.")

    ports = set()

    for part in port_string.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            try:
                start_str, end_str = part.split("-", 1)
                start = int(start_str.strip())
                end = int(end_str.strip())
                if start > end:
                    logger.warning(f"Invalid range {part}: start > end, skipping")
                    continue
                for port in range(start, end + 1):
                    if 1 <= port <= 65535:
                        ports.add(port)
                    else:
                        logger.warning(f"Port {port} out of range, skipping")
            except ValueError:
                logger.warning(f"Invalid port range format: {part}, skipping")
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    logger.warning(f"Port {port} out of range, skipping")
            except ValueError:
                logger.warning(f"Invalid port number: {part}, skipping")

    if not ports:
        raise ValueError("No valid ports found in the provided specification.")

    sorted_ports = sorted(ports)
    logger.debug(f"Parsed {len(sorted_ports)} unique port(s) from input")
    return sorted_ports


# ===========================================================================
#  SECTION 6 — BANNER GRABBER MODULE
# ===========================================================================
# Retrieves service banners from open ports. Banner grabbing reveals
# software names, versions, and configuration details. Some services
# (SSH, FTP) send banners immediately; HTTP servers require a probe.
# ===========================================================================

# Probes sent to elicit banner responses from HTTP-like services
_SERVICE_PROBES = {
    80:   "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    443:  "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    8080: "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    8443: "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    8888: "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
}

_MAX_BANNER_LENGTH = 4096


def _sanitize_banner(banner: str) -> str:
    """
    Clean a raw banner string for safe terminal display.

    Replaces non-printable characters, collapses blank lines,
    and truncates very long banners to a reasonable length.
    """
    sanitized = ""
    for char in banner:
        if char in ("\n", "\r", "\t"):
            sanitized += char
        elif 32 <= ord(char) <= 126:
            sanitized += char
        else:
            sanitized += "."

    lines = [line.strip() for line in sanitized.split("\n") if line.strip()]
    result = "\n".join(lines)

    if len(result) > 512:
        result = result[:509] + "..."

    return result.strip()


def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Attempt to retrieve the service banner from a specific port.

    Connects via TCP and reads the initial data. For HTTP services
    a HEAD request probe is sent to trigger a response.

    Args:
        host: The hostname or IP address of the target.
        port: The TCP port number to grab the banner from.
        timeout: Socket timeout in seconds (default: 3.0).

    Returns:
        The banner string if retrieved, or None on failure.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Attempting banner grab on {host}:{port}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send probe for HTTP-like services
            if port in _SERVICE_PROBES:
                probe = _SERVICE_PROBES[port].format(host=host)
                sock.sendall(probe.encode("utf-8", errors="ignore"))

            banner_bytes = sock.recv(_MAX_BANNER_LENGTH)
            if not banner_bytes:
                logger.debug(f"No banner data received from {host}:{port}")
                return None

            banner = _sanitize_banner(
                banner_bytes.decode("utf-8", errors="replace")
            )
            if banner:
                logger.info(f"Banner retrieved from {host}:{port}: {banner[:80]}...")
            return banner if banner else None

    except socket.timeout:
        logger.debug(f"Banner grab timed out on {host}:{port}")
        return None
    except ConnectionRefusedError:
        logger.debug(f"Connection refused on {host}:{port}")
        return None
    except socket.gaierror:
        logger.error(f"Cannot resolve hostname: {host}")
        return None
    except OSError as e:
        logger.debug(f"OS error during banner grab on {host}:{port}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error grabbing banner from {host}:{port}: {e}")
        return None


def grab_banners(host: str, ports: List[int], timeout: float = 3.0) -> List[Dict]:
    """
    Retrieve service banners from multiple open ports.

    Args:
        host: The hostname or IP address of the target.
        ports: A list of TCP port numbers.
        timeout: Per-port socket timeout in seconds (default: 3.0).

    Returns:
        A sorted list of dicts with 'port' and 'banner' keys.

    Raises:
        ValueError: If the host parameter is empty.
    """
    logger = logging.getLogger(__name__)

    if not host or not host.strip():
        raise ValueError("Host cannot be empty or whitespace.")

    host = host.strip()
    logger.info(f"Starting banner grab on {host} for {len(ports)} port(s)")

    results = []
    for port in sorted(ports):
        banner = grab_banner(host, port, timeout)
        results.append({
            "port": port,
            "banner": banner if banner else "No banner available",
        })

    successful = sum(1 for r in results if r["banner"] != "No banner available")
    logger.info(f"Banner grab complete: {successful}/{len(ports)} banner(s) retrieved")
    return results


# ===========================================================================
#  SECTION 7 — TRACEROUTE MODULE
# ===========================================================================
# Displays the network path (hop-by-hop) to a target host. Uses the
# system's native traceroute (Linux/macOS) or tracert (Windows).
# Falls back to 'tracepath' when traceroute is unavailable on Linux.
# ===========================================================================

def _detect_traceroute_command() -> str:
    """
    Determine the appropriate traceroute command for the current OS.

    Returns:
        The command name string ('traceroute', 'tracepath', or 'tracert').

    Raises:
        FileNotFoundError: If no suitable command is found.
    """
    logger = logging.getLogger(__name__)

    if platform.system().lower() == "windows":
        return "tracert"

    for cmd in ("traceroute", "tracepath"):
        try:
            result = subprocess.run(
                ["which", cmd], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.debug(f"Found traceroute command: {cmd}")
                return cmd
        except Exception:
            continue

    raise FileNotFoundError(
        "Neither 'traceroute' nor 'tracepath' found. "
        "Install with: sudo apt install traceroute"
    )


def _parse_traceroute_output(output: str, command: str) -> List[Dict]:
    """
    Parse raw traceroute/tracert/tracepath output into structured hop data.

    Handles the different output formats from Linux traceroute,
    Linux tracepath, and Windows tracert using regex patterns.

    Args:
        output: The raw stdout from the traceroute command.
        command: The command name used.

    Returns:
        A list of hop dicts with 'hop', 'host', 'latency', 'status'.
    """
    logger = logging.getLogger(__name__)
    hops = []
    lines = output.strip().split("\n")
    system = platform.system().lower()

    if system == "windows":
        # Windows tracert format:
        #   1    <1 ms    <1 ms    <1 ms  192.168.1.1
        pattern = re.compile(r"^\s*(\d+)\s+(.+?)\s+(\S+)\s*$")
        for line in lines:
            match = pattern.match(line)
            if match:
                hop_num = int(match.group(1))
                host_info = match.group(3).strip()
                if "timed out" in host_info.lower() or host_info == "*":
                    hops.append({"hop": hop_num, "host": "*", "latency": "timeout", "status": "timeout"})
                else:
                    latencies = re.findall(r"(\d+)\s*ms", match.group(2))
                    avg = f"{sum(int(l) for l in latencies) / len(latencies):.1f} ms" if latencies else "N/A"
                    hops.append({"hop": hop_num, "host": host_info, "latency": avg, "status": "ok"})

    elif command == "tracepath":
        # tracepath format:
        #   2:  192.168.1.1   1.234ms
        for line in lines:
            match = re.match(r"^\s*(\d+):?\s+(\S+)\s+.*?(\d+\.\d+)\s*ms", line)
            if match:
                hops.append({"hop": int(match.group(1)), "host": match.group(2),
                             "latency": f"{float(match.group(3)):.3f} ms", "status": "ok"})
            elif "no reply" in line.lower():
                hop_match = re.match(r"^\s*(\d+)", line)
                if hop_match:
                    hops.append({"hop": int(hop_match.group(1)), "host": "*",
                                 "latency": "timeout", "status": "timeout"})

    else:
        # Linux traceroute format:
        #   1  192.168.1.1 (192.168.1.1)  1.234 ms  0.987 ms  1.012 ms
        #   2  * * *
        for line in lines:
            hop_match = re.match(r"^\s*(\d+)\s+", line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                if "*" in line and not re.search(r"\d+\.\d+\s*ms", line):
                    hops.append({"hop": hop_num, "host": "*", "latency": "timeout", "status": "timeout"})
                else:
                    host_ip = re.search(r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)", line)
                    if host_ip:
                        hostname, ip = host_ip.group(1), host_ip.group(2)
                        display = f"{hostname} ({ip})" if hostname != ip else ip
                    else:
                        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        display = ip_match.group(1) if ip_match else "unknown"
                    lats = re.findall(r"(\d+\.\d+)\s*ms", line)
                    avg = f"{sum(float(l) for l in lats) / len(lats):.3f} ms" if lats else "N/A"
                    hops.append({"hop": hop_num, "host": display, "latency": avg, "status": "ok"})

    return hops


def traceroute(host: str, max_hops: int = 30, timeout: int = 5) -> Optional[List[Dict]]:
    """
    Trace the network path from the local host to a target destination.

    Executes the system's traceroute/tracert command and parses the
    output into a structured list of hop information.

    Args:
        host: The target hostname or IP address.
        max_hops: Maximum number of hops to trace (default: 30).
        timeout: Per-hop timeout in seconds (default: 5).

    Returns:
        A list of dicts with 'hop', 'host', 'latency', 'status',
        or None if the command fails entirely.

    Raises:
        ValueError: If the host parameter is empty.
    """
    logger = logging.getLogger(__name__)

    if not host or not host.strip():
        raise ValueError("Host cannot be empty or whitespace.")

    host = host.strip()
    logger.info(f"Starting traceroute to {host} (max_hops={max_hops})")

    try:
        command_name = _detect_traceroute_command()
    except FileNotFoundError as e:
        logger.error(str(e))
        return None

    system = platform.system().lower()
    if system == "windows":
        command = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), host]
    elif command_name == "traceroute":
        command = ["traceroute", "-m", str(max_hops), "-w", str(timeout), host]
    else:
        command = ["tracepath", "-m", str(max_hops), host]

    try:
        logger.debug(f"Executing: {' '.join(command)}")
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=max_hops * timeout + 30,
        )
        raw_output = result.stdout
        if not raw_output:
            logger.warning(f"No traceroute output for {host}")
            return None

        hops = _parse_traceroute_output(raw_output, command_name)
        logger.info(f"Traceroute to {host} complete: {len(hops)} hop(s) recorded")
        return hops

    except subprocess.TimeoutExpired:
        logger.error(f"Traceroute to {host} timed out")
        return None
    except FileNotFoundError:
        logger.error(f"Command '{command_name}' not found on this system")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during traceroute to {host}: {e}")
        return None


# ===========================================================================
#  SECTION 8 — LOGGING CONFIGURATION
# ===========================================================================
# Configures file and console logging. Log files are written to the
# 'logs/' directory next to main.py with timestamps. Console output
# is limited to WARNING+ to keep the interactive menu clean.
# ===========================================================================

def setup_logging() -> logging.Logger:
    """
    Configure application-wide logging to file and console.

    Creates a timestamped log file in the logs/ directory alongside
    main.py. File handler captures DEBUG+; console handler shows
    WARNING+ only.

    Returns:
        The root logger instance.
    """
    # Determine the directory where main.py lives (or cwd if frozen)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_filename = datetime.datetime.now().strftime("network_utils_%Y%m%d_%H%M%S.log")
    log_path = os.path.join(log_dir, log_filename)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # File handler — full debug output
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    # Console handler — warnings and errors only
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter(
        f"{Colors.YELLOW}[%(levelname)s]{Colors.RESET} %(message)s"
    ))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info("=" * 60)
    logger.info("Network Utils session started")
    logger.info(f"Log file: {log_path}")
    logger.info("=" * 60)

    return logger


# ===========================================================================
#  SECTION 9 — DISPLAY HELPERS
# ===========================================================================
# Functions for the interactive terminal UI: ASCII banner, menu,
# colored status messages, and user input helpers.
# ===========================================================================

def print_banner():
    """Display the application's ASCII art banner and version info."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                             ║
  ║   ███╗   ██╗███████╗████████╗ █████╗ ██╗      █████╗ ██╗   ║
  ║   ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██╔══██╗██║   ║
  ║   ██╔██╗ ██║█████╗     ██║   ███████║██║     ███████║██║   ║
  ║   ██║╚██╗██║██╔══╝     ██║   ██╔══██║██║     ██╔══██║██║   ║
  ║   ██║ ╚████║███████╗   ██║   ██║  ██║███████╗██║  ██║██║   ║
  ║   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝   ║
  ║                                                             ║
  ║            N E T W O R K   U T I L S  v1.0.0                ║
  ║                                                             ║
  ║       A Cybersecurity Student's Network Toolkit             ║
  ║                                                             ║
  ╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.DIM}  ⚠  For educational and authorized testing purposes only.{Colors.RESET}
"""
    print(banner)


def print_menu():
    """Display the main menu options with colored, numbered choices."""
    print(f"\n{Colors.BOLD}{Colors.WHITE}{'─' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}  MAIN MENU{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}{'─' * 55}{Colors.RESET}")
    print(f"""
  {Colors.GREEN}[1]{Colors.RESET}  Ping Host            {Colors.DIM}— Check host reachability{Colors.RESET}
  {Colors.GREEN}[2]{Colors.RESET}  DNS Lookup           {Colors.DIM}— Resolve domain names{Colors.RESET}
  {Colors.GREEN}[3]{Colors.RESET}  IP Information       {Colors.DIM}— View hostname & IP info{Colors.RESET}
  {Colors.GREEN}[4]{Colors.RESET}  Port Scanner         {Colors.DIM}— Scan for open ports{Colors.RESET}
  {Colors.GREEN}[5]{Colors.RESET}  Banner Grabbing      {Colors.DIM}— Retrieve service banners{Colors.RESET}
  {Colors.GREEN}[6]{Colors.RESET}  Traceroute           {Colors.DIM}— Trace network path{Colors.RESET}
  {Colors.GREEN}[0]{Colors.RESET}  Exit                 {Colors.DIM}— Quit the application{Colors.RESET}
""")
    print(f"{Colors.BOLD}{Colors.WHITE}{'─' * 55}{Colors.RESET}")


def print_section_header(title: str):
    """Print a visually distinct section header for tool output."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 55}")
    print(f"  {title}")
    print(f"{'═' * 55}{Colors.RESET}\n")


def print_success(message: str):
    """Print a success message in green with a checkmark."""
    print(f"  {Colors.GREEN}[✓]{Colors.RESET} {message}")


def print_error(message: str):
    """Print an error message in red with an X mark."""
    print(f"  {Colors.RED}[✗]{Colors.RESET} {message}")


def print_info(message: str):
    """Print an informational message in blue with an info icon."""
    print(f"  {Colors.BLUE}[i]{Colors.RESET} {message}")


def print_warning(message: str):
    """Print a warning message in yellow with an exclamation icon."""
    print(f"  {Colors.YELLOW}[!]{Colors.RESET} {message}")


def get_input(prompt: str) -> str:
    """
    Get user input with a styled prompt.

    Returns:
        The user's input stripped of whitespace, or empty string on
        interrupt.
    """
    try:
        return input(f"  {Colors.BOLD}{Colors.WHITE}{prompt}{Colors.RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return ""


def confirm_action(prompt: str) -> bool:
    """Ask the user for a yes/no confirmation. Returns True on y/yes."""
    response = get_input(f"{prompt} (y/N):").lower()
    return response in ("y", "yes")


# ===========================================================================
#  SECTION 10 — MENU HANDLERS
# ===========================================================================
# Each handler corresponds to a menu option. They handle user input,
# invoke the appropriate tool function, and format the output.
# ===========================================================================

def handle_ping():
    """Handle the Ping Host menu option."""
    print_section_header("PING HOST")

    host = get_input("Enter target host (e.g., example.com or 8.8.8.8):")
    if not host:
        print_error("No host provided. Returning to menu.")
        return

    count_input = get_input("Number of echo requests (default: 4):")
    try:
        count = int(count_input) if count_input else 4
        if count < 1 or count > 20:
            print_warning("Count must be between 1-20. Using default (4).")
            count = 4
    except ValueError:
        print_warning("Invalid count. Using default (4).")
        count = 4

    print_info(f"Pinging {host} with {count} request(s)...\n")
    result = ping_host(host, count)

    if result:
        print(result)
        print()
        print_success(f"Ping to {host} completed")
    else:
        print_error(f"Could not reach {host}. Check the hostname or network.")


def handle_dns_lookup():
    """Handle the DNS Lookup menu option."""
    print_section_header("DNS LOOKUP")

    print(f"  {Colors.GREEN}[1]{Colors.RESET} Forward Lookup (Domain → IP)")
    print(f"  {Colors.GREEN}[2]{Colors.RESET} Reverse Lookup (IP → Domain)")
    print(f"  {Colors.GREEN}[3]{Colors.RESET} Full DNS Records")

    choice = get_input("Select lookup type:")

    if choice == "1":
        domain = get_input("Enter domain name (e.g., example.com):")
        if not domain:
            print_error("No domain provided. Returning to menu.")
            return
        print_info(f"Resolving {domain}...\n")
        ips = dns_lookup(domain)
        if ips:
            print_success(f"Resolved {domain} to {len(ips)} address(es):")
            for ip in ips:
                ip_type = "IPv6" if ":" in ip else "IPv4"
                print(f"    {Colors.CYAN}{ip}{Colors.RESET} ({ip_type})")
        else:
            print_error(f"Could not resolve {domain}")

    elif choice == "2":
        ip_address = get_input("Enter IP address (e.g., 8.8.8.8):")
        if not ip_address:
            print_error("No IP address provided. Returning to menu.")
            return
        print_info(f"Performing reverse lookup for {ip_address}...\n")
        hostname = dns_reverse_lookup(ip_address)
        if hostname:
            print_success(f"Reverse DNS for {ip_address}:")
            print(f"    {Colors.CYAN}{hostname}{Colors.RESET}")
        else:
            print_error(f"No reverse DNS entry found for {ip_address}")

    elif choice == "3":
        domain = get_input("Enter domain name (e.g., example.com):")
        if not domain:
            print_error("No domain provided. Returning to menu.")
            return
        print_info(f"Querying DNS records for {domain}...\n")
        records = get_dns_records(domain)
        if records:
            print_success(f"DNS records for {domain}:")
            print(f"\n    {'Type':<8} {'Value'}")
            print(f"    {'─' * 8} {'─' * 45}")
            for rtype, values in records.items():
                for value in values:
                    print(f"    {Colors.CYAN}{rtype:<8}{Colors.RESET} {value}")
        else:
            print_error(f"No DNS records found for {domain}")
    else:
        print_warning("Invalid choice. Returning to menu.")


def handle_ip_info():
    """Handle the IP Information menu option."""
    print_section_header("IP INFORMATION")

    print(f"  {Colors.BOLD}Local Host Information{Colors.RESET}\n")

    hostname = get_hostname()
    local_ip = get_local_ip()

    print(f"    {'Hostname':<16} {Colors.CYAN}{hostname}{Colors.RESET}")
    print(f"    {'Local IP':<16} {Colors.CYAN}{local_ip or 'Unavailable'}{Colors.RESET}")

    interfaces = get_network_interfaces()
    if interfaces:
        print(f"\n    {'Address':<40} {'Family'}")
        print(f"    {'─' * 40} {'─' * 8}")
        for iface in interfaces:
            print(f"    {Colors.CYAN}{iface['address']:<40}{Colors.RESET} {iface['family']}")

    print()
    if confirm_action("Look up a remote host?"):
        domain = get_input("Enter domain or IP:")
        if domain:
            print()
            info = get_remote_ip_info(domain)
            if info:
                print_success(f"Information for {domain}:")
                print(f"    {'Domain':<16} {Colors.CYAN}{info.get('domain', 'N/A')}{Colors.RESET}")
                print(f"    {'IP Address':<16} {Colors.CYAN}{info.get('ip', 'N/A')}{Colors.RESET}")
                print(f"    {'FQDN':<16} {Colors.CYAN}{info.get('fqdn', 'N/A')}{Colors.RESET}")
                print(f"    {'Aliases':<16} {Colors.CYAN}{info.get('aliases', 'N/A')}{Colors.RESET}")
            else:
                print_error(f"Could not retrieve information for {domain}")


def handle_port_scanner():
    """Handle the Port Scanner menu option."""
    print_section_header("PORT SCANNER")

    print_warning("Only scan hosts you own or have authorization to test.\n")

    host = get_input("Enter target host:")
    if not host:
        print_error("No host provided. Returning to menu.")
        return

    print(f"\n  {Colors.GREEN}[1]{Colors.RESET} Scan common ports (top ~30 services)")
    print(f"  {Colors.GREEN}[2]{Colors.RESET} Scan specific ports")

    choice = get_input("Select scan type:")

    if choice == "1":
        timeout_input = get_input("Timeout per port in seconds (default: 1.0):")
        try:
            timeout = float(timeout_input) if timeout_input else 1.0
        except ValueError:
            timeout = 1.0
        print_info(f"Scanning common ports on {host}...\n")
        open_ports = scan_common_ports(host, timeout)

    elif choice == "2":
        port_input = get_input("Enter ports (e.g., 22,80,443 or 1-1024):")
        if not port_input:
            print_error("No ports specified. Returning to menu.")
            return
        try:
            ports = parse_port_range(port_input)
        except ValueError as e:
            print_error(f"Invalid port specification: {e}")
            return
        timeout_input = get_input("Timeout per port in seconds (default: 1.0):")
        try:
            timeout = float(timeout_input) if timeout_input else 1.0
        except ValueError:
            timeout = 1.0
        print_info(f"Scanning {len(ports)} port(s) on {host}...\n")
        open_ports = scan_ports(host, ports, timeout)

    else:
        print_warning("Invalid choice. Returning to menu.")
        return

    # Display results
    if open_ports:
        print_success(f"Found {len(open_ports)} open port(s) on {host}:")
        print(f"\n    {'Port':<10} {'State':<10} {'Service'}")
        print(f"    {'─' * 10} {'─' * 10} {'─' * 25}")
        for port_info in open_ports:
            port_str = f"{port_info['port']}/tcp"
            state = port_info["state"]
            service = port_info["service"]
            state_colored = f"{Colors.GREEN}{state}{Colors.RESET}" if state == "open" else state
            print(f"    {Colors.CYAN}{port_str:<10}{Colors.RESET} {state_colored:<18} {service}")

        # Offer banner grabbing
        print()
        if confirm_action("Grab banners from open ports?"):
            open_port_numbers = [p["port"] for p in open_ports]
            print_info("Retrieving service banners...\n")
            banners = grab_banners(host, open_port_numbers)
            print(f"    {'Port':<10} {'Banner'}")
            print(f"    {'─' * 10} {'─' * 45}")
            for b in banners:
                port_str = f"{b['port']}/tcp"
                banner_text = b["banner"]
                if len(banner_text) > 60:
                    banner_text = banner_text[:57] + "..."
                print(f"    {Colors.CYAN}{port_str:<10}{Colors.RESET} {banner_text}")
    else:
        print_warning(f"No open ports found on {host}")


def handle_banner_grab():
    """Handle the Banner Grabbing menu option."""
    print_section_header("BANNER GRABBING")

    print_warning("Ensure you have authorization before probing services.\n")

    host = get_input("Enter target host:")
    if not host:
        print_error("No host provided. Returning to menu.")
        return

    port_input = get_input("Enter port(s), comma-separated (e.g., 22,80,443):")
    if not port_input:
        print_error("No ports specified. Returning to menu.")
        return

    try:
        ports = [int(p.strip()) for p in port_input.split(",") if p.strip()]
        ports = [p for p in ports if 1 <= p <= 65535]
    except ValueError:
        print_error("Invalid port format. Use comma-separated numbers.")
        return

    if not ports:
        print_error("No valid ports provided. Returning to menu.")
        return

    timeout_input = get_input("Timeout in seconds (default: 3.0):")
    try:
        timeout = float(timeout_input) if timeout_input else 3.0
    except ValueError:
        timeout = 3.0

    print_info(f"Grabbing banners from {host} on {len(ports)} port(s)...\n")
    results = grab_banners(host, ports, timeout)

    print(f"    {'Port':<10} {'Banner'}")
    print(f"    {'─' * 10} {'─' * 50}")
    for r in results:
        port_str = f"{r['port']}/tcp"
        banner = r["banner"]
        if banner != "No banner available":
            print(f"    {Colors.CYAN}{port_str:<10}{Colors.RESET} {Colors.GREEN}{banner}{Colors.RESET}")
        else:
            print(f"    {Colors.CYAN}{port_str:<10}{Colors.RESET} {Colors.DIM}{banner}{Colors.RESET}")


def handle_traceroute():
    """Handle the Traceroute menu option."""
    print_section_header("TRACEROUTE")

    host = get_input("Enter target host (e.g., example.com):")
    if not host:
        print_error("No host provided. Returning to menu.")
        return

    hops_input = get_input("Maximum hops (default: 30):")
    try:
        max_hops = int(hops_input) if hops_input else 30
        if max_hops < 1 or max_hops > 64:
            print_warning("Hops must be between 1-64. Using default (30).")
            max_hops = 30
    except ValueError:
        max_hops = 30

    print_info(f"Tracing route to {host} (max {max_hops} hops)...\n")
    hops = traceroute(host, max_hops=max_hops)

    if hops:
        print_success(f"Traceroute to {host} — {len(hops)} hop(s):\n")
        print(f"    {'Hop':<6} {'Host':<45} {'Latency'}")
        print(f"    {'─' * 6} {'─' * 45} {'─' * 15}")

        for hop in hops:
            hop_num = str(hop["hop"])
            hop_host = hop["host"]
            latency = hop["latency"]
            status = hop["status"]

            if status == "timeout":
                hop_host_colored = f"{Colors.DIM}{hop_host}{Colors.RESET}"
                latency_colored = f"{Colors.YELLOW}{latency}{Colors.RESET}"
            else:
                hop_host_colored = f"{Colors.CYAN}{hop_host}{Colors.RESET}"
                latency_colored = f"{Colors.GREEN}{latency}{Colors.RESET}"

            print(f"    {hop_num:<6} {hop_host_colored:<55} {latency_colored}")
    else:
        print_error(f"Traceroute to {host} failed. Check the hostname or network.")


# ===========================================================================
#  SECTION 11 — MAIN APPLICATION LOOP
# ===========================================================================
# Entry point. Initializes logging, shows the banner, and enters the
# interactive menu loop until the user exits or presses Ctrl+C.
# ===========================================================================

def main():
    """
    Main entry point for the Network Utils application.

    Initializes logging, displays the ASCII banner, and enters the
    interactive menu loop. The loop continues until the user selects
    exit (0) or sends an interrupt signal (Ctrl+C).
    """
    # Initialize logging
    logger = setup_logging()

    # Display the application banner
    print_banner()

    # Map menu choices to handler functions
    menu_handlers = {
        "1": handle_ping,
        "2": handle_dns_lookup,
        "3": handle_ip_info,
        "4": handle_port_scanner,
        "5": handle_banner_grab,
        "6": handle_traceroute,
    }

    # Main application loop
    while True:
        try:
            print_menu()
            choice = get_input("Select an option:")

            if choice == "0":
                print(f"\n{Colors.CYAN}{Colors.BOLD}  Thank you for using Network Utils!{Colors.RESET}")
                print(f"{Colors.DIM}  Stay curious. Stay ethical.{Colors.RESET}\n")
                logger.info("Application exited by user")
                break

            handler = menu_handlers.get(choice)
            if handler:
                handler()
            else:
                print_warning("Invalid option. Please select 0-6.")

            # Pause before returning to menu
            print()
            get_input(f"{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        except KeyboardInterrupt:
            print(f"\n\n{Colors.CYAN}{Colors.BOLD}  Interrupted. Exiting...{Colors.RESET}")
            logger.info("Application interrupted by user (Ctrl+C)")
            break

        except Exception as e:
            print_error(f"An unexpected error occurred: {e}")
            logger.exception(f"Unhandled exception in main loop: {e}")

    # Cleanup
    logger.info("Network Utils session ended")
    logging.shutdown()


if __name__ == "__main__":
    main()
