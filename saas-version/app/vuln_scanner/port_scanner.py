"""
Port & service scanner built on top of Nmap (via the python-nmap wrapper).

Focuses on the checks that matter most for small businesses running a
single web server / office router, rather than a full enterprise-grade
sweep - the goal is fast, cheap, actionable results.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import nmap  # python-nmap
except ImportError:  # pragma: no cover - handled at runtime with a clear message
    nmap = None

logger = logging.getLogger("naija_vulnscan.port_scanner")

# Ports that are disproportionately risky for a small business to leave
# open to the public internet, with plain-language reasons.
RISKY_PORTS = {
    21: "FTP - often unencrypted, credentials sent in cleartext",
    22: "SSH - fine if key-based auth + firewall rules are used, risky with weak passwords",
    23: "Telnet - unencrypted remote access, should never face the internet",
    25: "SMTP - can be abused as an open relay if misconfigured",
    135: "MS RPC - common ransomware/worm entry point",
    139: "NetBIOS - legacy Windows file sharing, frequently exploited",
    445: "SMB - target of WannaCry/EternalBlue-style attacks",
    1433: "MSSQL - database should not be internet-facing",
    3306: "MySQL - database should not be internet-facing",
    3389: "RDP - a top target for ransomware brute-force attacks",
    5432: "PostgreSQL - database should not be internet-facing",
    5900: "VNC - remote desktop, frequently left with weak/no auth",
    6379: "Redis - frequently deployed with no authentication at all",
    27017: "MongoDB - historically a top source of exposed-database breaches",
}

DEFAULT_PORT_RANGE = "1-1024,1433,1521,3306,3389,3389,5432,5900,6379,8080,8443,27017"


@dataclass
class PortFinding:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    risk_note: Optional[str] = None

    @property
    def severity(self) -> str:
        if self.state != "open":
            return "info"
        if self.port in RISKY_PORTS:
            return "high"
        return "medium" if self.service in ("http", "https", "http-proxy") else "low"


@dataclass
class PortScanResult:
    target: str
    findings: List[PortFinding] = field(default_factory=list)
    raw_error: Optional[str] = None

    @property
    def open_ports(self) -> List[PortFinding]:
        return [f for f in self.findings if f.state == "open"]


def scan_target(target: str, port_range: str = DEFAULT_PORT_RANGE,
                 fast: bool = True, use_sudo: bool = False) -> PortScanResult:
    """
    Run an Nmap scan against `target` and return structured findings.

    `fast=True` uses `-sT -T4` (TCP connect scan, no root required) which
    is the right default for a business owner running this from a laptop.
    Set `fast=False` for a SYN scan (`-sS`) if run with elevated privileges,
    which is quieter and slightly faster on large ranges.
    """
    if nmap is None:
        return PortScanResult(
            target=target,
            raw_error=(
                "python-nmap is not installed, or the `nmap` binary is missing "
                "from PATH. Install with: pip install python-nmap  and  "
                "sudo apt install nmap"
            ),
        )

    scanner = nmap.PortScanner()
    scan_type = "-sT" if fast or not use_sudo else "-sS"
    arguments = f"{scan_type} -sV -T4 --version-light -p {port_range}"

    logger.info("Scanning %s with arguments: %s", target, arguments)
    try:
        scanner.scan(hosts=target, arguments=arguments)
    except Exception as exc:  # nmap.PortScannerError, socket errors, etc.
        return PortScanResult(target=target, raw_error=str(exc))

    result = PortScanResult(target=target)
    if target not in scanner.all_hosts():
        # Host may have resolved differently (e.g. hostname -> IP)
        hosts = scanner.all_hosts()
        if not hosts:
            result.raw_error = "Host did not respond. It may be offline, or blocking ICMP/scans."
            return result
        host_key = hosts[0]
    else:
        host_key = target

    host_data = scanner[host_key]
    for proto in host_data.all_protocols():
        ports = host_data[proto].keys()
        for port in sorted(ports):
            info = host_data[proto][port]
            finding = PortFinding(
                port=port,
                protocol=proto,
                state=info.get("state", "unknown"),
                service=info.get("name", "unknown"),
                product=info.get("product", ""),
                version=info.get("version", ""),
                risk_note=RISKY_PORTS.get(port),
            )
            result.findings.append(finding)

    return result
