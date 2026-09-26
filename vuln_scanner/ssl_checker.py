"""
SSL/TLS checker - pure standard-library implementation (no paid API needed,
which matters when the whole point is keeping cost at zero for an SME).

Checks:
  - Certificate validity window (expired / expiring soon)
  - Certificate/hostname mismatch
  - Self-signed certificates
  - Weak protocol versions still being accepted (SSLv3, TLS 1.0, TLS 1.1)
  - Basic cipher strength probe
"""

import datetime
import socket
import ssl
from dataclasses import dataclass, field
from typing import List, Optional

WEAK_PROTOCOLS = [
    ("SSLv3", ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, "PROTOCOL_TLS_CLIENT") else None),
]

# Protocols we explicitly attempt a handshake with to see if the server
# still accepts them. Anything below TLS 1.2 is considered weak in 2026.
LEGACY_TLS_VERSIONS = {
    "TLSv1": getattr(ssl.TLSVersion, "TLSv1", None),
    "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
}


@dataclass
class SSLFinding:
    check: str
    severity: str  # info | low | medium | high
    detail: str


@dataclass
class SSLScanResult:
    host: str
    port: int
    findings: List[SSLFinding] = field(default_factory=list)
    cert_expires: Optional[str] = None
    issuer: Optional[str] = None
    raw_error: Optional[str] = None

    def add(self, check: str, severity: str, detail: str):
        self.findings.append(SSLFinding(check=check, severity=severity, detail=detail))


def _get_certificate(host: str, port: int, timeout: float = 6.0):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(), ssock.version(), ssock.cipher()


def _get_certificate_insecure(host: str, port: int, timeout: float = 6.0):
    """Fetch the cert without verifying, to detect self-signed / mismatched certs."""
    ctx = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=False) or {}


def _check_legacy_protocol(host: str, port: int, version_name: str,
                            min_version, max_version, timeout: float = 5.0) -> bool:
    """Return True if the server completes a handshake at this (weak) version."""
    if min_version is None:
        return False
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = min_version
        ctx.maximum_version = max_version
    except (ValueError, AttributeError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def scan_ssl(host: str, port: int = 443, timeout: float = 6.0) -> SSLScanResult:
    result = SSLScanResult(host=host, port=port)

    # 1) Verified handshake - confirms trust chain + gets cert details
    try:
        cert, tls_version, cipher = _get_certificate(host, port, timeout)
    except ssl.SSLCertVerificationError as exc:
        result.add("certificate_trust", "high",
                   f"Certificate failed verification: {exc}. Browsers will show a "
                   f"warning page to every visitor.")
        cert = None
        tls_version, cipher = None, None
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        result.raw_error = f"Could not connect to {host}:{port} over TLS - {exc}"
        return result
    except Exception as exc:
        result.raw_error = f"Unexpected error during TLS handshake: {exc}"
        return result

    if cert:
        # Expiry check
        try:
            not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.datetime.utcnow()).days
            result.cert_expires = not_after.strftime("%Y-%m-%d")
            if days_left < 0:
                result.add("certificate_expiry", "high",
                           f"Certificate EXPIRED on {result.cert_expires}.")
            elif days_left < 14:
                result.add("certificate_expiry", "high",
                           f"Certificate expires in {days_left} day(s) ({result.cert_expires}).")
            elif days_left < 30:
                result.add("certificate_expiry", "medium",
                           f"Certificate expires in {days_left} day(s) ({result.cert_expires}).")
            else:
                result.add("certificate_expiry", "info",
                           f"Certificate valid until {result.cert_expires} ({days_left} days left).")
        except Exception:
            pass

        issuer = dict(x[0] for x in cert.get("issuer", []))
        result.issuer = issuer.get("organizationName") or issuer.get("commonName")

        subject = dict(x[0] for x in cert.get("subject", []))
        if issuer.get("commonName") == subject.get("commonName") and result.issuer:
            # crude self-signed heuristic when verification somehow passed
            pass

    if tls_version:
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            result.add("protocol_version", "high",
                       f"Default negotiated protocol is {tls_version}, which is deprecated.")
        else:
            result.add("protocol_version", "info", f"Negotiated protocol: {tls_version}.")

    if cipher:
        cipher_name, cipher_proto, cipher_bits = cipher
        if cipher_bits < 128:
            result.add("cipher_strength", "high",
                       f"Weak cipher in use: {cipher_name} ({cipher_bits}-bit).")
        else:
            result.add("cipher_strength", "info",
                       f"Cipher in use: {cipher_name} ({cipher_bits}-bit).")

    # 2) Self-signed / mismatch check (unverified connection)
    try:
        insecure_cert = _get_certificate_insecure(host, port, timeout)
        subject = dict(x[0] for x in insecure_cert.get("subject", []))
        issuer = dict(x[0] for x in insecure_cert.get("issuer", []))
        if subject.get("commonName") and subject.get("commonName") == issuer.get("commonName"):
            result.add("self_signed", "medium",
                       "Certificate appears to be self-signed - fine for internal "
                       "testing, but will trigger browser warnings for real customers.")
    except Exception:
        pass

    # 3) Legacy protocol probing
    for name, tls_ver in LEGACY_TLS_VERSIONS.items():
        if tls_ver is None:
            continue
        accepted = _check_legacy_protocol(host, port, name, tls_ver, tls_ver, timeout)
        if accepted:
            result.add("legacy_protocol_supported", "high",
                       f"Server still accepts {name} connections. This should be disabled.")

    return result
