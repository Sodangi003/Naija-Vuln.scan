"""
HTTP response header + basic server-fingerprint checks.

These checks are free, fast, and catch a lot of the "low-hanging fruit"
that automated bots scan for constantly (missing security headers,
verbose server banners revealing exact software versions, directory
listing left enabled, etc.)
"""

from dataclasses import dataclass, field
from typing import List, Optional

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "high",
        "Without HSTS, visitors can be silently downgraded to plain HTTP "
        "and have their traffic intercepted on public wifi."
    ),
    "X-Content-Type-Options": (
        "low",
        "Missing this lets browsers 'guess' file types, which can be abused "
        "to run malicious scripts disguised as harmless files."
    ),
    "X-Frame-Options": (
        "medium",
        "Without this, your site can be embedded in an invisible frame on "
        "another site to trick users into clicking things (clickjacking)."
    ),
    "Content-Security-Policy": (
        "medium",
        "No CSP means there's one less layer of defense if an attacker "
        "manages to inject a malicious script into a page."
    ),
    "Referrer-Policy": (
        "low",
        "Without this, full page URLs (sometimes containing sensitive "
        "tokens) can leak to third-party sites via the Referer header."
    ),
}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


@dataclass
class HeaderFinding:
    check: str
    severity: str
    detail: str


@dataclass
class HeaderScanResult:
    url: str
    findings: List[HeaderFinding] = field(default_factory=list)
    status_code: Optional[int] = None
    raw_error: Optional[str] = None

    def add(self, check: str, severity: str, detail: str):
        self.findings.append(HeaderFinding(check=check, severity=severity, detail=detail))


def scan_headers(url: str, timeout: float = 8.0, verify_ssl: bool = True) -> HeaderScanResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = HeaderScanResult(url=url)
    try:
        resp = requests.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
    except requests.exceptions.SSLError as exc:
        result.raw_error = f"SSL error while fetching headers: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result.raw_error = f"Could not reach {url}: {exc}"
        return result

    result.status_code = resp.status_code
    headers = resp.headers

    for header, (severity, reason) in SECURITY_HEADERS.items():
        if header not in headers:
            result.add(f"missing_{header.lower()}", severity, f"Missing '{header}' header. {reason}")

    for header in INFO_LEAK_HEADERS:
        if header in headers:
            result.add(f"info_leak_{header.lower()}", "low",
                       f"'{header}: {headers[header]}' reveals exact software/version "
                       f"to attackers, making it easier to target known exploits.")

    if url.startswith("http://"):
        result.add("plaintext_http", "high",
                   "Site is served over plain HTTP with no encryption at all.")

    cookies_no_secure = [c.name for c in resp.cookies if not c.secure]
    if cookies_no_secure:
        result.add("insecure_cookies", "medium",
                   f"Cookie(s) {cookies_no_secure} set without the 'Secure' flag - "
                   f"can be intercepted over unencrypted connections.")

    if not result.findings:
        result.add("headers_ok", "info", "Common security headers look present.")

    return result
