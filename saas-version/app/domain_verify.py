"""
Before we let a paying user point our scanner at a domain, we need some
evidence they actually control it - otherwise this service becomes a free
'scan anyone's website' tool, which is both a liability for us and
illegal for the user to do without authorization.

Two verification paths, same idea as domain verification in Google
Search Console / most SaaS products:
  1. DNS TXT record:      naijavulnscan-verify=<token>   at the root domain
  2. HTTP file upload:     https://<domain>/.well-known/naijavulnscan-<token>.txt
"""

import dns.resolver
import httpx


def dns_txt_instructions(hostname: str, token: str) -> str:
    return f"Add a TXT record on '{hostname}' with value: naijavulnscan-verify={token}"


def file_upload_instructions(hostname: str, token: str) -> str:
    return (
        f"Upload a file to https://{hostname}/.well-known/naijavulnscan-{token}.txt "
        f"containing just the token: {token}"
    )


def verify_via_dns(hostname: str, token: str) -> bool:
    expected = f"naijavulnscan-verify={token}"
    try:
        answers = dns.resolver.resolve(hostname, "TXT", lifetime=8.0)
        for rdata in answers:
            # TXT records can be split into multiple strings; join them.
            txt_value = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt_value.strip() == expected:
                return True
    except Exception:
        pass
    return False


def verify_via_file(hostname: str, token: str) -> bool:
    url = f"https://{hostname}/.well-known/naijavulnscan-{token}.txt"
    try:
        resp = httpx.get(url, timeout=8.0, follow_redirects=True)
        if resp.status_code == 200 and token in resp.text:
            return True
    except Exception:
        pass
    return False


def verify_domain(hostname: str, token: str) -> bool:
    """Try DNS first (more reliable / harder to fake), fall back to file check."""
    return verify_via_dns(hostname, token) or verify_via_file(hostname, token)
