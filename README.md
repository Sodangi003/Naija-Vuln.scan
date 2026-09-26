# NaijaVulnScan

A lightweight, mostly-free vulnerability assessment tool built for
small and medium businesses — with Nigerian SMEs specifically in mind,
but usable anywhere the security budget is close to zero.

## Why this exists

Most vulnerability scanners are priced for enterprises: Nessus, Qualys,
and similar tools run into thousands of dollars a year in licensing.
Meanwhile, a huge share of successful attacks on small businesses exploit
the same handful of avoidable mistakes:

- An expired or self-signed SSL certificate scaring away customers
- A database port (MySQL/MongoDB/Redis) left open to the entire internet
- RDP or SSH exposed with weak or default credentials
- Missing security headers that cost nothing to add
- Outdated server software with known, public exploits

A 2023 NITDA/CERT advisory and repeated reports from Nigeria's financial
sector (NIBSS, CBN circulars on cybersecurity) have flagged SMEs as a
soft target precisely because most can't justify a full-time security
hire or an enterprise scanning contract. This tool tries to close that
gap with things that are already free or nearly free: Nmap, OWASP ZAP,
Python's own `ssl` library, and Let's Encrypt for the fixes.

**Cost to run this tool: $0** (aside from your own laptop and internet).
**Cost of the fixes it recommends:** almost entirely free — firewall
rules, free SSL certificates, one-line config changes.

## What it checks

| Module | What it does | External tool needed |
|---|---|---|
| `ports` | Scans common ports, flags risky exposed services (databases, RDP, Telnet, etc.) with plain-language explanations | Nmap (free, open-source) |
| `ssl` | Certificate expiry, self-signed certs, weak/legacy TLS versions, weak ciphers | None — pure Python |
| `headers` | Missing security headers (HSTS, CSP, X-Frame-Options...), version-leaking banners, insecure cookies | None — just `requests` |
| `zap` (optional) | Deeper web-app scan for things like SQL injection and XSS | OWASP ZAP (free, open-source) |

Every finding in the generated report includes a **free or low-cost fix**,
not just "you have a problem."

## Setup

```bash
# 1. System dependency: Nmap (needed for the 'ports' module)
sudo apt install nmap        # Debian/Ubuntu
# or: brew install nmap      # macOS

# 2. Python dependencies
pip install -r requirements.txt

# 3. (Optional, for the 'zap' module) Install & start OWASP ZAP
# Download from https://www.zaproxy.org/download/
zap.sh -daemon -port 8080 -config api.key=CHANGE-ME
```

## Usage

```bash
# Basic scan of your own site: ports + SSL + headers
python -m vuln_scanner.cli \
  --target example.com \
  --business "Amaka's Bakery" \
  --modules ports ssl headers \
  --output report.html

# Shared hosting? You don't control the firewall/ports, so skip that module:
python -m vuln_scanner.cli --target example.com --modules ssl headers

# Add a deeper OWASP ZAP scan (only against sites you're authorized to
# actively test — this sends real attack payloads):
python -m vuln_scanner.cli \
  --target https://example.com \
  --modules ports ssl headers zap \
  --zap-api-key CHANGE-ME \
  --output report.html
```

The tool will ask you to type `yes` to confirm you're authorized to scan
the target before it does anything. Use `-y` to skip that prompt in
scripted/CI use — but only once you're sure of your authorization.

Open the generated `report.html` in any browser — it's a single
self-contained file you can also email to a client or save for your
records.

## ⚠️ Legal / ethical use

**Only scan systems you own or have explicit written permission to test.**

- In Nigeria, unauthorized access to or scanning of computer systems is
  a criminal offence under the **Cybercrimes (Prohibition, Prevention,
  etc.) Act, 2015**.
- Most other countries have equivalent computer-misuse laws (e.g. the
  UK Computer Misuse Act, the US CFAA).
- If you're a freelancer or agency running this for clients, get a
  signed authorization / statement of work first — a one-paragraph
  email confirming scope and consent is enough to protect both sides.
- The `zap` module with active scanning sends real attack traffic
  (SQL injection attempts, XSS payloads, etc.). Never run it against a
  production system without prior arrangement — use `--zap-no-active`
  for a safer, passive-only pass if you're unsure.

## Project structure

```
naija_vulnscan/
├── README.md
├── requirements.txt
└── vuln_scanner/
    ├── __init__.py
    ├── cli.py              # command-line entry point
    ├── port_scanner.py     # Nmap wrapper
    ├── ssl_checker.py      # TLS/certificate checks (stdlib only)
    ├── http_headers.py     # security header checks
    ├── zap_scanner.py      # optional OWASP ZAP integration
    └── report.py           # HTML report generator
```

## Roadmap ideas (not yet built)

- CVE lookup for fingerprinted software versions (e.g. via the NVD API)
- Scheduled scans + email/WhatsApp alert on new findings
- A Hausa/Yoruba/Igbo-language summary page for non-technical owners
- PDF export for the report (currently HTML only)
- A hosted free-tier version so non-technical owners don't need to
  install anything locally
