# Case Study: NaijaVulnScan

## The problem

Small businesses are some of the most frequently targeted, least protected
entities online. Enterprise vulnerability scanners (Nessus, Qualys, etc.)
are priced for companies with dedicated security budgets — often
thousands of dollars a year — which puts them out of reach for most SMEs,
especially in markets like Nigeria where cybersecurity spend is rarely a
line item at all.

Meanwhile, the majority of successful attacks on small businesses don't
require sophisticated techniques. They exploit a handful of avoidable,
well-known misconfigurations: expired SSL certificates, databases left
open to the public internet, missing security headers, outdated software
with public exploits.

## The approach

I built NaijaVulnScan around a simple constraint: **every tool it uses,
and every fix it recommends, needs to be free or near-free.**

- **Nmap** and **OWASP ZAP** for scanning — both free, open-source,
  industry-standard tools
- Python's own `ssl` and `requests` libraries for the SSL/TLS and header
  checks — no external service or paid API required
- Every finding in the generated report is paired with a **free or
  low-cost fix** (a Let's Encrypt certificate, a one-line server config
  change, a firewall rule), not just a list of problems

The output is a single self-contained HTML report a non-technical
business owner can open, understand, and act on — or forward to whoever
manages their hosting.

## What it checks

| Check | What it catches |
|---|---|
| Port scanning | Databases/admin ports exposed to the public internet (MySQL, MongoDB, RDP, etc.) |
| SSL/TLS | Expired or self-signed certificates, deprecated protocol versions, weak ciphers |
| HTTP headers | Missing security headers (HSTS, CSP, X-Frame-Options), version-leaking banners |
| OWASP ZAP (optional) | Deeper web-app issues like SQL injection and XSS |

## Design decisions worth calling out

- **Authorization gate before scanning.** The CLI requires typing `yes`
  to confirm the user is authorized to scan the target before doing
  anything — active scanning without permission is a real legal risk
  (in Nigeria, under the Cybercrimes Act 2015), not just bad manners.
- **Modular by design.** Each check (`ports`, `ssl`, `headers`, `zap`) is
  its own module and can be run independently — important for SMEs on
  shared hosting who don't control their own firewall/ports.
- **Plain-language explanations.** Every finding explains *why* it
  matters in terms a non-technical owner can understand, not just a
  CVE number or a raw port list.

## What I'd build next

- **CVE lookup** — match detected software versions against the NVD's
  free API to name specific known exploits, not just flag outdated
  version numbers generically
- **PDF export** alongside the current HTML report
- **Local-language summaries** (Hausa/Yoruba/Igbo) for non-technical
  owners
- **Scheduled scanning** with email/WhatsApp alerts on new findings,
  so this becomes an ongoing check rather than a one-time report

## Try it

See the [README](./README.md) for setup and usage instructions.
