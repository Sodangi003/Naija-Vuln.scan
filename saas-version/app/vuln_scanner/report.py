"""
Generates a single self-contained HTML report from all scan modules.

Deliberately opinionated toward *free or near-free* remediation steps
(Let's Encrypt, Cloudflare free tier, UFW/firewalld, etc.) since the
audience is small businesses without a dedicated security budget.
"""

import datetime
import html
from typing import Optional

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_COLOR = {"high": "#d64545", "medium": "#e0a030", "low": "#3f8fce", "info": "#7a7a7a"}

LOW_COST_TIPS = {
    "certificate_expiry": "Use Let's Encrypt (via Certbot) for free auto-renewing SSL certificates - avoids this entirely.",
    "legacy_protocol_supported": "Disable TLS 1.0/1.1 in your web server config (Nginx/Apache) or, if using shared hosting, ask your provider - most cPanel hosts have a toggle for this at no extra cost.",
    "self_signed": "Switch to a free Let's Encrypt certificate instead of a self-signed one.",
    "plaintext_http": "Enable free SSL via Let's Encrypt or your host's free SSL option, then force HTTPS redirects.",
    "missing_strict-transport-security": "Add one line to your server config: 'Strict-Transport-Security: max-age=31536000' - zero cost.",
    "missing_x-frame-options": "Add 'X-Frame-Options: SAMEORIGIN' to your server config - zero cost, 5-minute fix.",
    "missing_content-security-policy": "Start with a basic CSP header; free guides exist at owasp.org - no tooling cost.",
    "missing_x-content-type-options": "Add 'X-Content-Type-Options: nosniff' to your server config - zero cost.",
    "missing_referrer-policy": "Add 'Referrer-Policy: strict-origin-when-cross-origin' - zero cost.",
    "info_leak_server": "Turn off server version banners (e.g. 'server_tokens off;' in Nginx) - zero cost.",
    "info_leak_x-powered-by": "Disable the 'X-Powered-By' header in your framework config - zero cost.",
    "insecure_cookies": "Add the 'Secure' and 'HttpOnly' flags to cookies in your app/session config - zero cost.",
    "default_port_open": "Close the port at your firewall/router level, or restrict it to specific IPs (e.g. your office) using free tools like UFW.",
}

RISKY_PORT_GENERIC_TIP = (
    "If this service isn't meant to be public, block it at your router/firewall. "
    "Nigerian ISPs and most routers support basic port blocking at no extra cost. "
    "For remote admin access, use a free WireGuard/OpenVPN setup instead of exposing "
    "the service directly to the internet."
)


def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLOR.get(sev, "#7a7a7a")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;text-transform:uppercase;">{sev}</span>'


def _tip_for(check_key: str) -> Optional[str]:
    return LOW_COST_TIPS.get(check_key)


def build_html_report(
    business_name: str,
    target: str,
    port_result=None,
    ssl_result=None,
    header_result=None,
    zap_result=None,
) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    esc = html.escape

    rows_html = []
    high_count = medium_count = low_count = info_count = 0

    def bump(sev):
        nonlocal high_count, medium_count, low_count, info_count
        if sev == "high":
            high_count += 1
        elif sev == "medium":
            medium_count += 1
        elif sev == "low":
            low_count += 1
        else:
            info_count += 1

    # --- Port findings ---
    if port_result is not None:
        if port_result.raw_error:
            rows_html.append(f'<tr><td colspan="4">⚠ Port scan error: {esc(port_result.raw_error)}</td></tr>')
        else:
            for f in port_result.open_ports:
                sev = f.severity
                bump(sev)
                note = f.risk_note or "Confirm this service is intentionally public-facing."
                tip = RISKY_PORT_GENERIC_TIP if f.risk_note else "If not needed publicly, close it at the firewall - free."
                svc_display = f"{f.service} {f.product} {f.version}".strip()
                rows_html.append(
                    f"<tr><td>Port {f.port}/{esc(f.protocol)} open ({esc(svc_display)})</td>"
                    f"<td>{_severity_badge(sev)}</td>"
                    f"<td>{esc(note)}</td>"
                    f"<td>{esc(tip)}</td></tr>"
                )

    # --- SSL findings ---
    if ssl_result is not None:
        if ssl_result.raw_error:
            rows_html.append(f'<tr><td colspan="4">⚠ SSL check error: {esc(ssl_result.raw_error)}</td></tr>')
        else:
            for f in ssl_result.findings:
                if f.severity == "info":
                    info_count += 1
                    continue
                bump(f.severity)
                tip = _tip_for(f.check) or "Review your web server / hosting provider's SSL settings."
                rows_html.append(
                    f"<tr><td>{esc(f.check.replace('_', ' ').title())}</td>"
                    f"<td>{_severity_badge(f.severity)}</td>"
                    f"<td>{esc(f.detail)}</td>"
                    f"<td>{esc(tip)}</td></tr>"
                )

    # --- Header findings ---
    if header_result is not None:
        if header_result.raw_error:
            rows_html.append(f'<tr><td colspan="4">⚠ HTTP header check error: {esc(header_result.raw_error)}</td></tr>')
        else:
            for f in header_result.findings:
                if f.severity == "info":
                    info_count += 1
                    continue
                bump(f.severity)
                tip = _tip_for(f.check) or "Add the missing header in your server/app configuration."
                rows_html.append(
                    f"<tr><td>{esc(f.check.replace('_', ' ').title())}</td>"
                    f"<td>{_severity_badge(f.severity)}</td>"
                    f"<td>{esc(f.detail)}</td>"
                    f"<td>{esc(tip)}</td></tr>"
                )

    # --- ZAP findings ---
    if zap_result is not None:
        if zap_result.raw_error:
            rows_html.append(f'<tr><td colspan="4">⚠ OWASP ZAP scan error: {esc(zap_result.raw_error)}</td></tr>')
        else:
            for f in zap_result.findings:
                if f.risk == "info":
                    info_count += 1
                    continue
                bump(f.risk)
                tip = f.solution[:300] + ("..." if len(f.solution) > 300 else "") if f.solution else \
                    "See OWASP ZAP alert details for remediation guidance (free resource: owasp.org)."
                rows_html.append(
                    f"<tr><td>{esc(f.name)} ({esc(f.url)})</td>"
                    f"<td>{_severity_badge(f.risk)}</td>"
                    f"<td>{esc(f.description[:250])}{'...' if len(f.description) > 250 else ''}</td>"
                    f"<td>{esc(tip)}</td></tr>"
                )

    if not rows_html:
        rows_html.append('<tr><td colspan="4">No modules were run, or no data was returned.</td></tr>')

    total_issues = high_count + medium_count + low_count
    if high_count > 0:
        overall = ("HIGH RISK", "#d64545")
    elif medium_count > 0:
        overall = ("MEDIUM RISK", "#e0a030")
    elif low_count > 0:
        overall = ("LOW RISK", "#3f8fce")
    else:
        overall = ("LOOKS GOOD", "#3fa34d")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Assessment - {esc(business_name)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; background: #f4f6f8; color: #1c1f24; }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 32px 20px 60px; }}
  .header {{ background: #12213b; color: #fff; padding: 28px 32px; border-radius: 10px; margin-bottom: 24px; }}
  .header h1 {{ margin: 0 0 6px; font-size: 22px; }}
  .header p {{ margin: 2px 0; opacity: 0.85; font-size: 14px; }}
  .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: #fff; border-radius: 10px; padding: 16px 20px; flex: 1; min-width: 140px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .label {{ font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.04em; }}
  .overall {{ display:inline-block; padding: 6px 16px; border-radius: 20px; color: #fff; font-weight: 700; font-size: 14px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid #eef0f2; font-size: 13.5px; vertical-align: top; }}
  th {{ background: #eef1f5; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #444; }}
  tr:last-child td {{ border-bottom: none; }}
  .footer-note {{ margin-top: 28px; font-size: 12.5px; color: #666; line-height: 1.6; background:#fff9e6; border:1px solid #f0e4b0; padding:14px 18px; border-radius: 8px;}}
  .section-title {{ font-size: 15px; font-weight: 700; margin: 28px 0 10px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>Vulnerability Assessment Report</h1>
    <p><strong>Business:</strong> {esc(business_name)}</p>
    <p><strong>Target:</strong> {esc(target)}</p>
    <p><strong>Generated:</strong> {now}</p>
    <p style="margin-top:10px;"><span class="overall" style="background:{overall[1]}">{overall[0]}</span></p>
  </div>

  <div class="summary">
    <div class="card"><div class="num" style="color:{SEVERITY_COLOR['high']}">{high_count}</div><div class="label">High</div></div>
    <div class="card"><div class="num" style="color:{SEVERITY_COLOR['medium']}">{medium_count}</div><div class="label">Medium</div></div>
    <div class="card"><div class="num" style="color:{SEVERITY_COLOR['low']}">{low_count}</div><div class="label">Low</div></div>
    <div class="card"><div class="num">{total_issues}</div><div class="label">Total Issues</div></div>
  </div>

  <div class="section-title">Findings &amp; Free/Low-Cost Fixes</div>
  <table>
    <tr><th style="width:26%">Finding</th><th style="width:10%">Severity</th><th style="width:32%">Why it matters</th><th style="width:32%">Suggested fix</th></tr>
    {''.join(rows_html)}
  </table>

  <div class="footer-note">
    <strong>Disclaimer:</strong> This automated scan checks for common, well-known
    misconfigurations only - it is not a substitute for a full penetration test
    or compliance audit. Run this tool only against systems you own or have
    written authorization to test. Fix HIGH severity items first; most listed
    remediations use free or already-paid-for tools (your web server config,
    your hosting control panel, Let's Encrypt, or your router/firewall).
  </div>
</div>
</body>
</html>
"""
