"""
NaijaVulnScan CLI

Example usage:

    # Full check against your own site (ports + SSL + headers):
    python -m vuln_scanner.cli --target example.com --business "Amaka's Bakery" \\
        --modules ports ssl headers --output report.html

    # Include a deeper OWASP ZAP scan (requires ZAP daemon running):
    python -m vuln_scanner.cli --target https://example.com --business "Amaka's Bakery" \\
        --modules ports ssl headers zap --zap-api-key YOURKEY --output report.html

    # Website-only checks (no port scan), good for shared hosting where you
    # don't control the server/firewall:
    python -m vuln_scanner.cli --target example.com --modules ssl headers
"""

import argparse
import logging
import sys
from urllib.parse import urlparse

from . import port_scanner, ssl_checker, http_headers, zap_scanner, report

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("naija_vulnscan.cli")

AUTHORIZATION_NOTICE = """
================================================================================
  NaijaVulnScan - Vulnerability Assessment Tool for SMEs
================================================================================
  This tool performs active scanning (port probing, TLS handshakes, and
  optionally OWASP ZAP attack payloads). Only run it against:
    (a) systems/domains YOU own, or
    (b) systems you have explicit WRITTEN permission to test.

  Unauthorized scanning of third-party systems is a criminal offence under
  Nigeria's Cybercrimes (Prohibition, Prevention, etc.) Act 2015, and under
  equivalent computer-misuse laws elsewhere.
================================================================================
"""


def _bare_host(target: str) -> str:
    """Strip scheme/path so nmap and the ssl socket get a plain hostname."""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Lightweight vulnerability scanner for SME websites/networks.",
    )
    parser.add_argument("--target", required=True,
                         help="Domain, IP, or URL to scan, e.g. example.com or https://example.com")
    parser.add_argument("--business", default="",
                         help="Business name to show on the report (cosmetic only).")
    parser.add_argument("--modules", nargs="+", default=["ports", "ssl", "headers"],
                         choices=["ports", "ssl", "headers", "zap"],
                         help="Which checks to run. Default: ports ssl headers")
    parser.add_argument("--port-range", default=port_scanner.DEFAULT_PORT_RANGE,
                         help="Nmap port range/list to scan.")
    parser.add_argument("--https-port", type=int, default=443,
                         help="Port to run the SSL/TLS check against.")
    parser.add_argument("--zap-api-key", default=None,
                         help="API key for a locally running OWASP ZAP daemon.")
    parser.add_argument("--zap-proxy", default="http://127.0.0.1:8080",
                         help="Address of the ZAP daemon's proxy API.")
    parser.add_argument("--zap-no-active", action="store_true",
                         help="Only spider with ZAP; skip active attack payloads "
                              "(safer for production sites without prior arrangement).")
    parser.add_argument("--output", default="vuln_report.html",
                         help="Path to write the HTML report to.")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Skip the interactive authorization confirmation prompt.")

    args = parser.parse_args(argv)

    print(AUTHORIZATION_NOTICE)
    if not args.yes:
        confirm = input(f"Type 'yes' to confirm you are authorized to scan '{args.target}': ").strip().lower()
        if confirm != "yes":
            print("Aborting - authorization not confirmed.")
            sys.exit(1)

    host = _bare_host(args.target)
    url = args.target if args.target.startswith(("http://", "https://")) else f"https://{args.target}"

    port_result = ssl_result = header_result = zap_result = None

    if "ports" in args.modules:
        logger.info("Running port scan against %s ...", host)
        port_result = port_scanner.scan_target(host, port_range=args.port_range)
        if port_result.raw_error:
            logger.warning("Port scan issue: %s", port_result.raw_error)
        else:
            logger.info("Port scan found %d open port(s).", len(port_result.open_ports))

    if "ssl" in args.modules:
        logger.info("Running SSL/TLS check against %s:%d ...", host, args.https_port)
        ssl_result = ssl_checker.scan_ssl(host, port=args.https_port)
        if ssl_result.raw_error:
            logger.warning("SSL check issue: %s", ssl_result.raw_error)

    if "headers" in args.modules:
        logger.info("Checking HTTP security headers on %s ...", url)
        header_result = http_headers.scan_headers(url)
        if header_result.raw_error:
            logger.warning("Header check issue: %s", header_result.raw_error)

    if "zap" in args.modules:
        if not args.zap_api_key:
            logger.error("The 'zap' module requires --zap-api-key. Skipping ZAP scan.")
        else:
            logger.info("Running OWASP ZAP scan against %s (this can take a while) ...", url)
            zap_result = zap_scanner.run_zap_scan(
                url, zap_api_key=args.zap_api_key, zap_proxy=args.zap_proxy,
                active_scan=not args.zap_no_active,
            )
            if zap_result.raw_error:
                logger.warning("ZAP scan issue: %s", zap_result.raw_error)

    html_report = report.build_html_report(
        business_name=args.business or host,
        target=args.target,
        port_result=port_result,
        ssl_result=ssl_result,
        header_result=header_result,
        zap_result=zap_result,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_report)

    logger.info("Report written to %s", args.output)


if __name__ == "__main__":
    main()
