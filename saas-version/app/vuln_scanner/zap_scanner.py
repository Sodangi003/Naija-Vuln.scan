"""
Optional deeper web-app scan via OWASP ZAP's API.

This is kept separate from the free/instant checks above because it
requires ZAP to be installed and running as a daemon:

    zap.sh -daemon -port 8080 -config api.key=<your-key>

ZAP itself is free and open-source, which fits the "near-zero budget"
constraint - it's just an extra install step, not a paid tool.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from zapv2 import ZAPv2
except ImportError:  # pragma: no cover
    ZAPv2 = None

logger = logging.getLogger("naija_vulnscan.zap_scanner")

RISK_MAP = {"0": "info", "1": "low", "2": "medium", "3": "high"}


@dataclass
class ZapFinding:
    name: str
    risk: str
    url: str
    description: str
    solution: str


@dataclass
class ZapScanResult:
    target: str
    findings: List[ZapFinding] = field(default_factory=list)
    raw_error: Optional[str] = None


def run_zap_scan(target: str, zap_api_key: str, zap_proxy: str = "http://127.0.0.1:8080",
                  spider_timeout_s: int = 120, active_scan_timeout_s: int = 600,
                  active_scan: bool = True) -> ZapScanResult:
    """
    Spiders the target, then optionally runs an active scan.

    active_scan=True sends live attack payloads (SQLi, XSS probes, etc.)
    against the target - only ever run this against your own staging/test
    environment or a production site you have explicit written permission
    to actively test, since it can trigger WAF alerts, rate limits, or in
    rare cases affect a fragile application.
    """
    if ZAPv2 is None:
        return ZapScanResult(
            target=target,
            raw_error="python-owasp-zap-v2.4 is not installed. Install with: "
                      "pip install python-owasp-zap-v2.4",
        )

    result = ZapScanResult(target=target)
    zap = ZAPv2(apikey=zap_api_key, proxies={"http": zap_proxy, "https": zap_proxy})

    try:
        zap.urlopen(target)
        time.sleep(1)

        logger.info("Starting ZAP spider on %s", target)
        scan_id = zap.spider.scan(target)
        waited = 0
        while int(zap.spider.status(scan_id)) < 100 and waited < spider_timeout_s:
            time.sleep(2)
            waited += 2
        logger.info("Spider complete (or timed out) after %ss", waited)

        if active_scan:
            logger.info("Starting ZAP active scan on %s", target)
            ascan_id = zap.ascan.scan(target)
            waited = 0
            while int(zap.ascan.status(ascan_id)) < 100 and waited < active_scan_timeout_s:
                time.sleep(5)
                waited += 5
            logger.info("Active scan complete (or timed out) after %ss", waited)

        alerts = zap.core.alerts(baseurl=target)
        for alert in alerts:
            result.findings.append(ZapFinding(
                name=alert.get("alert", "Unknown"),
                risk=RISK_MAP.get(alert.get("riskcode", "0"), "info"),
                url=alert.get("url", target),
                description=alert.get("description", "").strip(),
                solution=alert.get("solution", "").strip(),
            ))

    except Exception as exc:
        result.raw_error = (
            f"ZAP scan failed: {exc}. Is the ZAP daemon running "
            f"(zap.sh -daemon -port 8080 -config api.key=...) and reachable at {zap_proxy}?"
        )

    return result
