"""
Runs the actual scan using the existing vuln_scanner modules, as a
background task so the HTTP request doesn't hang for the minute or two
a real scan takes.
"""

import datetime
import logging

from sqlalchemy.orm import Session

from . import config, models
from .database import SessionLocal
from .vuln_scanner import port_scanner, ssl_checker, http_headers, report

logger = logging.getLogger("naija_vulnscan_saas.scan_runner")


def run_scan_job(scan_id: int):
    """
    Entry point for FastAPI's BackgroundTasks. Opens its own DB session
    since it runs outside the request/response cycle.
    """
    db: Session = SessionLocal()
    try:
        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        scan.status = models.ScanStatus.running
        db.commit()

        domain = scan.domain
        hostname = domain.hostname
        modules = scan.modules.split(",")

        port_result = ssl_result = header_result = None

        try:
            if "ports" in modules:
                port_result = port_scanner.scan_target(hostname)
            if "ssl" in modules:
                ssl_result = ssl_checker.scan_ssl(hostname)
            if "headers" in modules:
                header_result = http_headers.scan_headers(f"https://{hostname}")

            html = report.build_html_report(
                business_name=scan.owner.email,
                target=hostname,
                port_result=port_result,
                ssl_result=ssl_result,
                header_result=header_result,
            )

            filename = f"scan_{scan.id}_{int(datetime.datetime.utcnow().timestamp())}.html"
            filepath = config.REPORTS_DIR / filename
            filepath.write_text(html, encoding="utf-8")

            scan.report_filename = filename
            scan.status = models.ScanStatus.completed
            scan.completed_at = datetime.datetime.utcnow()

        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            scan.status = models.ScanStatus.failed
            scan.error_message = str(exc)

        db.commit()
    finally:
        db.close()
