"""
scanner/orchestrator.py
───────────────────────
High-level scan coordinator.
Runs port scan + web scan, merges results, and computes a risk score.
"""

import logging
from datetime import datetime

from scanner.port_scanner import scan_ports
from scanner.web_scanner import scan_web
from scanner.utils import resolve_target, risk_score, sort_vulnerabilities, normalize_target

logger = logging.getLogger(__name__)


def run_full_scan(target: str, scan_options: dict | None = None) -> dict:
    """
    Orchestrate a complete scan of *target*.

    scan_options keys (all optional):
      - common_ports_only : bool   (default True)
      - port_start        : int    (default 1)
      - port_end          : int    (default 1024)
      - skip_web          : bool   (default False)
      - thread_count      : int    (default 100)
      - timeout           : float  (default 1.0)
    """
    opts = scan_options or {}
    target = normalize_target(target)

    started_at = datetime.utcnow().isoformat()
    logger.info("=== Full scan started: %s ===", target)

    # ── DNS Resolution ─────────────────────────────────────────────────────────
    ip_address = resolve_target(target)
    resolution_failed = ip_address is None
    if resolution_failed:
        logger.warning("Could not resolve %s – scanning may be partial", target)
        ip_address = target   # try anyway with raw value

    # ── Port Scan ──────────────────────────────────────────────────────────────
    common_only = opts.get("common_ports_only", True)
    port_range  = (opts.get("port_start", 1), opts.get("port_end", 1024))
    timeout     = opts.get("timeout", 1.0)
    workers     = opts.get("thread_count", 100)

    open_ports = scan_ports(
        host=ip_address,
        port_range=port_range,
        common_only=common_only,
        timeout=timeout,
        max_workers=workers,
    )

    # Collect port-level vulnerabilities
    port_vulns = []
    for p in open_ports:
        if "vulnerability" in p:
            port_vulns.append({
                **p["vulnerability"],
                "title": p["vulnerability"].get("message", ""),
                "context": f"Port {p['port']} ({p['service']})",
            })

    # ── Web Scan ───────────────────────────────────────────────────────────────
    web_result: dict = {}
    web_vulns:  list = []

    if not opts.get("skip_web", False):
        web_result = scan_web(target)
        web_vulns  = web_result.get("vulnerabilities", [])

    # ── Merge & Score ──────────────────────────────────────────────────────────
    all_vulns = sort_vulnerabilities(port_vulns + web_vulns)
    score     = risk_score(all_vulns)

    finished_at = datetime.utcnow().isoformat()

    result = {
        "target":           target,
        "ip_address":       ip_address,
        "resolution_failed": resolution_failed,
        "started_at":       started_at,
        "finished_at":      finished_at,
        "open_ports":       open_ports,
        "port_count":       len(open_ports),
        "web_scan":         web_result,
        "vulnerabilities":  all_vulns,
        "total_issues":     len(all_vulns),
        "risk_score":       score,
        "risk_level": (
            "Critical" if score >= 70 else
            "High"     if score >= 40 else
            "Medium"   if score >= 20 else
            "Low"      if score >  0  else
            "Safe"
        ),
    }

    logger.info("=== Scan complete: %s | score=%d | issues=%d ===", target, score, len(all_vulns))
    return result
