"""
api/routes.py
─────────────
FastAPI route definitions for the scanner API.

Endpoints
─────────
POST /scans          – Start a new scan (async background task)
GET  /scans          – List recent scan records
GET  /scans/{id}     – Get a specific scan result
DELETE /scans/{id}   – Delete a scan record
GET  /scans/{id}/report – Download JSON report
"""

import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from scanner.utils import validate_target, normalize_target
from scanner.orchestrator import run_full_scan
from models.database import (
    create_scan_record,
    update_scan_record,
    get_scan_record,
    list_scans,
    delete_scan_record,
)

logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    common_ports_only: bool = True
    port_start: int = 1
    port_end: int = 1024
    skip_web: bool = False
    thread_count: int = 100
    timeout: float = 1.0

    @field_validator("target")
    @classmethod
    def target_must_be_valid(cls, v):
        ok, reason = validate_target(v)
        if not ok:
            raise ValueError(reason)
        return normalize_target(v)

    @field_validator("port_end")
    @classmethod
    def port_end_range(cls, v):
        if not (1 <= v <= 65535):
            raise ValueError("port_end must be between 1 and 65535")
        return v

    @field_validator("thread_count")
    @classmethod
    def thread_count_limit(cls, v):
        return max(1, min(v, 200))   # cap at 200 threads


# ── Background scan worker ─────────────────────────────────────────────────────

def _run_scan_background(scan_id: int, target: str, opts: dict):
    """Executes the scan and writes results back to the database."""
    try:
        result = run_full_scan(target, opts)
        update_scan_record(scan_id, result, status="completed")
        logger.info("Scan %d completed for %s", scan_id, target)
    except Exception as exc:
        logger.error("Scan %d failed: %s", scan_id, exc, exc_info=True)
        update_scan_record(scan_id, {"error": str(exc)}, status="failed")


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/scans", status_code=202, tags=["Scans"])
@limiter.limit("5/minute")
async def start_scan(request: Request, body: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a vulnerability scan.
    ⚠️ Only scan systems you own or have explicit permission to test.
    """
    scan_id = create_scan_record(body.target, scan_type="full")
    opts = {
        "common_ports_only": body.common_ports_only,
        "port_start":        body.port_start,
        "port_end":          body.port_end,
        "skip_web":          body.skip_web,
        "thread_count":      body.thread_count,
        "timeout":           body.timeout,
    }
    background_tasks.add_task(_run_scan_background, scan_id, body.target, opts)
    logger.info("Scan %d queued for %s", scan_id, body.target)
    return {"scan_id": scan_id, "status": "running", "target": body.target}


@router.get("/scans", tags=["Scans"])
async def list_scan_history(limit: int = 20):
    """Return the last *limit* scan summaries."""
    limit = max(1, min(limit, 100))
    return list_scans(limit)


@router.get("/scans/{scan_id}", tags=["Scans"])
async def get_scan(scan_id: int):
    """Return full details of a single scan."""
    record = get_scan_record(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/scans/{scan_id}", tags=["Scans"])
async def delete_scan(scan_id: int):
    """Delete a scan record."""
    deleted = delete_scan_record(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}


@router.get("/scans/{scan_id}/report", tags=["Reports"])
async def download_report(scan_id: int):
    """Download the scan result as a JSON report."""
    record = get_scan_record(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    if record.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Scan not yet completed")

    filename = f"vuln-report-{record['target'].replace('.', '_')}-{scan_id}.json"
    return JSONResponse(
        content=record.get("result", record),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
