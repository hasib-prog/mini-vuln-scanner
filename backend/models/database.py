"""
Database layer – SQLite via sqlite3 (no ORM dependency needed for MVP).
Stores scan history so users can review past results.
"""

import sqlite3
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "scanner.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    return conn


def init_db():
    """Create tables if they don't exist."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT    NOT NULL,
                scan_type   TEXT    NOT NULL DEFAULT 'full',
                status      TEXT    NOT NULL DEFAULT 'pending',
                result_json TEXT,
                created_at  TEXT    NOT NULL,
                finished_at TEXT
            )
        """)
        conn.commit()
    logger.info("✅ Database initialised at %s", DB_PATH)


# ── CRUD helpers ───────────────────────────────────────────────────────────────

def create_scan_record(target: str, scan_type: str = "full") -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, scan_type, status, created_at) VALUES (?, ?, 'running', ?)",
            (target, scan_type, datetime.utcnow().isoformat()),
        )
        conn.commit()
        return cur.lastrowid


def update_scan_record(scan_id: int, result: dict, status: str = "completed"):
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET result_json=?, status=?, finished_at=? WHERE id=?",
            (json.dumps(result), status, datetime.utcnow().isoformat(), scan_id),
        )
        conn.commit()


def get_scan_record(scan_id: int) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    if d.get("result_json"):
        d["result"] = json.loads(d["result_json"])
    return d


def list_scans(limit: int = 20) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, target, scan_type, status, created_at, finished_at FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_scan_record(scan_id: int) -> bool:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0
