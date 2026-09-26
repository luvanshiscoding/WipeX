"""
WipeX - SQLite storage for forensic workflow tables (cases, evidence, legal holds,
audit log, background jobs, settings). Shares wipex.db with database.py.
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

DB_FILE = os.environ.get("WIPEX_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "wipex.db"))
WORKSPACE = os.environ.get("WIPEX_WORKSPACE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "workspace"))

_lock = threading.RLock()
_initialized_for: Optional[str] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    investigator TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    label TEXT NOT NULL,
    source_path TEXT NOT NULL,
    image_path TEXT,
    kind TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    sha256 TEXT,
    md5 TEXT,
    acquired_at TEXT,
    acquired_by TEXT,
    notes TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS legal_holds (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    target TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    reason TEXT DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    released_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    case_id TEXT,
    target TEXT,
    details TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER NOT NULL DEFAULT 0,
    message TEXT DEFAULT '',
    params TEXT DEFAULT '{}',
    result TEXT,
    case_id TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_holds_active ON legal_holds(active);
CREATE INDEX IF NOT EXISTS idx_jobs_kind ON jobs(kind);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    global _initialized_for
    with _lock:
        if _initialized_for == DB_FILE:
            return
        os.makedirs(WORKSPACE, exist_ok=True)
        conn = _connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()
        _initialized_for = DB_FILE


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    """Serialized write transaction."""
    init()
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def query(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    init()
    conn = _connect()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def query_one(sql: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    rows = query(sql, params)
    return rows[0] if rows else None


def get_setting(key: str, default: Any = None) -> Any:
    row = query_one("SELECT value FROM settings WHERE key = ?", (key,))
    return json.loads(row["value"]) if row else default


def set_setting(key: str, value: Any) -> None:
    with tx() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )


def workspace_path(*parts: str) -> str:
    path = os.path.join(WORKSPACE, *parts)
    os.makedirs(os.path.dirname(path) if os.path.splitext(path)[1] else path, exist_ok=True)
    return path
