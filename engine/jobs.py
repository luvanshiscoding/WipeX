"""
WipeX - Background job runner for long operations (recovery scans, acquisition,
file erasure, benchmarks). Progress and results are persisted in the jobs table
so the UI can poll /api/jobs/{id}. Jobs run with a copy of the caller's context, so
audit entries they write are still signed by the user who started them.
"""

import contextvars
import json
import secrets
import threading
import time
import traceback
from typing import Any, Callable, Dict, Optional

import store


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class JobContext:
    def __init__(self, job_id: str):
        self.id = job_id
        self._last = 0.0

    def progress(self, pct: int, message: str = "") -> None:
        # Throttle DB writes to ~5 per second
        now = time.time()
        if now - self._last < 0.2 and pct < 100:
            return
        self._last = now
        with store.tx() as conn:
            conn.execute("UPDATE jobs SET progress=?, message=? WHERE id=?", (int(pct), message, self.id))


def submit(kind: str, fn: Callable[[JobContext], Dict[str, Any]], params: Optional[Dict[str, Any]] = None,
           case_id: Optional[str] = None) -> str:
    job_id = f"JOB-{kind.upper().replace('.', '-')}-{secrets.token_hex(4).upper()}"
    with store.tx() as conn:
        conn.execute("INSERT INTO jobs(id,kind,status,progress,message,params,case_id,created_at) VALUES(?,?,?,?,?,?,?,?)",
                     (job_id, kind, "RUNNING", 0, "Queued", json.dumps(params or {}), case_id, _now()))

    def runner():
        ctx = JobContext(job_id)
        try:
            result = fn(ctx)
            with store.tx() as conn:
                conn.execute("UPDATE jobs SET status='COMPLETED', progress=100, message=?, result=?, finished_at=? WHERE id=?",
                             ((result or {}).get("summary", "Completed"), json.dumps(result or {}, default=str), _now(), job_id))
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            with store.tx() as conn:
                conn.execute("UPDATE jobs SET status='FAILED', message=?, result=?, finished_at=? WHERE id=?",
                             (str(exc), json.dumps({"error": str(exc), "trace": traceback.format_exc(limit=3)}), _now(), job_id))

    ctx = contextvars.copy_context()
    threading.Thread(target=ctx.run, args=(runner,), name=job_id, daemon=True).start()
    return job_id


def get(job_id: str) -> Optional[Dict[str, Any]]:
    row = store.query_one("SELECT * FROM jobs WHERE id=?", (job_id,))
    if row:
        row["params"] = json.loads(row["params"] or "{}")
        row["result"] = json.loads(row["result"]) if row["result"] else None
    return row


def list_jobs(kind: Optional[str] = None, limit: int = 50) -> list:
    if kind:
        rows = store.query("SELECT id,kind,status,progress,message,case_id,created_at,finished_at FROM jobs WHERE kind=? ORDER BY created_at DESC LIMIT ?", (kind, limit))
    else:
        rows = store.query("SELECT id,kind,status,progress,message,case_id,created_at,finished_at FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))
    return rows


def run_sync(fn: Callable[[JobContext], Dict[str, Any]]) -> Dict[str, Any]:
    """Run a job function inline (used by tests)."""
    class _Null:
        id = "inline"
        def progress(self, pct, message=""):
            pass
    return fn(_Null())
