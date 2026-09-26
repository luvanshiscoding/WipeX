"""
WipeX - erasure session and certificate ledger (SQLite, same file as store.py).

Kept as a separate module because the drive-erasure flow and the certificate
verification page use these tables directly. Everything is local: no server,
no network, suitable for an air-gapped workstation.
"""

import time
from typing import Any, Dict, List, Optional

import store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS wipe_records (
    wipe_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    method TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'IN_PROGRESS',
    progress INTEGER NOT NULL DEFAULT 0,
    pre_wipe_nonce TEXT NOT NULL,
    command TEXT,
    speed TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS certificates (
    certificate_id TEXT PRIMARY KEY,
    wipe_id TEXT,
    device_model TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    storage_type TEXT NOT NULL,
    capacity TEXT NOT NULL,
    standard TEXT NOT NULL,
    method_name TEXT NOT NULL,
    cleaned_status TEXT NOT NULL,
    trust_score TEXT NOT NULL,
    trust_score_label TEXT,
    audit_result TEXT NOT NULL,
    pre_wipe_nonce TEXT NOT NULL,
    sha256_digest TEXT NOT NULL,
    digital_signature TEXT NOT NULL,
    qr_payload TEXT DEFAULT '',
    tamper_detected INTEGER DEFAULT 0,
    verdict TEXT NOT NULL,
    issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(serial_number);
"""

_ready_for: Optional[str] = None


def init_db() -> None:
    global _ready_for
    if _ready_for == store.DB_FILE:
        return
    with store.tx() as conn:
        conn.executescript(_SCHEMA)
    _ready_for = store.DB_FILE


def save_wipe_record(wipe_id: str, device_id: str, method: str, nonce: str) -> None:
    init_db()
    with store.tx() as conn:
        conn.execute("INSERT OR REPLACE INTO wipe_records (wipe_id, device_id, method, pre_wipe_nonce, status, progress) "
                     "VALUES (?, ?, ?, ?, 'IN_PROGRESS', 0)", (wipe_id, device_id, method, nonce))


def update_wipe_progress(wipe_id: str, progress: int, status: str, speed: str = "", command: Optional[str] = None) -> None:
    init_db()
    done = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) if status != "IN_PROGRESS" else None
    with store.tx() as conn:
        conn.execute("UPDATE wipe_records SET progress = ?, status = ?, speed = ?, command = COALESCE(?, command), "
                     "completed_at = ? WHERE wipe_id = ?", (progress, status, speed, command, done, wipe_id))


def get_wipe_record(wipe_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    return store.query_one("SELECT * FROM wipe_records WHERE wipe_id = ?", (wipe_id,))


def get_all_wipe_records() -> List[Dict[str, Any]]:
    init_db()
    return [{"wipeId": r["wipe_id"], "deviceId": r["device_id"], "method": r["method"], "status": r["status"],
             "progress": r["progress"], "command": r["command"], "speed": r["speed"],
             "startedAt": r["started_at"], "completedAt": r["completed_at"]}
            for r in store.query("SELECT * FROM wipe_records ORDER BY started_at DESC LIMIT 100")]


def _cert(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "certificateId": row["certificate_id"], "wipeId": row["wipe_id"], "deviceModel": row["device_model"],
        "serialNumber": row["serial_number"], "storageType": row["storage_type"], "capacity": row["capacity"],
        "standard": row["standard"], "methodName": row["method_name"], "cleanedStatus": row["cleaned_status"],
        "trustScore": row["trust_score"], "trustScoreLabel": row["trust_score_label"],
        "auditResult": row["audit_result"], "preWipeNonce": row["pre_wipe_nonce"],
        "sha256Digest": row["sha256_digest"], "digitalSignature": row["digital_signature"],
        "qrPayload": row["qr_payload"], "tamperDetected": bool(row["tamper_detected"]),
        "verdict": row["verdict"], "issueDate": row["issue_date"],
    }


def get_all_certificates() -> List[Dict[str, Any]]:
    init_db()
    return [_cert(r) for r in store.query("SELECT * FROM certificates ORDER BY issue_date DESC LIMIT 100")]


def clear_all_history() -> bool:
    """Clear session and certificate ledger rows (the signed proofs and audit log are kept)."""
    init_db()
    with store.tx() as conn:
        conn.execute("DELETE FROM certificates")
        conn.execute("DELETE FROM wipe_records")
    return True


def save_certificate(cert: Dict[str, Any]) -> None:
    init_db()
    with store.tx() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO certificates (certificate_id, wipe_id, device_model, serial_number, storage_type, "
            "capacity, standard, method_name, cleaned_status, trust_score, trust_score_label, audit_result, "
            "pre_wipe_nonce, sha256_digest, digital_signature, qr_payload, tamper_detected, verdict, issue_date) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (cert["certificateId"], cert.get("wipe_id"), cert["deviceModel"], cert["serialNumber"], cert["storageType"],
             cert["capacity"], cert.get("standard", cert.get("methodName", "")), cert.get("methodName", cert.get("standard", "")),
             cert["cleanedStatus"], cert["trustScore"], cert.get("trustScoreLabel"), cert["auditResult"],
             cert["preWipeNonce"], cert["sha256Digest"], cert["digitalSignature"], cert.get("qrPayload", ""),
             1 if cert.get("tamperDetected") else 0, cert["verdict"], cert["issueDate"]))


def get_certificate_by_query(query: str) -> Optional[Dict[str, Any]]:
    """Exact lookup by certificate id or device serial number (no partial matches)."""
    init_db()
    q = (query or "").strip()
    row = store.query_one("SELECT * FROM certificates WHERE certificate_id = ? OR serial_number = ? "
                          "ORDER BY issue_date DESC LIMIT 1", (q, q))
    return _cert(row) if row else None
