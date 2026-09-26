"""
WipeX - Case, evidence and legal-hold management.

Legal holds implement the evidence-lock interlock: a device serial, device path,
image path or folder under an active hold cannot be erased by M1 or M2.
Every change is written to the tamper-evident audit log.
"""

import hashlib
import os
import secrets
import time
from typing import Any, Callable, Dict, List, Optional

import audit_log
import ewf
import store


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _norm_path(p: str) -> str:
    return os.path.normcase(os.path.abspath(p)) if p else ""


# ── Cases ────────────────────────────────────────────────────────────────────

def create_case(title: str, investigator: str, description: str = "") -> Dict[str, Any]:
    if not title.strip() or not investigator.strip():
        raise ValueError("Case title and investigator are required")
    case_id = f"CASE-{time.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    row = {"id": case_id, "title": title.strip(), "investigator": investigator.strip(),
           "description": description.strip(), "status": "OPEN", "created_at": _now()}
    with store.tx() as conn:
        conn.execute("INSERT INTO cases(id,title,investigator,description,status,created_at) VALUES(?,?,?,?,?,?)",
                     tuple(row.values()))
    audit_log.append("case.created", investigator, target=case_id, case_id=case_id,
                     details={"title": row["title"]})
    return row


def list_cases() -> List[Dict[str, Any]]:
    cases = store.query("SELECT * FROM cases ORDER BY created_at DESC")
    for c in cases:
        c["evidenceCount"] = store.query_one("SELECT COUNT(*) n FROM evidence WHERE case_id=?", (c["id"],))["n"]
        c["activeHolds"] = store.query_one("SELECT COUNT(*) n FROM legal_holds WHERE case_id=? AND active=1", (c["id"],))["n"]
    return cases


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    case = store.query_one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not case:
        return None
    case["evidence"] = store.query("SELECT * FROM evidence WHERE case_id=? ORDER BY acquired_at DESC", (case_id,))
    case["holds"] = store.query("SELECT * FROM legal_holds WHERE case_id=? ORDER BY created_at DESC", (case_id,))
    case["custody"] = audit_log.entries(limit=500, case_id=case_id)
    return case


def set_case_status(case_id: str, status: str, actor: str) -> None:
    if status not in ("OPEN", "CLOSED"):
        raise ValueError("Status must be OPEN or CLOSED")
    with store.tx() as conn:
        conn.execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))
    audit_log.append(f"case.{status.lower()}", actor, target=case_id, case_id=case_id)


# ── Evidence acquisition ─────────────────────────────────────────────────────

def acquire_evidence(case_id: str, source_path: str, label: str, actor: str,
                     progress: Optional[Callable[[int, str], None]] = None, fmt: str = "raw") -> Dict[str, Any]:
    """
    Forensic acquisition: read the source (raw image, raw device or E01, opened read-only)
    and write it into the case folder as a raw .dd or an E01 image, computing SHA-256 and
    MD5 of the media in the same pass. The stored image is then read back and re-hashed;
    acquisition fails unless the hashes match. Returns the evidence record.
    """
    if not store.query_one("SELECT id FROM cases WHERE id=?", (case_id,)):
        raise ValueError(f"Unknown case {case_id}")
    if not source_path:
        raise ValueError("Source path is required")
    if fmt not in ("raw", "e01"):
        raise ValueError("Format must be raw or e01")

    evidence_id = f"EV-{secrets.token_hex(4).upper()}"
    dest_dir = store.workspace_path("cases", case_id, "evidence")
    audit_log.append("evidence.acquisition_started", actor, target=source_path, case_id=case_id,
                     details={"evidenceId": evidence_id, "label": label, "format": fmt})

    src = ewf.open_image(source_path)
    source_format = "e01" if isinstance(src, ewf.EwfReader) else "raw"
    total = src.size
    sha, md5 = hashlib.sha256(), hashlib.md5()
    copied = 0
    chunk = 4 * 1024 * 1024
    notes = ""
    try:
        if fmt == "e01":
            dest_base = os.path.join(dest_dir, evidence_id)
            out = ewf.EwfWriter(dest_base, total, {"case_number": case_id, "evidence_number": evidence_id,
                                                   "description": label, "examiner_name": actor,
                                                   "notes": f"Source: {source_path}"})
            dest = ewf.segment_name(dest_base, 1)
        else:
            dest = os.path.join(dest_dir, f"{evidence_id}.dd")
            out = open(dest, "wb")
        while copied < total:
            block = src.read(copied, min(chunk, total - copied))
            if not block:
                break
            sha.update(block)
            md5.update(block)
            out.write(block)
            copied += len(block)
            if progress and total:
                progress(min(90, int(copied * 90 / total)), f"Imaged {copied // (1024 * 1024)} MB")
        info = out.close() if fmt == "e01" else (out.close() or {})
        if fmt == "e01" and total % 512:
            notes = f"Media padded from {total} to {info['mediaSize']} bytes (whole sectors) inside the E01"
        if source_format == "e01" and src.stored_md5 and src.stored_md5 != md5.hexdigest():
            notes = (notes + "; " if notes else "") + "Source E01 stored MD5 does not match its content"
    finally:
        src.close()
    source_sha = sha.hexdigest()

    if progress:
        progress(92, "Reading the stored image back to verify its hash")
    check = ewf.open_image(dest)
    try:
        verify = hashlib.sha256()
        pos = 0
        while pos < copied:
            block = check.read(pos, min(chunk, copied - pos))
            if not block:
                break
            verify.update(block)
            pos += len(block)
    finally:
        check.close()
    if verify.hexdigest() != source_sha:
        audit_log.append("evidence.acquisition_failed", actor, target=source_path, case_id=case_id,
                         details={"evidenceId": evidence_id, "reason": "hash mismatch after copy"})
        raise IOError("Acquired image hash does not match the source hash")

    record = {
        "id": evidence_id, "case_id": case_id, "label": label or os.path.basename(source_path),
        "source_path": source_path, "image_path": dest,
        "kind": ("device" if _is_device(source_path) else "image") + (" (E01)" if fmt == "e01" else ""),
        "size_bytes": copied, "sha256": source_sha, "md5": md5.hexdigest(),
        "acquired_at": _now(), "acquired_by": actor, "notes": notes,
    }
    with store.tx() as conn:
        conn.execute(
            "INSERT INTO evidence(id,case_id,label,source_path,image_path,kind,size_bytes,sha256,md5,acquired_at,acquired_by,notes) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", tuple(record.values()))
    audit_log.append("evidence.acquired", actor, target=source_path, case_id=case_id,
                     details={"evidenceId": evidence_id, "sha256": source_sha, "md5": record["md5"], "bytes": copied})
    return record


def get_evidence(evidence_id: str) -> Optional[Dict[str, Any]]:
    return store.query_one("SELECT * FROM evidence WHERE id=?", (evidence_id,))


def verify_evidence(evidence_id: str, actor: str) -> Dict[str, Any]:
    """Re-hash the stored image and compare with the acquisition hash."""
    ev = get_evidence(evidence_id)
    if not ev:
        raise ValueError("Unknown evidence item")
    sha = hashlib.sha256()
    img = ewf.open_image(ev["image_path"])
    try:
        pos, total = 0, int(ev["size_bytes"] or img.size)
        while pos < total:
            block = img.read(pos, min(4 * 1024 * 1024, total - pos))
            if not block:
                break
            sha.update(block)
            pos += len(block)
    finally:
        img.close()
    ok = sha.hexdigest() == ev["sha256"]
    audit_log.append("evidence.hash_verified" if ok else "evidence.hash_mismatch", actor,
                     target=evidence_id, case_id=ev["case_id"], details={"sha256": sha.hexdigest()})
    return {"evidenceId": evidence_id, "match": ok, "expected": ev["sha256"], "actual": sha.hexdigest()}


def _is_device(path: str) -> bool:
    return path.startswith("\\\\.\\") or path.startswith("/dev/")


# ── Legal holds (evidence lock) ──────────────────────────────────────────────

HOLD_KINDS = ("device_serial", "device_path", "path")


def add_hold(case_id: str, target: str, target_kind: str, reason: str, actor: str) -> Dict[str, Any]:
    if target_kind not in HOLD_KINDS:
        raise ValueError(f"target_kind must be one of {HOLD_KINDS}")
    if not store.query_one("SELECT id FROM cases WHERE id=?", (case_id,)):
        raise ValueError(f"Unknown case {case_id}")
    hold = {"id": f"HOLD-{secrets.token_hex(3).upper()}", "case_id": case_id, "target": target.strip(),
            "target_kind": target_kind, "reason": reason, "active": 1, "created_at": _now(), "released_at": None}
    with store.tx() as conn:
        conn.execute("INSERT INTO legal_holds(id,case_id,target,target_kind,reason,active,created_at,released_at) "
                     "VALUES(?,?,?,?,?,?,?,?)", tuple(hold.values()))
    audit_log.append("hold.placed", actor, target=hold["target"], case_id=case_id,
                     details={"holdId": hold["id"], "kind": target_kind, "reason": reason})
    return hold


def release_hold(hold_id: str, actor: str) -> None:
    hold = store.query_one("SELECT * FROM legal_holds WHERE id=?", (hold_id,))
    if not hold:
        raise ValueError("Unknown hold")
    with store.tx() as conn:
        conn.execute("UPDATE legal_holds SET active=0, released_at=? WHERE id=?", (_now(), hold_id))
    audit_log.append("hold.released", actor, target=hold["target"], case_id=hold["case_id"],
                     details={"holdId": hold_id})


def active_holds() -> List[Dict[str, Any]]:
    return store.query("SELECT * FROM legal_holds WHERE active=1")


def find_blocking_hold(device_serial: str = "", device_path: str = "", paths: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """Return the first active hold that covers the requested erasure target, else None."""
    paths = [_norm_path(p) for p in (paths or []) if p]
    for hold in active_holds():
        kind, target = hold["target_kind"], hold["target"]
        if kind == "device_serial" and device_serial and target.strip().lower() == device_serial.strip().lower():
            return hold
        if kind == "device_path" and device_path and _norm_path(target) == _norm_path(device_path):
            return hold
        if kind == "path":
            held = _norm_path(target)
            for p in paths + ([_norm_path(device_path)] if device_path else []):
                # Blocks the held path itself, anything inside it, and any parent folder containing it
                if p == held or p.startswith(held + os.sep) or held.startswith(p + os.sep):
                    return hold
    return None


# ── Two-person rule ──────────────────────────────────────────────────────────

def dual_approval_required() -> bool:
    return bool(store.get_setting("dual_approval", False))


def set_dual_approval(enabled: bool, actor: str) -> None:
    store.set_setting("dual_approval", bool(enabled))
    audit_log.append("settings.dual_approval", actor, details={"enabled": bool(enabled)})


def check_authorization(operator: str, approver: str) -> None:
    """Raise PermissionError when the two-person rule is on and not satisfied."""
    if not (operator or "").strip():
        raise PermissionError("Operator name is required for erasure")
    if dual_approval_required():
        if not (approver or "").strip():
            raise PermissionError("Two-person rule is on: an approver is required")
        if approver.strip().lower() == operator.strip().lower():
            raise PermissionError("Two-person rule is on: approver must be a different person")
