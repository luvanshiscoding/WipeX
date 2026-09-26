"""
WipeX - Tamper-evident audit log.

Every entry commits to the previous one:
    hash_n = SHA-256(prev_hash_n || canonical_json(entry_n))
and hash_n is signed with the workstation's ECDSA P-256 key. When the actor is the
signed-in user, hash_n is also signed with that user's personal key (users.py), so the
entry is attributable to a person. Editing, deleting or reordering any entry breaks the
chain from that point on, which verify_chain() reports.
Note: a hash chain proves integrity of what was logged, not that nothing was omitted.
"""

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

import store
from crypto_signer import CryptoSigner

GENESIS = "0" * 64
_columns_ready_for: Optional[str] = None


def _ensure_columns() -> None:
    """Add the personal-signature columns to databases created before they existed."""
    global _columns_ready_for
    if _columns_ready_for == store.DB_FILE:
        return
    with store.tx() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        for col in ("actor_key_id", "actor_sig"):
            if col not in cols:
                conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col} TEXT")
    _columns_ready_for = store.DB_FILE


def _canonical(entry: Dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_body(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "seq": row["seq"],
        "ts": row["ts"],
        "actor": row["actor"],
        "action": row["action"],
        "case_id": row.get("case_id"),
        "target": row.get("target"),
        "details": json.loads(row["details"]) if isinstance(row["details"], str) else row["details"],
    }


def _hash(prev_hash: str, body: Dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


def append(action: str, actor: str = "system", target: Optional[str] = None,
           case_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Append one entry; returns the stored entry including hash and signature(s)."""
    import users  # local import: users logs through this module
    _ensure_columns()
    details = details or {}
    with store.tx() as conn:
        last = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (last["seq"] + 1) if last else 1
        prev_hash = last["hash"] if last else GENESIS
        body = {
            "seq": seq,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "actor": actor or "system",
            "action": action,
            "case_id": case_id,
            "target": target,
            "details": details,
        }
        entry_hash = _hash(prev_hash, body)
        signature = CryptoSigner.sign_payload(entry_hash)
        personal = users.sign_current(body["actor"], entry_hash) or {}
        conn.execute(
            "INSERT INTO audit_log(seq, ts, actor, action, case_id, target, details, prev_hash, hash, signature, "
            "actor_key_id, actor_sig) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (seq, body["ts"], body["actor"], action, case_id, target,
             json.dumps(details, sort_keys=True, ensure_ascii=False), prev_hash, entry_hash, signature,
             personal.get("keyId"), personal.get("signature")),
        )
    return {**body, "prev_hash": prev_hash, "hash": entry_hash, "signature": signature,
            "actor_key_id": personal.get("keyId"), "actor_sig": personal.get("signature")}


def entries(limit: int = 200, offset: int = 0, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    _ensure_columns()
    if case_id:
        rows = store.query("SELECT * FROM audit_log WHERE case_id = ? ORDER BY seq DESC LIMIT ? OFFSET ?",
                           (case_id, limit, offset))
    else:
        rows = store.query("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ? OFFSET ?", (limit, offset))
    for r in rows:
        r["details"] = json.loads(r["details"])
    return rows


def count() -> int:
    row = store.query_one("SELECT COUNT(*) AS n FROM audit_log")
    return row["n"] if row else 0


def verify_chain() -> Dict[str, Any]:
    """Recompute every hash and signature. Returns the first break, if any."""
    import users
    _ensure_columns()
    rows = store.query("SELECT * FROM audit_log ORDER BY seq ASC")
    prev_hash = GENESIS
    expected_seq = 1
    personal = 0
    for row in rows:
        if row["seq"] != expected_seq:
            return {"valid": False, "entries": len(rows), "brokenAt": row["seq"],
                    "reason": f"Sequence gap: expected {expected_seq}, found {row['seq']} (entry removed)"}
        if row["prev_hash"] != prev_hash:
            return {"valid": False, "entries": len(rows), "brokenAt": row["seq"],
                    "reason": "Previous-hash link does not match the preceding entry"}
        recomputed = _hash(prev_hash, _entry_body(row))
        if recomputed != row["hash"]:
            return {"valid": False, "entries": len(rows), "brokenAt": row["seq"],
                    "reason": "Entry content was modified after it was logged"}
        if not CryptoSigner.verify_signature(row["hash"], row["signature"]):
            return {"valid": False, "entries": len(rows), "brokenAt": row["seq"],
                    "reason": "Signature does not verify with the workstation public key"}
        if row.get("actor_sig"):
            if not users.verify_user_signature(row.get("actor_key_id") or "", row["hash"], row["actor_sig"], row["actor"]):
                return {"valid": False, "entries": len(rows), "brokenAt": row["seq"],
                        "reason": f"Personal signature of '{row['actor']}' does not verify"}
            personal += 1
        prev_hash = row["hash"]
        expected_seq += 1
    return {"valid": True, "entries": len(rows), "brokenAt": None, "userSigned": personal,
            "headHash": prev_hash, "reason": "All entries verified"}
