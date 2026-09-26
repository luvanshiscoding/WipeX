"""
WipeX - users, roles and sessions (offline, no external identity provider).

* Passwords are stored as scrypt hashes (n=2^14, r=8, p=1) with a per-user salt.
* Every user owns an ECDSA P-256 key pair. The private key is kept encrypted with the
  user's password (PKCS#8, BestAvailableEncryption) and is only decrypted in memory for
  the lifetime of a login session. Audit entries and erasure approvals made in that
  session carry the user's own signature in addition to the workstation signature,
  so a record can be attributed to a person, not only to the machine.
* An admin password reset cannot decrypt the old key, so it issues a new key pair;
  old public keys stay in user_keys so earlier signatures keep verifying.

Roles
  admin         everything, including users and settings
  investigator  cases, evidence, recovery, legal holds; approves erasures (two-person rule)
  sanitizer     drive and file erasure, certificates, lab images
  auditor       read-only: cases, audit log, reports, certificate verification
"""

import base64
import contextvars
import hashlib
import hmac
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

import audit_log
import store

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    HAS_CRYPTO = False

SESSION_TTL = 8 * 3600
MIN_PASSWORD = 8

ROLES: Dict[str, Dict[str, Any]] = {
    "admin": {"label": "Administrator", "perms": {"*"}},
    "investigator": {"label": "Investigator", "perms": {
        "device.read", "case.read", "case.manage", "evidence.acquire", "recovery.run", "hold.manage",
        "erasure.approve", "report.read", "audit.read", "lab.manage"}},
    "sanitizer": {"label": "Sanitizer", "perms": {
        "device.read", "case.read", "erasure.run", "files.erase", "certificate.issue", "report.read",
        "audit.read", "lab.manage"}},
    "auditor": {"label": "Auditor", "perms": {"device.read", "case.read", "report.read", "audit.read"}},
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    pw_salt TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    key_id TEXT NOT NULL,
    enc_private_key TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS user_keys (
    key_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT
);
"""

_ready_for: Optional[str] = None
_sessions: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()

# The signed-in session for the current request; background jobs inherit it (see jobs.py)
current_session: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar("wipex_session", default=None)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def init() -> None:
    global _ready_for
    if _ready_for == store.DB_FILE:
        return
    with store.tx() as conn:
        conn.executescript(_SCHEMA)
    _ready_for = store.DB_FILE


# ── Passwords and keys ───────────────────────────────────────────────────────

def _hash_pw(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32).hex()


def _check_password_policy(password: str) -> None:
    if len(password or "") < MIN_PASSWORD:
        raise ValueError(f"Password must be at least {MIN_PASSWORD} characters")


def _new_keypair(password: str):
    key = ec.generate_private_key(ec.SECP256R1())
    enc = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(password.encode("utf-8"))).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return key, enc, pub


def _public_row(u: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": u["id"], "username": u["username"], "displayName": u["display_name"], "role": u["role"],
            "roleLabel": ROLES.get(u["role"], {}).get("label", u["role"]), "active": bool(u["active"]),
            "keyId": u["key_id"], "createdAt": u["created_at"], "lastLogin": u.get("last_login"),
            "permissions": sorted(ROLES.get(u["role"], {}).get("perms", set()))}


# ── Users ────────────────────────────────────────────────────────────────────

def count() -> int:
    init()
    return store.query_one("SELECT COUNT(*) n FROM users")["n"]


def setup_required() -> bool:
    return count() == 0


def list_users() -> List[Dict[str, Any]]:
    init()
    return [_public_row(u) for u in store.query("SELECT * FROM users ORDER BY created_at")]


def get_user(username: str) -> Optional[Dict[str, Any]]:
    init()
    return store.query_one("SELECT * FROM users WHERE lower(username) = lower(?)", ((username or "").strip(),))


def create_user(username: str, password: str, role: str, display_name: str = "", actor: str = "system") -> Dict[str, Any]:
    init()
    if not HAS_CRYPTO:
        raise RuntimeError("The cryptography library is required for user keys")
    username = (username or "").strip()
    if not username or not username.replace(".", "").replace("-", "").replace("_", "").isalnum() or len(username) > 40:
        raise ValueError("Username must be 1-40 letters, digits, '.', '-' or '_'")
    if role not in ROLES:
        raise ValueError(f"Role must be one of {', '.join(ROLES)}")
    _check_password_policy(password)
    if get_user(username):
        raise FileExistsError(f"User '{username}' already exists")
    salt = secrets.token_bytes(16)
    _key, enc, pub = _new_keypair(password)
    uid = f"U-{secrets.token_hex(4).upper()}"
    key_id = f"K-{secrets.token_hex(6).upper()}"
    with store.tx() as conn:
        conn.execute("INSERT INTO users(id,username,display_name,role,pw_salt,pw_hash,key_id,enc_private_key,active,created_at) "
                     "VALUES(?,?,?,?,?,?,?,?,1,?)",
                     (uid, username, display_name.strip() or username, role, salt.hex(), _hash_pw(password, salt),
                      key_id, enc, _now()))
        conn.execute("INSERT INTO user_keys(key_id,user_id,username,public_key,created_at) VALUES(?,?,?,?,?)",
                     (key_id, uid, username, pub, _now()))
    audit_log.append("user.created", actor, target=username, details={"role": role, "keyId": key_id})
    return _public_row(get_user(username))


def update_user(username: str, actor: str, role: Optional[str] = None, active: Optional[bool] = None,
                new_password: Optional[str] = None) -> Dict[str, Any]:
    """Admin changes. A password reset issues a new key pair (the old key cannot be decrypted)."""
    u = get_user(username)
    if not u:
        raise LookupError(f"No user '{username}'")
    changes: Dict[str, Any] = {}
    with store.tx() as conn:
        if role is not None and role != u["role"]:
            if role not in ROLES:
                raise ValueError(f"Role must be one of {', '.join(ROLES)}")
            if u["role"] == "admin" and _active_admins(conn) <= 1:
                raise ValueError("At least one active administrator is required")
            conn.execute("UPDATE users SET role=? WHERE id=?", (role, u["id"]))
            changes["role"] = role
        if active is not None and bool(active) != bool(u["active"]):
            if not active and u["role"] == "admin" and _active_admins(conn) <= 1:
                raise ValueError("At least one active administrator is required")
            conn.execute("UPDATE users SET active=? WHERE id=?", (1 if active else 0, u["id"]))
            changes["active"] = bool(active)
        if new_password:
            _check_password_policy(new_password)
            salt = secrets.token_bytes(16)
            _key, enc, pub = _new_keypair(new_password)
            key_id = f"K-{secrets.token_hex(6).upper()}"
            conn.execute("UPDATE user_keys SET retired_at=? WHERE key_id=?", (_now(), u["key_id"]))
            conn.execute("INSERT INTO user_keys(key_id,user_id,username,public_key,created_at) VALUES(?,?,?,?,?)",
                         (key_id, u["id"], u["username"], pub, _now()))
            conn.execute("UPDATE users SET pw_salt=?, pw_hash=?, key_id=?, enc_private_key=? WHERE id=?",
                         (salt.hex(), _hash_pw(new_password, salt), key_id, enc, u["id"]))
            changes["passwordReset"] = True
            changes["newKeyId"] = key_id
    if changes.get("active") is False or changes.get("passwordReset") or "role" in changes:
        _drop_sessions(u["id"])
    if changes:
        audit_log.append("user.updated", actor, target=u["username"], details=changes)
    return _public_row(get_user(username))


def change_password(username: str, old_password: str, new_password: str) -> None:
    """Self-service change: the same key pair is re-encrypted with the new password."""
    u = get_user(username)
    if not u or not _verify_pw(u, old_password):
        raise PermissionError("Current password is incorrect")
    _check_password_policy(new_password)
    key = serialization.load_pem_private_key(u["enc_private_key"].encode(), password=old_password.encode("utf-8"))
    enc = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(new_password.encode("utf-8"))).decode()
    salt = secrets.token_bytes(16)
    with store.tx() as conn:
        conn.execute("UPDATE users SET pw_salt=?, pw_hash=?, enc_private_key=? WHERE id=?",
                     (salt.hex(), _hash_pw(new_password, salt), enc, u["id"]))
    audit_log.append("user.password_changed", u["username"], target=u["username"])


def _active_admins(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]


def _verify_pw(u: Dict[str, Any], password: str) -> bool:
    return hmac.compare_digest(_hash_pw(password or "", bytes.fromhex(u["pw_salt"])), u["pw_hash"])


def authenticate(username: str, password: str) -> Dict[str, Any]:
    """Check credentials and return the user row with the decrypted signing key."""
    u = get_user(username)
    if not u or not _verify_pw(u, password):
        time.sleep(0.3)                                  # blunt online guessing
        raise PermissionError("Invalid username or password")
    if not u["active"]:
        raise PermissionError("This account is disabled")
    key = serialization.load_pem_private_key(u["enc_private_key"].encode(), password=password.encode("utf-8"))
    return {**u, "_key": key}


def has_perm(role: str, perm: str) -> bool:
    perms = ROLES.get(role, {}).get("perms", set())
    return "*" in perms or perm in perms


# ── Sessions ─────────────────────────────────────────────────────────────────

def login(username: str, password: str) -> Dict[str, Any]:
    u = authenticate(username, password)
    token = secrets.token_urlsafe(32)
    sess = {"token": token, "userId": u["id"], "username": u["username"], "displayName": u["display_name"],
            "role": u["role"], "keyId": u["key_id"], "key": u["_key"], "expires": time.time() + SESSION_TTL}
    with _lock:
        _sessions[token] = sess
    with store.tx() as conn:
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (_now(), u["id"]))
    token_ctx = current_session.set(sess)
    try:
        audit_log.append("user.login", u["username"], target=u["username"])
    finally:
        current_session.reset(token_ctx)
    return {"token": token, "user": _public_row(get_user(u["username"]))}


def logout(token: str) -> None:
    with _lock:
        sess = _sessions.pop(token, None)
    if sess:
        audit_log.append("user.logout", sess["username"], target=sess["username"])


def session_for(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    with _lock:
        sess = _sessions.get(token)
        if not sess:
            return None
        if sess["expires"] < time.time():
            _sessions.pop(token, None)
            return None
        sess["expires"] = time.time() + SESSION_TTL        # sliding expiry
        return sess


def _drop_sessions(user_id: str) -> None:
    with _lock:
        for t in [t for t, s in _sessions.items() if s["userId"] == user_id]:
            _sessions.pop(t, None)


# ── Personal signatures ──────────────────────────────────────────────────────

def sign_as(sess: Dict[str, Any], payload: str) -> Dict[str, str]:
    sig = sess["key"].sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return {"keyId": sess["keyId"], "signature": base64.b64encode(sig).decode()}


def sign_current(actor: str, payload: str) -> Optional[Dict[str, str]]:
    """Sign with the signed-in user's key when that user is the actor of the record."""
    sess = current_session.get()
    if not sess or not HAS_CRYPTO or sess["username"].lower() != (actor or "").lower():
        return None
    return sign_as(sess, payload)


def public_key(key_id: str) -> Optional[Dict[str, Any]]:
    init()
    return store.query_one("SELECT * FROM user_keys WHERE key_id=?", (key_id,))


def verify_user_signature(key_id: str, payload: str, signature_b64: str, expected_user: Optional[str] = None) -> bool:
    row = public_key(key_id)
    if not row or not HAS_CRYPTO:
        return False
    if expected_user and row["username"].lower() != expected_user.lower():
        return False
    try:
        pub = serialization.load_pem_public_key(row["public_key"].encode())
        pub.verify(base64.b64decode(signature_b64), payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001 - any failure means "does not verify"
        return False


# ── Access profiles (prototype: no sign-in page) ────────────────────────────
#
# The workstation opens straight into one of four NTRO access profiles. Each profile is a real
# account with its own role and personal signing key; its secret is derived from the workstation
# signing key, so a profile can only be opened by the WipeX engine on this workstation (the API
# accepts local requests only). Named accounts with passwords remain available through the API.

PROFILES: List[Dict[str, str]] = [
    {"id": "admin", "role": "admin", "username": "ntro.admin", "name": "NTRO Lab Administrator"},
    {"id": "investigator", "role": "investigator", "username": "ntro.investigator", "name": "NTRO Forensic Investigator"},
    {"id": "sanitizer", "role": "sanitizer", "username": "ntro.sanitizer", "name": "NTRO Sanitization Officer"},
    {"id": "auditor", "role": "auditor", "username": "ntro.auditor", "name": "NTRO Auditor"},
]


def _profile(ident: str) -> Optional[Dict[str, str]]:
    ident = (ident or "").lower()
    return next((p for p in PROFILES if ident in (p["id"], p["username"])), None)


def _profile_secret(username: str) -> str:
    from crypto_signer import CryptoSigner
    CryptoSigner._init_keys()
    pem = CryptoSigner._private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption())
    return hmac.new(pem, b"wipex-profile|" + username.encode(), hashlib.sha256).hexdigest()


def ensure_profiles() -> None:
    """Create the access profiles on first run; re-key one if the workstation key changed."""
    init()
    for p in PROFILES:
        secret = _profile_secret(p["username"])
        u = get_user(p["username"])
        if not u:
            create_user(p["username"], secret, p["role"], p["name"])
        elif not _verify_pw(u, secret) or u["role"] != p["role"] or not u["active"]:
            update_user(p["username"], "system", role=p["role"], active=True, new_password=secret)


def list_profiles() -> List[Dict[str, Any]]:
    return [{"id": p["id"], "name": p["name"], "username": p["username"], "role": p["role"],
             "roleLabel": ROLES[p["role"]]["label"], "permissions": sorted(ROLES[p["role"]]["perms"])} for p in PROFILES]


def profile_login(ident: str) -> Dict[str, Any]:
    p = _profile(ident)
    if not p:
        raise ValueError("Unknown access profile")
    if not get_user(p["username"]):
        ensure_profiles()
    try:
        return login(p["username"], _profile_secret(p["username"]))
    except PermissionError:
        ensure_profiles()
        return login(p["username"], _profile_secret(p["username"]))


def approve(approver: str, password: str, operator: str, action: str, target: str) -> Dict[str, Any]:
    """
    Two-person rule: the approver authenticates with their own password (not just a typed
    name), must hold erasure.approve, and must be a different person from the operator.
    Returns a signed approval record that is stored with the erasure. An access profile approves
    without a password: it is opened on this workstation like the operator's own profile.
    """
    profile = _profile(approver)
    if profile and not password:
        approver, password = profile["username"], _profile_secret(profile["username"])
    u = authenticate(approver, password)
    if u["username"].lower() == (operator or "").lower():
        raise PermissionError("Two-person rule: the approver must be a different user")
    if not has_perm(u["role"], "erasure.approve"):
        raise PermissionError(f"User '{u['username']}' ({u['role']}) is not allowed to approve erasures")
    payload = f"WIPEX-APPROVAL|{action}|{target}|operator={operator}|approver={u['username']}|{_now()}"
    sig = sign_as({"key": u["_key"], "keyId": u["key_id"]}, payload)
    return {"approver": u["username"], "payload": payload, **sig}
