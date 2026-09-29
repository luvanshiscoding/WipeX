"""
WipeX - Drive erasure engine (module M1) with verification and certificates.

Overwrite methods follow NIST SP 800-88 (Clear); hardware methods ask the device's own
controller to sanitize itself (Purge) - see hw_sanitize.py for the per-OS paths.

Verification:
  * pattern-aware read-back: the final pass is either a fixed byte or a keyed
    AES-256-CTR stream, so the verifier regenerates exactly what every sampled block
    must contain (entropy alone cannot distinguish "random wipe" from "encrypted data");
  * change check for hardware purges: sampled blocks captured before erasure must
    no longer hold their previous content;
  * canaries (lab images): marker blocks planted before erasure must be gone;
  * Recovery-as-Verifier: WipeX's own recovery engine (M3) is run against the target;
    the erasure only passes if nothing can be recovered.
"""

import hashlib
import json
import bisect
import math
import os
import platform
import random
import secrets
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

import audit_log
import cases
import database
import hw_sanitize
import lab_images
import store
import users
from crypto_signer import CryptoSigner

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_AES = True
except ImportError:  # pragma: no cover
    HAS_AES = False

CHUNK = 8 * 1024 * 1024                    # large sequential writes: what USB sticks handle best
BLOCK = 4096
FULL_VERIFY_LIMIT = 8 * 1024 ** 3         # read back every block up to 8 GiB; larger drives: sampled blocks
VERIFY_SAMPLES = 4096                      # sampled read-back on larger drives (NIST SP 800-88 allows sampling)
RECOVERY_VERIFY_LIMIT = 8 * 1024 ** 3     # run M3 recovery against targets up to 8 GiB
CANARY_MAGIC = b"WIPEX-CANARY-v1:"

_EXTRA_SCHEMA = """
CREATE TABLE IF NOT EXISTS erasures (
    wipe_id TEXT PRIMARY KEY,
    device TEXT NOT NULL,
    method TEXT NOT NULL,
    operator TEXT,
    approver TEXT,
    status TEXT NOT NULL,
    execution TEXT,
    verification TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS cert_proofs (
    certificate_id TEXT PRIMARY KEY,
    wipe_id TEXT,
    canonical TEXT NOT NULL,
    signature TEXT NOT NULL,
    public_key TEXT NOT NULL,
    issued_at TEXT NOT NULL
);
"""


_tables_ready_for: Optional[str] = None
# Operator-supplied secrets for a queued job (e.g. an Opal PSID); kept in memory only
_job_params: Dict[str, Dict[str, Any]] = {}


def _init_tables() -> None:
    global _tables_ready_for
    if _tables_ready_for == store.DB_FILE:
        return
    with store.tx() as conn:
        conn.executescript(_EXTRA_SCHEMA)
        for table, cols in (("erasures", ("approval",)), ("cert_proofs", ("operator_key_id", "operator_sig"))):
            have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for col in cols:
                if col not in have:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
    _tables_ready_for = store.DB_FILE


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ── Methods ──────────────────────────────────────────────────────────────────

def _gutmann() -> List[Any]:
    p: List[Any] = ["random"] * 4 + [b"\x55", b"\xAA", b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49"]
    p += [bytes([v]) for v in range(0x00, 0x100, 0x11)]
    p += [b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49", b"\x6D\xB6\xDB", b"\xB6\xDB\x6D", b"\xDB\x6D\xB6"]
    p += ["random"] * 3 + ["prng"]          # final pass is keyed and therefore verifiable
    return p


METHODS: Dict[str, Dict[str, Any]] = {
    "quick_used": {"name": "Quick erase: used space (file-system aware)", "category": "Not a Clear (used space only)",
                   "passes": [b"\x00"], "quick": True},
    "nist_800_88": {"name": "NIST SP 800-88 Clear (overwrite + verify)", "category": "Clear", "passes": [b"\x00"]},
    "single_pass": {"name": "Single-pass zero overwrite", "category": "Clear", "passes": [b"\x00"]},
    "random_pass": {"name": "Single-pass random overwrite", "category": "Clear", "passes": ["prng"]},
    "dod_5220_22_m": {"name": "DoD 5220.22-M three-pass overwrite", "category": "Clear", "passes": [b"\x00", b"\xFF", "prng"]},
    "gutmann": {"name": "Gutmann 35-pass overwrite", "category": "Clear", "passes": _gutmann()},
    "crypto_erase": {"name": "Cryptographic Erase (NVMe Sanitize / TCG Opal PSID revert)", "category": "Purge", "hardware": "crypto"},
    "block_erase": {"name": "NVMe Sanitize Block Erase", "category": "Purge", "hardware": "block"},
    "ata_sanitize": {"name": "ATA Enhanced Security Erase", "category": "Purge", "hardware": "ata"},
    "destroy": {"name": "Physical destruction", "category": "Destroy", "destroy": True},
}
ALIASES = {
    "purge-nvme-crypto": "crypto_erase", "sed-opal-crypto": "crypto_erase", "purge-ata-secure": "ata_sanitize",
    "clear-single": "single_pass", "quick-zero": "single_pass", "nist-clear": "nist_800_88",
    "dod-3pass": "dod_5220_22_m", "purge-dod-3pass": "dod_5220_22_m", "gutmann-35": "gutmann",
    "destroy-physical": "destroy",
}


def resolve_method(method_id: str) -> Tuple[str, Dict[str, Any]]:
    mid = ALIASES.get(method_id, method_id)
    if mid not in METHODS:
        raise ValueError(f"Unknown sanitization method '{method_id}'")
    return mid, METHODS[mid]


_PLATFORMS = {
    "crypto": ["Linux (nvme-cli, sedutil-cli)", "Windows (NVMe driver, sedutil-cli)"],
    "block": ["Linux (nvme-cli)", "Windows (NVMe driver)"],
    "ata": ["Linux (hdparm)"],
}


def method_catalog() -> List[Dict[str, Any]]:
    return [{"id": k, "name": v["name"], "category": v["category"],
             "passes": len(v.get("passes", [])), "hardware": v.get("hardware"),
             "platforms": _PLATFORMS.get(v.get("hardware"), ["Windows", "Linux", "macOS", "Disk images"])}
            for k, v in METHODS.items()]


# ── Keyed pattern stream ─────────────────────────────────────────────────────

def prng_bytes(key: bytes, offset: int, length: int) -> bytes:
    """AES-256-CTR keystream positioned at an absolute byte offset (reproducible for verification)."""
    if not HAS_AES:
        raise RuntimeError("cryptography library required for verifiable random passes")
    block, skip = divmod(offset, 16)
    enc = Cipher(algorithms.AES(key), modes.CTR(block.to_bytes(16, "big"))).encryptor()
    return enc.update(b"\x00" * (length + skip))[skip:]


def expected_bytes(pattern: Any, key: bytes, offset: int, length: int) -> bytes:
    if pattern == "prng":
        return prng_bytes(key, offset, length)
    if isinstance(pattern, bytes):
        if len(pattern) == 1:
            return pattern * length
        rep = pattern * ((offset % len(pattern) + length) // len(pattern) + 2)
        start = offset % len(pattern)
        return rep[start:start + length]
    raise ValueError("pattern not reproducible")


def _pass_buffer(pattern: Any, key: bytes, offset: int, length: int) -> bytes:
    if pattern == "random":
        return os.urandom(length)
    return expected_bytes(pattern, key, offset, length)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


# ── Device helpers ───────────────────────────────────────────────────────────

def resolve_target(device_id: str) -> Optional[Dict[str, Any]]:
    path = lab_images.path_for_id(device_id)
    if path:
        return lab_images.describe(path, with_files=False)
    from wipe_engine import WipeEngine
    return WipeEngine().resolve_device(device_id)


def _sample_offsets(capacity: int, n: int, seed: int) -> List[int]:
    blocks = max(1, capacity // BLOCK)
    rnd = random.Random(seed)
    picks = {0, blocks - 1} | {rnd.randrange(blocks) for _ in range(n)}
    return sorted(b * BLOCK for b in picks if (b + 1) * BLOCK <= capacity)


def _read(f, offset: int, length: int) -> bytes:
    f.seek(offset)
    return f.read(length)


def _io_path(dev: Dict[str, Any]) -> str:
    """macOS: use the raw character device (/dev/rdiskN) for unbuffered, much faster I/O."""
    path = dev["devicePath"]
    if platform.system() == "Darwin" and not dev.get("isImage") and path.startswith("/dev/disk"):
        return "/dev/r" + path[len("/dev/"):]
    return path


_volume_locks: Dict[str, List[int]] = {}


def _disk_letters(num: str) -> List[str]:
    res = subprocess.run(["powershell", "-NoProfile", "-Command",
                          f"(Get-Partition -DiskNumber {int(num)} -ErrorAction SilentlyContinue | "
                          "Where-Object DriveLetter).DriveLetter -join ','"],
                         capture_output=True, text=True, timeout=60)
    return [x.strip() for x in res.stdout.strip().split(",") if x.strip()]


FSCTL_LOCK_VOLUME, FSCTL_DISMOUNT_VOLUME = 0x00090018, 0x00090020


def _lock_volumes(path: str, num: str) -> None:
    """
    USB sticks and memory cards often cannot be taken offline. Instead, lock and dismount every
    volume on the disk (FSCTL_LOCK_VOLUME, FSCTL_DISMOUNT_VOLUME) and hold the handles until the
    erasure is finished, which is how raw-disk tools write to removable drives on Windows.
    When Explorer, an antivirus scan or the search indexer holds the drive open, the lock fails:
    WipeX then forces a dismount, which invalidates those handles, and locks again.
    """
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    invalid = wintypes.HANDLE(-1).value
    handles = []

    def release():
        for other in handles:
            k32.CloseHandle(other)

    for letter in _disk_letters(num):
        h = k32.CreateFileW(f"\\\\.\\{letter}:", 0x80000000 | 0x40000000, 0x1 | 0x2, None, 3, 0, None)
        if h in (None, invalid):
            release()
            raise PermissionError(f"Drive {letter}: cannot be opened for writing. Start WipeX as Administrator (WipeX.cmd).")
        got = wintypes.DWORD(0)
        ioctl = lambda code: bool(k32.DeviceIoControl(h, code, None, 0, None, 0, ctypes.byref(got), None))  # noqa: E731
        locked = ioctl(FSCTL_LOCK_VOLUME)
        if not locked:
            ioctl(FSCTL_DISMOUNT_VOLUME)             # forced: other programs' handles on the volume become invalid
            for _ in range(20):
                time.sleep(0.25)
                if ioctl(FSCTL_LOCK_VOLUME):
                    locked = True
                    break
        if not locked:
            k32.CloseHandle(h)
            release()
            raise PermissionError(f"Drive {letter}: is in use and could not be released. Close any window or "
                                  "program showing it (Explorer, antivirus scan) and try again.")
        ioctl(FSCTL_DISMOUNT_VOLUME)
        handles.append(h)
    _volume_locks[path] = handles


_WIN_ERRORS = {
    5: "Access denied: start WipeX as Administrator (WipeX.cmd).",
    19: "The drive is write-protected. Slide the lock switch on the card or stick to unlocked and try again.",
    21: "The drive is not ready. It may have been unplugged.",
    32: "The drive is in use by another program. Close any window showing it and try again.",
    55: "The drive was disconnected during the erasure.",
    433: "The drive was disconnected during the erasure.",
    1117: "The drive reported an I/O error. It may be failing: erase it again, or destroy it.",
    1167: "The drive was disconnected during the erasure.",
}


def friendly_error(exc: Exception) -> str:
    """Plain-language reason for an OS error during erasure (the technical text stays in the log)."""
    code = getattr(exc, "winerror", None)
    if code in _WIN_ERRORS:
        return _WIN_ERRORS[code]
    errno_ = getattr(exc, "errno", None)
    if errno_ in (1, 13):
        return "Permission denied: run WipeX as Administrator / root (sudo)."
    if errno_ in (6, 19):
        return "The drive was disconnected during the erasure."
    if errno_ == 30:
        return "The drive is write-protected."
    if errno_ == 16:
        return "The drive is busy: unmount it (or close programs using it) and try again."
    return str(exc)


def _prepare_physical(dev: Dict[str, Any]) -> None:
    """Release OS locks on a physical disk so raw writes succeed; raises with a clear reason."""
    path = dev["devicePath"]
    system = platform.system()
    if system == "Windows" and path.startswith("\\\\.\\PhysicalDrive"):
        num = path.replace("\\\\.\\PhysicalDrive", "")
        res = subprocess.run(["powershell", "-NoProfile", "-Command",
                              f"Set-Disk -Number {num} -IsOffline $true -ErrorAction Stop"],
                             capture_output=True, text=True, timeout=60)
        if res.returncode != 0:                      # typical for USB sticks: lock the volumes instead
            _lock_volumes(path, num)
    elif system == "Linux":
        for mp in dev.get("mountedPaths") or []:
            subprocess.run(["umount", "-f", mp], capture_output=True, timeout=30)
    elif system == "Darwin" and shutil.which("diskutil"):
        subprocess.run(["diskutil", "unmountDisk", "force", path], capture_output=True, timeout=30)


def _restore_physical(dev: Dict[str, Any]) -> None:
    path = dev["devicePath"]
    if platform.system() == "Windows" and path.startswith("\\\\.\\PhysicalDrive"):
        import ctypes
        for h in _volume_locks.pop(path, []):
            ctypes.windll.kernel32.CloseHandle(h)
        num = path.replace("\\\\.\\PhysicalDrive", "")
        subprocess.run(["powershell", "-NoProfile", "-Command", f"Set-Disk -Number {num} -IsOffline $false"],
                       capture_output=True, timeout=60)


# ── Job entry points ─────────────────────────────────────────────────────────

def start(device_id: str, method_id: str, operator: str, approver: str = "", case_id: Optional[str] = None,
          approval: Optional[Dict[str, Any]] = None, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Validate the request, record it, and return the wipe id. Execution runs in a background thread.
    approval: signed record from users.approve() when the two-person rule is on.
    options: operator inputs for hardware methods (e.g. {"psid": ...}); never written to disk.
    """
    _init_tables()
    mid, method = resolve_method(method_id)
    dev = resolve_target(device_id)
    if not dev:
        raise LookupError(f"Device {device_id} not found")
    if dev.get("isBootDrive"):
        raise PermissionError("The active operating-system disk cannot be erased from the running OS")
    cases.check_authorization(operator, approver)
    hold = cases.find_blocking_hold(dev.get("serialNumber", ""), dev.get("devicePath", ""))
    if hold:
        audit_log.append("erasure.blocked_by_hold", operator, target=dev.get("devicePath"), case_id=hold["case_id"],
                         details={"holdId": hold["id"], "method": mid})
        raise PermissionError(f"Device is under legal hold {hold['id']} (case {hold['case_id']})")
    if method.get("hardware"):
        if dev.get("isImage"):
            raise ValueError("Hardware purge commands need a physical NVMe/SATA device; use an overwrite method for disk images")
        caps = hw_sanitize.capabilities(dev)
        kind = method["hardware"]
        usable = caps.get(kind, {}).get("available") or (
            kind == "crypto" and (options or {}).get("psid") and caps.get("opal", {}).get("available"))
        if not usable:
            raise ValueError(f"{method['name']} is not available for this device: "
                             f"{caps.get(kind, {}).get('reason') or 'not supported'}")

    wipe_id = f"WIPE-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2).upper()}"
    nonce = CryptoSigner.generate_nonce()
    database.save_wipe_record(wipe_id, device_id, mid, nonce)
    device_snapshot = {k: dev.get(k) for k in ("id", "devicePath", "model", "serialNumber", "type", "interface",
                                               "capacity", "capacityBytes", "isImage", "reallocatedSectors")}
    with store.tx() as conn:
        conn.execute("INSERT INTO erasures(wipe_id,device,method,operator,approver,status,started_at,approval) "
                     "VALUES(?,?,?,?,?,?,?,?)",
                     (wipe_id, json.dumps(device_snapshot), mid, operator, approver, "IN_PROGRESS", _now(),
                      json.dumps(approval) if approval else None))
    if options:
        _job_params[wipe_id] = dict(options)
    audit_log.append("erasure.started", operator, target=dev.get("devicePath"), case_id=case_id,
                     details={"wipeId": wipe_id, "method": mid, "approver": approver or None,
                              "approvalSignature": (approval or {}).get("signature"),
                              "serial": dev.get("serialNumber"), "model": dev.get("model")})
    return {"wipeId": wipe_id, "nonce": nonce, "method": mid, "device": device_snapshot}


def run(wipe_id: str) -> Dict[str, Any]:
    """Execute and verify an erasure recorded by start()."""
    _init_tables()
    row = store.query_one("SELECT * FROM erasures WHERE wipe_id=?", (wipe_id,))
    rec = database.get_wipe_record(wipe_id)
    if not row or not rec:
        raise LookupError(wipe_id)
    dev = json.loads(row["device"])
    mid, method = resolve_method(row["method"])
    key = hashlib.sha256(("WIPEX-PASS-KEY:" + rec["pre_wipe_nonce"] + wipe_id).encode()).digest()
    capacity = int(dev.get("capacityBytes") or 0)
    path = _io_path(dev)
    params = _job_params.pop(wipe_id, {})

    last = {"t": 0.0, "pct": -1}

    def progress(pct: int, speed: str, msg: str, status: str = "IN_PROGRESS"):
        # at most ~3 database writes a second: a large drive reports thousands of chunks
        now = time.time()
        if status == "IN_PROGRESS" and pct == last["pct"] and now - last["t"] < 0.3:
            return
        last.update(t=now, pct=pct)
        database.update_wipe_progress(wipe_id, pct, status, speed, msg)

    execution: Dict[str, Any] = {"method": mid, "methodName": method["name"], "category": method["category"],
                                 "passes": [], "startedAt": _now()}
    verification: Dict[str, Any] = {}
    try:
        if method.get("destroy"):
            execution["note"] = "No data written. Device recorded for physical destruction."
            verification = {"verdict": "NOT_APPLICABLE", "summary": "Physical destruction ordered; no software verification."}
            final_status = "COMPLETED"
        else:
            if capacity <= 0:
                raise IOError("Device capacity unknown")
            if not dev.get("isImage"):
                _prepare_physical(dev)
            if method.get("quick"):
                verification = _quick_erase(path, capacity, bool(dev.get("isImage")), method["passes"][0], key,
                                            progress, execution)
            else:
                progress(2, "—", "Capturing pre-erasure samples")
                offsets = _sample_offsets(capacity, 256, seed=int.from_bytes(key[:4], "big"))
                before = {}
                canaries: List[Dict[str, Any]] = []
                with open(path, "r+b" if dev.get("isImage") else "rb", buffering=0) as f:
                    for off in offsets:
                        before[off] = hashlib.sha256(_read(f, off, BLOCK)).hexdigest()
                    if dev.get("isImage"):
                        canaries = _plant_canaries(f, capacity, 16)
                execution["canariesPlanted"] = len(canaries)

                if method.get("hardware"):
                    ok, msg = hw_sanitize.purge(dev, method["hardware"], params,
                                                progress=lambda p, m: progress(p, "—", m))
                    execution["hardware"] = {"ok": ok, "message": msg}
                    if not ok:
                        raise RuntimeError(f"Hardware purge failed: {msg}")
                    final_pattern = None
                else:
                    _overwrite(path, capacity, method["passes"], key, progress, execution)
                    final_pattern = method["passes"][-1]

                progress(90, "—", "Verifying")
                verification = verify(path, capacity, final_pattern, key, offsets, before, canaries, bool(dev.get("isImage")),
                                      lambda p, m: progress(90 + p * 9 // 100, "—", m),
                                      seed=int.from_bytes(key[4:8], "big"))
            final_status = "COMPLETED" if verification["verdict"] == "PASS" else "VERIFICATION_FAILED"
    except Exception as exc:  # noqa: BLE001
        execution["error"] = friendly_error(exc)
        execution["errorDetail"] = str(exc)
        verification = verification or {"verdict": "FAIL", "summary": f"Erasure did not complete: {execution['error']}"}
        final_status = "FAILED"
    finally:
        if not dev.get("isImage") and not method.get("destroy"):
            try:
                _restore_physical(dev)
            except Exception:  # noqa: BLE001
                pass

    execution["finishedAt"] = _now()
    with store.tx() as conn:
        conn.execute("UPDATE erasures SET status=?, execution=?, verification=?, finished_at=? WHERE wipe_id=?",
                     (final_status, json.dumps(execution), json.dumps(verification), _now(), wipe_id))
    progress(100 if final_status == "COMPLETED" else 0, execution.get("throughput", "—"),
             verification.get("summary", final_status), status=final_status)
    audit_log.append("erasure.finished", row["operator"] or "system", target=path,
                     details={"wipeId": wipe_id, "status": final_status, "verdict": verification.get("verdict"),
                              "error": execution.get("error")})
    return {"wipeId": wipe_id, "status": final_status, "execution": execution, "verification": verification}


def _overwrite(path: str, capacity: int, passes: List[Any], key: bytes, progress, execution: Dict[str, Any]) -> None:
    t0 = time.time()
    written_total = 0
    with open(path, "r+b", buffering=0) as f:
        for i, pattern in enumerate(passes):
            p0 = time.time()
            f.seek(0)
            offset = 0
            while offset < capacity:
                n = min(CHUNK, capacity - offset)
                f.write(_pass_buffer(pattern, key, offset, n))
                offset += n
                written_total += n
                done = (i + offset / capacity) / len(passes)
                elapsed = max(0.001, time.time() - t0)
                rate = written_total / elapsed
                left = (len(passes) * capacity - written_total) / max(rate, 1)
                progress(5 + int(done * 84), f"{rate / 1e6:.0f} MB/s",
                         f"Pass {i + 1} of {len(passes)} · {offset / 1e9:.1f} of {capacity / 1e9:.1f} GB · {_eta(left)}")
            f.flush()
            os.fsync(f.fileno())
            label = "random" if pattern == "random" else ("keyed random" if pattern == "prng" else "0x" + pattern.hex().upper())
            execution["passes"].append({"pass": i + 1, "pattern": label, "bytes": capacity,
                                        "seconds": round(time.time() - p0, 2)})
    elapsed = max(0.001, time.time() - t0)
    execution["bytesWritten"] = written_total
    execution["throughput"] = f"{written_total / elapsed / 1e6:.0f} MB/s"


# ── Quick erase: used space only ─────────────────────────────────────────────
# A whole-drive overwrite is bound by the drive's write speed (a 32 GB stick at 10 MB/s: ~55 min),
# whatever it holds. Quick erase overwrites what the file systems use or used (tables, directories,
# live files, deleted files they still describe, system files) and then samples the rest for old data.

QUICK_EDGE = 1024 * 1024                   # partition table at the start, backup GPT at the end
QUICK_SAMPLES = 512                        # free-space blocks sampled on a physical drive


def _merge(extents: List[Tuple[int, int]], capacity: int) -> List[Tuple[int, int]]:
    """Sorted, non-overlapping, 4 KiB-aligned (devices need sector-aligned writes) ranges inside the drive."""
    spans = []
    for off, n in extents:
        start, end = max(0, off - off % BLOCK), min(capacity, off + n + (-(off + n)) % BLOCK)
        if end > start:
            spans.append((start, end))
    merged: List[List[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e - s) for s, e in merged]


def used_space(path: str, capacity: int) -> Tuple[List[Tuple[int, int]], Dict[str, Any]]:
    from recovery import fs_recovery
    info = fs_recovery.used_extents(path)
    edges = [(0, QUICK_EDGE), (max(0, capacity - QUICK_EDGE), QUICK_EDGE)]
    return _merge(info["extents"] + edges, capacity), info


def _plant_canaries_in(f, extents: List[Tuple[int, int]], n: int) -> List[Dict[str, Any]]:
    """Test markers inside the used space (disk images only), so the check shows the erase reached the data."""
    blocks = [off + i * BLOCK for off, ln in extents for i in range(ln // BLOCK)]
    out = []
    for b in random.sample(blocks, min(n, len(blocks))):
        token = secrets.token_hex(16)
        f.seek(b)
        f.write((CANARY_MAGIC + token.encode()).ljust(BLOCK, b"\xA5"))
        out.append({"offset": b, "token": token})
    f.flush()
    os.fsync(f.fileno())
    return out


def _overwrite_extents(path: str, extents: List[Tuple[int, int]], pattern: Any, key: bytes, progress,
                       execution: Dict[str, Any]) -> None:
    total = sum(n for _, n in extents)
    t0, done = time.time(), 0
    with open(path, "r+b", buffering=0) as f:
        for off, n in extents:
            pos = off
            while pos < off + n:
                k = min(CHUNK, off + n - pos)
                f.seek(pos)
                f.write(_pass_buffer(pattern, key, pos, k))
                pos += k
                done += k
                rate = done / max(0.001, time.time() - t0)
                progress(5 + int(done * 84 / max(total, 1)), f"{rate / 1e6:.0f} MB/s",
                         f"Overwriting the used space: {done / 1e6:.1f} of {total / 1e6:.1f} MB")
        f.flush()
        os.fsync(f.fileno())
    elapsed = max(0.001, time.time() - t0)
    execution["passes"].append({"pass": 1, "pattern": "0x" + pattern.hex().upper(), "bytes": total,
                                "seconds": round(elapsed, 2)})
    execution["bytesWritten"] = total
    execution["throughput"] = f"{total / elapsed / 1e6:.0f} MB/s"


def _blank(block: bytes) -> bool:
    """Never written or wiped: one repeated byte (zeros, or 0xFF on unwritten flash)."""
    return not block or block.count(block[:1]) == len(block)


def verify_quick(path: str, capacity: int, extents: List[Tuple[int, int]], pattern: Any, key: bytes,
                 canaries: List[Dict[str, Any]], exhaustive: bool, progress=None, seed: int = 0) -> Dict[str, Any]:
    """Read back every overwritten byte, look for the test markers, check the rest of the drive for old data
    (every free block on a disk image, a random sample on a physical drive), then look for a file system."""
    res: Dict[str, Any] = {"checks": []}
    total = sum(n for _, n in extents)
    mismatches, read_errors, first = 0, 0, None
    free_data, free_checked = 0, 0
    with open(path, "rb", buffering=0) as f:
        for off, n in extents:
            pos = off
            while pos < off + n:
                k = min(CHUNK, off + n - pos)
                try:
                    if _read(f, pos, k) != expected_bytes(pattern, key, pos, k):
                        mismatches += 1
                        first = pos if first is None else first
                except OSError:
                    read_errors += 1
                pos += k
        res["checks"].append({"name": "Pattern read-back", "expected": "0x" + pattern.hex().upper(),
                              "coverage": f"all {total / 1e6:.1f} MB the file system used", "mismatchedRegions": mismatches,
                              "firstMismatchOffset": first, "readErrors": read_errors,
                              "passed": mismatches == 0 and read_errors == 0})
        if canaries:
            found = sum(1 for c in canaries if CANARY_MAGIC in _read(f, c["offset"], BLOCK))
            res["checks"].append({"name": "Canary blocks", "planted": len(canaries), "recovered": found, "passed": found == 0})
        if progress:
            progress(40, "Checking the free space for old data")
        starts = [s for s, _ in extents]

        def inside(o: int) -> bool:
            i = bisect.bisect_right(starts, o) - 1
            return i >= 0 and o < extents[i][0] + extents[i][1]
        if exhaustive:
            off = 0
            while off < capacity:
                chunk = _read(f, off, CHUNK)
                for i in range(0, len(chunk), BLOCK):
                    if not inside(off + i):
                        free_checked += 1
                        free_data += not _blank(chunk[i:i + BLOCK])
                off += CHUNK
            where = f"every free block ({free_checked:,})"
        else:
            picks = [o for o in _sample_offsets(capacity, QUICK_SAMPLES * 2, seed) if not inside(o)][:QUICK_SAMPLES]
            for o in picks:
                free_checked += 1
                free_data += not _blank(_read(f, o, BLOCK))
            where = f"{free_checked} sampled free blocks"
    res["checks"].append({"name": "Free space (not used by the file system)", "checked": where, "blocksWithData": free_data,
                          "passed": free_data == 0,
                          "detail": (f"No old data in {where}" if not free_data else
                                     f"{free_data:,} of {where} still hold old data (e.g. files from before a format): "
                                     "erase the whole drive with NIST SP 800-88 Clear")})
    rav = recovery_as_verifier(path, capacity, progress, carve=False,
                               why="no file system left; the used space read back as the erase pattern")
    res["checks"].append(rav)
    res["meanEntropy"] = None
    res["samples"] = free_checked
    res["verdict"] = "PASS" if all(c.get("passed", True) for c in res["checks"]) else "FAIL"
    if res["verdict"] == "PASS":
        res["summary"] = (f"Quick erase verified: all {total / 1e6:.1f} MB the file system used read back as the erase "
                          f"pattern, no file system left, no old data in {where}. Scope: used space, not a full NIST SP 800-88 Clear.")
    elif free_data and all(c.get("passed", True) for c in res["checks"] if not c["name"].startswith("Free space")):
        res["summary"] = (f"Quick erase done, but {free_data:,} of {where} still hold old data: "
                          "erase the whole drive with NIST SP 800-88 Clear to remove it.")
    else:
        res["summary"] = "Verification failed: " + ", ".join(c["name"] for c in res["checks"] if c.get("passed") is False)
    return res


def _quick_erase(path: str, capacity: int, is_image: bool, pattern: Any, key: bytes, progress,
                 execution: Dict[str, Any]) -> Dict[str, Any]:
    progress(3, "—", "Mapping what the file system uses")
    extents, info = used_space(path, capacity)
    canaries: List[Dict[str, Any]] = []
    if is_image:
        with open(path, "r+b", buffering=0) as f:
            canaries = _plant_canaries_in(f, extents, 16)
    execution["canariesPlanted"] = len(canaries)
    execution["usedSpace"] = {"bytes": sum(n for _, n in extents), "ranges": len(extents), "entries": info["files"],
                              "fileSystems": [v["fsType"] for v in info["volumes"]], "complete": info["complete"]}
    _overwrite_extents(path, extents, pattern, key, progress, execution)
    progress(90, "—", "Verifying")
    return verify_quick(path, capacity, extents, pattern, key, canaries, is_image,
                        lambda p, m: progress(90 + p * 9 // 100, "—", m), seed=int.from_bytes(key[4:8], "big"))


def _eta(seconds: float) -> str:
    if seconds < 60:
        return "under a minute left"
    if seconds < 3600:
        return f"about {round(seconds / 60)} min left"
    return f"about {seconds / 3600:.1f} h left"


def _plant_canaries(f, capacity: int, n: int) -> List[Dict[str, Any]]:
    out = []
    blocks = capacity // BLOCK
    for b in random.sample(range(1, max(2, blocks - 1)), min(n, max(1, blocks - 2))):
        token = secrets.token_hex(16)
        data = (CANARY_MAGIC + token.encode()).ljust(BLOCK, b"\xA5")
        f.seek(b * BLOCK)
        f.write(data)
        out.append({"offset": b * BLOCK, "token": token})
    f.flush()
    os.fsync(f.fileno())
    return out


def verify(path: str, capacity: int, final_pattern: Any, key: bytes, offsets: List[int], before: Dict[int, str],
           canaries: List[Dict[str, Any]], is_image: bool, progress=None, seed: int = 0) -> Dict[str, Any]:
    """Independent read-back verification. Returns verdict PASS / FAIL with evidence."""
    res: Dict[str, Any] = {"checks": []}
    full = final_pattern is not None and capacity <= FULL_VERIFY_LIMIT
    if final_pattern is not None and not full:       # large drive: many more sampled blocks than the pre-erasure set
        offsets = sorted(set(offsets) | set(_sample_offsets(capacity, VERIFY_SAMPLES, seed)))
    mismatches, unchanged, read_errors, entropies = 0, 0, 0, []
    first_mismatch = None
    with open(path, "rb", buffering=0) as f:
        if full:
            off = 0
            while off < capacity:
                n = min(CHUNK, capacity - off)
                try:
                    got = _read(f, off, n)
                except OSError:
                    read_errors += 1
                    off += n
                    continue
                if got != expected_bytes(final_pattern, key, off, n):
                    mismatches += 1
                    first_mismatch = first_mismatch if first_mismatch is not None else off
                off += n
                if progress:
                    progress(int(off * 60 / capacity), f"Reading every block back: {off / 1e9:.1f} of {capacity / 1e9:.1f} GB")
            for o in offsets[:64]:
                entropies.append(_entropy(_read(f, o, BLOCK)))
            coverage = "full"
        else:
            for o in offsets:
                try:
                    got = _read(f, o, BLOCK)
                except OSError:
                    read_errors += 1
                    continue
                entropies.append(_entropy(got))
                if final_pattern is not None:
                    if got != expected_bytes(final_pattern, key, o, BLOCK):
                        mismatches += 1
                        first_mismatch = first_mismatch if first_mismatch is not None else o
                elif hashlib.sha256(got).hexdigest() == before.get(o) and got.strip(b"\x00"):
                    unchanged += 1
            coverage = f"{len(offsets)} sampled blocks"

        label = ("0x" + final_pattern.hex().upper()) if isinstance(final_pattern, bytes) else \
                ("keyed AES-CTR stream" if final_pattern == "prng" else "previous content must be gone")
        res["checks"].append({"name": "Pattern read-back", "expected": label, "coverage": coverage,
                              "mismatchedRegions": mismatches, "unchangedBlocks": unchanged,
                              "firstMismatchOffset": first_mismatch, "readErrors": read_errors,
                              "passed": mismatches == 0 and unchanged == 0 and read_errors == 0})

        found = 0
        if canaries:
            for c in canaries:
                if CANARY_MAGIC in _read(f, c["offset"], BLOCK):
                    found += 1
            if is_image:
                off = 0
                while off < capacity:
                    if CANARY_MAGIC in _read(f, off, CHUNK + 64):
                        found += 1
                    off += CHUNK
            res["checks"].append({"name": "Canary blocks", "planted": len(canaries), "recovered": found,
                                  "passed": found == 0})

    pattern_ok = res["checks"][0]["passed"]
    # When every block was read back and matched the erase pattern, carving provably finds nothing:
    # the recovery attempt then only looks for a file system (seconds instead of another full read).
    rav = recovery_as_verifier(path, capacity, progress, carve=not (full and pattern_ok))
    res["checks"].append(rav)
    res["meanEntropy"] = round(sum(entropies) / len(entropies), 4) if entropies else None
    res["samples"] = len(offsets)
    res["verdict"] = "PASS" if all(c.get("passed", True) for c in res["checks"]) else "FAIL"
    failed = [c["name"] for c in res["checks"] if c.get("passed") is False]
    passed = ["pattern read-back matched" + (" on every block" if full else f" on {len(offsets)} sampled blocks")
              if final_pattern is not None else "sampled blocks changed"]
    if canaries:
        passed.append("no canary left")
    passed.append("nothing recoverable")
    res["summary"] = ("Verified: " + ", ".join(passed) + "." if res["verdict"] == "PASS"
                      else "Verification failed: " + ", ".join(failed))
    return res


def recovery_as_verifier(path: str, capacity: int, progress=None, carve: bool = True, why: str = "") -> Dict[str, Any]:
    """Run WipeX's own recovery engine against the erased target: erasure passes only if nothing is recoverable.
    The file-system search always runs (it reads only file-system structures); block carving runs on
    targets up to 8 GiB unless the full read-back already proved every block holds the erase pattern."""
    import recovery
    carve = carve and capacity <= RECOVERY_VERIFY_LIMIT
    out_dir = store.workspace_path("verify-tmp", secrets.token_hex(4))
    try:
        scan = recovery.scan(path, out_dir, use_carving=carve,
                             progress=(lambda p, m: progress(60 + p * 40 // 100, "Recovery attempt: " + m)) if progress else None)
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    fs = scan["filesystem"]
    fs_files = [e for e in fs.get("entries", []) if not e.get("isDir") and not str(e["name"]).startswith("$")]
    carved = scan["carving"].get("files", [])
    clean = not fs_files and not carved
    how = why or ("no file system and no carvable files" if carve else
                  "no file system; block carving not needed: every block matched the erase pattern"
                  if capacity <= FULL_VERIFY_LIMIT else "no file system; block carving skipped on drives over 8 GiB")
    return {"name": "Recovery attempt (M3)", "fileSystemsFound": len(fs.get("volumes", [])),
            "fileSystemEntries": len(fs_files), "carvedFiles": len(carved), "carving": carve,
            "passed": clean,
            "detail": how[0].upper() + how[1:] if clean
            else f"{len(fs_files)} file-system entries and {len(carved)} carved files still recoverable"}


def get(wipe_id: str) -> Optional[Dict[str, Any]]:
    _init_tables()
    row = store.query_one("SELECT * FROM erasures WHERE wipe_id=?", (wipe_id,))
    if not row:
        return None
    for k in ("device", "execution", "verification", "approval"):
        row[k] = json.loads(row[k]) if row.get(k) else None
    return row


# ── Reuse after erasure ──────────────────────────────────────────────────────

REUSE_FILESYSTEMS = ("exFAT", "FAT32", "NTFS")


def format_for_reuse(wipe_id: str, fs: str, actor: str) -> Dict[str, Any]:
    """
    After a completed erasure the drive holds no partition table, so the operating system shows it
    as unformatted. Create one partition and an empty file system so the stick can be used again.
    """
    er = get(wipe_id)
    if not er:
        raise LookupError(wipe_id)
    if er["status"] != "COMPLETED":
        raise ValueError("Only a drive whose erasure completed can be formatted for reuse")
    if fs not in REUSE_FILESYSTEMS:
        raise ValueError(f"File system must be one of {', '.join(REUSE_FILESYSTEMS)}")
    dev = er["device"] or {}
    path = dev.get("devicePath", "")
    if dev.get("isImage") or not path:
        raise ValueError("Lab disk images do not need formatting")
    if dev.get("isBootDrive"):
        raise PermissionError("Refusing to touch the system disk")
    system = platform.system()
    label = "WIPEX"
    if system == "Windows" and path.startswith("\\\\.\\PhysicalDrive"):
        num = int(path.replace("\\\\.\\PhysicalDrive", ""))
        ps = (f"$ErrorActionPreference='Stop'; $d = Get-Disk -Number {num}; "
              "if ($d.IsOffline) { Set-Disk -Number $d.Number -IsOffline $false }; "
              "if ($d.IsReadOnly) { Set-Disk -Number $d.Number -IsReadOnly $false }; "
              "if ($d.PartitionStyle -eq 'RAW') { Initialize-Disk -Number $d.Number -PartitionStyle MBR }; "
              f"$v = New-Partition -DiskNumber {num} -UseMaximumSize -AssignDriveLetter | "
              f"Format-Volume -FileSystem {fs} -NewFileSystemLabel {label} -Confirm:$false; "
              "$v.DriveLetter")
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=600)
        where = res.stdout.strip().splitlines()[-1] + ":" if res.returncode == 0 and res.stdout.strip() else ""
    elif system == "Linux":
        mkfs = {"exFAT": ["mkfs.exfat", "-L", label], "FAT32": ["mkfs.vfat", "-F", "32", "-n", label],
                "NTFS": ["mkfs.ntfs", "-Q", "-L", label]}[fs]
        part = path + ("p1" if path[-1].isdigit() else "1")
        steps = [["parted", "-s", path, "mklabel", "msdos", "mkpart", "primary", "1MiB", "100%"],
                 ["partprobe", path], mkfs + [part]]
        res = None
        for cmd in steps:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if res.returncode != 0:
                break
        where = part
    elif system == "Darwin":
        if fs == "NTFS":
            raise ValueError("macOS cannot create NTFS volumes; choose exFAT (works on Windows, macOS and Linux) or FAT32")
        res = subprocess.run(["diskutil", "eraseDisk", {"exFAT": "ExFAT", "FAT32": "MS-DOS FAT32"}[fs],
                              label, "MBR", path], capture_output=True, text=True, timeout=600)
        where = path
    else:
        raise ValueError(f"Formatting is not supported on {system}")
    if res is None or res.returncode != 0:
        raise RuntimeError("Formatting failed: " + ((res.stderr or res.stdout).strip()[:300] if res else "no command ran"))
    audit_log.append("erasure.formatted_for_reuse", actor, target=path, details={"wipeId": wipe_id, "fileSystem": fs,
                                                                                  "volume": where})
    return {"wipeId": wipe_id, "fileSystem": fs, "volume": where, "label": label}


# ── Certificates ─────────────────────────────────────────────────────────────

def issue_certificate(wipe_id: str, actor: str = "system") -> Dict[str, Any]:
    er = get(wipe_id)
    if not er:
        raise LookupError(wipe_id)
    if er["status"] == "IN_PROGRESS":
        raise ValueError("Erasure still running")
    existing = store.query_one("SELECT certificate_id FROM cert_proofs WHERE wipe_id=?", (wipe_id,))
    if existing:
        return lookup_certificate(existing["certificate_id"])

    dev, ver, exe = er["device"], er["verification"] or {}, er["execution"] or {}
    rec = database.get_wipe_record(wipe_id)
    mid, method = resolve_method(er["method"])
    verdict = ver.get("verdict", "FAIL")
    if method.get("destroy"):
        outcome, cleaned, label = "RED", "Not sanitized — physical destruction ordered", "Destroy — do not reissue"
    elif verdict == "PASS" and method.get("quick"):
        outcome, cleaned, label = ("GREEN", "Quick erase verified (used space)",
                                   "Reuse inside the organisation; before disposal erase the whole drive (NIST Clear)")
    elif verdict == "PASS":
        outcome, cleaned, label = "GREEN", "Sanitized and verified", "Cleared for reuse"
    else:
        outcome, cleaned, label = "RED", "Sanitization not verified", "Do not reissue — destroy or re-erase"

    slug = "".join(ch for ch in (dev.get("model") or "DEVICE").upper() if ch.isalnum())[:10] or "DEVICE"
    cert_id = f"WIPEX-{time.strftime('%Y')}-{slug}-{secrets.token_hex(4).upper()}"
    issued = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    canonical_obj = {
        "v": 3, "certificateId": cert_id, "issued": issued, "wipeId": wipe_id,
        "device": {"model": dev.get("model"), "serial": dev.get("serialNumber"), "type": dev.get("type"),
                   "capacityBytes": dev.get("capacityBytes")},
        "method": {"id": mid, "name": method["name"], "category": method["category"],
                   "passes": [p["pattern"] for p in exe.get("passes", [])]},
        "verification": {"verdict": verdict, "checks": ver.get("checks", []), "meanEntropy": ver.get("meanEntropy")},
        "operator": er.get("operator"), "approver": er.get("approver") or None,
        "approval": er.get("approval"),
        "nonce": rec["pre_wipe_nonce"] if rec else None, "outcome": outcome,
    }
    canonical = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    signature = CryptoSigner.sign_payload(canonical)
    personal = users.sign_current(actor, canonical) or {}
    cert = {
        "certificateId": cert_id, "wipe_id": wipe_id, "deviceModel": dev.get("model") or "Unknown",
        "serialNumber": dev.get("serialNumber") or "Unknown", "storageType": dev.get("type") or "Unknown",
        "capacity": dev.get("capacity") or "",
        "standard": f"{method['name']} (not a NIST SP 800-88 Clear)" if method.get("quick") else f"{method['name']} (NIST {method['category']})",
        "methodName": method["name"], "cleanedStatus": cleaned, "trustScore": outcome, "trustScoreLabel": label,
        "auditResult": ver.get("summary", verdict), "preWipeNonce": canonical_obj["nonce"] or "",
        "sha256Digest": digest, "digitalSignature": signature, "qrPayload": "", "tamperDetected": False,
        "verdict": ver.get("summary", ""), "issueDate": issued,
    }
    database.save_certificate(cert)
    with store.tx() as conn:
        conn.execute("INSERT INTO cert_proofs(certificate_id,wipe_id,canonical,signature,public_key,issued_at,"
                     "operator_key_id,operator_sig) VALUES(?,?,?,?,?,?,?,?)",
                     (cert_id, wipe_id, canonical, signature, CryptoSigner.get_public_key_pem(), issued,
                      personal.get("keyId"), personal.get("signature")))
    audit_log.append("certificate.issued", actor, target=cert_id, details={"wipeId": wipe_id, "outcome": outcome, "sha256": digest})
    return lookup_certificate(cert_id)


def lookup_certificate(query: str) -> Optional[Dict[str, Any]]:
    """Exact lookup by certificate id or serial number, with signature and tamper checks."""
    _init_tables()
    q = (query or "").strip()
    row = store.query_one("SELECT * FROM cert_proofs WHERE certificate_id = ?", (q,))
    if not row:
        row = store.query_one(
            "SELECT p.* FROM cert_proofs p JOIN certificates c ON c.certificate_id = p.certificate_id "
            "WHERE c.serial_number = ? ORDER BY p.issued_at DESC LIMIT 1", (q,))
    if not row:
        return None
    canonical = json.loads(row["canonical"])
    sig_ok = CryptoSigner.verify_signature(row["canonical"], row["signature"], row["public_key"])
    ledger = database.get_certificate_by_query(row["certificate_id"]) or {}
    # Ledger row must match what was signed
    tampered_fields = []
    if ledger:
        if ledger.get("serialNumber") != canonical["device"]["serial"]:
            tampered_fields.append("serial number")
        if ledger.get("deviceModel") != canonical["device"]["model"]:
            tampered_fields.append("model")
        if ledger.get("trustScore") != canonical["outcome"]:
            tampered_fields.append("outcome")
        if ledger.get("sha256Digest") != hashlib.sha256(row["canonical"].encode()).hexdigest():
            tampered_fields.append("digest")
    # Personal signatures: the user who issued the certificate and, if required, the approver
    issuer = None
    if row.get("operator_sig"):
        key = users.public_key(row.get("operator_key_id") or "") or {}
        issuer = {"user": key.get("username"), "keyId": row.get("operator_key_id"),
                  "valid": users.verify_user_signature(row.get("operator_key_id") or "", row["canonical"], row["operator_sig"])}
    approval = canonical.get("approval")
    approval_check = None
    if approval:
        approval_check = {"user": approval.get("approver"), "keyId": approval.get("keyId"),
                          "valid": users.verify_user_signature(approval.get("keyId", ""), approval.get("payload", ""),
                                                               approval.get("signature", ""), approval.get("approver"))}
    valid = sig_ok and not tampered_fields and (issuer is None or issuer["valid"]) and \
        (approval_check is None or approval_check["valid"])
    return {
        "certificateId": row["certificate_id"], "wipeId": row["wipe_id"], "isValid": valid,
        "signatureValid": sig_ok, "tamperDetected": not valid, "tamperedFields": tampered_fields,
        "issuerSignature": issuer, "approvalSignature": approval_check,
        "issueDate": canonical["issued"], "deviceModel": canonical["device"]["model"],
        "serialNumber": canonical["device"]["serial"], "storageType": canonical["device"]["type"],
        "capacityBytes": canonical["device"]["capacityBytes"],
        "standard": canonical["method"]["name"] + (" (not a NIST SP 800-88 Clear)" if METHODS.get(canonical["method"]["id"], {}).get("quick") else ""),
        "category": canonical["method"]["category"], "passes": canonical["method"]["passes"],
        "verification": canonical["verification"], "operator": canonical.get("operator"),
        "approver": canonical.get("approver"), "trustScore": canonical["outcome"],
        "trustScoreLabel": ledger.get("trustScoreLabel"), "cleanedStatus": ledger.get("cleanedStatus"),
        "sha256Digest": hashlib.sha256(row["canonical"].encode()).hexdigest(),
        "signatureAlgorithm": "ECDSA P-256 / SHA-256", "canonicalPayload": row["canonical"],
        "verdict": ("Signatures valid and ledger record matches the signed content." if valid else
                    ("Workstation signature does not verify." if not sig_ok else
                     "Ledger record was altered after signing: " + ", ".join(tampered_fields) if tampered_fields else
                     "A personal signature (issuer or approver) does not verify.")),
    }
