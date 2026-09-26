"""
WipeX - Secure File & Folder Eraser (module M2).

For each file: overwrite alternate data streams, overwrite content in place (N passes,
fsync after each), truncate, rename to random names (scrubs the directory-entry name),
reset timestamps, then delete. Folders are processed bottom-up.

Storage-aware policy (research gap G3): before erasing, WipeX inspects the volume and
reports honestly how much assurance an in-place overwrite gives there:
  * HDD + NTFS/FAT/exFAT/ext4 -> High (overwrite lands on the same sectors)
  * SSD / flash               -> Limited (wear-levelling and spare blocks); M1 Purge advised
  * APFS / Btrfs / ReFS / ZFS -> Not effective (copy-on-write writes new blocks)

Trace cleanup (research gap G2): after erasure WipeX removes OS artefacts that reveal the
file existed: Windows Recent shortcuts (.lnk) pointing at it, and on Linux the
recently-used list entry and freedesktop thumbnails. Jump Lists, thumbcache and Prefetch
are reported (they are shared databases that cannot be edited per file safely).
"""

import ctypes
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import string
import subprocess
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import audit_log
import cases
import store

SYSTEM = platform.system()
CHUNK = 1024 * 1024
PASS_SETS = {
    "zero": [b"\x00"],
    "random": ["random"],
    "dod": [b"\x00", b"\xFF", "random"],
}
COW_FILESYSTEMS = {"APFS", "BTRFS", "REFS", "ZFS", "BCACHEFS"}
_media_cache: Dict[str, Dict[str, Any]] = {}


# ── Safety ───────────────────────────────────────────────────────────────────

def _protected_roots() -> List[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    roots = [here]
    if SYSTEM == "Windows":
        sysdrive = os.environ.get("SystemDrive", "C:") + "\\"
        roots += [os.environ.get("SystemRoot", r"C:\Windows"), os.environ.get("ProgramFiles", r"C:\Program Files"),
                  os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                  os.environ.get("ProgramData", r"C:\ProgramData")]
        exact = [sysdrive, os.path.expanduser("~"), os.path.join(sysdrive, "Users")]
    else:
        roots += ["/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/sbin", "/sys", "/usr",
                  "/System", "/Library", "/Applications", "/private/etc", "/var/lib"]
        exact = ["/", os.path.expanduser("~"), "/home", "/Users", "/var", "/tmp"]
    return [os.path.normcase(os.path.abspath(r)) for r in roots if r], \
        [os.path.normcase(os.path.abspath(r)) for r in exact if r]


def check_path_allowed(path: str) -> Optional[str]:
    """Return a reason string when the path must not be erased, else None."""
    ap = os.path.normcase(os.path.abspath(path))
    roots, exact = _protected_roots()
    workspace = os.path.normcase(os.path.abspath(store.WORKSPACE))
    if ap == workspace or ap.startswith(workspace + os.sep):
        return None                                   # WipeX sandbox is always allowed
    if ap in exact:
        return "Refusing to erase a drive root, home folder or top-level system folder"
    for r in roots:
        if ap == r or ap.startswith(r + os.sep):
            return f"Protected location ({r})"
    return None


# ── Volume inspection ────────────────────────────────────────────────────────

def _volume_root(path: str) -> str:
    ap = os.path.abspath(path)
    if SYSTEM == "Windows":
        return os.path.splitdrive(ap)[0] + "\\"
    while not os.path.ismount(ap):
        parent = os.path.dirname(ap)
        if parent == ap:
            break
        ap = parent
    return ap


def _fs_type(root: str) -> str:
    if SYSTEM == "Windows":
        buf = ctypes.create_unicode_buffer(64)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(ctypes.c_wchar_p(root), None, 0, None, None, None, buf, 64)
        return buf.value.upper() if ok else "UNKNOWN"
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            best = ("", "UNKNOWN")
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and root.startswith(parts[1]) and len(parts[1]) >= len(best[0]):
                    best = (parts[1], parts[2].upper())
            return best[1]
    except OSError:
        pass
    if SYSTEM == "Darwin":
        out = subprocess.run(["diskutil", "info", root], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"Type \(Bundle\):\s*(\S+)", out)
        return m.group(1).upper() if m else "UNKNOWN"
    return "UNKNOWN"


def _media_info(root: str) -> Dict[str, Any]:
    if root in _media_cache:
        return _media_cache[root]
    info: Dict[str, Any] = {"mediaType": "Unknown", "trim": None, "busType": None}
    try:
        if SYSTEM == "Windows":
            letter = root[0]
            ps = (f"$p = Get-Partition -DriveLetter {letter} -ErrorAction Stop; "
                  "$d = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq [string]$p.DiskNumber }; "
                  "[pscustomobject]@{MediaType=[string]$d.MediaType; BusType=[string]$d.BusType} | ConvertTo-Json")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=20).stdout
            data = json.loads(out) if out.strip() else {}
            info["mediaType"] = {"SSD": "SSD", "HDD": "HDD"}.get(data.get("MediaType", ""), data.get("MediaType") or "Unknown")
            info["busType"] = data.get("BusType")
            if info["busType"] in ("USB", "SD", "MMC") and info["mediaType"] in ("Unknown", "Unspecified"):
                info["mediaType"] = "Flash"
            q = subprocess.run(["fsutil", "behavior", "query", "DisableDeleteNotify"], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"NTFS DisableDeleteNotify = (\d)", q)
            info["trim"] = (m.group(1) == "0") if m else None
        elif SYSTEM == "Linux":
            dev = subprocess.run(["findmnt", "-no", "SOURCE", root], capture_output=True, text=True, timeout=10).stdout.strip()
            name = os.path.basename(dev)
            base = re.sub(r"p?\d+$", "", name) if not name.startswith("nvme") else re.sub(r"p\d+$", "", name)
            with open(f"/sys/block/{base}/queue/rotational") as f:
                info["mediaType"] = "HDD" if f.read().strip() == "1" else "SSD"
            with open(f"/sys/block/{base}/queue/discard_max_bytes") as f:
                info["trim"] = int(f.read().strip()) > 0
        elif SYSTEM == "Darwin":
            out = subprocess.run(["diskutil", "info", root], capture_output=True, text=True, timeout=10).stdout
            info["mediaType"] = "SSD" if re.search(r"Solid State:\s*Yes", out) else ("HDD" if "Solid State" in out else "Unknown")
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    _media_cache[root] = info
    return info


def assess_volume(path: str) -> Dict[str, Any]:
    root = _volume_root(path)
    fs = _fs_type(root)
    media = _media_info(root)
    notes = []
    if fs in COW_FILESYSTEMS:
        level, advice = "Not effective", "Copy-on-write file system: overwrites are written to new blocks. Use M1 (whole-device Purge) or rely on full-disk encryption."
    elif media["mediaType"] in ("SSD", "Flash"):
        level, advice = "Limited", "Flash storage remaps writes (wear levelling, spare blocks). Content is overwritten logically; for full assurance sanitize the device with M1 Cryptographic Erase."
    elif media["mediaType"] == "HDD":
        level, advice = "High", "Magnetic disk with an in-place file system: overwrites land on the file's own sectors."
    else:
        level, advice = "Unverified", "Media type could not be determined; treat assurance as limited."
    if fs == "NTFS":
        notes.append("NTFS $LogFile and $UsnJrnl may retain the file name until they cycle.")
        notes.append("Files under ~700 bytes live inside the MFT record; in-place overwrite still covers them.")
    if media.get("trim") is True and media["mediaType"] in ("SSD", "Flash"):
        notes.append("TRIM is enabled: freed blocks are reported to the drive after deletion.")
    return {"volume": root, "fileSystem": fs, **media, "assurance": level, "advice": advice, "notes": notes}


# ── Alternate data streams (Windows) ─────────────────────────────────────────

class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]


def list_streams(path: str) -> List[Dict[str, Any]]:
    if SYSTEM != "Windows":
        return []
    k32 = ctypes.windll.kernel32
    k32.FindFirstStreamW.restype = ctypes.c_void_p
    data = _WIN32_FIND_STREAM_DATA()
    h = k32.FindFirstStreamW(ctypes.c_wchar_p(path), 0, ctypes.byref(data), 0)
    if h in (None, ctypes.c_void_p(-1).value):
        return []
    streams = []
    try:
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                streams.append({"name": name.split(":")[1], "size": int(data.StreamSize)})
            if not k32.FindNextStreamW(ctypes.c_void_p(h), ctypes.byref(data)):
                break
    finally:
        k32.FindClose(ctypes.c_void_p(h))
    return streams


# ── Trace discovery / cleanup ────────────────────────────────────────────────

def _recent_dir() -> Optional[str]:
    if SYSTEM == "Windows":
        return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent")
    return None


def find_traces(paths: List[str]) -> Dict[str, Any]:
    """Locate OS artefacts that reference any of the given files."""
    targets = [os.path.abspath(p) for p in paths]
    names = {os.path.basename(t).lower() for t in targets}
    found: Dict[str, List[Dict[str, str]]] = {"recentShortcuts": [], "jumpLists": [], "thumbnails": [], "recentlyUsed": []}
    if SYSTEM == "Windows":
        rd = _recent_dir()
        if rd and os.path.isdir(rd):
            needles = [t.encode("utf-16-le").lower() for t in targets] + [n.encode("utf-16-le") for n in names]
            for fname in os.listdir(rd):
                fp = os.path.join(rd, fname)
                if fname.lower().endswith(".lnk") and os.path.isfile(fp):
                    stem = os.path.splitext(fname)[0].lower()
                    try:
                        with open(fp, "rb") as f:
                            blob = f.read(65536)
                    except OSError:
                        continue
                    if stem in names or any(n in blob.lower() for n in needles):
                        found["recentShortcuts"].append({"path": fp, "action": "delete"})
            for sub in ("AutomaticDestinations", "CustomDestinations"):
                d = os.path.join(rd, sub)
                if not os.path.isdir(d):
                    continue
                full_needles = [t.encode("utf-16-le").lower() for t in targets]
                for fname in os.listdir(d):
                    fp = os.path.join(d, fname)
                    try:
                        with open(fp, "rb") as f:
                            blob = f.read().lower()
                    except OSError:
                        continue
                    if any(n in blob for n in full_needles):
                        found["jumpLists"].append({"path": fp, "action": "report"})
        thumbdir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Explorer")
        if os.path.isdir(thumbdir) and any(os.path.splitext(n)[1].lower() in (".jpg", ".png", ".bmp", ".gif", ".pdf", ".mp4") for n in names):
            found["thumbnails"].append({"path": thumbdir, "action": "report",
                                        "note": "thumbcache_*.db may hold a preview of image/video files"})
    elif SYSTEM == "Linux":
        cache = os.path.expanduser("~/.cache/thumbnails")
        for t in targets:
            uri = "file://" + quote(t)
            digest = hashlib.md5(uri.encode()).hexdigest()
            for size in ("normal", "large", "x-large", "xx-large"):
                fp = os.path.join(cache, size, digest + ".png")
                if os.path.exists(fp):
                    found["thumbnails"].append({"path": fp, "action": "delete"})
        xbel = os.path.expanduser("~/.local/share/recently-used.xbel")
        if os.path.exists(xbel):
            with open(xbel, encoding="utf-8", errors="replace") as f:
                text = f.read()
            for t in targets:
                if ("file://" + quote(t)) in text:
                    found["recentlyUsed"].append({"path": xbel, "entry": t, "action": "delete"})
    found["total"] = sum(len(v) for v in found.values() if isinstance(v, list))
    return found


def clean_traces(traces: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    for item in traces.get("recentShortcuts", []) + [t for t in traces.get("thumbnails", []) if t["action"] == "delete"]:
        try:
            _erase_one(item["path"], PASS_SETS["zero"])
            results.append({"path": item["path"], "result": "erased"})
        except OSError as exc:
            results.append({"path": item["path"], "result": f"failed: {exc}"})
    for item in traces.get("recentlyUsed", []):
        try:
            with open(item["path"], encoding="utf-8") as f:
                text = f.read()
            uri = re.escape("file://" + quote(item["entry"]))
            new = re.sub(r"\s*<bookmark href=\"" + uri + r"\".*?</bookmark>", "", text, flags=re.S)
            with open(item["path"], "w", encoding="utf-8") as f:
                f.write(new)
            results.append({"path": item["path"], "result": "entry removed"})
        except OSError as exc:
            results.append({"path": item["path"], "result": f"failed: {exc}"})
    for item in traces.get("jumpLists", []) + [t for t in traces.get("thumbnails", []) if t["action"] == "report"]:
        results.append({"path": item["path"], "result": "reported (shared database, not modified)"})
    return results


# ── Erasure ──────────────────────────────────────────────────────────────────

def _overwrite_handle(f, size: int, passes: List[Any]) -> None:
    for pattern in passes:
        f.seek(0)
        left = size
        while left > 0:
            n = min(CHUNK, left)
            f.write(os.urandom(n) if pattern == "random" else pattern * n)
            left -= n
        f.flush()
        os.fsync(f.fileno())


def _random_name(length: int) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(max(1, min(length, 64))))


def _erase_one(path: str, passes: List[Any]) -> Dict[str, Any]:
    info: Dict[str, Any] = {"path": path, "size": os.path.getsize(path), "streams": []}
    if os.stat(path).st_nlink > 1:
        info["warning"] = "File has other hard links; their names remain until each link is removed"
    os.chmod(path, 0o600)
    for s in list_streams(path):
        sp = f"{path}:{s['name']}"
        with open(sp, "r+b", buffering=0) as f:
            _overwrite_handle(f, s["size"], passes)
            f.truncate(0)
        os.remove(sp)
        info["streams"].append(s)
    with open(path, "r+b", buffering=0) as f:
        _overwrite_handle(f, info["size"], passes)
        f.truncate(0)
        f.flush()
        os.fsync(f.fileno())
    # Scrub the name stored in the directory entry, then the timestamps
    current = path
    base_len = len(os.path.basename(path))
    for _ in range(3):
        nxt = os.path.join(os.path.dirname(path), _random_name(base_len))
        os.replace(current, nxt)
        current = nxt
    os.utime(current, (315532800, 315532800))       # 1980-01-01
    os.remove(current)
    info["verified"] = not os.path.exists(path) and not os.path.exists(current)
    return info


def analyze(paths: List[str]) -> Dict[str, Any]:
    items, volumes, blocked = [], {}, []
    for p in paths:
        ap = os.path.abspath(p)
        entry: Dict[str, Any] = {"path": ap, "exists": os.path.exists(ap)}
        if not entry["exists"]:
            entry["error"] = "Not found"
            items.append(entry)
            continue
        reason = check_path_allowed(ap)
        hold = cases.find_blocking_hold(paths=[ap])
        if reason:
            entry["blocked"] = reason
        if hold:
            entry["blocked"] = f"Under legal hold {hold['id']} (case {hold['case_id']})"
        if entry.get("blocked"):
            blocked.append(ap)
        files = []
        if os.path.isdir(ap):
            for root, _dirs, fnames in os.walk(ap):
                files += [os.path.join(root, n) for n in fnames]
        else:
            files = [ap]
        entry.update({"isDir": os.path.isdir(ap), "fileCount": len(files),
                      "bytes": sum(os.path.getsize(f) for f in files if os.path.isfile(f)),
                      "streams": sum(len(list_streams(f)) for f in files[:500]),
                      "hardLinked": sum(1 for f in files[:500] if os.stat(f).st_nlink > 1)})
        vol = assess_volume(ap)
        volumes[vol["volume"]] = vol
        entry["volume"] = vol["volume"]
        items.append(entry)
    all_files = [i["path"] for i in items if i.get("exists")]
    traces = find_traces(all_files)
    return {"items": items, "volumes": list(volumes.values()), "traces": traces, "blocked": blocked}


def erase(paths: List[str], method: str, clean: bool, operator: str, approver: str = "",
          progress=None) -> Dict[str, Any]:
    cases.check_authorization(operator, approver)
    if method not in PASS_SETS:
        raise ValueError(f"method must be one of {list(PASS_SETS)}")
    pre = analyze(paths)
    if pre["blocked"]:
        raise PermissionError("Blocked targets: " + "; ".join(pre["blocked"]))
    job_id = f"FERASE-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2).upper()}"
    audit_log.append("file_erasure.started", operator, details={"jobId": job_id, "paths": paths, "method": method,
                                                                "approver": approver or None})
    files, dirs = [], []
    for item in pre["items"]:
        if not item.get("exists"):
            continue
        if item["isDir"]:
            for root, dnames, fnames in os.walk(item["path"], topdown=False):
                files += [os.path.join(root, n) for n in fnames]
                dirs += [os.path.join(root, d) for d in dnames]
            dirs.append(item["path"])
        else:
            files.append(item["path"])

    results, failures = [], []
    for i, fp in enumerate(files):
        try:
            results.append(_erase_one(fp, PASS_SETS[method]))
        except OSError as exc:
            failures.append({"path": fp, "error": str(exc)})
        if progress:
            progress(int((i + 1) * 85 / max(1, len(files))), f"Erased {i + 1} of {len(files)} files")
    for d in dirs:                                   # deepest first
        try:
            tmp = os.path.join(os.path.dirname(d), _random_name(len(os.path.basename(d))))
            os.replace(d, tmp)
            os.rmdir(tmp)
        except OSError as exc:
            failures.append({"path": d, "error": str(exc)})

    trace_results = clean_traces(pre["traces"]) if clean else []
    if progress:
        progress(100, "Done")
    report = {
        "jobId": job_id, "method": method, "passes": len(PASS_SETS[method]), "operator": operator,
        "approver": approver or None, "files": results, "failures": failures,
        "foldersRemoved": len(dirs) - sum(1 for f in failures if f["path"] in dirs),
        "streamsErased": sum(len(r["streams"]) for r in results), "bytesOverwritten": sum(r["size"] for r in results),
        "traces": trace_results, "volumes": pre["volumes"],
        "verdict": "PASS" if not failures and all(r["verified"] for r in results) else "PARTIAL",
        "finishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    report["summary"] = (f"{len(results)} files erased ({report['bytesOverwritten']:,} bytes, {report['passes']} pass(es)), "
                         f"{report['streamsErased']} alternate streams, {len([t for t in trace_results if t['result'] in ('erased', 'entry removed')])} traces removed"
                         + (f", {len(failures)} failures" if failures else ""))
    audit_log.append("file_erasure.finished", operator, details={"jobId": job_id, "verdict": report["verdict"],
                                                                 "files": len(results), "failures": len(failures)})
    with open(store.workspace_path("reports", f"{job_id}.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report


def create_sandbox(with_trace_demo: bool = True) -> Dict[str, Any]:
    """Create a disposable folder of sample files (inside the WipeX workspace) to demonstrate M2 safely."""
    root = store.workspace_path("m2-sandbox", time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(os.path.join(root, "Confidential"), exist_ok=True)
    samples = {
        "Salary_Sheet_2026.csv": "employee,salary\n" + "".join(f"E{i:03d},{50000 + i * 731}\n" for i in range(200)),
        "Confidential/Board_Minutes.txt": "Board minutes — strictly confidential.\n" * 120,
        "Confidential/Passwords_OLD.txt": "\n".join(f"account{i}: {secrets.token_urlsafe(10)}" for i in range(40)),
        "tiny_note.txt": "short note",   # small enough to be MFT-resident on NTFS
    }
    for rel, content in samples.items():
        with open(os.path.join(root, rel), "w", encoding="utf-8") as f:
            f.write(content)
    notes = []
    if SYSTEM == "Windows":
        target = os.path.join(root, "Salary_Sheet_2026.csv")
        with open(target + ":Zone.Identifier", "w") as f:           # alternate data stream
            f.write("[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://example.org/payroll\n")
        notes.append("Salary_Sheet_2026.csv has a Zone.Identifier alternate data stream")
        if with_trace_demo and _recent_dir():
            lnk = os.path.join(_recent_dir(), "Salary_Sheet_2026.csv.lnk")
            ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');"
                  f"$s.TargetPath='{target}';$s.Save()")
            subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=20)
            if os.path.exists(lnk):
                notes.append("A Recent Items shortcut to Salary_Sheet_2026.csv was created (trace demo)")
    audit_log.append("file_erasure.sandbox_created", "system", target=root)
    return {"path": root, "files": list(samples), "notes": notes}
