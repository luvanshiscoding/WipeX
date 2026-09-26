"""
WipeX - Secure File & Folder Eraser (module M2).

For each file: overwrite alternate data streams, overwrite content in place (N passes,
fsync after each), truncate, rename to random names (scrubs the directory-entry name),
reset timestamps, then delete. Folders are processed bottom-up.

Extended metadata: NTFS alternate data streams (Windows) and extended attributes
(Linux, macOS - e.g. com.apple.quarantine, user.xdg.origin.url) are overwritten and removed.

Storage-aware policy: before erasing, WipeX inspects the volume and reports honestly how
much assurance an in-place overwrite gives there:
  * HDD + NTFS/FAT/exFAT/ext4 -> High (overwrite lands on the same sectors)
  * SSD / flash               -> Limited (wear-levelling and spare blocks); M1 Purge advised
  * APFS / Btrfs / ReFS / ZFS -> Not effective (copy-on-write writes new blocks)

Trace cleanup: after erasure WipeX removes OS artefacts that reveal the file existed:
  Windows  Recent shortcuts (.lnk) and Jump List files that reference the file
           (the application's recent list is rebuilt by Windows); thumbcache is reported.
  Linux    recently-used.xbel entries and freedesktop thumbnails.
  macOS    the parent folder's .DS_Store (Finder keeps file names there), the Gatekeeper
           quarantine-events record for a downloaded file, and the QuickLook thumbnail cache.
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
import struct
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
        roots += ["/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/snap", "/sys",
                  "/usr", "/System", "/Library", "/Applications", "/private/etc", "/private/var/db", "/var/lib"]
        exact = ["/", os.path.expanduser("~"), "/home", "/Users", "/Volumes", "/var", "/tmp", "/private", "/opt"]
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
            dev = dev.split("[", 1)[0]                              # btrfs: /dev/sda2[/@home]
            name = os.path.basename(os.path.realpath(dev))          # /dev/mapper/x -> dm-0
            sysdir = os.path.realpath(f"/sys/class/block/{name}")
            if os.path.exists(os.path.join(sysdir, "partition")):
                sysdir = os.path.dirname(sysdir)                     # partition -> whole disk
            slaves = os.path.join(sysdir, "slaves")                  # LVM / dm-crypt -> underlying disk
            while os.path.isdir(slaves) and os.listdir(slaves):
                sysdir = os.path.realpath(os.path.join(slaves, sorted(os.listdir(slaves))[0]))
                if os.path.exists(os.path.join(sysdir, "partition")):
                    sysdir = os.path.dirname(sysdir)
                slaves = os.path.join(sysdir, "slaves")
            with open(os.path.join(sysdir, "queue", "rotational")) as f:
                info["mediaType"] = "HDD" if f.read().strip() == "1" else "SSD"
            with open(os.path.join(sysdir, "queue", "discard_max_bytes")) as f:
                info["trim"] = int(f.read().strip()) > 0
            try:
                with open(os.path.join(sysdir, "removable")) as f:
                    if f.read().strip() == "1":
                        info["mediaType"] = "Flash"
            except OSError:
                pass
        elif SYSTEM == "Darwin":
            out = subprocess.run(["diskutil", "info", root], capture_output=True, text=True, timeout=10).stdout
            info["mediaType"] = "SSD" if re.search(r"Solid State:\s*Yes", out) else ("HDD" if "Solid State" in out else "Unknown")
            m = re.search(r"Protocol:\s*(.+)", out)
            info["busType"] = m.group(1).strip() if m else None
            if info["busType"] in ("USB", "Secure Digital") and info["mediaType"] == "Unknown":
                info["mediaType"] = "Flash"
            info["trim"] = True if info["mediaType"] == "SSD" else None      # macOS enables TRIM on Apple SSDs
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
    journal = fs == "NTFS" and journal_state(root).get("active", False)
    if journal:
        notes.append("The NTFS change journal on this drive records file names; WipeX can clear it after erasing.")
    return {"volume": root, "fileSystem": fs, **media, "assurance": level, "advice": advice, "notes": notes,
            "changeJournal": journal}


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


# ── Extended attributes (Linux, macOS) ──────────────────────────────────────

_MAC_NOFOLLOW = 0x0001


def _maclibc():
    libc = ctypes.CDLL("libc.dylib", use_errno=True)
    libc.listxattr.restype = libc.getxattr.restype = ctypes.c_ssize_t
    libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
    libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    return libc


def get_xattr(path: str, name: str) -> Optional[bytes]:
    try:
        if SYSTEM == "Linux":
            return os.getxattr(path, name, follow_symlinks=False)
        if SYSTEM == "Darwin":
            libc = _maclibc()
            n = libc.getxattr(path.encode(), name.encode(), None, 0, 0, _MAC_NOFOLLOW)
            if n < 0:
                return None
            buf = ctypes.create_string_buffer(max(1, n))
            n = libc.getxattr(path.encode(), name.encode(), buf, n, 0, _MAC_NOFOLLOW)
            return buf.raw[:n] if n >= 0 else None
    except (OSError, AttributeError):
        return None
    return None


def list_xattrs(path: str) -> List[Dict[str, Any]]:
    """User-visible extended attributes (Linux user.*, all macOS attributes)."""
    names: List[str] = []
    try:
        if SYSTEM == "Linux":
            names = [n for n in os.listxattr(path, follow_symlinks=False) if n.startswith("user.")]
        elif SYSTEM == "Darwin":
            libc = _maclibc()
            n = libc.listxattr(path.encode(), None, 0, _MAC_NOFOLLOW)
            if n > 0:
                buf = ctypes.create_string_buffer(n)
                n = libc.listxattr(path.encode(), buf, n, _MAC_NOFOLLOW)
                names = [x.decode("utf-8", "replace") for x in buf.raw[:max(0, n)].split(b"\0") if x]
    except (OSError, AttributeError):
        return []
    return [{"name": n, "size": len(get_xattr(path, n) or b"")} for n in names]


def _erase_xattr(path: str, name: str, size: int) -> None:
    """Overwrite the attribute value with zeros, then remove it."""
    if SYSTEM == "Linux":
        if size:
            os.setxattr(path, name, b"\x00" * size, follow_symlinks=False)
        os.removexattr(path, name, follow_symlinks=False)
    elif SYSTEM == "Darwin":
        libc = _maclibc()
        if size:
            zeros = ctypes.create_string_buffer(size)
            libc.setxattr(path.encode(), name.encode(), zeros, size, 0, _MAC_NOFOLLOW)
        if libc.removexattr(path.encode(), name.encode(), _MAC_NOFOLLOW) != 0:
            raise OSError(ctypes.get_errno(), f"removexattr {name} failed")


# ── Trace discovery / cleanup ────────────────────────────────────────────────

def _recent_dir() -> Optional[str]:
    if SYSTEM == "Windows":
        return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent")
    return None


_THUMB_EXT = (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".heic", ".pdf", ".mp4", ".mov", ".avi", ".docx", ".pptx")
_QUARANTINE_DB = "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"


def find_traces(paths: List[str]) -> Dict[str, Any]:
    """Locate OS artefacts that reference any of the given files."""
    targets = [os.path.abspath(p) for p in paths]
    names = {os.path.basename(t).lower() for t in targets}
    found: Dict[str, List[Dict[str, Any]]] = {"recentShortcuts": [], "jumpLists": [], "thumbnails": [],
                                              "recentlyUsed": [], "finderMetadata": [], "quarantineEvents": [],
                                              "recentDocuments": []}
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
            full_needles = [t.encode("utf-16-le").lower() for t in targets]
            for sub in ("AutomaticDestinations", "CustomDestinations"):
                d = os.path.join(rd, sub)
                if not os.path.isdir(d):
                    continue
                for fname in os.listdir(d):
                    fp = os.path.join(d, fname)
                    try:
                        with open(fp, "rb") as f:
                            blob = f.read().lower()
                    except OSError:
                        continue
                    if any(n in blob for n in full_needles):
                        found["jumpLists"].append({"path": fp, "action": "delete",
                                                   "note": "per-application Jump List; Windows rebuilds it"})
        thumbdir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Explorer")
        if os.path.isdir(thumbdir) and any(n.endswith(_THUMB_EXT) for n in names):
            found["thumbnails"].append({"path": thumbdir, "action": "report",
                                        "note": "thumbcache_*.db may hold a preview; clear it with Disk Cleanup (Thumbnails)"})
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
    elif SYSTEM == "Darwin":
        for parent in {os.path.dirname(t) for t in targets}:
            ds = os.path.join(parent, ".DS_Store")
            if os.path.isfile(ds):
                try:
                    with open(ds, "rb") as f:
                        blob = f.read()
                except OSError:
                    continue
                hits = [t for t in targets if os.path.dirname(t) == parent
                        and os.path.basename(t).encode("utf-16-be") in blob]
                if hits:
                    found["finderMetadata"].append({"path": ds, "action": "delete",
                                                    "note": "Finder view data holding the file names; recreated by Finder"})
        db = os.path.expanduser(_QUARANTINE_DB)
        for t in targets:
            q = get_xattr(t, "com.apple.quarantine") if os.path.exists(t) else None
            parts = (q or b"").decode("utf-8", "replace").split(";")
            if len(parts) >= 4 and parts[3] and os.path.exists(db):
                found["quarantineEvents"].append({"path": db, "eventId": parts[3], "entry": t, "action": "delete-row",
                                                  "note": "download record (source URL) for this file"})
        if any(n.endswith(_THUMB_EXT) for n in names):
            found["thumbnails"].append({"path": "QuickLook thumbnail cache", "action": "reset-quicklook"})
        sfl = os.path.expanduser("~/Library/Application Support/com.apple.sharedfilelist")
        if os.path.isdir(sfl):
            needles = [t.encode("utf-8") for t in targets]
            for root, _dirs, files in os.walk(sfl):
                for fname in files:
                    fp = os.path.join(root, fname)
                    try:
                        with open(fp, "rb") as f:
                            blob = f.read()
                    except OSError:
                        continue
                    if any(n in blob for n in needles):
                        found["recentDocuments"].append({"path": fp, "action": "report",
                                                         "note": "recent-items list; clear it from the app's Open Recent menu"})
    found["total"] = sum(len(v) for v in found.values() if isinstance(v, list))
    return found


def clean_traces(traces: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    deletable = (traces.get("recentShortcuts", []) + traces.get("jumpLists", []) + traces.get("finderMetadata", [])
                 + [t for t in traces.get("thumbnails", []) if t["action"] == "delete"])
    for item in deletable:
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
    for item in traces.get("quarantineEvents", []):
        try:
            import sqlite3
            conn = sqlite3.connect(item["path"])
            try:
                n = conn.execute("DELETE FROM LSQuarantineEvent WHERE LSQuarantineEventIdentifier = ?",
                                 (item["eventId"],)).rowcount
                conn.commit()
            finally:
                conn.close()
            results.append({"path": item["path"], "result": "entry removed" if n else "no matching record"})
        except Exception as exc:  # noqa: BLE001 - locked or protected database
            results.append({"path": item["path"], "result": f"failed: {exc}"})
    for item in [t for t in traces.get("thumbnails", []) if t["action"] == "reset-quicklook"]:
        try:
            r = subprocess.run(["qlmanage", "-r", "cache"], capture_output=True, text=True, timeout=30)
            results.append({"path": item["path"], "result": "erased" if r.returncode == 0 else f"failed: {r.stderr.strip()[:120]}"})
        except (OSError, subprocess.SubprocessError) as exc:
            results.append({"path": item["path"], "result": f"failed: {exc}"})
    for item in traces.get("recentDocuments", []) + [t for t in traces.get("thumbnails", []) if t["action"] == "report"]:
        results.append({"path": item["path"], "result": "reported: " + item.get("note", "not modified")})
    return results


# ── NTFS change journal (Windows) ────────────────────────────────────────────

def _volume_letter(root: str) -> str:
    return root[:2] if SYSTEM == "Windows" and len(root) >= 2 and root[1] == ":" else ""


def journal_state(root: str) -> Dict[str, Any]:
    """Is the NTFS change journal ($UsnJrnl) active on this volume, and how is it sized?"""
    vol = _volume_letter(root)
    if not vol:
        return {"active": False}
    out = subprocess.run(["fsutil", "usn", "queryjournal", vol], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        return {"active": False, "detail": (out.stdout + out.stderr).strip()[:200]}
    size = re.search(r"Maximum Size\s*:\s*(0x[0-9a-fA-F]+)", out.stdout)
    delta = re.search(r"Allocation Delta\s*:\s*(0x[0-9a-fA-F]+)", out.stdout)
    return {"active": True, "maxSize": int(size.group(1), 16) if size else 32 * 1024 * 1024,
            "allocationDelta": int(delta.group(1), 16) if delta else 8 * 1024 * 1024}



def _journal_count_raw(letter: str, names: List[str]) -> Optional[int]:
    """Count change-journal records naming any of the files, reading $UsnJrnl through FSCTL_READ_USN_JOURNAL."""
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    handle = k32.CreateFileW("\\\\.\\" + letter, 0x80000000, 0x1 | 0x2, None, 3, 0, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        return None
    try:
        query = ctypes.create_string_buffer(80)
        got = wintypes.DWORD(0)
        if not k32.DeviceIoControl(handle, 0x000900F4, None, 0, query, 80, ctypes.byref(got), None):
            return None
        journal_id, first_usn = struct.unpack_from("<Qq", query.raw, 0)
        needles = [n.encode("utf-16-le") for n in names]
        out = ctypes.create_string_buffer(1 << 20)
        start, found = first_usn, 0
        while True:
            req = struct.pack("<qIIqqQ", start, 0xFFFFFFFF, 0, 0, 0, journal_id)
            if not k32.DeviceIoControl(handle, 0x000900BB, req, len(req), out, len(out), ctypes.byref(got), None):
                return None if found == 0 and start == first_usn else found
            if got.value <= 8:
                return found
            chunk = out.raw[8:got.value]
            pos = 0
            while pos + 60 <= len(chunk):                       # walk USN_RECORD_V2/V3 entries
                rec_len = struct.unpack_from("<I", chunk, pos)[0]
                if rec_len < 60 or pos + rec_len > len(chunk):
                    break
                major = struct.unpack_from("<H", chunk, pos + 4)[0]
                name_off = 56 if major == 2 else 72          # FileNameLength, FileNameOffset
                name_len, name_start = struct.unpack_from("<HH", chunk, pos + name_off)
                name = chunk[pos + name_start:pos + name_start + name_len]
                if name in needles:
                    found += 1
                pos += rec_len
            next_usn = struct.unpack_from("<q", out.raw, 0)[0]
            if next_usn <= start:
                return found
            start = next_usn
    finally:
        k32.CloseHandle(handle)


def journal_names_found(root: str, names: List[str]) -> Optional[int]:
    """How many journal records still carry one of the names (None when the journal cannot be read)."""
    vol = _volume_letter(root)
    if not vol or not names:
        return None
    fast = _journal_count_raw(vol, names)
    if fast is not None:
        return fast
    out = subprocess.run(["fsutil", "usn", "readjournal", vol, "csv"], capture_output=True, text=True,
                         errors="replace", timeout=300)
    if out.returncode != 0:
        return None
    wanted = {n.lower() for n in names}
    found = 0
    for line in out.stdout.splitlines():
        parts = line.split(",", 2)
        if len(parts) >= 2 and parts[1].strip('"').lower() in wanted:
            found += 1
    return found


def clear_journal(root: str) -> Dict[str, Any]:
    """Delete the change journal (removing every recorded file name) and start a new, empty one."""
    vol = _volume_letter(root)
    state = journal_state(root)
    if not state.get("active"):
        return {"volume": root, "result": "no active journal"}
    res = subprocess.run(["fsutil", "usn", "deletejournal", "/d", "/n", vol], capture_output=True, text=True, timeout=600)
    if res.returncode != 0:
        return {"volume": root, "result": "failed: " + (res.stdout + res.stderr).strip()[:200]}
    subprocess.run(["fsutil", "usn", "createjournal", f"m={state['maxSize']}", f"a={state['allocationDelta']}", vol],
                   capture_output=True, text=True, timeout=120)
    return {"volume": root, "result": "cleared and restarted empty"}


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
    info: Dict[str, Any] = {"path": path, "size": os.path.getsize(path), "streams": [], "xattrs": []}
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
    for x in list_xattrs(path):
        try:
            _erase_xattr(path, x["name"], x["size"])
            info["xattrs"].append(x)
        except OSError as exc:
            info.setdefault("xattrErrors", []).append(f"{x['name']}: {exc}")
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
    trace_files: List[str] = []
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
        trace_files += files[:2000 - len(trace_files)]
        entry.update({"isDir": os.path.isdir(ap), "fileCount": len(files),
                      "bytes": sum(os.path.getsize(f) for f in files if os.path.isfile(f)),
                      "streams": sum(len(list_streams(f)) for f in files[:500]),
                      "xattrs": sum(len(list_xattrs(f)) for f in files[:500]),
                      "hardLinked": sum(1 for f in files[:500] if os.stat(f).st_nlink > 1)})
        vol = assess_volume(ap)
        volumes[vol["volume"]] = vol
        entry["volume"] = vol["volume"]
        items.append(entry)
    traces = find_traces(trace_files)
    return {"items": items, "volumes": list(volumes.values()), "traces": traces, "blocked": blocked}


def erase(paths: List[str], method: str, clean: bool, operator: str, approver: str = "",
          progress=None, approval: Optional[Dict[str, Any]] = None, clear_journal_opt: bool = False) -> Dict[str, Any]:
    cases.check_authorization(operator, approver)
    if method not in PASS_SETS:
        raise ValueError(f"method must be one of {list(PASS_SETS)}")
    pre = analyze(paths)
    if pre["blocked"]:
        raise PermissionError("Blocked targets: " + "; ".join(pre["blocked"]))
    job_id = f"FERASE-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2).upper()}"
    audit_log.append("file_erasure.started", operator, details={"jobId": job_id, "paths": paths, "method": method,
                                                                "approver": approver or None,
                                                                "approvalSignature": (approval or {}).get("signature")})
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

    # Remember what must disappear, so the trace check afterwards can look for it
    fingerprints = _fingerprint(files + dirs)

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
    journal_results = []
    if clear_journal_opt:
        for vol in pre["volumes"]:
            if vol.get("changeJournal"):
                journal_results.append(clear_journal(vol["volume"]))
    if progress:
        progress(90, "Checking the drive for any remaining trace")
    trace_check = verify_no_traces(fingerprints)
    if progress:
        progress(100, "Done")
    report = {
        "jobId": job_id, "method": method, "passes": len(PASS_SETS[method]), "operator": operator,
        "approver": approver or None, "approval": approval, "files": results, "failures": failures,
        "foldersRemoved": len(dirs) - sum(1 for f in failures if f["path"] in dirs),
        "streamsErased": sum(len(r["streams"]) for r in results),
        "xattrsErased": sum(len(r.get("xattrs", [])) for r in results),
        "bytesOverwritten": sum(r["size"] for r in results),
        "traces": trace_results, "volumes": pre["volumes"], "journal": journal_results, "traceCheck": trace_check,
        "verdict": ("PARTIAL" if failures or not all(r["verified"] for r in results)
                    else "TRACES_REMAIN" if trace_check.get("tracesFound") else "PASS"),
        "finishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    report["summary"] = (f"{len(results)} files erased ({report['bytesOverwritten']:,} bytes, {report['passes']} pass(es)), "
                         f"{report['streamsErased'] + report['xattrsErased']} streams/attributes, {len([t for t in trace_results if t['result'] in ('erased', 'entry removed')])} traces removed"
                         + (f", {len(failures)} failures" if failures else ""))
    audit_log.append("file_erasure.finished", operator, details={"jobId": job_id, "verdict": report["verdict"],
                                                                 "files": len(results), "failures": len(failures),
                                                                 "traceCheck": trace_check.get("summary")})
    with open(store.workspace_path("reports", f"{job_id}.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report



# ── Post-erasure trace check ─────────────────────────────────────────────────

def _fingerprint(paths: List[str]) -> Dict[str, Any]:
    """Names and content hashes of everything about to be erased, grouped by volume and folder."""
    groups: Dict[str, Dict[str, Any]] = {}
    for p in paths:
        ap = os.path.abspath(p)
        root = _volume_root(ap)
        folder = os.path.dirname(ap)
        g = groups.setdefault(folder, {"volume": root, "folder": folder, "names": [], "hashes": set()})
        g["names"].append(os.path.basename(ap))
        try:
            if os.path.isfile(ap) and os.path.getsize(ap) <= 64 * 1024 * 1024:
                with open(ap, "rb") as f:
                    g["hashes"].add(hashlib.sha256(f.read()).hexdigest())
        except OSError:
            pass
    return groups


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin()) if SYSTEM == "Windows" else os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def _linux_device(mount_point: str) -> Optional[str]:
    """Return the block device path for a Linux mount point (e.g. /dev/sda2)."""
    try:
        out = subprocess.run(["findmnt", "-no", "SOURCE", mount_point],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        return out.split("[", 1)[0] or None  # btrfs: /dev/sda2[/@home] -> /dev/sda2
    except (OSError, subprocess.SubprocessError):
        return None


def _macos_device(mount_point: str) -> Optional[str]:
    """Return the BSD device node for a macOS mount point (e.g. /dev/disk2s1)."""
    try:
        out = subprocess.run(["diskutil", "info", mount_point],
                             capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"Device Node:\s*(/dev/\S+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def verify_no_traces(groups: Dict[str, Any]) -> Dict[str, Any]:
    """
    Read each erased folder directly from the volume with The Sleuth Kit to check whether
    the original names or content can still be found. On Windows also searches the NTFS
    change journal. Works on Windows (Administrator), Linux (root) and macOS (root).
    """
    if not _is_admin():
        msg = ("Trace check needs WipeX to run as Administrator" if SYSTEM == "Windows"
               else "Trace check needs WipeX to run as root (sudo wipex.py ...)")
        return {"checked": False, "summary": msg}
    from recovery import fs_recovery
    checks, names_found, content_found, journal_hits = [], [], [], 0
    journals: Dict[str, Any] = {}
    for g in groups.values():
        if SYSTEM == "Windows":
            letter = _volume_letter(g["volume"])
            if not letter:
                continue
            device = "\\\\.\\" + letter
            rel = g["folder"][len(g["volume"]):].replace("\\", "/")
        elif SYSTEM == "Linux":
            device = _linux_device(g["volume"])
            if not device:
                continue
            rel = g["folder"][len(g["volume"]):]
        elif SYSTEM == "Darwin":
            device = _macos_device(g["volume"])
            if not device:
                continue
            rel = g["folder"][len(g["volume"]):]
        else:
            continue
        res = fs_recovery.dir_traces(device, "/" + rel.strip("/"), g["names"], g["hashes"])
        checks.append({"folder": g["folder"], **res})
        names_found += res.get("namesFound", [])
        content_found += res.get("contentFound", [])
        if SYSTEM == "Windows":
            journals.setdefault(g["volume"], []).extend(g["names"])
    journal = []
    if SYSTEM == "Windows":
        for vol, names in journals.items():
            hits = journal_names_found(vol, names)
            journal.append({"volume": vol, "recordsWithNames": hits})
            journal_hits += hits or 0
    traces = bool(names_found or content_found or journal_hits)
    if not checks:
        summary = "No folder could be checked"
    elif traces:
        parts = []
        if names_found:
            parts.append(f"{len(names_found)} original name(s) still in folder metadata")
        if content_found:
            parts.append(f"{len(content_found)} file(s) still recoverable")
        if journal_hits:
            parts.append(f"{journal_hits} NTFS change-journal record(s) still name the files")
        summary = "Traces found: " + "; ".join(parts)
    else:
        summary = ("No trace found: no original names, no recoverable content, no change-journal records"
                   if SYSTEM == "Windows" else "No trace found: no original names, no recoverable content")
    return {"checked": bool(checks), "tracesFound": traces, "namesFound": names_found,
            "contentFound": content_found, "journal": journal, "folders": checks, "summary": summary}


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
