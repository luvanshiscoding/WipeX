"""
WipeX recovery - file-system-aware recovery via The Sleuth Kit (pytsk3).

Walks every file system found in an image or device (partition tables are handled),
lists live and deleted entries with their metadata, and extracts deleted files.
Extracted content is checked with the structural validators so the report can say
whether a deleted file's clusters still hold the original content or were reused.
"""

import hashlib
import os
import re
import time
from typing import Callable, Dict, List, Optional

import ewf

from .formats import EXT_TO_FORMAT, validate_bytes

try:
    import pytsk3
    HAS_TSK = True
except ImportError:  # pragma: no cover
    HAS_TSK = False

ProgressFn = Callable[[int, str], None]
MAX_EXTRACT = 512 * 1024 * 1024
HASH_LIVE_MAX = 64 * 1024 * 1024


def _ts(v) -> Optional[str]:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(v))) if v else None
    except (ValueError, OSError):
        return None


def _safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", name)[:120] or "unnamed"


if HAS_TSK:
    class _EwfImg(pytsk3.Img_Info):
        """Lets The Sleuth Kit read E01 images through WipeX's own EWF reader."""

        def __init__(self, reader):
            self._reader = reader
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._reader.close()

        def read(self, offset, size):
            return self._reader.read(offset, size)

        def get_size(self):
            return self._reader.size


def _open_img(path: str):
    return _EwfImg(ewf.EwfReader(path)) if ewf.is_ewf(path) else pytsk3.Img_Info(path)


def _open_filesystems(img) -> List[Dict[str, object]]:
    """Return [{offset, fs, description}] for each readable file system."""
    found = []
    try:
        volume = pytsk3.Volume_Info(img)
        block = volume.info.block_size
        for part in volume:
            if not int(part.flags) & int(pytsk3.TSK_VS_PART_FLAG_ALLOC):
                continue
            offset = part.start * block
            try:
                fs = pytsk3.FS_Info(img, offset=offset)
                found.append({"offset": offset, "fs": fs,
                              "description": part.desc.decode("utf-8", "replace")})
            except IOError:
                continue
    except IOError:
        pass
    if not found:
        try:
            found.append({"offset": 0, "fs": pytsk3.FS_Info(img, offset=0), "description": "Unpartitioned volume"})
        except IOError:
            pass
    return found


_FS_TYPE_NAMES = {}
if HAS_TSK:
    for _attr in dir(pytsk3):
        if _attr.startswith("TSK_FS_TYPE_") and not _attr.endswith(("_DETECT", "_ENUM")):
            try:
                _FS_TYPE_NAMES.setdefault(int(getattr(pytsk3, _attr)), _attr[len("TSK_FS_TYPE_"):])
            except (TypeError, ValueError):
                pass


def _fs_name(ftype) -> str:
    try:
        return _FS_TYPE_NAMES.get(int(ftype), str(ftype))
    except (TypeError, ValueError):
        return str(ftype)


def available() -> bool:
    return HAS_TSK


def scan(source_path: str, out_dir: Optional[str] = None, extract_deleted: bool = True,
         progress: Optional[ProgressFn] = None, max_entries: int = 50000, hash_live: bool = True,
         start_path: str = "") -> Dict[str, object]:
    """List all entries (or those under start_path); extract deleted files into out_dir when given."""
    if not HAS_TSK:
        return {"available": False, "reason": "pytsk3 (The Sleuth Kit) is not installed", "volumes": [], "entries": []}
    img = _open_img(source_path)
    try:
        return _scan_img(img, source_path, out_dir, extract_deleted, progress, max_entries, hash_live, start_path)
    finally:
        try:
            img.close()
        except Exception:  # noqa: BLE001
            pass


def _scan_img(img, source_path: str, out_dir: Optional[str], extract_deleted: bool,
              progress: Optional[ProgressFn], max_entries: int, hash_live: bool,
              start_path: str = "") -> Dict[str, object]:
    t0 = time.time()
    volumes, entries = [], []
    fss = _open_filesystems(img)
    if not fss:
        return {"available": True, "volumes": [], "entries": [],
                "reason": "No supported file system found (formatted, encrypted or overwritten)"}

    for vi, vol in enumerate(fss):
        fs = vol["fs"]
        fs_type = _fs_name(fs.info.ftype)
        volumes.append({"index": vi, "offset": vol["offset"], "fsType": fs_type,
                        "description": vol["description"], "blockSize": fs.info.block_size})
        seen = set()

        def walk(directory, parent: str, depth: int):
            if depth > 32 or len(entries) >= max_entries:
                return
            for entry in directory:
                name_info = entry.info.name
                name = name_info.name.decode("utf-8", "replace")
                if name in (".", "..") or name.startswith("$OrphanFiles"):
                    continue
                meta = entry.info.meta
                deleted = bool(int(name_info.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC))
                is_dir = bool(meta and int(meta.type) == int(pytsk3.TSK_FS_META_TYPE_DIR)) or \
                    int(name_info.type) == int(pytsk3.TSK_FS_NAME_TYPE_DIR)
                path = f"{parent}/{name}"
                rec = {
                    "volume": vi, "path": path, "name": name, "isDir": is_dir, "deleted": deleted,
                    "inode": int(meta.addr) if meta else None, "size": int(meta.size) if meta else 0,
                    "modified": _ts(meta.mtime) if meta else None, "created": _ts(meta.crtime) if meta else None,
                    "accessed": _ts(meta.atime) if meta else None,
                    "metaAllocated": bool(meta and int(meta.flags) & int(pytsk3.TSK_FS_META_FLAG_ALLOC)),
                }
                entries.append(rec)
                if progress and len(entries) % 200 == 0:
                    progress(min(60, 5 + len(entries) // 50), f"Listed {len(entries)} entries")

                if is_dir and meta is not None:
                    key = (vi, int(meta.addr))
                    if key in seen or deleted:
                        continue
                    seen.add(key)
                    try:
                        walk(entry.as_directory(), path, depth + 1)
                    except IOError:
                        continue
                elif deleted and meta is not None and extract_deleted and out_dir and 0 < rec["size"] <= MAX_EXTRACT:
                    _extract(entry, rec, out_dir)
                elif not deleted and meta is not None and hash_live and 0 < rec["size"] <= HASH_LIVE_MAX:
                    try:   # hash live files so carved results can be matched to them
                        rec["sha256"] = hashlib.sha256(entry.read_random(0, int(rec["size"]))).hexdigest()
                    except IOError:
                        pass

        start = "/" + start_path.replace("\\", "/").strip("/") if start_path else "/"
        try:
            walk(fs.open_dir(path=start), start.rstrip("/"), 0)
        except IOError:
            if start_path:
                return {"available": True, "volumes": volumes, "entries": [],
                        "reason": f"Folder {start} was not found on this volume"}
            continue

    deleted = [e for e in entries if e["deleted"] and not e["isDir"]]
    if progress:
        progress(100, f"{len(entries)} entries, {len(deleted)} deleted files")
    return {
        "available": True,
        "seconds": round(time.time() - t0, 3),
        "volumes": volumes,
        "entries": entries,
        "counts": {"total": len(entries), "deleted": len(deleted),
                   "recovered": sum(1 for e in deleted if e.get("recoveredPath")),
                   "intact": sum(1 for e in deleted if e.get("contentStatus") == "intact")},
    }


def _extract(entry, rec: Dict[str, object], out_dir: str) -> None:
    try:
        data = entry.read_random(0, int(rec["size"]))
    except IOError as exc:
        rec["contentStatus"] = "unreadable"
        rec["detail"] = str(exc)
        return
    if data and not data.strip(b"\x00"):
        # Nothing left to recover: SSDs and virtual disks erase freed blocks themselves (TRIM)
        rec["contentStatus"] = "zeroed"
        rec["detail"] = "The file's data blocks now read as zeros: the drive erased them (TRIM) or they were wiped"
        return
    os.makedirs(out_dir, exist_ok=True)
    fname = f"F{rec['inode']}_{_safe_name(str(rec['name']))}"
    path = os.path.join(out_dir, fname)
    with open(path, "wb") as fh:
        fh.write(data)
    rec["recoveredPath"] = path
    rec["sha256"] = hashlib.sha256(data).hexdigest()
    check = validate_bytes(data, str(rec["name"]))
    ext = str(rec["name"]).rsplit(".", 1)[-1].lower() if "." in str(rec["name"]) else ""
    if check is None and ext in EXT_TO_FORMAT:
        # A known file type whose blocks no longer start like that type: the space was reused
        rec["contentStatus"] = "overwritten"
        rec["detail"] = "The file's space now holds other data"
    elif check is None:
        # Text and other formats without a structure to check: content may or may not be original
        rec["contentStatus"] = "unverified"
    elif check.valid and check.end == len(data):
        rec["contentStatus"] = "intact"
    else:
        rec["contentStatus"] = "damaged"
        rec["detail"] = check.reason or "structure does not match the recorded size"


def dir_traces(device: str, dir_path: str, names: List[str], hashes: set, max_bytes: int = 64 * 1024 * 1024) -> Dict[str, object]:
    """
    Read one directory straight from the volume (live and deleted entries) and report whether any
    of the given file names, or any deleted entry whose content hashes to one of the given SHA-256
    values, can still be found. Used to verify a file erasure from the forensic side.
    """
    if not HAS_TSK:
        return {"checked": False, "reason": "The Sleuth Kit (pytsk3) is not installed"}
    wanted = {n.lower() for n in names}
    img = _open_img(device)
    try:
        fs = pytsk3.FS_Info(img, offset=0)
        directory = fs.open_dir(path=dir_path or "/")
        name_hits, content_hits, entries = [], [], 0
        for entry in directory:
            name = entry.info.name.name.decode("utf-8", "replace")
            if name in (".", ".."):
                continue
            entries += 1
            if name.lower() in wanted:
                name_hits.append(name)
            meta = entry.info.meta
            deleted = bool(int(entry.info.name.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC))
            if deleted and meta is not None and hashes and 0 < int(meta.size) <= max_bytes:
                try:
                    data = entry.read_random(0, int(meta.size))
                except IOError:
                    continue
                if hashlib.sha256(data).hexdigest() in hashes:
                    content_hits.append(name)
        return {"checked": True, "entries": entries, "namesFound": name_hits, "contentFound": content_hits}
    except IOError as exc:
        return {"checked": False, "reason": f"Could not read the directory from the volume: {exc}"}
    finally:
        try:
            img.close()
        except Exception:  # noqa: BLE001
            pass
