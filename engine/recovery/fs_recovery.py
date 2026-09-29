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
import struct
import time
from typing import Callable, Dict, List, Optional, Tuple

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


def _metadata_span(img, offset: int, fs) -> int:
    """Bytes from the start of a file system to its data area: boot sector, FATs and (FAT12/16) root
    directory, or exFAT's region before the cluster heap. NTFS keeps all metadata in files ($MFT...),
    which the walk collects, so only its boot sectors are added here."""
    try:
        boot = img.read(offset, 512)
    except IOError:
        boot = b""
    if len(boot) == 512 and boot[3:11] == b"EXFAT   ":
        return struct.unpack_from("<I", boot, 88)[0] << boot[108]            # cluster heap offset x sector size
    if len(boot) == 512 and boot[3:7] == b"NTFS":
        return 16 * 512
    if len(boot) == 512 and boot[510:512] == b"\x55\xAA":
        bps, reserved, nfats, root_entries = (struct.unpack_from("<H", boot, 11)[0], struct.unpack_from("<H", boot, 14)[0],
                                              boot[16], struct.unpack_from("<H", boot, 17)[0])
        fat_sectors = struct.unpack_from("<H", boot, 22)[0] or struct.unpack_from("<I", boot, 36)[0]
        if bps in (512, 1024, 2048, 4096) and nfats:
            return (reserved + nfats * fat_sectors) * bps + root_entries * 32
    return 32 * 1024 * 1024                                                  # unknown layout: the first 32 MiB


def used_extents(source_path: str, max_entries: int = 200000) -> Dict[str, object]:
    """Every byte range the file systems on a drive use or used: file-system tables, directories, the data of
    live files and of deleted files the file system still describes, and system files ($MFT, bitmaps...).
    Quick erase overwrites exactly these. Returns {"extents": [(offset, length)], "volumes", "files", "complete"}."""
    if not HAS_TSK:
        raise RuntimeError("The Sleuth Kit (pytsk3) is needed to map the file system")
    img = _open_img(source_path)
    extents: List[Tuple[int, int]] = []
    volumes: List[Dict[str, object]] = []
    count = 0
    complete = True
    try:
        for vol in _open_filesystems(img):
            fs, base = vol["fs"], int(vol["offset"])
            bs = int(fs.info.block_size)
            extents.append((base, _metadata_span(img, base, fs)))
            last = int(fs.info.last_block)
            extents.append((base + last * bs, bs))                           # NTFS backup boot sector, FAT32 tail
            volumes.append({"offset": base, "fsType": _fs_name(fs.info.ftype), "blockSize": bs})
            seen: set = set()

            def runs(entry):
                for attr in entry:
                    if not int(attr.info.flags) & int(pytsk3.TSK_FS_ATTR_NONRES):
                        continue                                             # resident: inside $MFT, mapped with it
                    for run in attr:                                 # skip sparse runs and fillers (no disk location)
                        if int(run.len) > 0 and not int(run.flags) & (int(pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE)
                                                                      | int(pytsk3.TSK_FS_ATTR_RUN_FLAG_FILLER)):
                            extents.append((base + int(run.addr) * bs, int(run.len) * bs))

            def walk(directory, depth: int):
                nonlocal count, complete
                for entry in directory:
                    if count >= max_entries:
                        complete = False
                        return
                    name = entry.info.name.name
                    if name in (b".", b".."):
                        continue
                    meta = entry.info.meta
                    if meta is None:
                        continue
                    count += 1
                    try:
                        runs(entry)
                    except IOError:
                        pass
                    key = int(meta.addr)
                    if int(meta.type) == int(pytsk3.TSK_FS_META_TYPE_DIR) and key not in seen and depth < 64:
                        seen.add(key)
                        try:
                            walk(entry.as_directory(), depth + 1)
                        except IOError:
                            pass

            try:
                walk(fs.open_dir(path="/"), 0)
            except IOError:
                complete = False
    finally:
        try:
            img.close()
        except Exception:  # noqa: BLE001
            pass
    return {"extents": extents, "volumes": volumes, "files": count, "complete": complete}


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

        def walk(directory, parent: str, depth: int, gone: bool = False):
            if depth > 32 or len(entries) >= max_entries:
                return
            for entry in directory:
                name_info = entry.info.name
                name = name_info.name.decode("utf-8", "replace")
                if name in (".", "..") or name.startswith("$OrphanFiles"):
                    continue
                meta = entry.info.meta
                deleted = gone or bool(int(name_info.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC))
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
                    # A deleted folder keeps its entries in its own directory data (e.g. after Shift+Delete of a
                    # whole folder): walk it too, unless its record now belongs to something else.
                    if key in seen or (deleted and rec["metaAllocated"]):
                        continue
                    seen.add(key)
                    try:
                        walk(entry.as_directory(), path, depth + 1, deleted)
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
        if not start_path and fs_type.startswith("NTFS"):
            _ntfs_unlinked(fs, vi, entries, out_dir if extract_deleted else None, max_entries)

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


MFT_SWEEP_LIMIT = 2_000_000


def _ntfs_file_name(f) -> Tuple[str, int]:
    """Long name and parent reference (record number + sequence) from a record's $FILE_NAME attribute(s)."""
    best, parent = "", -1
    for attr in f:
        if int(attr.info.type) != int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME):
            continue
        try:
            raw = f.read_random(0, int(attr.info.size), attr.info.type, attr.info.id)
        except IOError:
            continue
        if len(raw) < 66:
            continue
        nlen, namespace = raw[64], raw[65]
        name = raw[66:66 + 2 * nlen].decode("utf-16-le", "replace")
        if namespace != 2 or not best:                        # 2 = DOS 8.3 alias: keep only as a fallback
            best, parent = name, struct.unpack_from("<Q", raw, 0)[0]
    return best, parent


def _ntfs_folder(fs, ref: int, dirs: Dict[int, str], cache: Dict[int, str], depth: int = 0) -> str:
    """Path of the folder a deleted record points to; deleted folders are named from their own records."""
    addr, seq = ref & 0xFFFFFFFFFFFF, ref >> 48
    if addr == 5:                                              # the root folder
        return ""
    if addr in dirs:
        return dirs[addr]
    if addr not in cache:
        cache[addr] = "/(deleted folder)"
        try:
            f = fs.open_meta(inode=addr)
            m = f.info.meta
            # Same folder, possibly deleted since (deleting a record raises its sequence number by one)
            if depth < 16 and m is not None and int(m.type) == int(pytsk3.TSK_FS_META_TYPE_DIR) \
                    and int(getattr(m, "seq", seq)) in (seq, seq + 1):
                name, parent = _ntfs_file_name(f)
                if name:
                    cache[addr] = f"{_ntfs_folder(fs, parent, dirs, cache, depth + 1)}/{name}"
        except IOError:
            pass
    return cache[addr]


def _ntfs_unlinked(fs, vi: int, entries: List[Dict[str, object]], out_dir: Optional[str], max_entries: int) -> None:
    """
    NTFS: when a whole folder is deleted, Windows raises the folder record's sequence number, so The Sleuth
    Kit no longer links the deleted files to it and lists them nowhere. Their MFT records still hold name,
    parent, size and data runs: sweep the MFT for deleted file records not listed yet and add them under the
    deleted folder's path when it is known.
    """
    have = {(e["volume"], e["inode"]) for e in entries}
    dirs = {e["inode"]: e["path"] for e in entries if e["volume"] == vi and e["isDir"] and e["inode"] is not None}
    folders: Dict[int, str] = {}
    alloc, reg = int(pytsk3.TSK_FS_META_FLAG_ALLOC), int(pytsk3.TSK_FS_META_TYPE_REG)
    for addr in range(16, min(int(fs.info.last_inum), MFT_SWEEP_LIMIT) + 1):   # 0-15 are NTFS system files
        if len(entries) >= max_entries:
            return
        if (vi, addr) in have:
            continue
        try:
            f = fs.open_meta(inode=addr)
        except IOError:
            continue
        meta = f.info.meta
        if meta is None or int(meta.flags) & alloc or int(meta.type) != reg:
            continue
        name, parent = _ntfs_file_name(f)
        if not name:
            continue
        rec = {"volume": vi, "path": f"{_ntfs_folder(fs, parent, dirs, folders)}/{name}", "name": name, "isDir": False,
               "deleted": True, "inode": addr, "size": int(meta.size), "modified": _ts(meta.mtime),
               "created": _ts(meta.crtime), "accessed": _ts(meta.atime), "metaAllocated": False}
        entries.append(rec)
        if out_dir and 0 < rec["size"] <= MAX_EXTRACT:
            _extract(f, rec, out_dir)


# Confidence that a recovered deleted file is the original, from what the checks could prove:
# name and size from the file system and a structure that validates end to end (intact), content
# present but with no structure to check (unverified), and so on down to blocks already reused.
CONFIDENCE = {"intact": 0.97, "unverified": 0.6, "damaged": 0.35, "overwritten": 0.05, "zeroed": 0.0, "unreadable": 0.0}


def _extract(entry, rec: Dict[str, object], out_dir: str) -> None:
    _extract_content(entry, rec, out_dir)
    rec["confidence"] = CONFIDENCE.get(str(rec.get("contentStatus")), 0.0)


def _extract_content(entry, rec: Dict[str, object], out_dir: str) -> None:
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


def dir_traces(device: str, dir_path: str, names: List[str], hashes: set,
               max_bytes: int = 64 * 1024 * 1024, depth: int = 4) -> Dict[str, object]:
    """
    Read one directory straight from the volume and report whether any of the given names, or any
    deleted entry whose content hashes to one of the given SHA-256 values, can still be found. Deleted
    subfolders are searched too, since an erased folder's entries live on in its own directory data.
    Used to verify a file erasure from the forensic side.
    """
    return dir_traces_many(device, [(dir_path, names, hashes)], max_bytes, depth)[0]


def dir_traces_many(device: str, targets: List[Tuple[str, List[str], set]],
                    max_bytes: int = 64 * 1024 * 1024, depth: int = 4) -> List[Dict[str, object]]:
    """dir_traces for several folders of one volume, opening the file system once (on a large NTFS
    volume The Sleuth Kit needs 10-20 s to open it, so this keeps a multi-folder check to one open)."""
    if not HAS_TSK:
        return [{"checked": False, "reason": "The Sleuth Kit (pytsk3) is not installed"} for _ in targets]
    img = _open_img(device)
    try:
        try:
            fs = pytsk3.FS_Info(img, offset=0)
        except IOError as exc:
            return [{"checked": False, "reason": f"Could not read the folder from the volume: {exc}"} for _ in targets]
        return [_dir_traces_in(fs, dir_path, names, hashes, max_bytes, depth) for dir_path, names, hashes in targets]
    finally:
        try:
            img.close()
        except Exception:  # noqa: BLE001
            pass


def _dir_traces_in(fs, dir_path: str, names: List[str], hashes: set, max_bytes: int, depth: int) -> Dict[str, object]:
    wanted = {n.lower() for n in names}
    name_hits: List[str] = []
    content_hits: List[str] = []
    seen: set = set()
    count = [0]

    def walk(directory, level: int) -> None:
        for entry in directory:
            if count[0] >= 50000:
                return
            name = entry.info.name.name.decode("utf-8", "replace")
            if name in (".", ".."):
                continue
            count[0] += 1
            if name.lower() in wanted:
                name_hits.append(name)
            meta = entry.info.meta
            if meta is None or not int(entry.info.name.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC):
                continue
            if int(meta.type) == int(pytsk3.TSK_FS_META_TYPE_DIR):
                if level < depth and int(meta.addr) not in seen:
                    seen.add(int(meta.addr))
                    try:
                        walk(entry.as_directory(), level + 1)
                    except IOError:
                        pass
            elif hashes and 0 < int(meta.size) <= max_bytes:
                try:
                    data = entry.read_random(0, int(meta.size))
                except IOError:
                    continue
                if hashlib.sha256(data).hexdigest() in hashes:
                    content_hits.append(name)

    try:
        walk(fs.open_dir(path=dir_path or "/"), 0)
    except IOError as exc:
        return {"checked": False, "reason": f"Could not read the folder from the volume: {exc}"}
    return {"checked": True, "entries": count[0], "namesFound": name_hits, "contentFound": content_hits}
