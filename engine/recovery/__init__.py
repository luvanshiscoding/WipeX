"""
WipeX recovery package (module M3): file-system-aware recovery (The Sleuth Kit)
combined with signature + structure carving and bifragment gap carving.
"""

import os
import time
from typing import Callable, Dict, List, Optional

import ewf

from . import carver, fs_recovery
from .formats import FORMATS

ProgressFn = Callable[[int, str], None]


def _source_size(path: str) -> int:
    try:
        img = ewf.open_image(path)
        try:
            return img.size
        finally:
            img.close()
    except OSError:
        return 0


def supported_formats() -> List[Dict[str, str]]:
    return [{"ext": f.ext, "name": f.name} for f in FORMATS]


def scan(source_path: str, out_dir: str, use_fs: bool = True, use_carving: bool = True,
         types: Optional[List[str]] = None, include_partial: bool = False,
         progress: Optional[ProgressFn] = None, start_path: str = "") -> Dict[str, object]:
    """Run file-system recovery then carving; merge results and de-duplicate by hash."""
    if not os.path.exists(source_path) and not source_path.startswith("\\\\.\\"):
        raise FileNotFoundError(f"Source not found: {source_path}")
    t0 = time.time()
    fs_result: Dict[str, object] = {"available": False, "entries": [], "volumes": []}
    carve_result: Dict[str, object] = {"files": [], "stats": {}}

    def sub(lo: int, hi: int):
        return (lambda p, m: progress(lo + p * (hi - lo) // 100, m)) if progress else None

    if use_fs:
        size = _source_size(source_path)
        # Hashing live files only helps to label carved duplicates; skip it on whole drives
        fs_result = fs_recovery.scan(source_path, os.path.join(out_dir, "filesystem"), progress=sub(0, 40 if use_carving else 100),
                                     hash_live=size <= 4 * 1024 ** 3, start_path=start_path)
    if use_carving:
        carve_result = carver.carve(source_path, os.path.join(out_dir, "carved"), types=types,
                                    include_partial=include_partial, progress=sub(40 if use_fs else 0, 100))

    fs_hashes = {e.get("sha256"): e for e in fs_result.get("entries", []) if e.get("sha256")}
    for f in carve_result.get("files", []):
        match = fs_hashes.get(f["sha256"])
        if match:
            f["alsoFoundAs"] = match["path"]

    deleted = [e for e in fs_result.get("entries", []) if e.get("deleted") and not e.get("isDir")]
    carved = carve_result.get("files", [])
    only_by_carving = [f for f in carved if not f.get("alsoFoundAs")]
    summary = (f"{len(deleted)} deleted entries in file system, {len(carved)} files carved "
               f"({len(only_by_carving)} found only by carving)")
    return {
        "source": source_path,
        "seconds": round(time.time() - t0, 2),
        "filesystem": fs_result,
        "carving": carve_result,
        "summary": summary,
    }
