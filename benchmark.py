"""
WipeX - Recovery benchmark (research gap G4).

Runs file-system recovery and carving separately against an image with a ground-truth
file (<image>.truth.json, written by lab_images or supplied for public datasets in the
same format: [{name, ext, sha256, size, state}]) and reports recall, precision and
throughput per technique and per file type. Matching is by SHA-256, so only byte-exact
recoveries count.
"""

import json
import os
import shutil
import time
from collections import defaultdict
from typing import Any, Dict, Optional

import store
from recovery import carver, fs_recovery
from recovery.formats import EXT_TO_FORMAT


def _load_truth(image_path: str, truth_path: Optional[str]) -> Dict[str, Any]:
    with open(truth_path or image_path + ".truth.json", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {"files": data}


def run(image_path: str, truth_path: Optional[str] = None, progress=None) -> Dict[str, Any]:
    truth = _load_truth(image_path, truth_path)["files"]
    work = store.workspace_path("benchmarks", f"run-{int(time.time())}")
    size = os.path.getsize(image_path)
    try:
        t = time.time()
        fs = fs_recovery.scan(image_path, os.path.join(work, "fs"), progress=(lambda p, m: progress(p * 40 // 100, m)) if progress else None)
        fs_secs = time.time() - t
        t = time.time()
        cv = carver.carve(image_path, os.path.join(work, "carved"), progress=(lambda p, m: progress(40 + p * 55 // 100, m)) if progress else None)
        cv_secs = time.time() - t
    finally:
        shutil.rmtree(work, ignore_errors=True)

    by_sha = {f["sha256"]: f for f in truth}
    not_live = [f for f in truth if f["state"] != "live"]
    carvable = [f for f in truth if f["ext"] in EXT_TO_FORMAT]

    fs_hits = {e["sha256"] for e in fs.get("entries", []) if e.get("sha256") and e.get("contentStatus") == "intact"}
    fs_deleted_truth = [f for f in truth if f["state"] == "deleted"]
    carved_hashes = [f["sha256"] for f in cv["files"]]
    carve_tp = {h for h in carved_hashes if h in by_sha}
    carve_fp = [h for h in carved_hashes if h not in by_sha]

    per_type = defaultdict(lambda: {"inTruth": 0, "carved": 0, "fsRecovered": 0, "fragmented": 0})
    for f in carvable:
        pt = per_type[f["ext"]]
        pt["inTruth"] += 1
        pt["fragmented"] += int(bool(f.get("fragmented")))
        pt["carved"] += int(f["sha256"] in carve_tp)
        pt["fsRecovered"] += int(f["sha256"] in fs_hits)

    combined = {f["sha256"] for f in not_live if f["sha256"] in fs_hits or f["sha256"] in carve_tp}

    def ratio(a, b):
        return round(a / b, 3) if b else None

    result = {
        "image": os.path.basename(image_path), "imageBytes": size, "truthFiles": len(truth),
        "fileSystem": {
            "recall": ratio(len([f for f in fs_deleted_truth if f["sha256"] in fs_hits]), len(fs_deleted_truth)),
            "recovered": len([f for f in fs_deleted_truth if f["sha256"] in fs_hits]), "of": len(fs_deleted_truth),
            "seconds": round(fs_secs, 2), "scope": "deleted files with directory entries",
        },
        "carving": {
            "recall": ratio(len(carve_tp), len(carvable)), "precision": ratio(len(carve_tp), len(carve_tp) + len(carve_fp)),
            "recovered": len(carve_tp), "of": len(carvable), "falsePositives": len(carve_fp),
            "repairedFragments": sum(1 for f in cv["files"] if f["status"] == "repaired"),
            "seconds": round(cv_secs, 2), "throughputMBps": cv["throughputMBps"],
            "scope": "all files of carvable types (live, deleted, orphaned)",
        },
        "combined": {"recall": ratio(len(combined), len(not_live)), "recovered": len(combined), "of": len(not_live),
                     "scope": "deleted and orphaned files, either technique"},
        "perType": dict(per_type),
        "missed": [f["name"] for f in not_live if f["sha256"] not in combined],
    }
    result["summary"] = (f"Combined recall {result['combined']['recovered']}/{result['combined']['of']}, "
                         f"carving precision {result['carving']['precision']}, {result['carving']['throughputMBps']} MB/s")
    if progress:
        progress(100, "Benchmark complete")
    return result
