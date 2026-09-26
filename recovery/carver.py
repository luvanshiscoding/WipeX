"""
WipeX recovery - signature + structure file carver.

Scans a disk image or a raw device (opened read-only) for file headers at sector
boundaries, parses each candidate with a format-specific structural parser, and
writes out files whose structure validates.

Fragmented files: for formats with strong integrity checks (PNG chunk CRCs, ZIP
member CRCs) the carver attempts bifragment gap carving (Garfinkel 2007): when the
structure breaks, it searches cluster-aligned split points and gap lengths for the
one combination that makes the integrity checks pass again.
"""

import hashlib
import os
import re
import struct
import time
import zlib
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .formats import FORMATS, Format, ParseResult, parse_png, parse_zip

ProgressFn = Callable[[int, str], None]


@dataclass
class CarvedFile:
    id: str
    type: str
    ext: str
    offset: int
    size: int
    sha256: str
    status: str            # valid | repaired | partial
    technique: str
    confidence: float
    detail: str = ""
    info: Dict[str, object] = field(default_factory=dict)
    path: str = ""
    fragments: List[Tuple[int, int]] = field(default_factory=list)


class Source:
    """Read-only random access over an image file or raw device."""

    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "rb", buffering=0)
        self.size = self.f.seek(0, os.SEEK_END)
        self.f.seek(0)

    def read(self, offset: int, length: int) -> bytes:
        if offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        # Raw devices on Windows need sector-aligned reads
        start = offset - (offset % 512)
        end = offset + length
        end_aligned = min(self.size, end + (-end % 512))
        self.f.seek(start)
        buf = self.f.read(end_aligned - start)
        return buf[offset - start:offset - start + length]

    def close(self):
        self.f.close()


def detect_cluster_size(src: "Source", default: int = 4096) -> int:
    """Allocation unit from the volume boot record (FAT/NTFS) or ext superblock."""
    try:
        boot = src.read(0, 2048)
        if boot[510:512] == bytes([0x55, 0xAA]):
            bps = struct.unpack("<H", boot[11:13])[0]
            spc = boot[13]
            if boot[3:7] == b"NTFS" and spc > 0x80:
                spc = 1 << (256 - spc)
            if bps in (512, 1024, 2048, 4096) and spc and not spc & (spc - 1):
                return bps * spc
        if boot[1024 + 56:1024 + 58] == bytes([0x53, 0xEF]):
            return 1024 << struct.unpack("<I", boot[1024 + 24:1024 + 28])[0]
    except (OSError, struct.error):
        pass
    return default


def _parse_growing(src: "Source", off: int, fmt: Format) -> Tuple[bytes, Optional[ParseResult]]:
    """Parse with a small window first; grow it only while the parser reports truncation."""
    size = 4 * 1024 * 1024
    while True:
        window = src.read(off, min(size, fmt.max_size))
        pr = fmt.parser(window)
        truncated = pr is not None and not pr.valid and pr.end >= len(window) - 1
        if not truncated or len(window) >= fmt.max_size or off + len(window) >= src.size:
            return window, pr
        size *= 4


def _write(out_dir: str, name: str, blob: bytes) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "wb") as fh:
        fh.write(blob)
    return path


# ── Bifragment gap carving ───────────────────────────────────────────────────

def _png_bifragment(src: Source, start: int, break_rel: int, cluster: int, max_gap: int, max_size: int,
                    deadline: float) -> Optional[Tuple[bytes, Tuple[int, int], Tuple[int, int]]]:
    """
    Chunks before break_rel passed their CRCs, so the fragment boundary lies inside the
    chunk that starts at break_rel. For each cluster-aligned split inside that chunk and
    each gap length, recompute only that chunk's CRC; on a match, re-validate the whole file.
    """
    window = src.read(start, min(max_size, break_rel + 16 * 1024 * 1024) + max_gap)
    # Files start on a cluster boundary, so fragment boundaries are cluster multiples from the file start
    first_split = break_rel + (-break_rel % cluster)
    head1 = window[break_rel:break_rel + 8]
    known_len = struct.unpack(">I", head1[:4])[0] if len(head1) == 8 and head1[4:8].isalpha() else None
    span_end = break_rel + 12 + known_len if known_len is not None and known_len < 0x7FFFFFFF else break_rel + 1024 * 1024
    s_rel = max(first_split, cluster)
    while s_rel < min(span_end, len(window)):
        p1 = window[break_rel:s_rel]
        for gap in range(cluster, max_gap + 1, cluster):
            if time.time() > deadline:
                return None
            p2_start = s_rel + gap
            if p2_start + 8 > len(window):
                break
            head = (p1 + window[p2_start:p2_start + 8])[:8]
            length = struct.unpack(">I", head[:4])[0]
            if length > 0x7FFFFFFF or not head[4:8].isalpha():
                continue
            need = 12 + length - len(p1)
            if need <= 0:
                continue
            p2 = window[p2_start:p2_start + need]
            if len(p2) < need:
                continue
            chunk = p1 + p2
            if zlib.crc32(chunk[4:8 + length]) & 0xFFFFFFFF != struct.unpack(">I", chunk[8 + length:12 + length])[0]:
                continue
            full = window[:s_rel] + window[p2_start:]
            result = parse_png(full)
            if result and result.valid:
                return full[:result.end], (start, s_rel), (start + p2_start, result.end - s_rel)
        s_rel += cluster
    return None


def _zip_reassemble(src: Source, start: int, pr: ParseResult, cluster: int, deadline: float) -> Optional[Tuple[bytes, Tuple[int, int], Tuple[int, int]]]:
    """ZIP: the gap length is known from the central-directory offset mismatch; search the split point."""
    gap = int(pr.info.get("gap", 0))
    if gap <= 0 or gap % cluster:
        return None
    window = src.read(start, pr.end)
    cd_off = int(pr.info.get("cd_offset", 0))
    for s_rel in range(cluster, cd_off + cluster, cluster):
        if time.time() > deadline:
            return None
        candidate = window[:s_rel] + window[s_rel + gap:]
        result = parse_zip(candidate)
        if result and result.valid:
            return candidate[:result.end], (start, s_rel), (start + s_rel + gap, result.end - s_rel)
    return None


# ── Main carve loop ──────────────────────────────────────────────────────────

def carve(source_path: str, out_dir: str, types: Optional[List[str]] = None, aligned: bool = True,
          cluster: Optional[int] = None, max_gap: int = 1024 * 1024, include_partial: bool = False,
          progress: Optional[ProgressFn] = None, limit_files: int = 5000,
          time_budget_s: float = 600.0) -> Dict[str, object]:
    """
    Carve files from source_path into out_dir.
    aligned: only accept headers on 512-byte boundaries (how file systems allocate).
    cluster: allocation unit used for gap carving of fragmented files.
    """
    t0 = time.time()
    src = Source(source_path)
    cluster = cluster or detect_cluster_size(src)
    formats = [f for f in FORMATS if not types or f.ext in types]
    # One regex per format: each starts with a literal, so the regex engine can use a fast prefix scan
    header_res = [(re.compile(f.header, re.S), f) for f in formats]

    chunk = 16 * 1024 * 1024
    overlap = 64
    candidates: List[Tuple[int, Format]] = []
    pos = 0
    while pos < src.size:
        buf = src.read(pos, chunk + overlap)
        if not buf:
            break
        for rx, fmt in header_res:
            for m in rx.finditer(buf):
                if m.start() >= chunk:          # belongs to next chunk (overlap region)
                    continue
                off = pos + m.start() - fmt.header_offset
                if off < 0 or (aligned and off % 512):
                    continue
                candidates.append((off, fmt))
        pos += chunk
        if progress:
            progress(min(40, int(pos * 40 / max(1, src.size))), f"Scanned {min(pos, src.size) // (1024 * 1024)} MB for headers")

    candidates.sort(key=lambda c: c[0])
    claimed: List[Tuple[int, int]] = []
    files: List[CarvedFile] = []
    stats = {"candidates": len(candidates), "valid": 0, "repaired": 0, "partial": 0, "rejected": 0}

    def is_claimed(off: int) -> bool:
        return any(a <= off < b for a, b in claimed)

    deadline = t0 + time_budget_s
    for idx, (off, fmt) in enumerate(candidates):
        if len(files) >= limit_files or time.time() > deadline:
            break
        if progress and idx % 20 == 0:
            progress(40 + int(idx * 58 / max(1, len(candidates))), f"Validating candidate {idx + 1} of {len(candidates)}")
        if is_claimed(off):
            continue
        window, pr = _parse_growing(src, off, fmt)
        if pr is None:
            stats["rejected"] += 1
            continue
        ext = pr.ext or fmt.ext
        blob, status, technique, fragments = None, "", "", []

        if pr.valid:
            blob = window[:pr.end]
            status, technique, fragments = "valid", "signature + structure", [(off, pr.end)]
        elif fmt.ext == "png" and pr.break_at:
            got = _png_bifragment(src, off, pr.break_at, cluster, max_gap, fmt.max_size, min(deadline, time.time() + 20))
            if got:
                blob, f1, f2 = got
                status, technique, fragments = "repaired", "bifragment gap carving (CRC-validated)", [f1, f2]
        elif fmt.ext == "zip" and pr.info.get("gap"):
            got = _zip_reassemble(src, off, pr, cluster, min(deadline, time.time() + 20))
            if got:
                blob, f1, f2 = got
                recheck = parse_zip(blob)
                ext = (recheck.ext if recheck else None) or ext
                status, technique, fragments = "repaired", "bifragment gap carving (ZIP CRC-validated)", [f1, f2]

        if blob is None and include_partial and fmt.ext in ("jpg", "png", "gif") and pr.end > 1024:
            blob = window[:pr.end]
            status, technique, fragments = "partial", "signature + structure (incomplete)", [(off, pr.end)]

        if blob is None:
            stats["rejected"] += 1
            continue

        sha = hashlib.sha256(blob).hexdigest()
        fid = f"C{len(files) + 1:04d}"
        name = f"{fid}_{off:010x}.{ext}"
        path = _write(out_dir, name, blob)
        conf = {"valid": 0.95, "repaired": 0.9, "partial": 0.4}[status]
        if status == "valid" and pr.info.get("decoded") is False:
            conf = 0.85
        files.append(CarvedFile(fid, fmt.name, ext, off, len(blob), sha, status, technique, conf,
                                pr.reason if status != "valid" else "", dict(pr.info), path, fragments))
        stats[status] += 1
        for a, length in fragments:
            claimed.append((a, a + length))

    src.close()
    elapsed = max(0.001, time.time() - t0)
    if progress:
        progress(100, f"Carved {len(files)} files")
    return {
        "source": source_path,
        "bytesScanned": src.size,
        "clusterSize": cluster,
        "seconds": round(elapsed, 3),
        "throughputMBps": round(src.size / (1024 * 1024) / elapsed, 1),
        "stats": stats,
        "files": [asdict(f) for f in files],
    }
