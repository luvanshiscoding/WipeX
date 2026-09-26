"""
WipeX - Lab disk images.

Builds real FAT16 disk images (boot sector, two FATs, root directory, sub-directories,
long file names) with a known ground truth:
  * live files, deleted files (directory entry marked 0xE5, FAT chain freed),
  * fragmented files (a gap of other data between two cluster runs),
  * orphaned data (content in unallocated clusters with no directory entry).

The images are safe, genuine targets for the Drive Eraser, Recovery and benchmark
modules: every operation on them is real, but no physical disk is touched.
"""

import datetime
import hashlib
import io
import json
import math
import os
import random
import secrets
import sqlite3
import struct
import tempfile
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import store

SECTOR = 512
IMAGES_DIR_PARTS = ("images",)


def images_dir() -> str:
    return store.workspace_path(*IMAGES_DIR_PARTS)


# ── FAT16 writer ─────────────────────────────────────────────────────────────

def _lfn_checksum(short11: bytes) -> int:
    s = 0
    for c in short11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def _fat_datetime(dt: datetime.datetime) -> Tuple[int, int]:
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    tm = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return date, tm


class Fat16Image:
    def __init__(self, size_mb: int = 64, sectors_per_cluster: int = 8, label: str = "WIPEX LAB"):
        self.spc = sectors_per_cluster
        self.cluster_size = SECTOR * self.spc
        self.total_sectors = size_mb * 2048
        self.reserved = 4
        self.nfats = 2
        self.root_entries = 512
        self.root_sectors = self.root_entries * 32 // SECTOR
        fat_sectors = 1
        while True:
            data_sectors = self.total_sectors - self.reserved - self.nfats * fat_sectors - self.root_sectors
            clusters = data_sectors // self.spc
            needed = math.ceil((clusters + 2) * 2 / SECTOR)
            if needed <= fat_sectors:
                break
            fat_sectors = needed
        self.fat_sectors = fat_sectors
        self.data_start = self.reserved + self.nfats * fat_sectors + self.root_sectors
        self.clusters = (self.total_sectors - self.data_start) // self.spc
        if not 4085 <= self.clusters < 65525:
            raise ValueError("Size does not produce a FAT16 cluster count")
        self.fat = [0] * (self.clusters + 2)
        self.fat[0], self.fat[1] = 0xFFF8, 0xFFFF
        self.buf = bytearray(self.total_sectors * SECTOR)
        self.label = label.upper()[:11].ljust(11)
        self.volume_id = secrets.randbits(32)
        self.dirs: Dict[str, Dict[str, Any]] = {"/": {"cluster": 0, "entries": []}}
        self.next_free = 2
        self._short_names: Dict[str, set] = {"/": set()}

    # geometry
    def cluster_offset(self, c: int) -> int:
        return (self.data_start + (c - 2) * self.spc) * SECTOR

    def alloc(self, n: int) -> List[int]:
        start = self.next_free
        if start + n > self.clusters + 2:
            raise ValueError("Image is full")
        self.next_free += n
        return list(range(start, start + n))

    def _link(self, chain: List[int]) -> None:
        for a, b in zip(chain, chain[1:]):
            self.fat[a] = b
        if chain:
            self.fat[chain[-1]] = 0xFFFF

    def _write(self, chain: List[int], data: bytes) -> List[Tuple[int, int]]:
        """Write data across the cluster chain; return absolute (offset, length) runs."""
        runs: List[Tuple[int, int]] = []
        for i, c in enumerate(chain):
            piece = data[i * self.cluster_size:(i + 1) * self.cluster_size]
            off = self.cluster_offset(c)
            self.buf[off:off + len(piece)] = piece
            if runs and runs[-1][0] + runs[-1][1] == off:
                runs[-1] = (runs[-1][0], runs[-1][1] + len(piece))
            else:
                runs.append((off, len(piece)))
        return runs

    # directory entries
    def _short_name(self, dir_path: str, name: str) -> bytes:
        base, _, ext = name.rpartition(".") if "." in name else (name, "", "")
        clean = lambda s: "".join(ch for ch in s.upper() if ch.isalnum() or ch in "_-")
        b, e = clean(base), clean(ext)[:3]
        used = self._short_names.setdefault(dir_path, set())
        if len(b) <= 8 and b and name.upper() == (b + ("." + e if e else "")):
            cand = b.ljust(8) + e.ljust(3)
        else:
            i = 1
            while True:
                stem = b[:8 - len(f"~{i}")] + f"~{i}"
                cand = stem.ljust(8) + e.ljust(3)
                if cand not in used:
                    break
                i += 1
        used.add(cand)
        return cand.encode("ascii")

    def _entries_for(self, dir_path: str, name: str, attr: int, cluster: int, size: int,
                     when: datetime.datetime) -> List[bytearray]:
        short = self._short_name(dir_path, name)
        entries: List[bytearray] = []
        needs_lfn = name.upper() != (short[:8].decode().strip() + ("." + short[8:].decode().strip() if short[8:].strip() else ""))
        if needs_lfn or name != name.upper():
            chk = _lfn_checksum(short)
            chars = name.encode("utf-16-le")
            units = [chars[i:i + 2] for i in range(0, len(chars), 2)]
            parts = math.ceil(len(units) / 13)
            units += [b"\x00\x00"] + [b"\xff\xff"] * (parts * 13 - len(units) - 1) if len(units) % 13 else []
            for p in range(parts, 0, -1):
                seg = units[(p - 1) * 13:p * 13]
                e = bytearray(32)
                e[0] = p | (0x40 if p == parts else 0)
                e[1:11] = b"".join(seg[0:5])
                e[11] = 0x0F
                e[13] = chk
                e[14:26] = b"".join(seg[5:11])
                e[28:32] = b"".join(seg[11:13])
                entries.append(e)
        d, t = _fat_datetime(when)
        e = bytearray(32)
        e[0:11] = short
        e[11] = attr
        struct.pack_into("<HHHHHHHI", e, 14, t, d, d, 0, t, d, cluster, size)
        entries.append(e)
        return entries

    def _dir(self, path: str) -> Dict[str, Any]:
        if path not in self.dirs:
            raise ValueError(f"No such directory {path}")
        return self.dirs[path]

    def add_dir(self, parent: str, name: str, when: datetime.datetime) -> str:
        cluster = self.alloc(1)[0]
        self._link([cluster])
        path = (parent.rstrip("/") + "/" + name) if parent != "/" else "/" + name
        self._dir(parent)["entries"].append({"name": name, "raw": self._entries_for(parent, name, 0x10, cluster, 0, when)})
        dot = bytearray(32); dot[0:11] = b".          "; dot[11] = 0x10
        struct.pack_into("<H", dot, 26, cluster)
        dotdot = bytearray(32); dotdot[0:11] = b"..         "; dotdot[11] = 0x10
        struct.pack_into("<H", dotdot, 26, self._dir(parent)["cluster"])
        self.dirs[path] = {"cluster": cluster, "entries": [{"name": ".", "raw": [dot]}, {"name": "..", "raw": [dotdot]}]}
        self._short_names[path] = set()
        return path

    def add_file(self, dir_path: str, name: str, data: bytes, when: datetime.datetime,
                 fragment_gap: Optional[bytes] = None, gap_allocated: bool = True) -> Dict[str, Any]:
        n = max(1, math.ceil(len(data) / self.cluster_size))
        if fragment_gap is not None and n >= 2:
            first = self.alloc(n // 2)
            gap_clusters = self.alloc(max(1, math.ceil(len(fragment_gap) / self.cluster_size)))
            self._write(gap_clusters, fragment_gap)
            if gap_allocated:
                self._link(gap_clusters)   # gap belongs to another allocated stream
            # else: gap is left as unallocated residue (defeats contiguous-recovery heuristics)
            second = self.alloc(n - n // 2)
            chain = first + second
        else:
            chain = self.alloc(n)
        self._link(chain)
        runs = self._write(chain, data)
        self._dir(dir_path)["entries"].append({"name": name, "raw": self._entries_for(dir_path, name, 0x20, chain[0], len(data), when)})
        return {"chain": chain, "runs": runs}

    def add_orphan(self, data: bytes) -> Dict[str, Any]:
        """Content in unallocated clusters with no directory entry (e.g. after a quick format)."""
        chain = self.alloc(max(1, math.ceil(len(data) / self.cluster_size)))
        runs = self._write(chain, data)
        return {"chain": chain, "runs": runs}

    def delete(self, dir_path: str, name: str) -> None:
        """Delete like FAT drivers do: mark entries 0xE5 and free the cluster chain; data remains."""
        for item in self._dir(dir_path)["entries"]:
            if item["name"] == name:
                for e in item["raw"]:
                    e[0] = 0xE5
                c = struct.unpack_from("<H", item["raw"][-1], 26)[0]
                while 2 <= c < 0xFFF8:
                    nxt = self.fat[c]
                    self.fat[c] = 0
                    c = nxt
                return
        raise ValueError(f"{name} not found in {dir_path}")

    def build(self) -> bytes:
        bs = bytearray(SECTOR)
        bs[0:3] = b"\xEB\x3C\x90"
        bs[3:11] = b"MSWIN4.1"
        struct.pack_into("<HBHBHHBHHHII", bs, 11, SECTOR, self.spc, self.reserved, self.nfats,
                         self.root_entries, 0, 0xF8, self.fat_sectors, 32, 64, 0, self.total_sectors)
        struct.pack_into("<BBBI", bs, 36, 0x80, 0, 0x29, self.volume_id)
        bs[43:54] = self.label.encode("ascii")
        bs[54:62] = b"FAT16   "
        bs[510:512] = b"\x55\xAA"
        self.buf[0:SECTOR] = bs

        fat_bytes = struct.pack(f"<{len(self.fat)}H", *self.fat)
        for i in range(self.nfats):
            off = (self.reserved + i * self.fat_sectors) * SECTOR
            self.buf[off:off + len(fat_bytes)] = fat_bytes

        # Root directory: volume label entry first
        root_off = (self.reserved + self.nfats * self.fat_sectors) * SECTOR
        lbl = bytearray(32); lbl[0:11] = self.label.encode("ascii"); lbl[11] = 0x08
        raw_root = [lbl] + [e for item in self.dirs["/"]["entries"] for e in item["raw"]]
        if len(raw_root) > self.root_entries:
            raise ValueError("Root directory full")
        for i, e in enumerate(raw_root):
            self.buf[root_off + i * 32:root_off + (i + 1) * 32] = e
        for path, d in self.dirs.items():
            if path == "/":
                continue
            raw = [e for item in d["entries"] for e in item["raw"]]
            if len(raw) * 32 > self.cluster_size:
                raise ValueError(f"Directory {path} exceeds one cluster")
            off = self.cluster_offset(d["cluster"])
            for i, e in enumerate(raw):
                self.buf[off + i * 32:off + (i + 1) * 32] = e
        return bytes(self.buf)


# ── Sample content generators ────────────────────────────────────────────────

def _photo_jpeg(seed: int, w: int = 800, h: int = 600, text: str = "") -> bytes:
    from PIL import Image, ImageDraw
    rnd = random.Random(seed)
    im = Image.new("RGB", (w, h))
    px = im.load()
    r0, g0, b0 = rnd.randint(40, 200), rnd.randint(40, 200), rnd.randint(40, 200)
    for y in range(h):
        for x in range(0, w, 4):
            v = (x * 3 + y * 2 + rnd.randint(-12, 12)) % 256
            c = ((r0 + v) % 256, (g0 + y // 3) % 256, (b0 + x // 5) % 256)
            for dx in range(4):
                px[x + dx, y] = c
    d = ImageDraw.Draw(im)
    for _ in range(12):
        x, y = rnd.randint(0, w - 80), rnd.randint(0, h - 80)
        d.ellipse([x, y, x + rnd.randint(20, 120), y + rnd.randint(20, 120)],
                  fill=(rnd.randint(0, 255), rnd.randint(0, 255), rnd.randint(0, 255)))
    d.rectangle([0, h - 40, w, h], fill=(20, 20, 20))
    d.text((12, h - 30), text or f"WipeX lab photo #{seed}", fill=(240, 240, 240))
    out = io.BytesIO()
    im.save(out, "JPEG", quality=88)
    return out.getvalue()


def _diagram_png(seed: int, w: int = 900, h: int = 640) -> bytes:
    from PIL import Image, ImageDraw
    rnd = random.Random(seed)
    im = Image.new("RGB", (w, h), (250, 250, 247))
    d = ImageDraw.Draw(im)
    nodes = [(rnd.randint(40, w - 140), rnd.randint(40, h - 80)) for _ in range(14)]
    for (x1, y1), (x2, y2) in zip(nodes, nodes[1:] + nodes[:1]):
        d.line([x1 + 50, y1 + 20, x2 + 50, y2 + 20], fill=(40, 90, 140), width=2)
    for i, (x, y) in enumerate(nodes):
        d.rectangle([x, y, x + 100, y + 40], outline=(20, 60, 100), fill=(220, 235, 245), width=2)
        d.text((x + 8, y + 12), f"10.0.{seed}.{i + 10}", fill=(10, 30, 50))
    # add noise so the file spans several clusters and several IDAT chunks
    px = im.load()
    for _ in range(60000):
        x, y = rnd.randrange(w), rnd.randrange(h)
        px[x, y] = (rnd.randint(200, 255), rnd.randint(200, 255), rnd.randint(200, 255))
    out = io.BytesIO()
    im.save(out, "PNG", compress_level=6)
    return out.getvalue()


def _gif(seed: int) -> bytes:
    from PIL import Image, ImageDraw
    im = Image.new("P", (240, 120), 0)
    d = ImageDraw.Draw(im)
    d.rectangle([10, 10, 230, 110], outline=3, fill=5)
    d.text((30, 50), f"WIPEX LOGO {seed}", fill=1)
    out = io.BytesIO()
    im.save(out, "GIF")
    return out.getvalue()


def _bmp(seed: int) -> bytes:
    from PIL import Image
    rnd = random.Random(seed)
    im = Image.new("RGB", (320, 220))
    px = im.load()
    for y in range(220):
        for x in range(320):
            px[x, y] = ((x + seed) % 256, (y * 2) % 256, rnd.randint(0, 40))
    out = io.BytesIO()
    im.save(out, "BMP")
    return out.getvalue()


def _pdf(title: str, lines: List[str]) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    out = io.BytesIO()
    c = canvas.Canvas(out, pagesize=A4)
    for page in range(2):
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, 780, f"{title} — page {page + 1}")
        c.setFont("Helvetica", 11)
        y = 750
        for line in lines:
            c.drawString(72, y, line)
            y -= 16
        c.showPage()
    c.save()
    return out.getvalue()


def _docx(paragraphs: List[str]) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    files = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>',
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return out.getvalue()


def _zip(seed: int, members: int = 6) -> bytes:
    rnd = random.Random(seed)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        for i in range(members):
            zf.writestr(f"logs/server_{i:02d}.log", "".join(
                f"2026-08-{rnd.randint(1, 28):02d} 10:{rnd.randint(0, 59):02d} host-{rnd.randint(1, 9)} event={rnd.getrandbits(40):x}\n"
                for _ in range(900)))
    return out.getvalue()


def _sqlite(seed: int) -> bytes:
    rnd = random.Random(seed)
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE contacts(id INTEGER PRIMARY KEY, name TEXT, phone TEXT, note TEXT)")
        conn.executemany("INSERT INTO contacts(name, phone, note) VALUES(?,?,?)",
                         [(f"Contact {i}", f"+91-9{rnd.randint(100000000, 999999999)}", "x" * rnd.randint(10, 200))
                          for i in range(400)])
        conn.commit()
        conn.close()
        with open(path, "rb") as f:
            return f.read()
    finally:
        os.remove(path)


# ── Sample image recipe ──────────────────────────────────────────────────────

def build_sample_image(path: str, size_mb: int = 64, seed: int = 2026) -> Dict[str, Any]:
    """Write a FAT16 evidence image and <path>.truth.json describing every planted file."""
    rnd = random.Random(seed)
    img = Fat16Image(size_mb=size_mb)
    base = datetime.datetime(2026, 8, 14, 10, 30, 0)
    truth: List[Dict[str, Any]] = []

    def record(name, fpath, data, state, placement, fragmented=False):
        truth.append({"name": name, "path": fpath, "ext": name.rsplit(".", 1)[-1].lower(), "size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "state": state, "fragmented": fragmented,
                      "offset": placement["runs"][0][0], "runs": placement["runs"]})

    def when(i):
        return base + datetime.timedelta(hours=i * 7, minutes=i * 13)

    notes = ("Case notes — lab image generated by WipeX.\n" * 40).encode()
    record("Case_Notes.txt", "/Case_Notes.txt", notes, "live", img.add_file("/", "Case_Notes.txt", notes, when(0)))

    ev = img.add_dir("/", "Evidence", when(1))
    docs = img.add_dir("/", "Documents", when(1))

    items = [
        (ev, "Site_Photo_01.jpg", _photo_jpeg(seed + 1), "live", None),
        (ev, "Site_Photo_02.jpg", _photo_jpeg(seed + 2), "deleted", None),
        (ev, "Site_Photo_03.jpg", _photo_jpeg(seed + 3), "live", os.urandom(3 * 4096)),
        (ev, "Network_Diagram.png", _diagram_png(seed + 4), "deleted", bytes(rnd.getrandbits(8) for _ in range(5 * 4096)), False),
        (ev, "Scan_0042.bmp", _bmp(seed + 5), "deleted", None),
        (ev, "Logo.gif", _gif(seed + 6), "live", None),
        (docs, "Quarterly_Report.pdf", _pdf("Quarterly Report Q2-2026", [f"Line item {i}: INR {rnd.randint(1000, 99999)}" for i in range(30)]), "deleted", None),
        (docs, "Contract_Draft.docx", _docx([f"Clause {i}. The parties agree to term {rnd.randint(1, 99)}." for i in range(60)]), "deleted", None),
        (docs, "Archive_2025.zip", _zip(seed + 7), "live", None),
        (docs, "Backup_Old.zip", _zip(seed + 8, members=4), "deleted", os.urandom(2 * 4096)),
        (docs, "contacts.db", _sqlite(seed + 9), "deleted", None),
    ]
    items = [it if len(it) == 6 else it + (True,) for it in items]
    for i, (d, name, data, state, gap, gap_alloc) in enumerate(items):
        placement = img.add_file(d, name, data, when(i + 2), fragment_gap=gap, gap_allocated=gap_alloc)
        record(name, f"{d}/{name}", data, state, placement, fragmented=gap is not None)

    for name, data in [("orphan_photo.jpg", _photo_jpeg(seed + 20, 640, 480, "Recovered only by carving")),
                       ("orphan_invoice.pdf", _pdf("Invoice 2026-118", [f"Item {i}" for i in range(20)]))]:
        record(name, None, data, "orphan", img.add_orphan(data))

    for d, name, _data, state, _gap, _ga in items:
        if state == "deleted":
            img.delete(d, name)

    with open(path, "wb") as f:
        f.write(img.build())
    meta = {"kind": "lab-sample", "seed": seed, "sizeMB": size_mb, "clusterSize": img.cluster_size,
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": truth}
    with open(path + ".truth.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return meta


# ── Image registry (lab targets) ─────────────────────────────────────────────

def _meta_path(img_path: str) -> str:
    return img_path + ".meta.json"


def create_image(name: str, kind: str = "sample", size_mb: int = 64) -> Dict[str, Any]:
    """kind: 'sample' (FAT16 with planted files) or 'blank' (zero-filled)."""
    safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_") or f"lab-{secrets.token_hex(2)}"
    path = os.path.join(images_dir(), f"{safe}.img")
    if os.path.exists(path):
        raise FileExistsError(f"Image {safe}.img already exists")
    size_mb = max(16, min(int(size_mb), 1024))
    if kind == "sample":
        build_sample_image(path, size_mb=size_mb)
    else:
        with open(path, "wb") as f:
            f.truncate(size_mb * 1024 * 1024)
    meta = {"serial": f"LAB-{secrets.token_hex(4).upper()}", "kind": kind,
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(_meta_path(path), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    return describe(path)


def reset_image(image_id: str) -> Dict[str, Any]:
    """Rebuild a sample image in place (after it was erased) keeping its serial."""
    path = path_for_id(image_id)
    if not path:
        raise FileNotFoundError(image_id)
    meta = _read_meta(path)
    size_mb = os.path.getsize(path) // (1024 * 1024)
    build_sample_image(path, size_mb=size_mb)
    meta["kind"] = "sample"
    with open(_meta_path(path), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    return describe(path)


def delete_image(image_id: str) -> None:
    path = path_for_id(image_id)
    if not path:
        raise FileNotFoundError(image_id)
    for p in (path, _meta_path(path), path + ".truth.json"):
        if os.path.exists(p):
            os.remove(p)


def _read_meta(path: str) -> Dict[str, Any]:
    try:
        with open(_meta_path(path), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"serial": f"LAB-{hashlib.sha1(path.encode()).hexdigest()[:8].upper()}", "kind": "unknown"}


def truth_for(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path + ".truth.json", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def image_id(path: str) -> str:
    return "img-" + os.path.splitext(os.path.basename(path))[0]


def path_for_id(img_id: str) -> Optional[str]:
    if not img_id.startswith("img-"):
        return None
    path = os.path.join(images_dir(), img_id[4:] + ".img")
    return path if os.path.exists(path) else None


def _fs_listing(path: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Live and deleted files seen by The Sleuth Kit (used for the Drive Eraser file view)."""
    try:
        from recovery import fs_recovery
        res = fs_recovery.scan(path, out_dir=None, extract_deleted=False, max_entries=2000, hash_live=False)
    except Exception:  # noqa: BLE001
        return [], []
    live, deleted = [], []
    for e in res.get("entries", []):
        if e["isDir"]:
            continue
        item = {"name": e["path"].lstrip("/"), "size": _human(e["size"]), "bytes": e["size"]}
        if e["deleted"]:
            deleted.append({**item, "recoverability": "High" if e.get("metaAllocated") is False else "Medium"})
        else:
            live.append(item)
    return live, deleted


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n} B"


def describe(path: str, with_files: bool = True) -> Dict[str, Any]:
    meta = _read_meta(path)
    size = os.path.getsize(path)
    live, deleted = _fs_listing(path) if with_files else ([], [])
    name = os.path.splitext(os.path.basename(path))[0]
    return {
        "id": image_id(path),
        "devicePath": path,
        "model": f"Lab disk image · {name}",
        "type": "Disk image",
        "interface": "File-backed (FAT16)" if meta.get("kind") == "sample" else "File-backed",
        "capacity": _human(size),
        "capacityBytes": size,
        "serialNumber": meta["serial"],
        "maskedSerial": meta["serial"],
        "firmware": "—",
        "healthStatus": "HEALTHY",
        "healthScore": 100,
        "reallocatedSectors": 0,
        "powerOnHours": "Lab image",
        "temperature": "—",
        "isBootDrive": False,
        "isImage": True,
        "imageKind": meta.get("kind"),
        "hasTruth": os.path.exists(path + ".truth.json"),
        "expectedOutcome": "GREEN",
        "isAlreadyClean": not live and not deleted,
        "currentFiles": live,
        "deletedRecoverableFiles": deleted,
        "capacityUsedBytes": sum(f.get("bytes", 0) for f in live),
        "mountedPaths": [],
    }


def list_images(with_files: bool = True) -> List[Dict[str, Any]]:
    d = images_dir()
    out = []
    for fname in sorted(os.listdir(d)):
        if fname.endswith(".img"):
            try:
                out.append(describe(os.path.join(d, fname), with_files))
            except OSError:
                continue
    return out


def ensure_default_images() -> None:
    """First run: provide one evidence image for recovery and one disk for erasure demos."""
    d = images_dir()
    if not any(f.endswith(".img") for f in os.listdir(d)):
        create_image("evidence-sample", "sample")
        create_image("lab-disk-01", "sample")
