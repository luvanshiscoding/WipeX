"""
WipeX recovery - file format signatures and structural parsers.

Each parser receives a byte window that starts at a candidate header and returns a
ParseResult with the exact end offset (relative to the window) and whether the file's
internal structure validated. Validation is format-specific and strict where the
format allows it (PNG chunk CRCs, ZIP member CRCs), so a "valid" result means the
bytes form a structurally complete file, not merely that a header was seen.
"""

import io
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

try:
    from PIL import Image, ImageFile
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    HAS_PIL = True
except ImportError:  # pragma: no cover
    HAS_PIL = False


@dataclass
class ParseResult:
    end: int                      # bytes from window start to end of file
    valid: bool                   # structure fully validated
    reason: str = ""              # why validation failed / partial
    info: Dict[str, object] = field(default_factory=dict)
    break_at: Optional[int] = None  # first offset where structure broke (for gap carving)
    ext: Optional[str] = None     # refined extension (e.g. docx inside zip)


# ── PNG ──────────────────────────────────────────────────────────────────────
PNG_SIG = b"\x89PNG\r\n\x1a\n"


def parse_png(data: bytes) -> Optional[ParseResult]:
    if not data.startswith(PNG_SIG):
        return None
    pos = 8
    info: Dict[str, object] = {}
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        if length > 0x7FFFFFFF or not re.fullmatch(rb"[A-Za-z]{4}", ctype):
            return ParseResult(pos, False, "invalid chunk header", info, break_at=pos)
        chunk_end = pos + 12 + length
        if chunk_end > len(data):
            return ParseResult(len(data), False, "truncated", info, break_at=pos)
        crc = struct.unpack(">I", data[chunk_end - 4:chunk_end])[0]
        if zlib.crc32(data[pos + 4:pos + 8 + length]) & 0xFFFFFFFF != crc:
            return ParseResult(pos, False, f"CRC mismatch in {ctype.decode()} chunk", info, break_at=pos)
        if ctype == b"IHDR" and length >= 8:
            info["width"], info["height"] = struct.unpack(">II", data[pos + 8:pos + 16])
        pos = chunk_end
        if ctype == b"IEND":
            return ParseResult(pos, True, "", info)
    return ParseResult(len(data), False, "no IEND chunk", info, break_at=pos)


# ── JPEG ─────────────────────────────────────────────────────────────────────

def parse_jpeg(data: bytes) -> Optional[ParseResult]:
    if not data.startswith(b"\xff\xd8\xff"):
        return None
    pos, n = 2, len(data)
    seen_sos = False
    info: Dict[str, object] = {}
    while pos + 2 <= n:
        if data[pos] != 0xFF:
            return ParseResult(pos, False, "marker expected", info, break_at=pos)
        marker = data[pos + 1]
        if marker == 0xFF:                      # fill byte
            pos += 1
            continue
        if marker == 0xD8 or marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xD9:                      # EOI
            end = pos + 2
            if not seen_sos:
                return ParseResult(end, False, "no image data (SOS)", info)
            return _validate_image(data[:end], ParseResult(end, True, "", info))
        if pos + 4 > n:
            break
        seglen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if seglen < 2:
            return ParseResult(pos, False, "bad segment length", info, break_at=pos)
        if marker in (0xC0, 0xC1, 0xC2) and pos + 9 <= n:
            info["height"], info["width"] = struct.unpack(">HH", data[pos + 5:pos + 9])
        if marker == 0xDA:                      # SOS: skip entropy-coded data
            seen_sos = True
            pos += 2 + seglen
            while True:
                idx = data.find(b"\xff", pos)
                if idx < 0 or idx + 1 >= n:
                    return ParseResult(n, False, "truncated in scan data", info, break_at=n)
                nxt = data[idx + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    pos = idx + 1 if nxt == 0xFF else idx + 2
                    continue
                pos = idx
                break
            continue
        pos += 2 + seglen
    return ParseResult(n, False, "no EOI marker", info, break_at=pos)


def _validate_image(blob: bytes, result: ParseResult) -> ParseResult:
    """Fully decode with Pillow; a decode error means the structure lied."""
    if not HAS_PIL:
        result.info["decoded"] = False
        return result
    try:
        with Image.open(io.BytesIO(blob)) as im:
            im.load()
            result.info.setdefault("width", im.width)
            result.info.setdefault("height", im.height)
            result.info["decoded"] = True
    except Exception as exc:  # noqa: BLE001
        result.valid = False
        result.reason = f"decode failed: {exc}"
    return result


# ── GIF ──────────────────────────────────────────────────────────────────────

def parse_gif(data: bytes) -> Optional[ParseResult]:
    if data[:6] not in (b"GIF87a", b"GIF89a") or len(data) < 13:
        return None
    width, height, flags = struct.unpack("<HHB", data[6:11])
    pos = 13
    if flags & 0x80:
        pos += 3 * (2 ** ((flags & 0x07) + 1))

    def skip_subblocks(p: int) -> int:
        while p < len(data):
            size = data[p]
            p += 1
            if size == 0:
                return p
            p += size
        return -1

    frames = 0
    while pos < len(data):
        b = data[pos]
        if b == 0x3B:
            return _validate_image(data[:pos + 1], ParseResult(pos + 1, True, "", {"width": width, "height": height, "frames": frames}))
        if b == 0x21:
            pos = skip_subblocks(pos + 2)
        elif b == 0x2C:
            if pos + 10 > len(data):
                break
            lflags = data[pos + 9]
            pos += 10
            if lflags & 0x80:
                pos += 3 * (2 ** ((lflags & 0x07) + 1))
            pos = skip_subblocks(pos + 1)
            frames += 1
        else:
            return ParseResult(pos, False, "unknown block", {}, break_at=pos)
        if pos < 0:
            break
    return ParseResult(len(data), False, "no trailer", {}, break_at=len(data))


# ── BMP ──────────────────────────────────────────────────────────────────────

def parse_bmp(data: bytes) -> Optional[ParseResult]:
    if len(data) < 30 or data[:2] != b"BM":
        return None
    size, _res, pix_off, dib = struct.unpack("<IIII", data[2:18])
    if dib not in (12, 40, 52, 56, 108, 124) or not (26 <= pix_off < size) or size > 512 * 1024 * 1024:
        return None
    if dib == 12:
        w, h = struct.unpack("<HH", data[18:22])
    else:
        w, h = struct.unpack("<ii", data[18:26])
    if not (0 < w < 40000 and 0 < abs(h) < 40000):
        return None
    if size > len(data):
        return ParseResult(len(data), False, "truncated", {"width": w, "height": abs(h)})
    return _validate_image(data[:size], ParseResult(size, True, "", {"width": w, "height": abs(h)}))


# ── PDF ──────────────────────────────────────────────────────────────────────
_OBJ_RE = re.compile(rb"\s*(\d+\s+\d+\s+obj|xref|%PDF)")


def parse_pdf(data: bytes) -> Optional[ParseResult]:
    if not re.match(rb"%PDF-[12]\.\d", data[:8]):
        return None
    best: Optional[ParseResult] = None
    for m in re.finditer(rb"%%EOF", data):
        end = m.end()
        while end < len(data) and data[end:end + 1] in (b"\r", b"\n"):
            end += 1
        tail = data[max(0, m.start() - 1024):m.start()]
        sx = re.search(rb"startxref\s+(\d+)", tail)
        ok = False
        if sx:
            xref_at = int(sx.group(1))
            if xref_at < m.start():
                head = data[xref_at:xref_at + 32]
                ok = head.startswith(b"xref") or bool(re.match(rb"\d+\s+\d+\s+obj", head))
        pages = len(re.findall(rb"/Type\s*/Page[^s]", data[:end]))
        best = ParseResult(end, ok, "" if ok else "startxref does not point to a cross-reference", {"pages": pages})
        # An incremental update follows if the next bytes start another object or xref section
        nxt = _OBJ_RE.match(data, end)
        if not nxt or nxt.group(1).startswith(b"%PDF"):
            break
    if best is None:
        return ParseResult(len(data), False, "no %%EOF", {}, break_at=len(data))
    return best


# ── ZIP / OOXML / ODF ────────────────────────────────────────────────────────

def _zip_kind(names: List[str]) -> str:
    s = set(names)
    if "word/document.xml" in s:
        return "docx"
    if "xl/workbook.xml" in s:
        return "xlsx"
    if "ppt/presentation.xml" in s:
        return "pptx"
    if "mimetype" in s and "content.xml" in s:
        return "odt"
    if "AndroidManifest.xml" in s:
        return "apk"
    if "META-INF/MANIFEST.MF" in s:
        return "jar"
    return "zip"


def _test_zip(blob: bytes) -> Optional[List[str]]:
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            if zf.testzip() is not None:
                return None
            return zf.namelist()
    except Exception:  # noqa: BLE001
        return None


def parse_zip(data: bytes) -> Optional[ParseResult]:
    if not data.startswith(b"PK\x03\x04"):
        return None
    for m in re.finditer(rb"PK\x05\x06", data):
        e = m.start()
        if e + 22 > len(data):
            break
        _disk, _cd_disk, _n_disk, n_total, cd_size, cd_off, clen = struct.unpack("<HHHHIIH", data[e + 4:e + 22])
        end = e + 22 + clen
        actual_cd = e - cd_size
        if actual_cd < 0 or data[actual_cd:actual_cd + 4] != b"PK\x01\x02" and n_total > 0:
            continue
        info = {"entries": n_total}
        if actual_cd == cd_off:
            names = _test_zip(data[:end])
            if names is not None:
                kind = _zip_kind(names)
                return ParseResult(end, True, "", {**info, "kind": kind}, ext=kind)
            return ParseResult(end, False, "member CRC check failed", info, ext="zip")
        # Central directory is further away than it claims: the archive is fragmented
        # (or has a prefix). Report the gap so the carver can attempt reassembly.
        return ParseResult(end, False, "fragmented: central directory offset mismatch",
                           {**info, "gap": actual_cd - cd_off, "cd_offset": cd_off}, ext="zip")
    return ParseResult(len(data), False, "no end-of-central-directory record", {}, break_at=len(data))


# ── SQLite ───────────────────────────────────────────────────────────────────

def parse_sqlite(data: bytes) -> Optional[ParseResult]:
    if not data.startswith(b"SQLite format 3\x00") or len(data) < 100:
        return None
    page_size = struct.unpack(">H", data[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size & (page_size - 1):
        return None
    change_ctr, page_count = struct.unpack(">II", data[24:32])
    version_valid = struct.unpack(">I", data[92:96])[0]
    if page_count == 0 or version_valid != change_ctr:
        return ParseResult(len(data), False, "header page count not trustworthy", {"pageSize": page_size})
    size = page_size * page_count
    if size > len(data):
        return ParseResult(len(data), False, "truncated", {"pageSize": page_size, "pages": page_count})
    return ParseResult(size, True, "", {"pageSize": page_size, "pages": page_count})


# ── MP4 / MOV (ISO base media) ───────────────────────────────────────────────
_ISO_BOXES = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"pdin",
              b"moof", b"mfra", b"meta", b"styp", b"sidx", b"pnot"}


def parse_mp4(data: bytes) -> Optional[ParseResult]:
    if len(data) < 12 or data[4:8] != b"ftyp":
        return None
    pos, seen = 0, set()
    brand = data[8:12].decode("latin-1", "replace")
    while pos + 8 <= len(data):
        size = struct.unpack(">I", data[pos:pos + 4])[0]
        btype = data[pos + 4:pos + 8]
        if btype not in _ISO_BOXES:
            break
        if size == 1 and pos + 16 <= len(data):
            size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]
        if size < 8:
            break
        seen.add(btype)
        if pos + size > len(data):
            return ParseResult(len(data), False, "truncated", {"brand": brand}, break_at=pos)
        pos += size
    ok = b"moov" in seen and (b"mdat" in seen or b"moof" in seen)
    return ParseResult(pos, ok, "" if ok else "missing moov/mdat box", {"brand": brand})


# ── Registry ─────────────────────────────────────────────────────────────────

@dataclass
class Format:
    name: str
    ext: str
    header: bytes          # regex (bytes) matched at the file start
    parser: Callable[[bytes], Optional[ParseResult]]
    max_size: int
    header_offset: int = 0  # header found this many bytes into the file (MP4 'ftyp')


MB = 1024 * 1024
FORMATS: List[Format] = [
    Format("JPEG image", "jpg", rb"\xff\xd8\xff[\xc0-\xfe]", parse_jpeg, 32 * MB),
    Format("PNG image", "png", re.escape(PNG_SIG), parse_png, 64 * MB),
    Format("GIF image", "gif", rb"GIF8[79]a", parse_gif, 32 * MB),
    Format("BMP image", "bmp", rb"BM....\x00\x00\x00\x00", parse_bmp, 64 * MB),
    Format("PDF document", "pdf", rb"%PDF-[12]\.\d", parse_pdf, 128 * MB),
    Format("ZIP / Office document", "zip", rb"PK\x03\x04", parse_zip, 256 * MB),
    Format("SQLite database", "sqlite", rb"SQLite format 3\x00", parse_sqlite, 256 * MB),
    Format("MP4 / MOV video", "mp4", rb"ftyp(?:isom|iso2|mp4[12]|avc1|M4V |M4A |qt  |3gp[4-6])", parse_mp4, 512 * MB, header_offset=4),
]

FORMAT_BY_EXT: Dict[str, Format] = {f.ext: f for f in FORMATS}

EXT_TO_FORMAT = {"jpg": "jpg", "jpeg": "jpg", "png": "png", "gif": "gif", "bmp": "bmp", "pdf": "pdf",
                 "zip": "zip", "docx": "zip", "xlsx": "zip", "pptx": "zip", "odt": "zip", "apk": "zip",
                 "jar": "zip", "db": "sqlite", "sqlite": "sqlite", "mp4": "mp4", "mov": "mp4", "m4v": "mp4"}


def validate_bytes(blob: bytes, filename: str = "") -> Optional[ParseResult]:
    """Validate a complete file (e.g. one recovered from a file system) by its structure."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    candidates = [FORMAT_BY_EXT[EXT_TO_FORMAT[ext]]] if ext in EXT_TO_FORMAT else FORMATS
    for fmt in candidates:
        if not re.match(fmt.header, blob[fmt.header_offset:fmt.header_offset + 32], re.S):
            continue
        result = fmt.parser(blob)
        if result is not None:
            result.ext = result.ext or fmt.ext
            return result
    return None
