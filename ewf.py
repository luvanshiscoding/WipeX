"""
WipeX - Expert Witness Format (EWF / E01) images, pure Python (zlib only).

Reader: EnCase-style E01 segment sets (.E01, .E02, ...): header/volume/disk/data,
sectors, table/table2, hash, digest, next/done sections. Compressed chunks are zlib
streams; uncompressed chunks carry an Adler-32 checksum, which is checked.
Writer: E01 with zlib-compressed 32 KiB chunks, case metadata in the header section,
MD5 (hash section) and MD5 + SHA-1 (digest section), split into segment files.

Works on every OS without native libraries. Tests cross-check the output against
libewf (pyewf) when it is installed. EWF2 (.Ex01) is not supported.
"""

import glob
import hashlib
import os
import re
import struct
import time
import uuid
import zlib
from typing import Any, Dict, List, Optional, Tuple

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
DESCRIPTOR = 76
MAX_TABLE_ENTRIES = 16375
DEFAULT_SEGMENT = 1500 * 1024 * 1024


def _adler(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def is_ewf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) == SIGNATURE
    except OSError:
        return False


def segment_name(base: str, number: int) -> str:
    """base.E01 ... base.E99, then base.EAA ... base.EZZ, base.FAA ..."""
    if number < 100:
        return f"{base}.E{number:02d}"
    n = number - 100
    first = chr(ord("E") + n // 676)
    return f"{base}.{first}{chr(ord('A') + n // 26 % 26)}{chr(ord('A') + n % 26)}"


def _segment_paths(first: str) -> List[str]:
    base, _ext = os.path.splitext(first)
    paths = []
    number = 1
    while True:
        p = segment_name(base, number)
        if not os.path.exists(p):
            alt = [c for c in glob.glob(glob.escape(base) + ".*") if os.path.normcase(c) == os.path.normcase(p)]
            if not alt:
                break
            p = alt[0]
        paths.append(p)
        number += 1
    return paths or [first]


# ── Reader ───────────────────────────────────────────────────────────────────

class EwfReader:
    """Random-access reader over the media data stored in an E01 segment set."""

    def __init__(self, path: str, cache_chunks: int = 64):
        self.path = path
        self.segments = _segment_paths(path)
        self.files = [open(p, "rb") for p in self.segments]
        self.chunks: List[Tuple[int, int, int, bool]] = []     # (segment index, offset, stored size, compressed)
        self.bytes_per_sector = 512
        self.sectors_per_chunk = 64
        self.sector_count = 0
        self.stored_md5: Optional[str] = None
        self.stored_sha1: Optional[str] = None
        self.header: Dict[str, str] = {}
        self._cache: Dict[int, bytes] = {}
        self._cache_max = cache_chunks
        try:
            for idx, f in enumerate(self.files):
                self._parse_segment(idx, f)
        except Exception:
            self.close()
            raise
        self.chunk_size = self.bytes_per_sector * self.sectors_per_chunk
        self.size = self.sector_count * self.bytes_per_sector
        if not self.chunks or not self.size:
            self.close()
            raise ValueError("No media data found in EWF image")

    def _parse_segment(self, idx: int, f) -> None:
        head = f.read(13)
        if head[:8] != SIGNATURE:
            raise ValueError(f"{self.segments[idx]} is not an EWF segment")
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        offset = 13
        sectors_ranges: List[Tuple[int, int]] = []
        while offset + DESCRIPTOR <= file_size:
            f.seek(offset)
            desc = f.read(DESCRIPTOR)
            stype = desc[:16].rstrip(b"\x00").decode("ascii", "replace")
            nxt, size = struct.unpack_from("<QQ", desc, 16)
            if struct.unpack_from("<I", desc, 72)[0] != _adler(desc[:72]):
                raise ValueError(f"Section descriptor checksum mismatch at offset {offset} ({stype})")
            body_len = max(0, size - DESCRIPTOR) if size else 0
            if stype in ("header", "header2") and not self.header:
                self._parse_header(f.read(body_len), stype)
            elif stype in ("volume", "disk", "data"):
                self._parse_volume(f.read(min(body_len, 1052)))
            elif stype == "sectors":
                sectors_ranges.append((offset + DESCRIPTOR, offset + size))
            elif stype == "table":
                self._parse_table(idx, f, offset + DESCRIPTOR, offset + size, sectors_ranges)
            elif stype == "hash":
                self.stored_md5 = f.read(16).hex()
            elif stype == "digest":
                d = f.read(36)
                self.stored_md5 = d[:16].hex() if d[:16].strip(b"\x00") else self.stored_md5
                self.stored_sha1 = d[16:36].hex() if d[16:36].strip(b"\x00") else None
            if stype in ("done", "next") or nxt == offset or nxt <= offset:
                break
            offset = nxt

    def _parse_header(self, blob: bytes, stype: str) -> None:
        try:
            text = zlib.decompress(blob)
            text = text.decode("utf-16") if stype == "header2" else text.decode("latin-1")
        except (zlib.error, UnicodeDecodeError):
            return
        lines = [ln.rstrip("\r") for ln in text.split("\n")]
        for i, ln in enumerate(lines):
            if ln == "main" and i + 2 < len(lines):
                keys, vals = lines[i + 1].split("\t"), lines[i + 2].split("\t")
                self.header = {k: v for k, v in zip(keys, vals)}
                return

    def _parse_volume(self, data: bytes) -> None:
        if len(data) >= 24:
            chunks, spc, bps = struct.unpack_from("<III", data, 4)
            count = struct.unpack_from("<Q", data, 16)[0] if len(data) >= 1052 else struct.unpack_from("<I", data, 16)[0]
            if spc and bps:
                self.sectors_per_chunk, self.bytes_per_sector, self.sector_count = spc, bps, count

    def _parse_table(self, idx: int, f, start: int, end: int, sectors_ranges: List[Tuple[int, int]]) -> None:
        f.seek(start)
        hdr = f.read(24)
        count = struct.unpack_from("<I", hdr, 0)[0]
        base = struct.unpack_from("<Q", hdr, 8)[0]
        raw = f.read(4 * count)
        entries = struct.unpack(f"<{count}I", raw[:4 * count])
        offsets = [(base + (e & 0x7FFFFFFF), bool(e & 0x80000000)) for e in entries]
        for j, (off, comp) in enumerate(offsets):
            if j + 1 < len(offsets):
                stored = offsets[j + 1][0] - off
            else:
                limit = next((b for a, b in sectors_ranges if a <= off < b), start - DESCRIPTOR)
                stored = limit - off
            self.chunks.append((idx, off, stored, comp))

    def _chunk(self, n: int) -> bytes:
        got = self._cache.get(n)
        if got is not None:
            return got
        seg, off, stored, comp = self.chunks[n]
        f = self.files[seg]
        f.seek(off)
        blob = f.read(stored)
        if comp:
            data = zlib.decompressobj().decompress(blob)
        else:
            data = blob[:self.chunk_size] if len(blob) >= self.chunk_size + 4 else blob[:-4]
            check = blob[len(data):len(data) + 4]
            if len(check) == 4 and struct.unpack("<I", check)[0] != _adler(data):
                raise IOError(f"Chunk {n} checksum mismatch (image is damaged)")
        if len(self._cache) >= self._cache_max:
            self._cache.pop(next(iter(self._cache)))
        self._cache[n] = data
        return data

    def read(self, offset: int, length: int) -> bytes:
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        while length > 0:
            n, within = divmod(offset, self.chunk_size)
            if n >= len(self.chunks):
                break
            piece = self._chunk(n)[within:within + length]
            if not piece:
                break
            out += piece
            offset += len(piece)
            length -= len(piece)
        return bytes(out)

    def hashes(self, progress=None) -> Dict[str, str]:
        sha256, md5, sha1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
        pos = 0
        step = self.chunk_size * 128
        while pos < self.size:
            block = self.read(pos, step)
            if not block:
                break
            sha256.update(block)
            md5.update(block)
            sha1.update(block)
            pos += len(block)
            if progress:
                progress(int(pos * 100 / self.size), f"Hashed {pos // (1024 * 1024)} MB")
        return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "sha1": sha1.hexdigest()}

    def info(self) -> Dict[str, Any]:
        return {"format": "EWF (E01)", "segments": [os.path.basename(p) for p in self.segments],
                "mediaSize": self.size, "bytesPerSector": self.bytes_per_sector,
                "sectorsPerChunk": self.sectors_per_chunk, "chunks": len(self.chunks),
                "storedMd5": self.stored_md5, "storedSha1": self.stored_sha1, "header": self.header}

    def close(self) -> None:
        for f in self.files:
            try:
                f.close()
            except OSError:
                pass


# ── Writer ───────────────────────────────────────────────────────────────────

def _descriptor(stype: str, offset: int, size: int, nxt: Optional[int] = None) -> bytes:
    body = stype.encode("ascii").ljust(16, b"\x00") + struct.pack("<QQ", offset + size if nxt is None else nxt, size) + b"\x00" * 40
    return body + struct.pack("<I", _adler(body))


class EwfWriter:
    """
    Stream media data into an E01 segment set.
        w = EwfWriter(base_path_without_ext, media_size, {"case_number": ..., "examiner_name": ...})
        w.write(data) ...; info = w.close()
    """

    def __init__(self, base: str, media_size: int, meta: Optional[Dict[str, str]] = None,
                 sectors_per_chunk: int = 64, bytes_per_sector: int = 512,
                 segment_size: int = DEFAULT_SEGMENT, level: int = 6):
        if media_size <= 0:
            raise ValueError("Media size must be positive")
        self.base = base
        self.bps = bytes_per_sector
        self.spc = sectors_per_chunk
        self.chunk_size = sectors_per_chunk * bytes_per_sector
        self.sector_count = -(-media_size // bytes_per_sector)
        self.media_size = self.sector_count * bytes_per_sector      # padded to whole sectors
        self.total_chunks = -(-self.media_size // self.chunk_size)
        self.segment_size = max(segment_size, 4 * 1024 * 1024)
        self.level = level
        self.meta = meta or {}
        self.guid = uuid.uuid4().bytes
        self.md5, self.sha1 = hashlib.md5(), hashlib.sha1()
        self.pending = bytearray()
        self.written = 0
        self.paths: List[str] = []
        self.f = None
        self.segment_no = 0
        self.table: List[int] = []
        self.sectors_start = 0
        self._open_segment()

    # sections -----------------------------------------------------------------
    def _write_section(self, stype: str, body: bytes) -> None:
        off = self.f.tell()
        self.f.write(_descriptor(stype, off, DESCRIPTOR + len(body)))
        self.f.write(body)

    def _header_text(self) -> bytes:
        t = time.localtime()
        stamp = f"{t.tm_year} {t.tm_mon} {t.tm_mday} {t.tm_hour} {t.tm_min} {t.tm_sec}"
        m = self.meta
        keys = ["c", "n", "a", "e", "t", "av", "ov", "m", "u", "p", "r"]
        vals = [m.get("case_number", ""), m.get("evidence_number", ""), m.get("description", ""),
                m.get("examiner_name", ""), m.get("notes", ""), "WipeX", m.get("os", ""), stamp, stamp, "0", "f"]
        vals = [re.sub(r"[\t\r\n]", " ", str(v)) for v in vals]
        return ("1\nmain\n" + "\t".join(keys) + "\n" + "\t".join(vals) + "\n\n").encode("latin-1", "replace")

    def _volume_body(self) -> bytes:
        body = bytearray(1052)
        struct.pack_into("<B", body, 0, 0x01)                        # fixed disk
        struct.pack_into("<III", body, 4, self.total_chunks, self.spc, self.bps)
        struct.pack_into("<Q", body, 16, self.sector_count)
        body[36] = 0x01                                              # image file
        body[52] = 1                                                 # compression: fast
        struct.pack_into("<I", body, 56, self.spc)                   # error granularity
        body[64:80] = self.guid
        struct.pack_into("<I", body, 1048, _adler(bytes(body[:1048])))
        return bytes(body)

    def _open_segment(self) -> None:
        self.segment_no += 1
        path = segment_name(self.base, self.segment_no)
        self.paths.append(path)
        self.f = open(path, "wb")
        self.f.write(SIGNATURE + b"\x01" + struct.pack("<H", self.segment_no) + b"\x00\x00")
        if self.segment_no == 1:
            self._write_section("header", zlib.compress(self._header_text(), 9))
            self._write_section("volume", self._volume_body())
        else:
            self._write_section("data", self._volume_body())
        self._begin_sectors()

    def _begin_sectors(self) -> None:
        self.sectors_start = self.f.tell()
        self.f.write(b"\x00" * DESCRIPTOR)                           # patched in _end_sectors
        self.table = []

    def _end_sectors(self) -> None:
        end = self.f.tell()
        self.f.seek(self.sectors_start)
        self.f.write(_descriptor("sectors", self.sectors_start, end - self.sectors_start))
        self.f.seek(end)
        if not self.table:
            return
        entries = struct.pack(f"<{len(self.table)}I", *self.table)
        head = struct.pack("<IIQI", len(self.table), 0, 0, 0)
        body = head + struct.pack("<I", _adler(head)) + entries + struct.pack("<I", _adler(entries))
        self._write_section("table", body)
        self._write_section("table2", body)

    # data -----------------------------------------------------------------------
    def _emit_chunk(self, chunk: bytes) -> None:
        comp = zlib.compress(chunk, self.level)
        if len(comp) < len(chunk):
            stored, flag = comp, 0x80000000
        else:
            stored, flag = chunk + struct.pack("<I", _adler(chunk)), 0
        if self.f.tell() + len(stored) > self.segment_size or self.f.tell() + len(stored) >= 0x7FFFFFFF \
                or len(self.table) >= MAX_TABLE_ENTRIES:
            self._end_sectors()
            if self.f.tell() + len(stored) + 4096 > self.segment_size or self.f.tell() >= 0x7FFFFFFF - self.chunk_size * 2:
                off = self.f.tell()
                self.f.write(_descriptor("next", off, DESCRIPTOR, nxt=off))
                self.f.close()
                self._open_segment()
            else:
                self._begin_sectors()
        self.table.append(self.f.tell() | flag)
        self.f.write(stored)

    def write(self, data: bytes) -> None:
        if self.written + len(data) > self.media_size:
            raise ValueError("More data than the declared media size")
        self.md5.update(data)
        self.sha1.update(data)
        self.written += len(data)
        self.pending += data
        while len(self.pending) >= self.chunk_size:
            self._emit_chunk(bytes(self.pending[:self.chunk_size]))
            del self.pending[:self.chunk_size]

    def close(self) -> Dict[str, Any]:
        if self.written < self.media_size:                           # pad the final partial sector
            self.write(b"\x00" * (self.media_size - self.written))
        if self.pending:
            self._emit_chunk(bytes(self.pending))
            self.pending = bytearray()
        self._end_sectors()
        md5, sha1 = self.md5.digest(), self.sha1.digest()
        h = md5 + b"\x00" * 16
        self._write_section("hash", h + struct.pack("<I", _adler(h)))
        d = md5 + sha1 + b"\x00" * 40
        self._write_section("digest", d + struct.pack("<I", _adler(d)))
        off = self.f.tell()
        self.f.write(_descriptor("done", off, DESCRIPTOR, nxt=off))
        self.f.close()
        return {"segments": self.paths, "md5": md5.hex(), "sha1": sha1.hex(), "mediaSize": self.media_size,
                "chunks": self.total_chunks}


# ── Uniform access to raw and E01 images ─────────────────────────────────────

def _windows_device_size(path: str) -> int:
    """Size of a Windows disk or volume (\\\\.\\PhysicalDriveN, \\\\.\\E:) via IOCTL_DISK_GET_LENGTH_INFO."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    handle = k32.CreateFileW(path, 0x80000000, 0x1 | 0x2, None, 3, 0, None)   # GENERIC_READ, share r/w
    if handle in (None, wintypes.HANDLE(-1).value):
        raise PermissionError(f"Cannot open {path}: run WipeX as Administrator")
    try:
        length = ctypes.c_longlong(0)
        returned = wintypes.DWORD(0)
        if not k32.DeviceIoControl(handle, 0x0007405C, None, 0, ctypes.byref(length), 8, ctypes.byref(returned), None):
            raise OSError(f"Cannot read the size of {path} (error {ctypes.GetLastError()})")
        return int(length.value)
    finally:
        k32.CloseHandle(handle)


class RawImage:
    def __init__(self, path: str):
        self.path = path
        self.is_device = path.startswith("\\\\.\\") or path.startswith("/dev/")
        self.align = 4096 if self.is_device else 512      # devices need sector-aligned reads (4K covers 512e/4Kn)
        self.f = open(path, "rb", buffering=0)
        if self.is_device and os.name == "nt":
            self.size = _windows_device_size(path)
        else:
            self.size = self.f.seek(0, os.SEEK_END)

    def read(self, offset: int, length: int) -> bytes:
        if offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        start = offset - (offset % self.align)
        end = min(self.size, offset + length + (-(offset + length) % self.align))
        self.f.seek(start)
        buf = self.f.read(end - start)
        return buf[offset - start:offset - start + length]

    def close(self) -> None:
        self.f.close()


def open_image(path: str):
    """Reader with .read(offset, length), .size and .close() for a raw image, device or E01."""
    return EwfReader(path) if is_ewf(path) else RawImage(path)
