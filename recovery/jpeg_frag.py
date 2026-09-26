"""
WipeX recovery - JPEG fragment reassembly (bifragment gap carving for JPEG).

JPEG files carry no checksums, but the entropy-coded data of a baseline JPEG can be
checked without rebuilding a single pixel: every Huffman code must exist in the file's
own tables, every 8x8 block must end within 64 coefficients, restart markers must
arrive in order, and the scan must reach EOI exactly after the number of MCUs the frame
header announces. Bytes from another file break these rules within a few hundred bytes.
That locates the fragmentation point; the continuation is the cluster-aligned position
after it whose bytes decode cleanly all the way to the announced end of the image.
"""

import bisect
import functools
import struct
import time
from typing import List, Optional, Tuple

DONE, STOP, NEED_DATA, INVALID = "done", "stop", "need-data", "invalid"
_SIGNATURES = (b"\xff\xd8\xff", b"\x89PNG", b"PK\x03\x04", b"%PDF", b"GIF8", b"SQLite format 3")


class Spec:
    """What the entropy decoder needs from the headers of a baseline JPEG."""
    __slots__ = ("width", "height", "mcus", "blocks", "restart", "dcmax", "acmax", "scan_start")


def _ceil(a: int, b: int) -> int:
    return -(-a // b)


@functools.lru_cache(maxsize=64)                         # cameras reuse the same tables in every photo
def _lookup_table(counts: bytes, symbols: bytes) -> Optional[List[int]]:
    """16-bit look-ahead table: entry = symbol << 5 | code length; 0 marks a code the table does not define."""
    table = [0] * 65536
    code = k = 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            span = 1 << (16 - length)
            first = code * span
            if k >= len(symbols) or first + span > 65536:
                return None
            table[first:first + span] = [symbols[k] << 5 | length] * span
            code += 1
            k += 1
        code <<= 1
    return table


def parse_spec(data: bytes) -> Tuple[Optional[Spec], str]:
    """Read the tables and frame layout up to the start of the scan data."""
    if not data.startswith(b"\xff\xd8"):
        return None, "not a JPEG"
    dc, ac, frame, restart = {}, {}, None, 0
    pos, n = 2, len(data)
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            return None, "marker expected"
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        seglen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg = data[pos + 4:pos + 2 + seglen]
        if seglen < 2 or len(seg) < seglen - 2:
            return None, "truncated header"
        if marker == 0xC4:                                   # DHT
            p = 0
            while p + 17 <= len(seg):
                cls, ident = seg[p] >> 4, seg[p] & 15
                total = sum(seg[p + 1:p + 17])
                table = _lookup_table(seg[p + 1:p + 17], seg[p + 17:p + 17 + total])
                if table is None or cls > 1:
                    return None, "invalid Huffman table"
                (dc if cls == 0 else ac)[ident] = table
                p += 17 + total
        elif marker in (0xC0, 0xC1):                         # baseline / extended sequential, Huffman
            if len(seg) < 6 or len(seg) < 6 + 3 * seg[5]:
                return None, "truncated frame header"
            height, width = struct.unpack(">HH", seg[1:5])
            comps = {seg[6 + 3 * i]: (seg[7 + 3 * i] >> 4, seg[7 + 3 * i] & 15) for i in range(seg[5])}
            frame = (seg[0], width, height, comps)
        elif 0xC2 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            return None, "progressive, lossless or arithmetic-coded JPEG"
        elif marker == 0xDD and len(seg) >= 2:               # DRI
            restart = struct.unpack(">H", seg[:2])[0]
        elif marker == 0xDA:                                 # SOS
            if frame is None:
                return None, "scan before frame header"
            precision, width, height, comps = frame
            ns = seg[0] if seg else 0
            if not width or not height or not comps or ns != len(comps) or len(seg) < 1 + 2 * ns:
                return None, "multi-scan or empty JPEG"
            if any(h < 1 or v < 1 for h, v in comps.values()):
                return None, "invalid sampling factors"
            hmax = max(h for h, _ in comps.values())
            vmax = max(v for _, v in comps.values())
            blocks = []
            for i in range(ns):
                cid, tables = seg[1 + 2 * i], seg[2 + 2 * i]
                if cid not in comps or tables >> 4 not in dc or tables & 15 not in ac:
                    return None, "scan references a missing table"
                h, v = comps[cid] if ns > 1 else (1, 1)
                blocks += [(dc[tables >> 4], ac[tables & 15])] * (h * v)
            spec = Spec()
            spec.width, spec.height, spec.blocks, spec.restart = width, height, blocks, restart
            spec.mcus = (_ceil(width, 8 * hmax) * _ceil(height, 8 * vmax) if ns > 1
                         else _ceil(width, 8) * _ceil(height, 8))
            spec.dcmax, spec.acmax = precision + 3, precision + 2
            spec.scan_start = pos + 2 + seglen
            return spec, ""
        pos += 2 + seglen
    return None, "no scan found"


def _fill(buf: bytes, pos: int, acc: int, nbits: int, n: int) -> Tuple[int, int, int]:
    """Load whole bytes (undoing FF 00 stuffing) until 25+ bits are buffered; never consume a marker."""
    while nbits <= 24 and pos < n:
        b = buf[pos]
        if b == 0xFF:
            if pos + 1 >= n or buf[pos + 1]:
                break
            pos += 2
        else:
            pos += 1
        acc = acc << 8 | b
        nbits += 8
    return pos, acc, nbits


def _exhausted(buf: bytes, pos: int, n: int) -> bool:
    return pos >= n or (pos == n - 1 and buf[pos] == 0xFF)


def decode(spec: Spec, buf: bytes, pos: int, state: Tuple[int, int, int, int],
           checkpoints: Optional[List[tuple]] = None) -> Tuple[str, int, Tuple[int, int, int, int]]:
    """
    Walk the entropy-coded data from byte pos with state (mcu, bit buffer, bit count, next RST index).
    Returns (DONE, offset after EOI, state), (INVALID, offset where the data stopped making sense, state)
    or (NEED_DATA, offset, state) from which decoding resumes once more bytes are appended to buf.
    """
    mcu, acc, nbits, rst = state
    n, total, interval = len(buf), spec.mcus, spec.restart
    dcmax, acmax, blocks = spec.dcmax, spec.acmax, spec.blocks
    while mcu < total:
        mcu_pos, mcu_state = pos, (mcu, acc, nbits, rst)
        if checkpoints is not None:
            checkpoints.append((pos, mcu, acc, nbits, rst))
        for dct, act in blocks:
            k = 0
            while k < 64:
                if nbits < 25:
                    pos, acc, nbits = _fill(buf, pos, acc, nbits, n)
                acc &= (1 << nbits) - 1
                e = (dct if k == 0 else act)[acc >> (nbits - 16) if nbits >= 16 else acc << (16 - nbits)]
                length = e & 31
                if not e or length > nbits:
                    if (e or nbits < 16) and _exhausted(buf, pos, n):
                        return NEED_DATA, mcu_pos, mcu_state
                    return INVALID, pos, (mcu, acc, nbits, rst)
                nbits -= length
                sym = e >> 5
                if k == 0:                                   # DC difference category
                    size = sym
                    if size > dcmax:
                        return INVALID, pos, (mcu, acc, nbits, rst)
                    k = 1
                else:                                        # AC run/size
                    size, run = sym & 15, sym >> 4
                    if size:
                        k += run
                        if k > 63 or size > acmax:
                            return INVALID, pos, (mcu, acc, nbits, rst)
                        k += 1
                    elif run == 15:                          # sixteen zeros
                        k += 16
                        if k > 63:
                            return INVALID, pos, (mcu, acc, nbits, rst)
                    elif run == 0:                           # end of block
                        break
                    else:
                        return INVALID, pos, (mcu, acc, nbits, rst)
                if size:
                    if size > nbits:
                        pos, acc, nbits = _fill(buf, pos, acc, nbits, n)
                        if size > nbits:
                            if _exhausted(buf, pos, n):
                                return NEED_DATA, mcu_pos, mcu_state
                            return INVALID, pos, (mcu, acc, nbits, rst)
                    nbits -= size
        mcu += 1
        if mcu == total or (interval and mcu % interval == 0):
            acc &= (1 << nbits) - 1
            pad = nbits & 7                                  # rest of the current byte: must be 1-bits
            if acc >> (nbits - pad) != (1 << pad) - 1:
                return INVALID, pos, (mcu, acc, nbits, rst)
            nbits -= pad
            acc &= (1 << nbits) - 1
            if nbits:                                        # whole bytes left before the marker
                return INVALID, pos, (mcu, acc, nbits, rst)
            if mcu == total:
                while pos + 1 < n and buf[pos] == 0xFF and buf[pos + 1] == 0xFF:
                    pos += 1
                if pos + 1 >= n:
                    return NEED_DATA, mcu_pos, mcu_state
                if buf[pos] == 0xFF and buf[pos + 1] == 0xD9:
                    return DONE, pos + 2, (mcu, 0, 0, rst)
                return INVALID, pos, (mcu, 0, 0, rst)
            if pos + 1 >= n:
                return NEED_DATA, mcu_pos, mcu_state
            if buf[pos] != 0xFF or buf[pos + 1] != 0xD0 + rst:
                return INVALID, pos, (mcu, 0, 0, rst)
            pos, acc, nbits, rst = pos + 2, 0, 0, (rst + 1) & 7
    return STOP, pos, (mcu, acc, nbits, rst)


def check(blob: bytes) -> Tuple[Optional[bool], str]:
    """True: the image data decodes exactly to EOI. False: it does not. None: format not supported."""
    spec, why = parse_spec(blob)
    if spec is None:
        return None, why
    status, pos, _ = decode(spec, blob, spec.scan_start, (0, 0, 0, 0))
    if status == DONE:
        return True, ""
    return False, f"image data breaks at byte {pos}" if status == INVALID else "image data ends early"


_LOW_BYTES = bytes(range(128))


def _first_foreign(data: bytes, start: int, end: int) -> int:
    """
    Offset of the first 512-byte-aligned block in [start, end) that cannot be entropy-coded image data:
    about half the bytes of genuine scan data are >= 0x80, while zero-filled or text clusters have almost none.
    """
    b = start + (-start % 512)
    while b + 512 <= end:
        if len(data[b:b + 512].translate(None, _LOW_BYTES)) < 26:
            return b
        b += 512
    return -1


def _scan_start(data: bytes) -> int:
    pos, n = 2, len(data)
    while pos + 4 <= n and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
        elif marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
        else:
            seglen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if marker == 0xDA:
                return pos + 2 + seglen
            pos += 2 + seglen
    return -1


def suspicious(blob: bytes) -> bool:
    """Cheap hints that a structurally complete JPEG swallowed foreign clusters (zero or text blocks, file headers)."""
    start = _scan_start(blob)
    if start < 0:
        return False
    if _first_foreign(blob, start, len(blob) - 2) >= 0:
        return True
    for sig in _SIGNATURES:
        i = blob.find(sig, start)
        while i >= 0:
            if i % 512 == 0:
                return True
            i = blob.find(sig, i + 1)
    return False


def _implausible(probe: bytes) -> bool:
    """A cluster that cannot continue JPEG scan data: empty, zero-filled, a new file, or an illegal marker."""
    if not probe or not probe.strip(b"\x00") or probe.startswith(_SIGNATURES):
        return True
    i = probe.find(b"\xff")
    while 0 <= i < len(probe) - 1:
        nxt = probe[i + 1]
        if nxt == 0xD9:
            return False                                     # end of image; the rest is slack
        if nxt not in (0x00, 0xFF) and not 0xD0 <= nxt <= 0xD7:
            return True
        i = probe.find(b"\xff", i + 1)
    return False


def _continue(spec: Spec, src, abs2: int, head: bytes, state: tuple, first: bytes, limit: int) -> Optional[bytes]:
    """Decode head + the continuation at abs2, reading more as needed; return the continuation up to EOI."""
    buf, have, pos = head + first, len(first), 0
    while True:
        status, pos, state = decode(spec, buf, pos, state)
        if status == DONE:
            return buf[len(head):pos] if pos > len(head) else None
        if status != NEED_DATA or have >= limit:
            return None
        more = src.read(abs2 + have, min(max(have, 64 * 1024) * 2, limit - have))
        if not more:
            return None
        buf += more
        have += len(more)


def reassemble(src, start: int, window: bytes, cluster: int, max_gap: int, max_size: int,
               deadline: float) -> Optional[Tuple[bytes, Tuple[int, int], Tuple[int, int]]]:
    """
    window holds the file from its header at `start`. Find where its image data stops decoding; then, for
    the cluster boundaries just before that point and each gap length, test whether the data after the gap
    continues the image to its end. Returns (file bytes, fragment 1, fragment 2) or None.
    """
    spec, _ = parse_spec(window)
    if spec is None or cluster <= 0:
        return None
    checkpoints: List[tuple] = []
    status, broke_at, _ = decode(spec, window, spec.scan_start, (0, 0, 0, 0), checkpoints)
    if status != INVALID:
        return None
    from .formats import parse_jpeg
    positions = [c[0] for c in checkpoints]
    # Zero-filled or text clusters can decode as valid-looking blocks; where they start is a better hint
    foreign = _first_foreign(window, spec.scan_start, broke_at)
    # The decoder looks one byte ahead (FF 00 stuffing, markers), so foreign data may start at broke_at + 1
    hint = foreign if foreign >= 0 else broke_at + 1
    last = hint // cluster * cluster
    for split in range(last, max(spec.scan_start, last - 4 * cluster), -cluster):
        idx = bisect.bisect_right(positions, split) - 1
        if idx < 0:
            continue
        ck_pos, mcu, acc, nbits, rst = checkpoints[idx]
        head = window[ck_pos:split]
        for gap in range(cluster, max_gap + 1, cluster):
            if time.time() > deadline:
                return None
            abs2 = start + split + gap
            if abs2 >= src.size:
                break
            probe = src.read(abs2, 2 * cluster)
            if _implausible(probe):
                continue
            tail = _continue(spec, src, abs2, head, (mcu, acc, nbits, rst), probe, max_size - split)
            if tail is None:
                continue
            blob = window[:split] + tail
            final = parse_jpeg(blob)
            if final is not None and final.valid and final.end == len(blob):
                return blob, (start, split), (abs2, len(tail))
    return None
