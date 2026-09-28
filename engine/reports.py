"""
WipeX - PDF reports (ReportLab): erasure certificate, recovery report and file-erasure
report, each followed by a draft annexure in the style of a certificate under
Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (electronic records).
The annexure is a template to be completed and signed by the responsible person; WipeX
does not claim that the generated document is legally sufficient on its own.

Layout: a branded header and "page x of y" on every page, a verdict banner, summary tiles,
then tables. Long paths wrap anywhere; hashes are shortened in tables and listed in full in a
hash register, so every value stays readable and nothing overflows the page.
"""

import hashlib
import io
import os
import platform
import time
from typing import Any, Dict, List, Optional, Sequence

from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from crypto_signer import CryptoSigner

# ── Palette and type ─────────────────────────────────────────────────────────
INK = colors.HexColor("#14212a")
TEXT2 = colors.HexColor("#475761")
MUTED = colors.HexColor("#7a8990")
LINE = colors.HexColor("#dce3e0")
SOFT = colors.HexColor("#f4f7f6")
ACCENT = colors.HexColor("#0e7470")
TONES = {  # verdict tone -> (strong, soft)
    "ok": (colors.HexColor("#157a3c"), colors.HexColor("#e6f4ea")),
    "warn": (colors.HexColor("#a85a06"), colors.HexColor("#fdf2e0")),
    "bad": (colors.HexColor("#b3261e"), colors.HexColor("#fcebea")),
    "info": (colors.HexColor("#2458a6"), colors.HexColor("#e8effa")),
}
PAGE_W, PAGE_H = A4
MARGIN = 16 * mm
CONTENT_W = PAGE_W - 2 * MARGIN


def _style(name: str, **kw) -> ParagraphStyle:
    base = dict(fontName="Helvetica", fontSize=9.2, leading=12.6, textColor=INK, alignment=TA_LEFT)
    base.update(kw)
    return ParagraphStyle(name, **base)


TITLE = _style("title", fontName="Helvetica-Bold", fontSize=19, leading=23)
SUBTITLE = _style("subtitle", fontSize=9.5, textColor=TEXT2, leading=13)
H2 = _style("h2", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=INK, spaceBefore=12, spaceAfter=5)
BODY = _style("body")
SMALL = _style("small", fontSize=7.8, leading=10.2, textColor=MUTED)
CELL = _style("cell", fontSize=8, leading=10.2)
CELL_PATH = _style("cellpath", fontSize=7.8, leading=10, wordWrap="CJK")           # breaks anywhere
MONO = _style("mono", fontName="Courier", fontSize=7.4, leading=9.4, wordWrap="CJK")
KEY = _style("key", fontSize=8.4, leading=11, textColor=MUTED)
VAL = _style("val", fontName="Helvetica-Bold", fontSize=8.8, leading=11.4, wordWrap="CJK")
TILE_N = _style("tilen", fontName="Helvetica-Bold", fontSize=16, leading=19, alignment=TA_CENTER)
TILE_L = _style("tilel", fontSize=7.6, leading=9.6, textColor=TEXT2, alignment=TA_CENTER)


def _esc(v: Any) -> str:
    return str(v if v is not None else "—").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _when(ts: Optional[str]) -> str:
    """2026-09-28T14:56:43Z / '2026-09-28 14:56:51 UTC' -> '28 Sep 2026, 14:56 UTC'."""
    if not ts:
        return "—"
    raw = str(ts).replace("T", " ").replace("Z", "").replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return time.strftime("%d %b %Y, %H:%M UTC", time.strptime(raw[:19], fmt))
        except ValueError:
            continue
    return str(ts)


def _plural(n: int, one: str, many: str) -> str:
    return f"{n:,} {one if n == 1 else many}"


def _size(n: Any) -> str:
    n = float(n or 0)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{int(n):,} bytes" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1000
    return str(n)


def _short(h: Optional[str], n: int = 16) -> str:
    return f"{h[:n]}…" if h else "—"


# ── Page decoration ──────────────────────────────────────────────────────────

def _logo(c, x: float, y: float, size: float) -> None:
    """The WipeX mark (hexagon with an X whose second stroke dissolves into wiped blocks)."""
    s = size / 64.0
    P = lambda px, py: (x + px * s, y + (64 - py) * s)  # noqa: E731
    hexagon = [P(32, 5), P(55.4, 18.5), P(55.4, 45.5), P(32, 59), P(8.6, 45.5), P(8.6, 18.5)]
    c.saveState()
    path = c.beginPath()
    path.moveTo(*hexagon[0])
    for pt in hexagon[1:]:
        path.lineTo(*pt)
    path.close()
    c.clipPath(path, stroke=0, fill=0)
    try:
        c.linearGradient(x + 10 * s, y + 64 * s, x + 54 * s, y, (colors.HexColor("#22c7b8"), ACCENT, colors.HexColor("#0b3f47")),
                         (0, 0.55, 1), extend=True)
    except Exception:  # noqa: BLE001  (older ReportLab: flat colour)
        c.setFillColor(ACCENT)
        c.rect(x, y, size, size, stroke=0, fill=1)
    c.restoreState()
    c.saveState()
    c.setStrokeColor(colors.white)
    c.setLineCap(1)
    c.setLineWidth(7 * s)
    c.line(*P(21.5, 20.5), *P(42.5, 43.5))
    c.line(*P(42.5, 20.5), *P(31, 33))
    c.setFillColor(colors.white)
    for bx, by, bw, alpha in ((23.6, 35.6, 5.6, .85), (19.6, 40.6, 4.4, .58), (16.4, 45, 3.2, .34)):
        c.setFillAlpha(alpha)
        c.roundRect(x + bx * s, y + (64 - by - bw) * s, bw * s, bw * s, 1 * s, stroke=0, fill=1)
    c.restoreState()


class _NumberedCanvas(pdfcanvas.Canvas):
    """Draws the header and footer after the page count is known ("Page 2 of 3")."""

    def __init__(self, *args, doc_label: str = "", doc_id: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._pages: List[Dict[str, Any]] = []
        self._label, self._id = doc_label, doc_id

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for state in self._pages:
            self.__dict__.update(state)
            self._decorate(total)
            super().showPage()
        super().save()

    def _decorate(self, total: int) -> None:
        top = PAGE_H - 12 * mm
        _logo(self, MARGIN, top - 3.2 * mm, 8.5 * mm)
        self.setFillColor(INK)
        self.setFont("Helvetica-Bold", 11.5)
        self.drawString(MARGIN + 10.5 * mm, top + 0.4 * mm, "WipeX")
        self.setFont("Helvetica", 7.4)
        self.setFillColor(MUTED)
        self.drawString(MARGIN + 10.5 * mm, top - 3 * mm, "Integrated secure erasure and forensic recovery")
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(ACCENT)
        self.drawRightString(PAGE_W - MARGIN, top + 0.4 * mm, self._label.upper())
        self.setFont("Courier", 7.6)
        self.setFillColor(TEXT2)
        self.drawRightString(PAGE_W - MARGIN, top - 3 * mm, self._id)
        self.setStrokeColor(ACCENT)
        self.setLineWidth(1.2)
        self.line(MARGIN, top - 5.6 * mm, PAGE_W - MARGIN, top - 5.6 * mm)
        self.setStrokeColor(LINE)
        self.setLineWidth(0.5)
        self.line(MARGIN, 13 * mm, PAGE_W - MARGIN, 13 * mm)
        self.setFont("Helvetica", 7)
        self.setFillColor(MUTED)
        self.drawString(MARGIN, 9 * mm, f"Generated by WipeX on workstation {platform.node() or 'unknown'} · "
                                        f"{time.strftime('%d %b %Y, %H:%M UTC', time.gmtime())} · check it in WipeX → Verify Certificate")
        self.drawRightString(PAGE_W - MARGIN, 9 * mm, f"Page {self._pageNumber} of {total}")


def _build(story: List[Any], title: str, label: str, doc_id: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=24 * mm,
                            bottomMargin=19 * mm, title=title, author="WipeX", subject=label, creator="WipeX")
    doc.build(story, canvasmaker=lambda *a, **k: _NumberedCanvas(*a, doc_label=label, doc_id=doc_id, **k))
    return buf.getvalue()


# ── Building blocks ──────────────────────────────────────────────────────────

def _heading(title: str, subtitle: str) -> List[Any]:
    return [Paragraph(_esc(title), TITLE), Spacer(1, 3), Paragraph(subtitle, SUBTITLE), Spacer(1, 10)]


def _banner(tone: str, headline: str, detail: str = "") -> Table:
    strong, soft = TONES[tone]
    mark = {"ok": "✓", "warn": "!", "bad": "×", "info": "i"}[tone]
    badge = Table([[Paragraph(f'<font color="white"><b>{mark}</b></font>', _style("m", fontName="Helvetica-Bold", fontSize=13, leading=15, alignment=TA_CENTER))]],
                  colWidths=[9 * mm], rowHeights=[9 * mm],
                  style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), strong), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                    ("ROUNDEDCORNERS", [4.5 * mm] * 4), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    text = [Paragraph(f'<font color="{strong.hexval().replace("0x", "#")}"><b>{_esc(headline)}</b></font>',
                      _style("bh", fontName="Helvetica-Bold", fontSize=12.5, leading=15))]
    if detail:
        text.append(Paragraph(_esc(detail), _style("bd", fontSize=8.8, leading=11.8, textColor=TEXT2)))
    t = Table([[badge, text]], colWidths=[13 * mm, CONTENT_W - 13 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), soft), ("BOX", (0, 0), (-1, -1), 0.8, strong),
                           ("ROUNDEDCORNERS", [3 * mm] * 4), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                           ("LEFTPADDING", (0, 0), (0, 0), 8)]))
    return t


def _tiles(items: Sequence[Sequence[Any]]) -> Table:
    """Summary numbers side by side: [(value, label), ...]."""
    w = (CONTENT_W - (len(items) - 1) * 3 * mm) / len(items)
    cells = [[Paragraph(_esc(v), TILE_N), Paragraph(_esc(l), TILE_L)] for v, l in items]
    inner = [Table([[c[0]], [c[1]]], colWidths=[w], style=TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SOFT), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("ROUNDEDCORNERS", [2.5 * mm] * 4),
        ("TOPPADDING", (0, 0), (-1, 0), 7), ("BOTTOMPADDING", (0, -1), (-1, -1), 7), ("TOPPADDING", (0, 1), (-1, 1), 0)]))
             for c in cells]
    row: List[Any] = []
    widths: List[float] = []
    for i, t in enumerate(inner):
        if i:
            row.append("")
            widths.append(3 * mm)
        row.append(t)
        widths.append(w)
    return Table([row], colWidths=widths, style=TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))


def _section(title: str) -> Paragraph:
    return Paragraph(f'<font color="#0e7470">▌</font> {_esc(title)}', H2)


def _kv(rows: Sequence[Sequence[Any]], width: float = CONTENT_W, key_w: float = 42 * mm) -> Table:
    data = [[Paragraph(_esc(k), KEY), v if not isinstance(v, str) else Paragraph(_esc(v), VAL)] for k, v in rows]
    t = Table(data, colWidths=[key_w, width - key_w])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
                           ("TOPPADDING", (0, 0), (-1, -1), 3.2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.2),
                           ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    return t


def _two_col(left: List[Any], right: List[Any]) -> Table:
    gap = 8 * mm
    w = (CONTENT_W - gap) / 2
    return Table([[left, "", right]], colWidths=[w, gap, w],
                 style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                   ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))


def _pill(text: str, tone: str) -> Table:
    strong, soft = TONES[tone]
    return Table([[Paragraph(f'<font color="{strong.hexval().replace("0x", "#")}"><b>{_esc(text)}</b></font>',
                             _style("p", fontName="Helvetica-Bold", fontSize=7.4, leading=9, alignment=TA_CENTER))]],
                 colWidths=[len(text) * 1.55 * mm + 7 * mm], hAlign="LEFT",
                 style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), soft), ("ROUNDEDCORNERS", [2 * mm] * 4),
                                   ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))


def _grid(header: Sequence[str], rows: List[List[Any]], widths: Sequence[float], align_right: Sequence[int] = ()) -> Table:
    def cell(c, col):
        if not isinstance(c, str):
            return c
        style = _style(f"c{col}", fontSize=8, leading=10.2, alignment=2) if col in align_right else CELL
        return Paragraph(_esc(c), style)
    head = [Paragraph(_esc(h), _style(f"h{i}", fontName="Helvetica-Bold", fontSize=7.6, leading=9.5, textColor=colors.white,
                                      alignment=2 if i in align_right else 0)) for i, h in enumerate(header)]
    data = [head] + [[cell(c, i) for i, c in enumerate(r)] for r in rows]
    scale = CONTENT_W / sum(widths)
    t = Table(data, colWidths=[w * scale for w in widths], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), ACCENT), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 3.4), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.4),
             ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
             ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE), ("BOX", (0, 0), (-1, -1), 0.5, LINE)]
    style += [("BACKGROUND", (0, i), (-1, i), SOFT) for i in range(2, len(data), 2)]
    t.setStyle(TableStyle(style))
    return t


def _mono(text: str) -> Paragraph:
    return Paragraph(_esc(text), MONO)


def _path(text: str) -> Paragraph:
    return Paragraph(_esc(text), CELL_PATH)


def _qr(text: str, size: float = 30 * mm) -> Drawing:
    widget = QrCodeWidget(text)
    x0, y0, x1, y1 = widget.getBounds()
    drawing = Drawing(size, size, transform=[size / (x1 - x0), 0, 0, size / (y1 - y0), 0, 0])
    drawing.add(widget)
    return drawing


def _annexure(record_desc: str, device_desc: str, digest: str, produced_by: str) -> List[Any]:
    key_fp = hashlib.sha256(CryptoSigner.get_public_key_pem().encode()).hexdigest()[:32]
    def sign() -> Table:
        t = _kv([["Name", " "], ["Designation", " "], ["Date and place", " "], ["Signature", " "]],
                width=(CONTENT_W - 8 * mm) / 2, key_w=30 * mm)
        t.setStyle(TableStyle([("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                               ("LINEBELOW", (0, -1), (-1, -1), 0.4, LINE)]))
        return t
    return [
        PageBreak(),
        *_heading("Annexure: certificate for an electronic record",
                  "Draft in the form contemplated by Section 63 of the Bharatiya Sakshya Adhiniyam, 2023. Generated by WipeX; "
                  "to be reviewed, completed and signed by the person responsible for the device or process and, where "
                  "required, by an expert."),
        _section("Part A · The record"),
        _kv([["Electronic record", record_desc], ["Produced from", device_desc],
             ["Produced by", "WipeX workstation, operated by " + (produced_by or "—")],
             ["Hash value (SHA-256)", _mono(digest)], ["Signing key fingerprint", _mono(key_fp)]]),
        Spacer(1, 8),
        Paragraph("I state that the electronic record identified above was produced by the computer / software named, "
                  "which was operating properly during the relevant period, and that the information was stored and "
                  "processed in the ordinary course of its use. The hash value above identifies the record exactly.", BODY),
        Spacer(1, 6),
        _two_col([_section("Part A · Declarant"), sign()], [_section("Part B · Expert (where applicable)"), sign()]),
    ]


def _describe_check(c: Dict[str, Any]) -> str:
    if c.get("name") == "Pattern read-back":
        text = (f"Expected {c.get('expected')}; coverage {c.get('coverage')}; "
                f"{c.get('mismatchedRegions', 0)} mismatched region(s)")
        if c.get("unchangedBlocks"):
            text += f"; {c['unchangedBlocks']} block(s) still hold old content"
        if c.get("readErrors"):
            text += f"; {c['readErrors']} read error(s)"
        return text
    if c.get("name") == "Canary blocks":
        return f"{c.get('planted')} marker blocks planted before erasure; {c.get('recovered')} found afterwards"
    if c.get("name") == "Recovery attempt (M3)":
        return c.get("reason") if c.get("skipped") else c.get("detail", "")
    return ", ".join(f"{k}: {v}" for k, v in c.items() if k not in ("name", "passed"))


def _result_pill(passed: Optional[bool]) -> Table:
    return _pill("PASS", "ok") if passed else _pill("SKIPPED", "info") if passed is None else _pill("FAIL", "bad")


# ── Erasure certificate ──────────────────────────────────────────────────────

def certificate_pdf(cert: Dict[str, Any], verify_url: Optional[str] = None) -> bytes:
    v = cert.get("verification") or {}
    ok = cert.get("trustScore") == "GREEN"
    cid = cert["certificateId"]
    passes = cert.get("passes") or []
    story: List[Any] = _heading("Certificate of Data Sanitization", f"Issued {_esc(_when(cert.get('issueDate')))} · "
                                f"Certificate ID <b>{_esc(cid)}</b>")
    story.append(_banner("ok" if ok else "bad", "Sanitized and verified" if ok else "Not sanitized",
                         " · ".join(x for x in (cert.get("trustScoreLabel"), cert.get("standard"),
                                                "read back and recovery attempted" if ok else cert.get("cleanedStatus")) if x)))
    story.append(Spacer(1, 10))
    story.append(_two_col(
        [_section("Device"), _kv([["Model", cert.get("deviceModel") or "—"], ["Serial number", cert.get("serialNumber") or "—"],
                                  ["Media type", cert.get("storageType") or "—"],
                                  ["Capacity", _size(cert.get("capacityBytes"))]], width=(CONTENT_W - 8 * mm) / 2, key_w=30 * mm)],
        [_section("Sanitization"), _kv([["Method", cert.get("standard") or "—"], ["NIST SP 800-88", cert.get("category") or "—"],
                                        ["Passes", ", ".join(passes) if passes else "Drive firmware command"],
                                        ["Operator", cert.get("operator") or "—"],
                                        ["Approver", cert.get("approver") or "— (two-person rule off)"]],
                                       width=(CONTENT_W - 8 * mm) / 2, key_w=30 * mm)]))
    story.append(_section("Verification: WipeX tried to read the data back and recover files"))
    rows = [[Paragraph(f"<b>{_esc(c.get('name', ''))}</b>", CELL), _result_pill(c.get("passed")), _describe_check(c)]
            for c in v.get("checks", [])]
    story.append(_grid(["Check", "Result", "Evidence"], rows, [44, 18, 112]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Overall verdict <b>{_esc(v.get('verdict', '—'))}</b>. Mean entropy of sampled blocks "
                           f"{_esc(v.get('meanEntropy'))} bits/byte (informational; the verdict comes from the read-back "
                           "and the recovery attempt).", SMALL))
    qr = _qr(verify_url or cid, 30 * mm)
    integrity = [_section("Integrity and signature"),
                 _kv([["SHA-256 of the signed content", _mono(cert["sha256Digest"])],
                      ["Signature", cert.get("signatureAlgorithm", "ECDSA P-256")],
                      ["Signature status", "Valid" if cert.get("isValid") else "INVALID: do not rely on this certificate"]],
                     width=CONTENT_W - 44 * mm, key_w=38 * mm)]
    qr_box = [Spacer(1, 18), qr, Paragraph("Scan to open this certificate in WipeX → Verify Certificate", SMALL)]
    story.append(KeepTogether(Table([[integrity, qr_box]], colWidths=[CONTENT_W - 40 * mm, 40 * mm],
                                    style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                                      ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))))
    story += _annexure(f"Certificate of data sanitization {cid}", f"{cert.get('deviceModel')} (serial {cert.get('serialNumber')})",
                       cert["sha256Digest"], cert.get("operator") or "")
    return _build(story, f"WipeX certificate {cid}", "Sanitization certificate", cid)


# ── Recovery report ──────────────────────────────────────────────────────────

CONDITION = {"intact": ("Intact", "ok"), "unverified": ("Recovered", "ok"), "damaged": ("Damaged", "warn"),
             "overwritten": ("Overwritten", "bad"), "zeroed": ("Erased by drive", "bad"), "unreadable": ("Unreadable", "bad"),
             "valid": ("Intact", "ok"), "repaired": ("Rebuilt", "ok"), "partial": ("Partial", "warn")}


def _confidence(c: Optional[float]) -> str:
    if c is None:
        return "—"
    return f"{round(c * 100)}% {'high' if c >= 0.85 else 'medium' if c >= 0.5 else 'low'}"


def recovery_pdf(job: Dict[str, Any], case: Optional[Dict[str, Any]] = None, evidence: Optional[Dict[str, Any]] = None) -> bytes:
    res = job.get("result") or {}
    fs = res.get("filesystem") or {}
    carving = res.get("carving") or {}
    deleted = [e for e in fs.get("entries", []) if e.get("deleted") and not e.get("isDir") and (e.get("size") or 0) > 0]
    carved = carving.get("files") or []
    only_carved = [f for f in carved if not f.get("alsoFoundAs")]
    rebuilt = [f for f in carved if len(f.get("fragments") or []) > 1]
    items = ([{"name": e["path"], "short": e["path"], "size": e["size"], "how": "File system", "state": e.get("contentStatus", "unreadable"),
               "conf": e.get("confidence"), "sha": e.get("sha256")} for e in deleted] +
             [{"name": f"{f['id']}.{f['ext']} (no name: found at offset {f['offset']:,})", "short": f"{f['id']}.{f['ext']}", "size": f["size"],
               "how": "Carving · rebuilt" if len(f.get("fragments") or []) > 1 else "Carving",
               "state": f["status"], "conf": f.get("confidence"), "sha": f["sha256"]} for f in only_carved])
    recovered = [i for i in items if CONDITION.get(i["state"], ("", "bad"))[1] == "ok"]
    high = [i for i in items if (i["conf"] or 0) >= 0.85]
    source = res.get("sourceLabel") or res.get("source", "—")
    story: List[Any] = _heading("Forensic Recovery Report", f"Job <b>{_esc(job['id'])}</b> · finished {_esc(_when(job.get('finished_at') or job.get('created_at')))}")
    story.append(_banner("info" if items else "warn",
                         f"{_plural(len(items), 'deleted file', 'deleted files')} found · {len(recovered)} recovered",
                         f"Source: {source}. The source was opened read-only."))
    story.append(Spacer(1, 8))
    story.append(_tiles([(len(deleted), "found by the file system"), (len(only_carved), "found only by carving"),
                         (len(rebuilt), "rebuilt from fragments"), (len(high), "with high confidence")]))
    story.append(_section("Case and source"))
    story.append(_kv([["Case", f"{case['id']} · {case['title']}" if case else "— (not linked to a case)"],
                      ["Investigator", case["investigator"] if case else "—"], ["Source", source],
                      ["Evidence item", f"{evidence['id']} ({evidence['label']})" if evidence else "—"],
                      ["Acquisition SHA-256", _mono(evidence["sha256"]) if evidence else "—"],
                      ["Scan", f"{res.get('seconds', '—')} s · " + (f"{_size(carving.get('bytesScanned'))} searched block by block"
                                                                     if carving.get("bytesScanned") else "file system only (quick scan)")]]))
    story.append(_section("How the files were found"))
    for n, text in enumerate([
            "<b>File system</b> (The Sleuth Kit): entries marked deleted are listed with their names and dates, and their "
            "clusters read back; the content is checked against the file type's structure.",
            "<b>Carving</b>: every block is searched for file signatures; each candidate is parsed (JPEG markers, PNG and ZIP "
            "checksums, PDF cross-reference, GIF blocks, SQLite header), so it works after a format too.",
            "<b>Fragment rebuild</b>: split JPEG, PNG and ZIP files are joined again only when the format's own checksum or "
            "decoder accepts the result."], 1):
        story.append(Paragraph(f"{n}. {text}", BODY))
    story.append(Paragraph("<b>Confidence</b>: 95–97 % when the structure validates end to end, 90 % when rebuilt from fragments "
                           "and validated, 60 % when content is present but has no structure to check, lower when damaged.", SMALL))
    if items:
        story.append(CondPageBreak(40 * mm))
        story.append(_section(f"Recovered files ({len(items)})"))
        rows = []
        for n, i in enumerate(items, 1):
            label, tone = CONDITION.get(i["state"], (i["state"], "info"))
            rows.append([str(n), _path(i["name"]), _size(i["size"]), i["how"], _pill(label, tone), _confidence(i["conf"])])
        story.append(_grid(["#", "File", "Size", "Found by", "Condition", "Confidence"], rows, [7, 70, 19, 28, 22, 22], align_right=(2,)))
    volumes = fs.get("volumes") or []
    if volumes:
        story.append(_section("File systems on the source"))
        story.append(_grid(["#", "Type", "Offset (bytes)", "Description"],
                           [[str(v["index"]), v["fsType"], f"{v['offset']:,}", v["description"]] for v in volumes], [8, 22, 30, 114]))
    hashed = [i for i in items if i["sha"]]
    if hashed:
        story.append(CondPageBreak(40 * mm))
        story.append(_section("Hash register (SHA-256 of each recovered file)"))
        story.append(_grid(["#", "File", "SHA-256"], [[str(n), _path(i["short"]), _mono(i["sha"])] for n, i in enumerate(hashed, 1)],
                           [7, 58, 109]))
    digest = hashlib.sha256(repr(sorted(i["sha"] for i in hashed)).encode()).hexdigest()
    story += _annexure(f"Recovery report {job['id']} listing {len(items)} files", source,
                       evidence["sha256"] if evidence else digest, case["investigator"] if case else "")
    return _build(story, f"WipeX recovery report {job['id']}", "Forensic recovery report", job["id"])


# ── File erasure report ──────────────────────────────────────────────────────

VERDICTS = {"PASS": ("ok", "Permanently deleted: no trace found"), "TRACES_REMAIN": ("warn", "Deleted, but some traces remain"),
            "ERASED_UNVERIFIED": ("warn", "Deleted and overwritten; the drive check could not run"),
            "PARTIAL": ("bad", "Some files could not be erased")}
PATTERNS = {"zero": "1 pass, zeros", "random": "1 pass, random data", "dod": "3 passes (zeros, ones, random)"}
ASSURANCE = {"High": "ok", "Limited": "warn", "Not effective": "bad"}


def file_erasure_pdf(report: Dict[str, Any]) -> bytes:
    tone, headline = VERDICTS.get(report["verdict"], ("info", report["verdict"]))
    files = report.get("files") or []
    tc = report.get("traceCheck") or {}
    traces_removed = [t for t in report.get("traces") or [] if t.get("result") in ("erased", "entry removed")]
    story: List[Any] = _heading("File and Folder Erasure Report", f"Job <b>{_esc(report['jobId'])}</b> · finished {_esc(_when(report.get('finishedAt')))}")
    story.append(_banner(tone, headline, tc.get("summary") or report.get("summary", "")))
    story.append(Spacer(1, 8))
    story.append(_tiles([(len(files), "files erased"), (_size(report.get("bytesOverwritten")), "overwritten"),
                         (report.get("streamsErased", 0) + report.get("xattrsErased", 0), "hidden streams removed"),
                         (len(traces_removed), "system traces removed")]))
    story.append(_section("Job"))
    story.append(_kv([["Overwrite pattern", PATTERNS.get(report.get("method"), report.get("method") or "—")],
                      ["Operator", report.get("operator") or "—"], ["Approver", report.get("approver") or "— (two-person rule off)"],
                      ["Folders removed", str(report.get("foldersRemoved", 0))],
                      *([["Links removed", f"{report['linksRemoved']} (removed without following them)"]] if report.get("linksRemoved") else [])]))
    for vol in report.get("volumes", []):
        story.append(_section(f"Storage: drive {vol['volume']}"))
        story.append(_kv([["File system and media", f"{vol['fileSystem']} · {vol['mediaType']}"],
                          ["Assurance", _pill(vol["assurance"], ASSURANCE.get(vol["assurance"], "info"))],
                          ["What it means", vol["advice"]], ["Notes", " ".join(vol.get("notes", [])) or "—"]]))
    if files:
        paths = [f["path"] for f in files]
        try:
            common = os.path.commonpath(paths) if len(paths) > 1 else os.path.dirname(paths[0])
        except ValueError:
            common = ""
        rel = lambda p: os.path.relpath(p, common) if common else p  # noqa: E731
        story.append(CondPageBreak(40 * mm))
        story.append(_section(f"Files erased ({len(files)})"))
        if common:
            story.append(Paragraph(f"In <font name='Courier'>{_esc(common)}</font>", SMALL))
            story.append(Spacer(1, 3))
        story.append(_grid(["#", "File", "Size", "Hidden streams", "Overwrite checked"],
                           [[str(n), _path(rel(f["path"])), _size(f["size"]),
                             ", ".join(s["name"] for s in f["streams"] + (f.get("xattrs") or [])) or "—",
                             _pill("Verified", "ok") if f["verified"] else _pill("Not verified", "bad")] for n, f in enumerate(files, 1)],
                           [7, 86, 22, 32, 27], align_right=(2,)))
    story.append(_section("Drive check: the volume was read directly, the way a forensic examiner would"))
    story.append(Paragraph(_esc(tc.get("summary", "Not run")), BODY))
    rows = [[_path(f["folder"]), str(f.get("entries", 0)), ", ".join(f.get("namesFound", [])) or "none",
             ", ".join(f.get("contentFound", [])) or "none"] for f in tc.get("folders", [])]
    rows += [[_path(s["folder"]), "—", "not checked", s["reason"]] for s in tc.get("skipped", [])]
    rows += [[_path(j["volume"] + " change journal"), "—", _plural(j["recordsWithNames"], "record", "records"), "—"] for j in tc.get("journal", [])]
    if rows:
        story.append(Spacer(1, 4))
        story.append(_grid(["Folder read from the volume", "Entries", "Original names found", "Content found"], rows, [86, 18, 36, 34]))
    if report.get("traces"):
        story.append(_section("System traces"))
        story.append(_grid(["Trace", "Result"], [[_path(t["path"]), t["result"]] for t in report["traces"]], [140, 34]))
    if report.get("failures"):
        story.append(_section("Failures"))
        story.append(_grid(["Path", "Error"], [[_path(f["path"]), f["error"]] for f in report["failures"]], [100, 74]))
    digest = hashlib.sha256(repr(report).encode()).hexdigest()
    story += _annexure(f"File erasure report {report['jobId']}", ", ".join(v["volume"] for v in report.get("volumes", [])),
                       digest, report.get("operator") or "")
    return _build(story, f"WipeX file erasure {report['jobId']}", "File erasure report", report["jobId"])
