# WipeX — System Specification (SIH 2026 · SIH26149 · NTRO)

> **Mission:** One integrated forensic workstation that (a) securely erases drives, (b) securely erases individual files and folders together with their metadata traces, and (c) recovers deleted files from damaged or formatted media. Every operation is verified, logged and reported.

See [README.md](README.md) for the competitor landscape and research gaps (G1–G8) behind this design.

---

## 1. Modules

### M1 — Secure Drive Eraser (existing; extend)
| Item | Spec |
|---|---|
| Inputs | Physical drive (SATA HDD/SSD, NVMe, USB, SD), Android device (ADB), raw disk image |
| Methods | NIST 800-88 Clear (1-pass), DoD 3-pass, Gutmann 35-pass, NVMe Sanitize/Format SES, ATA Secure Erase, TCG Opal crypto-erase, physical-destroy order |
| Method selection | By media type: flash media is steered to crypto/firmware purge; magnetic media to overwrite |
| Safety | Boot-disk lock; **evidence lock** (refuses media under legal hold, G5); dual approval |
| Verification | Pattern-aware read-back (G8) + Recovery-as-Verifier (G1) |
| Output | ECDSA P-256 signed certificate (JSON/PDF) + audit-log entries |
| Code | `wipe_engine.py`, `entropy_auditor.py`, `crypto_signer.py` |

### M2 — Secure File & Folder Eraser (new)
| Item | Spec |
|---|---|
| Inputs | File or folder paths on a mounted volume, or inside an image |
| Content erasure | Overwrite (pattern per policy) → flush → rename to random name → truncate → unlink |
| Metadata erasure | Timestamps, ADS / xattrs, and filename traces in parent directory |
| Artifact cleanup (G2) | Windows: LNK, Jump Lists, thumbcache, Prefetch, Recent. NTFS: `$UsnJrnl` / `$I30` / VSS reporting. Linux: ext4 journal, thumbnails cache |
| Storage policy (G3) | Detects SSD/TRIM, copy-on-write file systems (APFS, Btrfs, ReFS) and flash media; warns the operator and offers M1 escalation |
| Verification | Re-scan with M3 for the erased file's signatures and name |
| Code | `file_eraser.py` (planned) |

### M3 — Advanced File Carving & Recovery (new)
| Item | Spec |
|---|---|
| Inputs | Raw/dd image, E01 (optional), or read-only device handle |
| Acquisition | Hash the source (SHA-256) → work only on a copy → log a custody event |
| Techniques | (1) FS-metadata recovery: NTFS `$MFT`, FAT32/exFAT, ext4 deleted entries; (2) signature carving; (3) **structural validation**: JPEG markers, PNG CRC, PDF xref, ZIP/DOCX central directory, MP4 atoms; (4) bifragment gap carving for fragmented files |
| Output | Recovered files + per-file SHA-256, offset, technique used, validation result, confidence score |
| Code | `recovery/` package (planned) |

---

## 2. Cross-cutting Services
| Service | Spec |
|---|---|
| **Audit log** | Append-only; each entry = `{seq, ts, actor, action, target, details, prev_hash, hash, signature}`; signature via `CryptoSigner.sign_payload`; `/api/audit/verify` recomputes the chain and reports the first break |
| **Cases & custody** | Tables: `cases`, `evidence`, `custody_events`, `legal_holds`. Every M1/M2/M3 action references a case ID |
| **Reports** | PDF (ReportLab) + JSON: recovery report, erasure certificate, BSA 2023 §63 annexure (G7) |
| **Roles** | Investigator (M3), Sanitizer (M1/M2), Auditor (read-only logs and reports) |
| **Benchmarks (G4)** | `benchmarks/` runs M3 on DFRWS 2006/2007, NIST CFReDS and Digital Corpora images; reports precision, recall and MB/s against PhotoRec and Scalpel |

---

## 3. Workflows

```
RECOVER:   Case → Acquire (hash) → Parse FS → Carve → Validate → Review → Signed report
ERASE:     Case check (legal hold?) → Dual approval → Erase (M1/M2) → Verify:
                pattern read-back (G8) → Recovery-as-Verifier with M3 (G1) → Signed certificate
AUDIT:     Every step → hash-chained, signed log entry → verifiable at any time
```

---

## 4. API Surface (implemented — `main.py`, docs at `/docs`)
| Area | Endpoints |
|---|---|
| Health | `GET /api/health` (capabilities, admin rights, counts) |
| M1 devices & erasure | `GET /api/devices?refresh=`, `GET /api/methods`, `POST /api/wipe/start`, `GET /api/wipe/status/{id}`, `POST /api/audit/run/{id}` (verification) |
| Certificates | `POST /api/certificates/generate`, `GET /api/verify/{id or serial}` (exact match), `GET /api/certificates/{id}/pdf`, `GET /api/certificates` |
| Lab images | `GET/POST /api/lab/images`, `POST /api/lab/images/{id}/reset`, `DELETE /api/lab/images/{id}` |
| M2 files | `GET /api/fs/list`, `POST /api/files/analyze`, `POST /api/files/erase` (job), `POST /api/files/sandbox`, `GET /api/files/report/{job}.pdf` |
| M3 recovery | `POST /api/recovery/scan` (job), `GET /api/recovery/file`, `GET /api/recovery/{job}/report.pdf`, `GET /api/recovery/formats`, `POST /api/benchmark` (job) |
| Jobs | `GET /api/jobs`, `GET /api/jobs/{id}` |
| Cases | `GET/POST /api/cases`, `GET /api/cases/{id}`, `POST /api/cases/{id}/status`, `POST /api/cases/{id}/evidence` (job), `POST /api/evidence/{id}/verify` |
| Holds & policy | `POST /api/cases/{id}/holds`, `POST /api/holds/{id}/release`, `GET /api/holds`, `GET/POST /api/settings/dual-approval` |
| Audit | `GET /api/audit/log`, `GET /api/audit/verify`, `GET /api/audit/export` |
| Android | `GET /api/devices/android`, `POST /api/wipe/android/start` |

## 5. Non-functional Requirements
- **Forensic soundness:** recovery never writes to source media; all analysis runs on hashed working copies.
- **Offline:** no network dependency at runtime (air-gapped deployment).
- **Honesty:** every report states the verification level actually reached (e.g. "Clear, file-level, SSD: physical erasure not guaranteed").
- **Portability:** Windows 10/11, Linux (hardware sanitize commands), macOS.
