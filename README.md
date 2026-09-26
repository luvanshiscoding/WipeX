# WipeX — Integrated Secure Data Erasure & Forensic Recovery Platform

**Smart India Hackathon 2026 · Problem Statement SIH26149 · National Technical Research Organisation (NTRO)**
**Theme:** Blockchain & Cybersecurity · **Category:** Software

> *Recover what must be preserved as evidence. Erase what must never be recovered. Prove both.*

WipeX was first built for SIH 2025 (PS SIH25070, secure wiping for IT-asset recycling). For SIH 2026 it is being re-engineered for **SIH26149**. Its drive-sanitization engine becomes one module of a single forensic workstation that also erases individual files and folders and recovers deleted data.

---

## 1. The Problem (SIH26149)

> *"Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization"*

Agencies face two opposing needs:
- **Permanently destroy** sensitive information so it can never be recovered.
- **Recover deleted evidence** during forensic examinations.

Current tools handle only one of these, so professionals juggle several platforms. NTRO asks for **one integrated tool** with three modules:

| # | Required module | What NTRO expects |
|---|---|---|
| M1 | **Secure Drive Eraser** | Sanitize various storage types, with verification and compliance reporting |
| M2 | **Secure File & Folder Eraser** | Selectively delete files and folders, with **metadata removal**, across multiple file systems |
| M3 | **Advanced File Carving & Recovery** | Restore deleted files from damaged or formatted media using multiple techniques |

**Cross-cutting deliverables:** comprehensive audit logging, a reporting system, a user dashboard, support for multiple storage devices and file systems, technical documentation, and **performance evaluations**.

---

## 2. Current Status — What Works Today

Legend: ✅ implemented and tested · 🟡 implemented, platform-limited or not yet validated on hardware · 🔲 planned

Everything marked ✅ is covered by the automated test suite (`python -m unittest discover -s tests`, 22 tests) and was exercised end to end in the browser.

### M1 — Secure Drive Eraser (`erasure.py`, `wipe_engine.py`)
| Capability | Status | Notes |
|---|---|---|
| Device discovery (Windows `Get-Disk`, Linux `lsblk`, macOS `diskutil`) + lab disk images | ✅ | Lab images are real FAT16 disks in a file — every operation on them is genuine |
| Overwrite methods: NIST 800-88 Clear, single zero, keyed random, DoD 3-pass, Gutmann 35 | ✅ | 140–200 MB/s on lab images; fsync after every pass |
| **Pattern-aware verification** (G8) | ✅ | Final random pass is keyed AES-256-CTR, so read-back regenerates the exact expected bytes. Full read-back up to 2 GiB, sampled beyond |
| **Canary blocks** | ✅ | 16 marker blocks planted before erasure on lab images; must be gone afterwards |
| **Recovery-as-Verifier** (G1) | ✅ | M3 (Sleuth Kit + carver) is run against the erased target; any recoverable file fails the job |
| NVMe Sanitize / Format, ATA Secure Erase, TCG Opal | 🟡 | Linux only (`nvme-cli`, `hdparm`, `sedutil-cli`); shown as unavailable with a reason elsewhere; not yet validated on sacrificial hardware |
| Physical disks on Windows | 🟡 | Disk is taken offline for raw writes; needs Administrator. The active system disk is always refused |
| HPA inspection | 🟡 | Linux `hdparm -N`; reports the real output (no longer a hard-coded "unlocked") |
| Android wipe (ADB) | 🟡 | Existing ADB path; not re-validated in this release |
| Signed certificate (ECDSA P-256), QR code, PDF + BSA 2023 §63 draft annexure (G7) | ✅ | Signed canonical payload stored separately; ledger tampering is detected |

### M2 — Secure File & Folder Eraser (`file_eraser.py`)
| Capability | Status | Notes |
|---|---|---|
| In-place overwrite (zero / random / DoD 3-pass) + fsync, truncate, 3× random rename, timestamp scrub, delete | ✅ | Folders removed bottom-up |
| NTFS alternate data streams overwritten and removed | ✅ | e.g. `Zone.Identifier` |
| **Storage-aware assurance** (G3) | ✅ | Detects file system, SSD/HDD/flash, bus type and TRIM; rates High / Limited / Not effective and recommends M1 when needed |
| **OS trace cleanup** (G2) | ✅ / 🟡 | ✅ Windows Recent shortcuts, Linux recently-used + thumbnails. 🟡 Jump Lists and thumbcache are reported only (shared databases) |
| Protected paths, legal-hold check, two-person rule | ✅ | System folders, drive roots, home folders and WipeX itself are refused |
| PDF report | ✅ | |

### M3 — Carving & Recovery (`recovery/`)
| Capability | Status | Notes |
|---|---|---|
| File-system recovery via The Sleuth Kit (pytsk3) | ✅ | NTFS, FAT, exFAT, ext2/3/4, HFS+, ISO 9660, partition tables; deleted entries extracted and checked (intact / damaged / overwritten) |
| Signature + structure carving | ✅ | JPEG, PNG, GIF, BMP, PDF, ZIP/DOCX/XLSX/PPTX/ODT, SQLite, MP4/MOV; each candidate fully parsed, images decoded |
| **Bifragment gap carving** | ✅ | PNG (chunk CRC) and ZIP (member CRC) reassembled byte-exact |
| Read-only sources: lab images, acquired evidence, image paths, raw devices | ✅ / 🟡 | Raw devices need Administrator |
| **Benchmark against ground truth** (G4) | ✅ | Measured results below |
| JPEG fragment reassembly, E01 images | 🔲 | JPEG has no checksum to validate a split; E01 via pyewf planned |

### Case management, audit and integrity
| Capability | Status | Notes |
|---|---|---|
| Cases, evidence acquisition (SHA-256 + MD5, copy re-hashed), hash re-verification | ✅ | `cases.py` |
| **Legal holds / evidence lock** (G5) | ✅ | Blocks M1 and M2 for held device serials, device paths and folders |
| Two-person rule | ✅ | Approver must differ from the operator |
| **Tamper-evident audit log** | ✅ | SHA-256 hash chain, every entry ECDSA-signed; edits, deletions and reordering detected (`audit_log.py`) |
| Signature verification fails closed | ✅ | Previously any signature verified when `cryptography` was missing |

### Measured results (64 MB FAT16 lab image, this workstation)
| Technique | Recall | Precision | Notes |
|---|---|---|---|
| File system (Sleuth Kit) | 6/7 deleted files intact | — | The 7th is fragmented across unallocated garbage; TSK recovers it damaged |
| Carving | 12/13 carvable files | 100% (0 false positives) | Misses only the fragmented JPEG (no checksum to validate a split) |
| **Combined** | **9/9 deleted + orphaned files** | — | ~70–120 MB/s carving throughput |

Erasure: NIST Clear, DoD 3-pass and random pass all verify with full read-back, 0/16 canaries recovered and 0 recoverable files. A deliberately incomplete wipe is rejected (tested).

---

## 3. Competitive Landscape — What Other SIH26149 Teams Show

We reviewed **7 publicly posted SIH26149 demo videos** and **9 public GitHub repositories** (September 2026). For the videos we analysed titles, descriptions and runtime; claims are as stated by each team, not independently verified.

### 3.1 YouTube demonstrations

| Video | Team | Claimed features |
|---|---|---|
| [TraceLock](https://youtu.be/aCbG-Jp-hto) (1:30) | Rising Bytes | Concept pitch: secure recovery with integrity and traceability, "blockchain" theme |
| [Secure-X](https://youtu.be/ejlcsuXyiCs) (1:27) | Lift Up | Sanitize → Verify → Certify, erasure certificate, "secure recovery vault", ITAD, audited workflow |
| [ForenSafe](https://youtu.be/YDkouZfagXQ) (9:20) | Igniters | Cases & evidence, acquisition, SHA-256, carving, **fragment reconstruction**, drive/file/folder erase, NIST 800-88 Rev.2, RBAC (Investigator/Sanitizer/Auditor), chain of custody, signed reports, **air-gapped** operation |
| [Integrated Erasure & Recovery](https://youtu.be/SknC5k1fIm0) (2:56) | Runtime Rebels | PySide6 desktop app, zero-fill, read-only recovery, before/after SHA-256, audit log, ReportLab PDF, NIST 800-86 |
| [Forensic Assurance](https://youtu.be/eE-bAVM5AEI) (6:49) | Aikta | No description published |
| [VANISH](https://youtu.be/tqRTS6Dq6FI) (11:02) | bitmanipulators | "Secure data sanitization and recovery" (no further detail) |
| [ForensicShield](https://youtu.be/JlJlc3ymn68) (5:00) | Technominds | Deleted-file recovery, carving, sanitization, verification, hashing, tamper-evident audit |

### 3.2 GitHub repositories

| Repo | Notable | Stated limitation |
|---|---|---|
| [Blaze-809/SIH-2026](https://github.com/Blaze-809/SIH-2026) (NULLSEC) | Erase → Verify → Recover → Prove loop; JPEG carving; hash-chained JSONL | Synthetic images only; JPEG only |
| [Vigneshe247 — DataShield](https://github.com/Vigneshe247/Secure-Data-Erasure-Recovery) | Media-aware sanitization, 6-format carving, confidence score, 5-role RBAC | Sandbox `.img` demo |
| [pulkit6732/AKHANDA](https://github.com/pulkit6732/AKHANDA) | Dual-signed custody ledger, **BSA 2023 §63** certificate, CFReDS test (66.7% fragmented-PNG recall) | SSDs untested |
| [pushpam2404/sih_149](https://github.com/pushpam2404/sih_149) | pytsk3 + PhotoRec + bulk_extractor wrappers; CoW warnings | Physical drives untested |
| [tevi87637-ship-it/Re-Trace](https://github.com/tevi87637-ship-it/Re-Trace) | Structural validators (PNG CRC, PDF xref, ZIP CD); Ed25519 reports | "Not a physical-drive eraser"; no E01; no fragments |
| [Akarsh-x64 — SanitizeX](https://github.com/Akarsh-x64/Secure-data-erasure-and-recovery) | C++ engines, NTFS/ext4/exFAT/FAT32/XFS, entropy + χ² verification | Controller-dependent |
| [SAYALI8106 — SecureForensics](https://github.com/SAYALI8106/SIH_2026) | Carving + 6-factor confidence score | Simulation only |
| [AbdullahShaikh4226](https://github.com/AbdullahShaikh4226/DataSanitization_SIH26) | C17 / CMake; SHA-256 audit chain | Linux only |

### 3.3 Table stakes (nearly every team has these)
NIST 800-88 / DoD overwrite · signature file carving (JPEG/PNG/PDF/ZIP) · SHA-256 before/after hashing · hash-chained audit log · PDF/JSON report · dashboard. **WipeX must reach parity on all of these (Roadmap Phase 1).**

---

## 4. Research Gaps — What Nobody Is Doing

| # | Gap | Closest competitor | WipeX approach |
|---|---|---|---|
| **G1** | **Recovery-as-Verifier.** Teams verify erasure with entropy or zero-checks, never by trying to recover the data. | Blaze (JPEG-only toy) | Seed canary files → erase → run WipeX's *own* carver and file-system parser against the media. The erasure passes only if **recovery recall = 0**. This links modules M1 and M2 to M3. |
| **G2** | **Artifact-complete file erasure.** Deleting a file still leaves traces: LNK, Jump Lists, thumbcache, Prefetch, `$UsnJrnl`, `$I30` slack, ADS, MFT-resident data, Volume Shadow Copies, ext4 journal. | None (warnings only) | Forensic knowledge drives the erasure. M2 finds and cleans each OS artifact that reveals the erased file existed, which is what NTRO's "metadata removal" requirement asks for. |
| **G3** | **Storage-aware honesty.** A file-level overwrite does not reliably erase data on SSD, TRIM, copy-on-write (APFS/Btrfs/ReFS) or flash media. | DataShield (partial) | Detect media type and file system, **warn the operator**, and escalate to crypto-erase or whole-drive sanitize (already built in M1). |
| **G4** | **Measured performance.** The PS explicitly asks for performance evaluations; almost nobody publishes numbers. | AKHANDA (partial) | Reproducible benchmark on DFRWS 2006/2007 carving challenges, NIST CFReDS and Digital Corpora images. Publish precision, recall and throughput against PhotoRec and Scalpel. |
| **G5** | **Evidence-lock interlock.** The tool is dual-use: the same operator can recover or destroy. | ForenSafe (roles only) | Media or files linked to an open case or **legal hold cannot be erased**. Erasure needs dual approval, and every decision is logged. |
| **G6** | **Real hardware and mobile.** Almost every competitor works only on synthetic disk images. | None | WipeX **already** probes live drives on three operating systems, issues NVMe/ATA/Opal commands and wipes Android devices. |
| **G7** | **Indian legal output.** | AKHANDA only | Certificate annexure under Bharatiya Sakshya Adhiniyam 2023 §63, plus a DPDP Act 2023 erasure record. |
| **G8** | **Pattern-aware verification.** "Entropy = 0 means clean" is wrong after random or crypto-erase passes, which should read ≈ 8 bits/byte. | None | Verify against the *expected* final pattern, then confirm with G1. |

---

## 5. Architecture

```
 Browser UI (Vite, vanilla JS modules, top navigation)
   Overview · Drive Eraser · File Eraser · Recovery · Cases · Audit Log · Verify
                              │  REST / JSON
 FastAPI (main.py) ───────────┼──────────────────────────────────────────────────────────
   erasure.py        M1  methods, keyed passes, pattern read-back, canaries, certificates
   file_eraser.py    M2  storage assessment, ADS, rename/timestamp scrub, trace cleanup
   recovery/         M3  fs_recovery (Sleuth Kit) · carver (structure + gap carving) · formats
   cases.py              cases, evidence acquisition + hashing, legal holds, two-person rule
   audit_log.py          SHA-256 hash chain, ECDSA-signed entries, chain verification
   reports.py            PDF certificate / recovery / file-erasure reports + BSA §63 annexure
   benchmark.py          recall / precision / throughput against ground truth
   lab_images.py         FAT16 image builder with live, deleted, fragmented, orphaned files
   jobs.py               background jobs with progress
   wipe_engine.py        device probing (Win/Linux/macOS), hardware sanitize commands, ADB
                              │
 SQLite (wipex.db) · workspace/ (lab images, evidence copies, recovered files, reports) · keys/
```

---

## 6. Roadmap

### Phase 0 — Idea submission (by 30 Sep 2026)
- [x] Research SIH26149 competitors and identify gaps (this README)
- [ ] PPT (6-slide SIH format): all content maintained in [SIH_PPT_CONTENT.md](SIH_PPT_CONTENT.md)
- [ ] Demo video: erase a lab image → certificate → recover from the evidence image → benchmark

### Phase 1 — Integrated MVP (done)
- [x] Hash-chained, signed audit log with verification and export
- [x] Cases, evidence acquisition with hashing, legal holds, two-person rule
- [x] Structure-validated carver (8 format families) + Sleuth Kit file-system recovery
- [x] File & folder eraser with ADS removal and storage-aware policy
- [x] New UI with a page per module

### Phase 2 — Differentiators (done)
- [x] G1 Recovery-as-Verifier with canaries; G8 pattern-aware verification
- [x] G2 trace cleanup (Windows Recent, Linux recently-used and thumbnails)
- [x] Bifragment gap carving (PNG, ZIP); PDF reports with BSA §63 draft annexure (G7)
- [x] G5 evidence lock

### Phase 3 — Evaluation and hardening (to Grand Finale, Dec 2026)
- [ ] Run the benchmark on DFRWS 2006/2007 and NIST CFReDS images (convert their answer keys to the `truth.json` format) and compare with PhotoRec
- [ ] Validate NVMe/ATA/Opal purge on sacrificial drives (Linux live USB); Windows NVMe sanitize via IOCTL
- [ ] JPEG fragment handling (decoder-driven split search); E01 input
- [ ] Role-based access (Investigator / Sanitizer / Auditor) with per-user keys
- [ ] Offline installer / bootable live image

---

## 7. Quick Start

**Prerequisites:** Python 3.10+, Node.js 18+.

```bash
pip install -r requirements.txt        # fastapi, cryptography, pytsk3 (The Sleuth Kit), reportlab, Pillow
npm install

python -m uvicorn main:app --host 127.0.0.1 --port 8000   # backend
npm run dev                                               # UI on http://localhost:5173
```

On first start WipeX creates two **lab disk images** in `workspace/images/` (a FAT16 disk with live, deleted, fragmented and orphaned files, plus its ground truth). Use them to try every module safely:

1. **Drive Eraser** → pick `lab-disk-01` → NIST Clear → watch the read-back, canary and recovery checks → download the certificate PDF.
2. **Recovery** → scan `evidence-sample` → see deleted files, carved files and the two reassembled fragments → run the benchmark.
3. **File Eraser** → *Sample files* → Analyze → Erase (creates a real alternate data stream and Recent shortcut, then removes them).
4. **Cases** → new case → acquire `evidence-sample` → place a legal hold → try to erase the held device (refused).
5. **Audit Log** → verify the chain; **Verify** → look up a certificate (or scan its QR code).

> ⚠️ **Physical disks:** erasing a real disk needs Administrator rights and destroys all data on it. The active system disk is always refused. Practise on lab images.

### Tests
```bash
python -m unittest discover -s tests -v
```
22 tests: FAT16 image read by The Sleuth Kit, byte-exact carving including fragment reassembly, zero false positives, corrupted PNG/ZIP/JPEG rejection, erasure verification (including a deliberately incomplete wipe that must fail and a random wipe that must pass despite ~8 bits/byte entropy), certificate tamper detection, audit-chain edit and deletion detection, legal holds, two-person rule, evidence hashing, file-eraser guards and ADS removal, benchmark recall/precision.

### Third-party components
| Component | Used for | Licence |
|---|---|---|
| The Sleuth Kit via `pytsk3` | File-system recovery | Apache 2.0 (pytsk3); TSK: CPL / IBM PL / others |
| `cryptography` | ECDSA P-256 signatures, AES-CTR keyed passes | Apache 2.0 / BSD |
| ReportLab | PDF reports | BSD |
| Pillow | Image decode validation, sample content | MIT-CMU |
| qrcode-generator | Certificate QR codes | MIT |
| nvme-cli, hdparm, sedutil-cli (called, not bundled) | Hardware purge on Linux | GPL |

No code was copied from other SIH teams' repositories; erasure follows NIST SP 800-88 and the published tool documentation.

---

## 8. Standards & Legal References
- **NIST SP 800-88 Rev. 2**: Guidelines for Media Sanitization (Clear / Purge / Destroy)
- **NIST SP 800-86**: Guide to Integrating Forensic Techniques into Incident Response
- **IEEE 2883-2022**: Standard for Sanitizing Storage
- **DoD 5220.22-M** (legacy overwrite reference)
- **TCG Opal 2.0**: Self-Encrypting Drive cryptographic erase
- **Bharatiya Sakshya Adhiniyam 2023, §63**: admissibility certificate for electronic records
- **Digital Personal Data Protection Act 2023**: data-erasure obligations

---

## 9. Responsible Use
WipeX is dual-use by design. Recovery features are for **authorised forensic examination** only, and erasure features must not be used to destroy evidence. The evidence-lock interlock (G5), two-person rule and signed audit trail exist to enforce this.
