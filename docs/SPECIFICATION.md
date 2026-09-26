# WipeX — System Specification

**SIH 2026 · SIH26149 · NTRO** — integrated secure data erasure and advanced file recovery.

> **Mission:** one offline forensic workstation that (a) securely erases drives, (b) securely erases individual files and folders together with their metadata traces, and (c) recovers deleted files from damaged or formatted media. Every operation is verified, attributed to a person (access profile), logged and reported.

---

## 1. Modules

### M1 — Secure Drive Eraser
| Item | Spec |
|---|---|
| Inputs | Physical drives (SATA HDD/SSD, NVMe, USB pendrives, SD cards, portable disks), Android devices (ADB), disk images |
| Removable media (Windows) | If the disk cannot be taken offline (typical for USB sticks), every volume on it is locked and dismounted (`FSCTL_LOCK_VOLUME`, `FSCTL_DISMOUNT_VOLUME`) for the duration of the write; a volume in use is reported by drive letter |
| Reuse | After a completed erasure: one partition and an empty exFAT, FAT32 or NTFS file system (`POST /api/wipe/{id}/format`); the certificate is unaffected |
| Methods | NIST 800-88 Clear (1 pass), single zero, keyed random, DoD 3-pass, Gutmann 35; Purge: NVMe Sanitize crypto / block erase, NVMe Format with crypto erase, ATA Security Erase, TCG Opal PSID revert; Destroy order |
| Method selection | Per device and OS: firmware capabilities are read from the controller (NVMe Identify SANICAP/FNA, hdparm security state, sedutil) and unavailable methods are shown with the reason |
| Safety | System disk refused; legal-hold lock; two-person rule with password-verified approver; PSID used once and never stored |
| Verification | Pattern read-back (full up to 2 GiB, sampled beyond), before/after change check for firmware purges, canary blocks (images), recovery attempt with M3 |
| Output | Certificate signed by the workstation key and the operator's personal key, with the approver's signed approval embedded; PDF with QR code and BSA §63 annexure draft |
| Code | `engine/erasure.py`, `engine/hw_sanitize.py`, `engine/wipe_engine.py` |

### M2 — Secure File & Folder Eraser
| Item | Spec |
|---|---|
| Inputs | Files and folders on a mounted volume |
| Content erasure | Overwrite (zero / random / 3-pass) → fsync → truncate → 3 random renames → timestamp reset → delete; folders bottom-up |
| Directory entries | Placeholder files take over the slots that held the erased names (FAT/exFAT keep deleted names); with raw access WipeX reads the folder back and repeats in growing batches until no deleted entry carries an erased name |
| Metadata erasure | NTFS alternate data streams; Linux `user.*` and macOS extended attributes (overwritten, then removed) |
| Trace cleanup | Windows: Recent shortcuts, Jump Lists referencing the file, thumbcache (reported). Linux: recently-used.xbel, thumbnails. macOS: parent `.DS_Store`, Gatekeeper quarantine-event record, QuickLook cache, recent-items lists (reported) |
| Storage policy | Detects file system, media type, bus and TRIM (incl. LVM / dm-crypt / btrfs on Linux); rates assurance High / Limited / Not effective and recommends M1 when needed |
| Change journal | NTFS `$UsnJrnl` state detected; optional clearing after erasure (the journal is restarted empty) |
| Verification | Drive check after every erasure: the nearest remaining folder is read straight from the volume with The Sleuth Kit, including deleted subfolders, for the original names and for deleted entries holding the original content (SHA-256). Needs Administrator on Windows, root on Linux/macOS; APFS, Btrfs, ZFS and ReFS cannot be read this way and are reported as not checked. On Windows the NTFS change journal is also searched via `FSCTL_READ_USN_JOURNAL`. Verdict PASS / TRACES_REMAIN / ERASED_UNVERIFIED (drive check could not run) / PARTIAL |
| Guards | Protected system locations, drive roots, mount points and home folders refused; legal holds; two-person rule |
| Code | `engine/file_eraser.py` |

### M3 — Carving & Recovery
| Item | Spec |
|---|---|
| Inputs | Drive letters of USB pendrives, memory cards and disks (whole volume or one folder, read-only, Administrator), raw images, raw devices, E01 images; acquired evidence |
| Acquisition | Read source once → write raw `.dd` or E01 (zlib chunks, case metadata, MD5 + SHA-1 sections) → re-read and re-hash; SHA-256 + MD5 recorded |
| Techniques | (1) File-system metadata via The Sleuth Kit (NTFS, FAT, exFAT, ext2/3/4, HFS+, ISO 9660, partition tables); (2) signature carving with structural validation (JPEG decode, PNG CRC, GIF, BMP, PDF, ZIP/Office member CRC, SQLite, MP4); (3) bifragment gap carving for PNG (chunk CRC), ZIP (member CRC) and baseline JPEG (the entropy-coded data must decode exactly to EOI; restart-marker order checked) |
| Output | Recovered files with SHA-256, offset, technique, validation result, confidence; content status for deleted entries (intact / damaged / overwritten / zeroed by TRIM / unverified); PDF report with a BSA §63 annexure draft |
| Code | `engine/recovery/`, `engine/ewf.py` |

## 2. Cross-cutting services
| Service | Spec |
|---|---|
| Access and roles | The prototype opens without a sign-in page into one of four NTRO access profiles (Lab Administrator, Forensic Investigator, Sanitization Officer, Auditor), switched with *View as*. Each profile is an account with its own role and ECDSA P-256 key; its secret is derived from the workstation signing key, so it can be opened only through the local engine. Named accounts with scrypt password hashes and keys encrypted with the password remain available through the API; a password reset issues a new key and old keys stay verifiable (`engine/users.py`) |
| Audit log | Append-only; entry = `{seq, ts, actor, action, case_id, target, details}`; `hash = SHA-256(prev_hash ‖ canonical JSON)`; signed by the workstation key and, when the actor is signed in, by the actor's key; verification reports the first break (`engine/audit_log.py`) |
| Cases and custody | Cases, evidence items, legal holds; every module action is logged with its case id (`engine/cases.py`) |
| Reports | PDF certificate, recovery report, file-erasure report; JSON audit export including all user public keys (`engine/reports.py`) |
| Benchmark | Recall, precision and throughput per technique and file type against a truth file; raw or E01 images (`engine/benchmark.py`) |
| Storage | One SQLite file, a workspace folder and a keys folder in the per-user data directory (`engine/paths.py`, `store.py`, `database.py`) |

## 3. Workflows

```
RECOVER:  Case → Acquire (raw or E01, hashed, re-verified) → Sleuth Kit + carving → review → PDF report (file hashes, BSA §63 annexure)
ERASE:    Legal-hold check → two-person approval (approver signs in) → erase (M1 / M2) →
          verify: M1 pattern read-back → canaries → recovery attempt with M3 → signed certificate
                  M2 drive check (names, content, NTFS change journal) → report
AUDIT:    Every step → hash-chained entry signed by workstation + person → verifiable at any time
```

## 4. API (`engine/main.py`, OpenAPI docs at `/docs`)
| Area | Endpoints | Permission |
|---|---|---|
| Health | `GET /api/health` | public |
| Access | `GET /api/auth/profiles`, `POST /api/auth/profile` (open an access profile), `GET /api/auth/state`, `POST /api/auth/login` (named accounts), `POST /api/auth/logout`, `POST /api/auth/password` | local requests only |
| Users | `GET /api/roles`, `GET/POST /api/users`, `PATCH /api/users/{username}` | users.manage |
| Devices | `GET /api/devices`, `GET /api/methods`, `POST /api/storage/unfreeze/{id}` | device.read / erasure.run |
| Drive erasure | `POST /api/wipe/start`, `GET /api/wipe/status/{id}`, `POST /api/audit/run/{id}`, `POST /api/wipe/{id}/format` | erasure.run / device.read |
| Certificates | `POST /api/certificates/generate`, `GET /api/verify/{id or serial}` (public), `GET /api/certificates/{id}/pdf`, `GET /api/certificates` | certificate.issue / report.read |
| Android | `GET /api/devices/android`, `POST /api/wipe/android/start` (job) | device.read / erasure.run |
| Lab images | `GET/POST /api/lab/images`, `POST /api/lab/images/{id}/reset`, `DELETE /api/lab/images/{id}` | lab.manage |
| File erasure | `GET /api/fs/list`, `POST /api/files/analyze`, `POST /api/files/erase` (job), `POST /api/files/sandbox`, `GET /api/files/report/{job}.pdf` | files.erase |
| Recovery | `GET /api/recovery/sources`, `POST /api/recovery/scan` (job; source drive / lab / evidence / path, optional folder), `POST /api/recovery/{job}/open`, `GET /api/recovery/file`, `GET /api/recovery/{job}/report.pdf`, `GET /api/recovery/formats`, `POST /api/benchmark` (job) | recovery.run / report.read |
| Jobs | `GET /api/jobs`, `GET /api/jobs/{id}` | signed in |
| Cases | `GET/POST /api/cases`, `GET /api/cases/{id}`, `POST /api/cases/{id}/status`, `POST /api/cases/{id}/evidence` (job, raw or E01), `POST /api/evidence/{id}/verify`, `GET /api/evidence/{id}/info` | case.read / case.manage / evidence.acquire |
| Holds and policy | `POST /api/cases/{id}/holds`, `POST /api/holds/{id}/release`, `GET /api/holds`, `GET/POST /api/settings/dual-approval` | hold.manage / settings.manage |
| Audit | `GET /api/audit/log`, `GET /api/audit/verify`, `GET /api/audit/export` | audit.read |

## 5. Non-functional requirements
- **Forensic soundness:** recovery never writes to source media; evidence is analysed from hashed copies.
- **Offline:** no network access at runtime; the engine serves the UI and accepts only local requests.
- **Honesty:** reports state the verification level actually reached and every method that could not run is explained.
- **Portability:** Windows 10/11, Linux, macOS; see README §5 for the per-OS capability matrix.
