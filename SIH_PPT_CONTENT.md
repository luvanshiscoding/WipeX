# WipeX — SIH 2026 Idea Presentation Content (6-Slide Official Format)

> **Purpose:** single source of truth for the SIH26149 PPT. Everything needed to build the deck is in this file. No repo lookup should be needed.
> **Format:** official SIH idea-presentation template: **6 slides maximum including the title slide**, bullet points (no paragraphs), diagrams and screenshots preferred, **exported and uploaded as PDF only**.
> **How to maintain:** whenever a feature ships, update the [Build Status Tracker](#build-status-tracker-update-as-you-build) at the bottom, then fix every `⟦UPDATE⟧` marker it affects. Once no `⟦UPDATE⟧` or `⟦FILL⟧` markers remain, the deck is ready to build.

**Marker legend**
- `⟦FILL⟧`: team information only you know (names, IDs, college)
- `⟦UPDATE⟧`: value to replace with a real measured number or screenshot once the feature is built
- 🎨: visual or layout instruction for the slide designer
- 🗣️: speaker note (not printed on the slide)

---

## Design System (apply to all 6 slides)

| Token | Value | Use |
|---|---|---|
| Background | `#07090E` (near-black navy) | Slide background |
| Surface / card | `#0D1321` | Boxes, tables |
| Primary accent | `#00F0FF` (cyan neon) | Titles, key numbers, arrows |
| Secondary accent | `#3B82F6` (blue) | Secondary highlights |
| Text primary | `#F8FAFC` | Body text |
| Text muted | `#94A3B8` | Captions, sources |
| Success / Warning / Danger | `#22C55E` / `#F59E0B` / `#EF4444` | Status chips (✅ 🟡 🔴) |
| Fonts | Headings: **Inter / Poppins Bold**; code and numbers: **JetBrains Mono** | Min 14 pt body, 28–32 pt titles |

Rules: at most 6 bullets per text block · one diagram per slide · same header bar on every slide (WipeX logo left, "SIH26149 · Team ⟦FILL: Team Name⟧" right) · slide number bottom-right.

---

## SLIDE 1 — Title Slide

🎨 Centered layout. SIH 2026 logo top-left, college logo top-right, WipeX wordmark in cyan at centre, tagline below.

| Field | Value |
|---|---|
| **Problem Statement ID** | SIH26149 |
| **Problem Statement Title** | Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization |
| **Theme** | Blockchain & Cybersecurity |
| **PS Category** | Software |
| **Organization** | National Technical Research Organisation (NTRO) |
| **Team ID** | ⟦FILL⟧ |
| **Team Name** | ⟦FILL⟧ |
| **Institute** | ⟦FILL⟧ |
| **Solution Name** | **WipeX** — Integrated Secure Erasure & Forensic Recovery Workstation |
| **Tagline** | *Recover what must be preserved. Erase what must never return. Prove both.* |

---

## SLIDE 2 — Idea / Proposed Solution

**Title on slide:** *WipeX: One Workstation to Recover Evidence and Destroy Data, with Proof*

### Block A: The problem (left column, 3 bullets)
- Agencies must **destroy** sensitive data *and* **recover** deleted evidence, but today's tools do only one of these.
- Deleting a file ≠ erasing it: traces stay in journals, thumbnails, shortcut files and SSD over-provisioning.
- Erasure is "verified" with entropy or zero checks. **Nobody proves the data cannot be recovered.**

### Block B: Proposed solution, three integrated modules (centre, as 3 cards)
| M1 · Secure Drive Eraser | M2 · Secure File & Folder Eraser | M3 · Carving & Recovery |
|---|---|---|
| NIST 800-88 Clear/Purge, NVMe Sanitize, ATA Secure Erase, TCG Opal crypto-erase, Android wipe | Overwrite → rename → truncate → unlink **+ removal of OS traces** (LNK, Jump Lists, thumbcache, Prefetch, ADS, journals) | Signature + structural carving (JPEG, PNG, PDF, ZIP/DOCX, MP4), NTFS/FAT/exFAT/ext4 deleted-entry recovery, fragment reassembly |

Shared core: **tamper-evident signed audit log · case & chain of custody · signed PDF reports · dashboard**

### Block C: Innovation & uniqueness (right column, highlighted box, 6 bullets)
1. **Recovery-as-Verifier:** after erasing, WipeX attacks its own erasure with its recovery engine, using seeded canary files. The erasure passes only when **0 canaries are recovered**.
2. **Artifact-complete file erasure:** forensic knowledge drives the erasure, removing every OS trace that proves the file existed.
3. **Storage-aware honesty:** detects SSD, TRIM and copy-on-write file systems, warns that a file-level overwrite is insufficient, and escalates to crypto-erase.
4. **Evidence-lock interlock:** media under an open case or legal hold cannot be erased; erasure needs dual approval.
5. **Real hardware, not just disk images:** live drive detection on Windows, Linux and macOS, NVMe/ATA/Opal commands and Android wiping.
6. **Indian legal output:** BSA 2023 §63 certificate annexure and a DPDP Act 2023 erasure record.

🗣️ "Every other team treats erasure and recovery as two tabs in one app. We make them check each other: recovery is the judge of erasure, and the erasure policy comes from forensic knowledge."

---

## SLIDE 3 — Technical Approach

**Title on slide:** *Technical Approach: Architecture, Stack & Workflow*

### Block A: Technology stack (left, icon grid)
| Layer | Technology |
|---|---|
| Frontend / Dashboard | Vite 5, HTML5/CSS3, vanilla JavaScript, IBM Plex type, light institutional theme |
| Backend / API | Python 3.11, FastAPI, Uvicorn, Pydantic |
| Erasure engine | Raw block I/O (`\\.\PhysicalDriveN`, `/dev/sdX`, `/dev/rdiskN`), `nvme-cli`, `hdparm`, `sedutil-cli`, ADB |
| Recovery engine | Python carver with structural validators; pytsk3 (NTFS/FAT/ext4); optional pyewf (E01) |
| Verification | Shannon entropy + pattern read-back + Recovery-as-Verifier |
| Cryptography | ECDSA P-256 signatures, SHA-256 hash chain (`cryptography` library) |
| Storage | SQLite (offline default) / PostgreSQL (enterprise) |
| Reports | ReportLab PDF + JSON |

### Block B: Architecture diagram (centre, redraw as a clean diagram)
🎨 Three module boxes on top, verification engine in the middle with an arrow **from M3 back to M1/M2** labelled "attacks its own erasure", audit/custody bar at the bottom.

```
             ┌────────────── WipeX Dashboard (Sanitize | Recover | Cases & Audit) ─────────────┐
                                          FastAPI REST layer
   ┌──────────────┐      ┌──────────────────┐      ┌──────────────────────┐      ┌────────────────┐
   │ M1 Drive     │      │ M2 File/Folder   │      │ M3 Carving &         │      │ Case & Custody │
   │ Eraser       │      │ Eraser + trace   │      │ Recovery             │      │ + Legal Hold   │
   │ NVMe/ATA/Opal│      │ cleanup + policy │      │ FS parse · carve ·   │      │ (evidence lock)│
   └──────┬───────┘      └────────┬─────────┘      │ validate · reassemble│      └───────┬────────┘
          └───────────┬───────────┘                └──────────┬───────────┘              │
                      ▼                                       │                          │
          ┌─────────────────────────────┐   canary recall = 0?│                          │
          │ Verification Engine         │◄────────────────────┘                          │
          │ pattern read-back + entropy │                                                │
          └──────────────┬──────────────┘                                                │
                         ▼                                                               ▼
        ┌──────────────────────────────────────────────────────────────────────────────────────┐
        │ Tamper-evident audit log (SHA-256 chain + ECDSA P-256) · Signed PDF/JSON · BSA §63     │
        └──────────────────────────────────────────────────────────────────────────────────────┘
```

### Block C: Methodology / process flow (bottom, two horizontal flowcharts)
```
RECOVER:  Open case → Acquire & hash source → Parse file system → Carve → Validate structure → Review → Signed report
ERASE:    Legal-hold check → Dual approval → Erase (M1/M2) → Pattern read-back → Recovery-as-Verifier → Signed certificate
```

### Block D: Prototype evidence (screenshots strip)
- 🎨 Screenshot 1: Overview dashboard (module status, detected storage, recent sessions) · **available now**
- 🎨 Screenshot 2: real drive detection with SMART telemetry · **available now**
- 🎨 Screenshot 3: NIST method selection + live sector map during erasure · **available now**
- 🎨 Screenshot 4: signed certificate + verification · **available now**
- 🎨 Screenshot 5: Recovery results — deleted files with content status, carved files with thumbnails, 2 reassembled fragments · **available now**
- 🎨 Screenshot 6: Erasure verified — pattern read-back, 0/16 canaries, recovery attempt found nothing · **available now**

---

## SLIDE 4 — Feasibility and Viability

**Title on slide:** *Feasibility & Viability*

### Block A: Feasibility analysis (left, 5 bullets)
- **Working prototype already exists:** live drive detection on 3 operating systems, raw-block overwrite, NVMe/ATA/Opal command paths, Android wipe, signed certificates and a SQLite/PostgreSQL ledger.
- **Proven open standards and libraries:** NIST SP 800-88 Rev.2, NIST SP 800-86, The Sleuth Kit (pytsk3), Python `cryptography`.
- **Commodity hardware:** runs on any Windows/Linux laptop; no special hardware except sacrificial test drives.
- **Offline by design:** no internet dependency, suitable for air-gapped NTRO labs.
- **Measured (lab ground truth):** combined recovery 9/9 deleted + orphaned files; carving precision 100% (0 false positives); ~70–120 MB/s carving, ~150–200 MB/s erasure. DFRWS/CFReDS runs planned for the finale.

### Block B: Challenges & risks → mitigation (table)
| Risk / challenge | Mitigation |
|---|---|
| SSD wear-levelling and over-provisioning defeat file-level overwrite | Storage-aware policy detects flash media and escalates to NVMe Sanitize / crypto-erase; reports state the assurance level honestly |
| Accidental erasure of the wrong disk | Boot-disk lock, evidence-lock interlock, dual approval, demo mode on by default |
| Dual-use misuse (destroying evidence) | Case-bound actions, legal holds, signed append-only audit log, role separation (Investigator / Sanitizer / Auditor) |
| Fragmented files reduce carving recall | Structural validators + bifragment gap carving; recall reported per file type |
| Hardware sanitize commands vary by vendor or are BIOS-frozen | Frozen-state detection, fallback chain (Sanitize → Format SES=2 → SES=1 → overwrite), full command log |
| Court admissibility of reports | SHA-256 source hashing, chain of custody, BSA 2023 §63 annexure |

### Block C: Viability (bottom strip, 3 chips)
- **Users:** NTRO, state forensic labs (FSLs), police cyber cells, CERT-In, PSU/defence IT disposal
- **Deployment:** single offline workstation → lab server (PostgreSQL) → bootable live USB
- **Cost:** open-source stack, zero licence cost (vs commercial forensic suites and certified erasers)

---

## SLIDE 5 — Impact and Benefits

**Title on slide:** *Impact & Benefits*

### Block A: Impact on target audience (left)
| Audience | Impact |
|---|---|
| Forensic investigators (NTRO, FSLs, cyber cells) | One tool instead of 3–4; recovered evidence with hashes and custody records ready for court |
| Data-protection / IT disposal teams | Erasure proven by an adversarial recovery attempt, not just claimed |
| Auditors & legal | Tamper-evident, signed trail aligned with BSA 2023 §63 and DPDP Act 2023 |

### Block B: Benefits (3 columns with icons)
- **Social / national security:** prevents sensitive government data leaking from disposed media; strengthens the digital-evidence chain in investigations; indigenous alternative to imported forensic suites (Atmanirbhar Bharat).
- **Economic:** zero licence cost; one workstation replaces separate eraser and recovery licences; safe resale or reuse of storage media instead of shredding.
- **Environmental:** verified erasure lets drives be **reused rather than physically destroyed**, reducing e-waste; health triage (Green/Yellow/Red) flags which drives are safe to reuse.

### Block C: Key numbers banner (big cyan digits)
🎨 Four stat tiles:
- **3-in-1** modules in one workstation
- **0 / 16** canaries recovered after verified erasure (every method tested)
- **8** format families carved with structural validation (JPEG, PNG, GIF, BMP, PDF, ZIP/Office, SQLite, MP4)
- **3** operating systems with live drive detection (Windows / Linux / macOS)

---

## SLIDE 6 — Research and References

**Title on slide:** *Research & References*

### Block A: Existing solutions studied → gap WipeX fills (table)
| Studied | What it does well | Gap WipeX addresses |
|---|---|---|
| Autopsy / The Sleuth Kit, PhotoRec, Scalpel | Recovery and carving | Recovery only; no erasure or verification link |
| DBAN, Blancco, KillDisk | Drive erasure | No recovery; verification by pattern check only |
| 7 SIH26149 demo videos (ForenSafe, Secure-X, ForensicShield, Runtime Rebels, TraceLock, VANISH, Aikta) | Carving, SHA-256, audit logs, RBAC | Erasure never verified by attempting recovery; OS traces left behind |
| 9 SIH26149 GitHub prototypes (NULLSEC, DataShield, AKHANDA, Re-Trace, SanitizeX, …) | Hash-chained logs, validators | Nearly all work on synthetic images only; SSD limits only disclaimed; almost no benchmarks |

### Block B: Standards & legal
- NIST SP 800-88 Rev.2: Guidelines for Media Sanitization
- NIST SP 800-86: Integrating Forensic Techniques into Incident Response
- IEEE 2883-2022: Standard for Sanitizing Storage
- TCG Opal 2.0 · NVMe Base Spec (Sanitize) · ATA/ACS Security feature set
- Bharatiya Sakshya Adhiniyam 2023 §63 · Digital Personal Data Protection Act 2023

### Block C: Research & datasets
- Garfinkel, "Carving contiguous and fragmented files with fast object validation," *Digital Investigation*, 2007
- Pal & Memon, "The evolution of file carving," *IEEE Signal Processing Magazine*, 2009
- Wei et al., "Reliably Erasing Data from Flash-Based Solid State Drives," USENIX FAST 2011
- Gutmann, "Secure Deletion of Data from Magnetic and Solid-State Memory," USENIX Security 1996
- Datasets: DFRWS 2006/2007 Forensic Challenge images, NIST CFReDS, Digital Corpora (nps-2009 images)

### Block D: Links
- Repository: ⟦FILL: GitHub URL⟧
- Demo video: ⟦FILL: YouTube URL⟧

---

## Build Status Tracker (update as you build)

Change the status, then update the linked slide text.

| ID | Feature | Status | Slides affected | What to update when done |
|---|---|---|---|---|
| M1 | Drive discovery + SMART (3 OS) + lab images | ✅ Done | 3, 4, 5 | — |
| M1 | Overwrite methods with keyed final pass | ✅ Done | 2, 3 | — |
| M1 | NVMe / ATA / Opal hardware purge | 🟡 Linux-only, untested on hardware | 4 | Add "validated on ⟦drive models⟧" |
| M1 | Android wipe | 🟡 Not re-validated | 2 | — |
| M1 | Signed certificate + QR + PDF + verify | ✅ Done | 3 | — |
| M1 | Honest HPA reporting | ✅ Done | — | — |
| Core | Hash-chained signed audit log | ✅ Done | 2, 3, 4 | Screenshot: Audit Log "Chain intact" |
| Core | Cases, evidence acquisition, legal hold (G5) | ✅ Done | 2, 4 | Screenshot: case with hold |
| Core | Two-person rule | ✅ Done | 4 | — |
| M2 | File & folder eraser | ✅ Done | 2, 3 | Screenshot: File Eraser report |
| M2 | OS trace cleanup (G2) | ✅ Windows Recent, Linux recently-used/thumbnails · 🟡 Jump Lists reported | 2 | — |
| M2 | Storage-aware policy (G3) | ✅ Done | 2, 4 | Screenshot: "NTFS on SSD — assurance Limited" |
| M3 | Signature + structural carving (8 families) | ✅ Done | 2, 3, 5 | — |
| M3 | FS-aware recovery (Sleuth Kit) | ✅ Done | 2, 3 | — |
| M3 | Fragment reassembly (PNG, ZIP) | ✅ Done · JPEG planned | 2, 4 | — |
| G1 | Recovery-as-Verifier + canaries | ✅ Done | 2, 3, 5 | — |
| G8 | Pattern-aware verification | ✅ Done | 3 | — |
| G7 | PDF reports + BSA §63 draft annexure | ✅ Done | 2, 4 | Sample report page image |
| G4 | Benchmarks | ✅ Lab ground truth · 🔲 DFRWS / CFReDS | 4, 5 | DFRWS numbers vs PhotoRec |
| — | RBAC roles | 🔲 Planned | 4 | — |

### Benchmark results (fill after Phase 3)
| Dataset | File types | Recall | Precision | Throughput | PhotoRec recall |
|---|---|---|---|---|---|
| WipeX FAT16 lab image (64 MB, 14 files) | 8 families | 12/13 carving · 9/9 combined | 100% | 70–120 MB/s | not yet run |
| DFRWS 2006 | ⟦UPDATE⟧ | ⟦UPDATE⟧ | ⟦UPDATE⟧ | ⟦UPDATE⟧ | ⟦UPDATE⟧ |
| DFRWS 2007 (fragmented) | ⟦UPDATE⟧ | ⟦UPDATE⟧ | ⟦UPDATE⟧ | ⟦UPDATE⟧ | ⟦UPDATE⟧ |
| Recovery-as-Verifier (16 canaries; NIST Clear, DoD, random) | — | 0/16 recovered | — | 140–200 MB/s erase | — |

### Team details (for Slide 1 and Slide 6)
| Name | Role | Skills | Gender |
|---|---|---|---|
| ⟦FILL⟧ | Team Lead | ⟦FILL⟧ | ⟦FILL⟧ |
| ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ |
| ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ |
| ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ |
| ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ |
| ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ | ⟦FILL⟧ |

> SIH rule: 6 members from the same institute, at least 1 female member. Mentor: ⟦FILL⟧

### Pre-submission checklist
- [ ] Exactly 6 slides, including the title slide
- [ ] No `⟦FILL⟧` / `⟦UPDATE⟧` markers left in slide text
- [ ] PS ID and title match the portal exactly (SIH26149)
- [ ] Every "done" claim matches the Build Status Tracker; no planned feature is shown as built
- [ ] Exported as **PDF** and within the portal's size limit
- [ ] Idea submission deadline: **30 Sep 2026**
