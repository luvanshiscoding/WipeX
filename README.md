# WipeX 🛡️

**Zero-Trust Data Sanitization & Hardware-Bound Verification Platform**

WipeX is an enterprise-grade platform for secure physical data erasure, mathematical Shannon entropy verification, hardware health triage, and tamper-proof compliance certificate generation for NVMe SSDs, SATA SSDs, and Magnetic Hard Drives.

---

## 🌟 Key Features

- **Storage Discovery & Tree View Explorer**: Identifies connected drives (NVMe, SATA SSD, HDD), inspects SMART telemetry, and provides a file explorer with active vs. recoverable deleted storage footprints.
- **Hidden Storage Unlocker (HPA/DCO)**: Automatically unlocks protected and hidden storage areas (Host Protected Areas, Device Configuration Overlays) to ensure 100% of physical LBAs are sanitized.
- **NIST SP 800-88 Rev. 1 Compliance**: Protocol selection matching storage media (NVMe Cryptographic Erase SES=2, ATA Enhanced Security Erase, Single-pass Clear).
- **Interactive Live Wipe Visualizer**: 256-cluster sector grid with animated write progress and real-time MB/s throughput telemetry.
- **Zero-Trust Shannon Entropy Audit**: Reads random sectors across the physical disk to mathematically calculate Shannon Entropy ($H(X) = 0.000000$), confirming zero residual data.
- **Safety Traffic Light Rating Engine**:
  - 🟢 **Safe to Reuse / Resell**: 100% sanitized, zero defects, healthy SMART wear life.
  - 🟡 **Aged Hardware (Caution)**: 100% sanitized data, but elevated lifetime hours.
  - 🔴 **Damaged Drive (Physical Shred Mandate)**: Hardware bad sectors prevent 100% erasure.
- **Hardware-Bound Tamper-Proof Certificate**:
  - Bound to drive Serial Number, Model, Unique Nonce (128-bit), and Cryptographic SHA-256 Digest.
  - Vector QR code linking directly to verification portal, printable PDF format, and anti-forgery watermarks.
- **Public Verification Portal**: Real-time certificate lookup detecting counterfeit or transferred certificates.
- **Interactive Demo Mode Toggle**: Header switch enabling 1-click test presets, fast-forward wiping, and sample verification queries.

---

## 🚀 Quick Start

### 1. Run the Frontend UI (Local Preview)
Serve the frontend using Python's built-in HTTP server:
```bash
python3 -m http.server 5173
```
Then visit **[http://localhost:5173](http://localhost:5173)** in your browser.

> The UI runs as a fully functional standalone prototype with realistic mock storage presets, and automatically connects to the FastAPI backend service whenever it is online.

### 2. Run the FastAPI Backend Service (Optional)
```bash
pip install -r requirements.txt
python3 main.py
```
The REST API server will start at `http://localhost:8000` with interactive Swagger docs at `http://localhost:8000/docs`.

### 3. Database Schema (PostgreSQL)
To initialize the central ledger in PostgreSQL:
```bash
psql -U postgres -d wipex -f database.sql
```

---

## 📁 Repository Structure

```
.
├── index.html                  # Main Application UI
├── css/
│   └── styles.css              # Cyber Pro Max Glassmorphic Design System
├── js/
│   ├── app.js                  # Master application controller & Demo Mode state
│   ├── app_drive_status.js     # Storage capacity meters & badge helpers
│   ├── app_tree_view.js        # File and directory hierarchy tree builder
│   ├── app_modals.js           # Danger confirmation modals & countdown timers
│   ├── data/
│   │   ├── mockDevices.js      # Realistic hardware storage presets
│   │   ├── nistStandards.js    # NIST SP 800-88 sanitization standards
│   │   └── certificateStore.js # Public ledger store & tamper detection records
│   └── utils/
│       ├── crypto.js           # SHA-256 hashing & ECDSA signature engine
│       ├── entropy.js          # Shannon Entropy calculation & sector generator
│       └── qrGenerator.js      # Vector SVG QR code generator
├── main.py                     # FastAPI REST backend service
├── wipe_engine.py              # Low-level ATA/NVMe hardware sanitizer
├── entropy_auditor.py          # Mathematical Shannon entropy auditor
├── crypto_signer.py            # Hardware-bound SHA-256 / ECDSA signer
├── database.sql                # PostgreSQL central ledger DDL & schema
├── requirements.txt            # Python dependencies
├── PROJECT_SPEC.md             # Complete master architecture & project prompt blueprint
└── README.md
```

---

## 📖 Complete Master Architecture & Specification
For the detailed end-to-end technical specification, mathematical Shannon entropy proofs, hardware command sets (`nvme-cli`, `hdparm`), database DDL, and full system prompts, refer to **[PROJECT_SPEC.md](PROJECT_SPEC.md)**.
