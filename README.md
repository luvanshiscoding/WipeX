# WipeX 🛡️

**Zero-Trust Data Sanitization & Hardware-Bound Verification Platform**

A modern, user-friendly platform for secure data erasure, independent verification, and tamper-proof compliance certificate generation for SSDs and Hard Drives.

---

## 🌟 Key Features

- **Device Discovery & Health Triage**: Identifies connected drives (NVMe, SATA SSD, HDD) and checks for hardware defects.
- **Hidden Storage Unlocker (HPA/DCO)**: Automatically unlocks protected and hidden storage areas so 100% of the drive is wiped.
- **Certified Sanitization (NIST SP 800-88)**: Clear, 1-line options matching media architecture (NVMe Cryptographic Erase, ATA Secure Erase, Single-pass Clear).
- **Interactive Live Wipe Visualizer**: 256-cluster sector grid with animated write progress and a *Fast-Forward Demo ⏩* shortcut.
- **Independent Verification Check**: Reads random sectors across the drive to confirm zero data remains.
- **Safety Traffic Light Score**:
  - 🟢 **Safe to Reuse / Resell**
  - 🟡 **Wiped Clean, but Hardware is Old**
  - 🔴 **Damaged Drive — Must be Shredded**
- **Hardware-Bound Certificate**:
  - Features **Sanitization Method Used** and **Drive Cleaned Status (YES / 100% ERASED)**.
  - Digital SHA-256 hash seal, vector QR code, and 1-Click Print (PDF).
- **Public Verification Portal**:
  - Real-time certificate lookup with anti-tampering and forgery detection.

---

## 🚀 Getting Started

### 1. Run the FastAPI Backend Service
```bash
pip install -r requirements.txt
python3 main.py
```
The REST API server will start at `http://localhost:8000` with interactive Swagger docs at `http://localhost:8000/docs`.

### 2. Run the Frontend UI
Open `index.html` directly in any web browser or serve via:
```bash
python3 -m http.server 5173
```
Then visit `http://localhost:5173`. The UI automatically binds to the live FastAPI backend when running at port 8000, with instant client-side standalone fallback if offline.

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
│   └── styles.css              # Clean, modern light design system
├── js/
│   ├── app.js                  # Master application controller (Hybrid API & Offline)
│   ├── data/
│   │   ├── mockDevices.js      # Storage drive presets (NVMe, SATA, Damaged)
│   │   ├── nistStandards.js    # NIST SP 800-88 sanitization standards
│   │   └── certificateStore.js # Public ledger store & tamper detection
│   └── utils/
│       ├── crypto.js           # SHA-256 hashing & signature simulator
│       ├── entropy.js          # Shannon Entropy calculation & sector generator
│       └── qrGenerator.js      # Standalone vector SVG QR code generator
├── main.py                     # FastAPI REST backend service
├── wipe_engine.py              # Low-level ATA/NVMe hardware sanitizer
├── entropy_auditor.py          # Mathematical Shannon entropy auditor
├── crypto_signer.py            # Hardware-bound SHA-256 / ECDSA signer
├── database.sql                # Complete PostgreSQL central ledger DDL & seeds
├── requirements.txt            # Python dependencies
├── BACKEND_AND_PROJECT_SPEC.md # Full architecture & technical specification
└── README.md
```

---

## 🛠️ Backend & Development Specification
For the complete FastAPI backend implementation, PostgreSQL database schema (DDL), low-level Python wipe scripts (`hdparm`, `nvme-cli`), and Shannon entropy auditor code, see [BACKEND_AND_PROJECT_SPEC.md](BACKEND_AND_PROJECT_SPEC.md).
