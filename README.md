# WipeX

**Zero-Trust Data Sanitization, Hardware-Bound Verification, and Tamper-Proof Certification Platform**

WipeX is an enterprise-grade platform for physical storage sanitization, mathematical Shannon entropy auditing, circular economy triage, and cryptographic compliance certification for NVMe SSDs, SATA SSDs, magnetic hard drives, and mobile flash media.

---

## Key Capabilities

### 1. Guided 6-Phase Sanitization Stepper
- **Step 1: Select Drive & File Tree Explorer**: Real-time connected storage discovery (macOS `diskutil`, Windows PowerShell `Get-Disk`, Linux `lsblk`, Android ADB) with active vs. recoverable deleted file footprint analysis.
- **Step 2: Choose Method (Curated ITAD Recycling Tiers)**: Automatic intelligent recommendation based on physical media type:
  - *Standard ITAD Tier*: Quick Single-Pass Zero Clear (NIST SP 800-88 Clear)
  - *NVMe Flash Tier*: NIST SP 800-88 Cryptographic Purge (Native Controller Hardware Key Destruction)
  - *SATA Flash Tier*: NIST SP 800-88 Enhanced Security Erase (Purge with HPA/DCO boundary unfreezing)
  - *Magnetic Platter Tier*: DoD 5220.22-M 3-Pass Overwrite
  - *High-Assurance / Defense Tier*: Peter Gutmann 35-Pass Forensic Magnetic Platter Purge
  - *Mandatory Shred Tier*: NIST SP 800-88 Mechanical Disintegration (<2mm shredding) for failing hardware
- **Step 3: Erase Data (256-Cluster Matrix Visualizer)**: Real-time sector-by-sector write progress, write throughput (MB/s), live ETA, and block state transitions.
- **Step 4: Zero-Trust Mathematical Audit**: Independent read sampling across physical LBA geometry computing exact Shannon Entropy $H(X) = -\sum P(x)\log_2 P(x) = 0.000000 \text{ bits/byte}$.
- **Step 5: Safety Assessment (Circular Economy)**: Traffic-light triage (Green: Safe for Reuse/Resale, Yellow: Internal Reuse, Red: Physical Shred Mandate).
- **Step 6: Cryptographic Certificate & Decentralized Verification**: Hardware-bound SHA-256 digest, NIST P-256 ECDSA digital signature, ISO/IEC 18004 scannable vector QR code, and anti-forgery watermarks.

---

### 2. Full Drive Wipe vs. Selective File/Folder Shredding
- **Full Drive Wipe (Default)**: Sanitizes 100% of the physical storage block device across all sectors, hidden partitions, and overprovisioned blocks.
- **Selective File Wipe**: Allows single-select or multi-select file/folder targeted sanitization via checkboxes in the File Explorer. Overwrites selected target files with cryptographic patterns, resets metadata, truncates file headers, and unlinks from the file system while leaving unselected data intact. Generates a dedicated **Certificate of Targeted File Sanitization**.

---

### 3. Low-Level Kernel & Hardware Storage Engine
- **Direct Raw Block Streaming**: Streams unbuffered binary buffers directly to `/dev/rdiskX` (macOS), `/dev/sdX` / `/dev/nvmeXn1` (Linux), and `\\.\PhysicalDriveX` (Windows).
- **Automated Safe Unmounting**: Automatically forces unmount of active partition mount points before raw block writes.
- **Pre-Wipe MBR Backup**: Backs up the master boot record (first 512 bytes) before erasure.
- **Hardware Controller Purges**: Native NVMe crypto-erase (`nvme sanitize -a crypto`), two-step ATA Enhanced Security Erase (`hdparm --security-set-pass` -> `--security-erase-enhanced`), and TCG Opal 2.0 SED crypto-erase (`sedutil-cli`).
- **Android Mobile Sanitization**: Detects connected Android devices via ADB, executes Fastboot partition format and recovery master clear.

---

### 4. Hardware-Bound Asymmetric Cryptography (NIST P-256 ECDSA)
- Digitally signs certificate digests with a NIST P-256 (secp256r1) ECDSA private key.
- Canonical SHA-256 digest binds drive serial number, model, digital nonce, sanitization standard, timestamp, and outcome.
- Signatures are encoded in Base64 ASN.1 DER format and cryptographically verified in both frontend (Web Crypto API) and backend.

---

### 5. ISO/IEC 18004 Scannable QR Code & Public Verification Portal
- Generated using the standardized `qrcode-generator` engine with Reed-Solomon Error Correction (Level M) and clean 4-module quiet zones.
- **Instant Auto-Detection**: Scanning the QR code with any smartphone camera automatically opens the Public Verification Portal, populates the search bar, recomputes the cryptographic proof offline, and displays the verified certificate details.
- **Anti-Tamper Fraud Alert**: Any alteration to the certificate URL parameters triggers a `FRAUD ALERT — SIGNATURE MISMATCH` warning.

---

### 6. Deep Media Diagnostics & False Alarm Scanner
- Eliminates false positive bad sector alerts caused by transient SATA/NVMe CRC bus glitches vs. genuine physical flash cell wear.
- Performs direct LBA re-read passes across fault zones to verify if a drive can be safely sanitized or must be physically shredded per NIST SP 800-88 §4.4.

---

### 7. Step Anti-Corruption Safety Lockout
- Once wiping begins or completes, backwards navigation to Steps 1, 2, or 3 is strictly locked (`🔒`) to prevent state corruption, accidental double-wipes, or parameter tampering.
- A dedicated **"Wipe Another Drive"** reset cleanly initializes a fresh cryptographic session for the next drive.

---

## Quick Start

### 1. Run the Web Frontend (Static Server)
```bash
python3 -m http.server 5173
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.

### 2. Run the FastAPI Hardware Backend Service
```bash
pip install -r requirements.txt
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```
Interactive Swagger API documentation is available at `http://localhost:8000/docs`.

### 3. Initialize PostgreSQL Ledger Database (Optional)
```bash
psql -U postgres -d wipex -f database.sql
```

---

## Technical Specifications

### Shannon Entropy Post-Wipe Verification
To guarantee zero residual data beyond forensic reconstruction, WipeX computes Shannon Entropy $H(X)$ across 10,000 random sectors:

$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

| Data State | Shannon Entropy $H(X)$ | Audit Verdict |
|---|---|---|
| Zeroed / Purged Media | $0.000000 \text{ bits/byte}$ | **PASSED (100% Clean)** |
| Formatted Filesystem Residue | $0.050000 - 1.200000 \text{ bits/byte}$ | **FAILED (Metadata Leaked)** |
| Plaintext Documents / Code | $3.500000 - 6.500000 \text{ bits/byte}$ | **FAILED (Unwiped Data)** |
| High-Entropy Encrypted / PRNG Residue | $7.990000 - 8.000000 \text{ bits/byte}$ | **FAILED (Residual Encrypted Blocks)** |

---

## Repository Structure

```
.
├── index.html                  # Master Web UI (Dark Void & Cyber Glass Design)
├── css/
│   └── styles.css              # Responsive stylesheet & animations
├── js/
│   ├── app.js                  # Master application controller & step router
│   ├── app_drive_status.js     # Storage explorer, capacity bars & selective file wipe
│   ├── app_modals.js           # Modal popups, 10s destruction countdown & wipe loops
│   ├── data/
│   │   ├── mockDevices.js      # Enterprise drive presets for Demo Mode
│   │   ├── nistStandards.js    # NIST SP 800-88 & ITAD recycling standards catalog
│   │   └── certificateStore.js # Client-side certificate ledger
│   └── utils/
│       ├── crypto.js           # Web Crypto SHA-256 and nonce generator
│       ├── entropy.js          # Shannon entropy calculator
│       └── qrGenerator.js      # ISO/IEC 18004 vector QR code engine
├── main.py                     # FastAPI REST backend service
├── wipe_engine.py              # Low-level raw block & controller sanitization engine
├── entropy_auditor.py          # Multiprocess Shannon entropy audit runner
├── crypto_signer.py            # NIST P-256 ECDSA key management & signing
├── database.py                 # SQLite / PostgreSQL dual-persistence ledger
├── database.sql                # PostgreSQL schema definition
├── keys/                       # ECDSA P-256 public & private key PEMs
└── package.json                # Project dependencies
```
