# WipeX 🛡️

**Zero-Trust Data Sanitization & Hardware-Bound Verification Platform**

WipeX is an enterprise-grade platform for secure physical data erasure, mathematical Shannon entropy verification, hardware health triage, and tamper-proof compliance certificate generation for NVMe SSDs, SATA SSDs, and Magnetic Hard Drives.

---

## 🌟 Key Capabilities

1. **Step-by-Step Guided Sanitization Workflow (6-Phase Wizard)**
   - **Step 1: Select Drive & File Tree Explorer**: Real-time connected storage probing (macOS `diskutil`, Windows PowerShell `Get-Disk`, Linux `lsblk`) with active vs. recoverable deleted file footprint analysis.
   - **Step 2: Choose Method (NIST SP 800-88 Rev. 1 & IEEE 2883-2022)**: Automatic recommendation based on physical media type (NVMe Cryptographic Purge SES=2, SATA Enhanced Security Erase, Single-pass Overwrite Clear).
   - **Step 3: Erase Data (256-Cluster Canvas Visualizer)**: Real-time sector-by-sector write progress, write throughput, and live time-to-completion ETA.
   - **Step 4: Zero-Trust Dual Verification Audit**: Random LBA sampling across the drive computing exact Shannon Entropy $H(X) = 0.000000 \text{ bits/byte}$ and Chi-Square uniformity ($\chi^2, p > 0.999$), distinguishing Raw Block I/O vs. Filesystem Volume audits.
   - **Step 5: Drive Safety Assessment (Circular Economy)**: Traffic light triage (🟢 Safe for Reuse/Resale, 🔴 Physical Shred Mandate).
   - **Step 6: Cryptographic Certificate of Sanitization**: Hardware-bound SHA-256 seal signed with 128-bit digital nonce, vector QR code, and anti-forgery watermarks.

2. **Step Anti-Corruption Safety Lockout**
   - Once wiping begins or completes, backwards navigation to Steps 1, 2, or 3 is locked (`🔒`) to prevent state corruption, accidental double-wipes, or parameter modification.
   - A dedicated **"Wipe Another Drive"** reset action cleanly initializes a fresh cryptographic session for the next drive.

3. **Deep Media Diagnostics & False Alarm Scanner**
   - Eliminates false positive bad sector alerts caused by transient SATA/NVMe CRC bus glitches vs. genuine physical flash cell wear.
   - Performs direct LBA re-read passes across fault zones to verify if a drive can be safely sanitized or must be physically shredded per NIST SP 800-88 §4.4.

4. **Cross-Platform Compatibility (macOS, Windows, Linux)**
   - **Windows**: Uses PowerShell `Get-Disk` / `Get-Partition` for drive discovery, `\\.\PhysicalDriveN` raw device paths, and `Clear-Disk` / `Initialize-Disk` volume sanitization.
   - **macOS**: Uses `diskutil list` / `diskutil info` for storage topology and `diskutil zeroDisk` / `dd` for secure block overwrites.
   - **Linux**: Uses `lsblk`, `nvme-cli` (`nvme format --ses=2`), and `hdparm` (`--security-erase-enhanced`).

5. **Public Verification Portal & Tamper Detection**
   - Real-time ledger lookup by Certificate ID or Drive Serial Number.
   - Automatically detects counterfeit or cloned certificates with an instant `🚨 FRAUD ALERT — SIGNATURE MISMATCH` flag.

6. **Interactive Demo Mode Switch**
   - Top-right toggle to instantly test realistic storage presets (Healthy NVMe, Hidden Partition SATA SSD, Damaged Drive) without requiring physical root privileges.

---

## 🚀 Quick Start

### 1. Run the Frontend UI (Local Preview)
```bash
python3 -m http.server 5173
```
Open **[http://localhost:5173](http://localhost:5173)** in your web browser.

### 2. Run the FastAPI Backend Service (Hardware Mode)
```bash
pip install -r requirements.txt
python3 main.py
```
The REST API starts at `http://localhost:8000` with interactive Swagger docs at `http://localhost:8000/docs`.

### 3. Initialize PostgreSQL Ledger Database (Optional)
```bash
psql -U postgres -d wipex -f database.sql
```

---

## 🔬 Technical Explanation (How It Works)

### Why Third-Party Mathematical Entropy Verification Matters
Competitor tools often display a simple "100% Erased" message based solely on whether the write command returned exit code 0. However, silent SSD controller write errors, bad blocks, or drive write-caching can result in residual data remaining on the physical media.

WipeX solves this through **Zero-Trust Post-Sanitization Sampling**:
1. **LBA Seeking**: Reads 10,000 random sectors across the physical disk geometry.
2. **Shannon Entropy Calculation**: Computes $H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$.
   - Target post-wipe state: $H(X) = 0.000000 \text{ bits/byte}$ (pure $0x00$ null bytes).
   - Residual user data / text: $3.00 \le H(X) \le 6.50 \text{ bits/byte}$.
   - Encrypted data: $H(X) \approx 7.999 \text{ bits/byte}$.
3. **Audit Level Transparency**:
   - `RAW_BLOCK`: Direct unbuffered physical drive I/O (Gold standard).
   - `FILE_LEVEL`: Filesystem volume probe + unallocated space test block check.
   - `SIMULATED`: Interactive client-side demo preset.

### Hardware-Bound Cryptographic Sealing
Every certificate is bound to the physical drive through a cryptographic payload:
$$\text{Digest} = \text{SHA256}(\text{Serial} \mathbin{\Vert} \text{Nonce} \mathbin{\Vert} \text{Method} \mathbin{\Vert} \text{Timestamp})$$
This ensures certificates cannot be copied or re-assigned to other storage media.

---

## 📁 Repository Structure

```
.
├── index.html                  # Master Web UI (Dark Void & Cyber Glass Design)
├── css/
│   └── styles.css              # Custom responsive stylesheet & animations
├── js/
│   ├── app.js                  # Master application controller, step routing & diagnostics
│   ├── app_drive_status.js     # Storage capacity breakdown & action box
│   ├── app_tree_view.js        # File tree explorer with active vs recoverable storage
│   ├── app_modals.js           # Danger modals & 10s destruction countdown timer
│   ├── data/
│   │   ├── mockDevices.js      # Realistic storage presets for Demo Mode
│   │   ├── nistStandards.js    # NIST SP 800-88 & IEEE 2883-2022 standards reference
│   │   └── certificateStore.js # In-memory ledger & tamper detection records
│   └── utils/
│       ├── crypto.js           # Nonce generator & SHA-256 WebCrypto hashing
│       ├── entropy.js          # Shannon Entropy calculator & Chi-square tester
│       └── qrGenerator.js      # Vector SVG QR code generator
├── main.py                     # FastAPI REST API endpoints
├── wipe_engine.py              # Cross-platform hardware sanitizer (Windows / macOS / Linux)
├── entropy_auditor.py          # LBA sampling Shannon Entropy auditor
├── crypto_signer.py            # ECDSA P-256 & SHA-256 hardware binder
├── database.sql                # PostgreSQL central ledger schema
├── requirements.txt            # Python dependencies
├── PROJECT_SPEC.md             # Complete master architectural prompt
└── README.md
```
