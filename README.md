# WipeX — Enterprise Data Sanitization & Hardware Compliance Platform

**Enterprise-Exclusive Zero-Trust Physical Media Sanitization, Mathematical Shannon Entropy Verification, and Cryptographic Compliance Ledger**

---

> ### 🔒 Restricted Access Notice
> **WipeX is an enterprise B2B platform exclusively accessible to verified IT organizations, ITADs (IT Asset Disposition), Enterprise Data Centers, and Certified Electronics Recyclers.**  
> *To prevent malicious abuse—including unauthorized forensic tampering or cyber-theft evidence destruction—WipeX is not offered as an unvetted public utility. Prospective enterprise clients undergo strict corporate identity validation, compliance accreditation screening (e.g., ISO 27001, R2v3, e-Stewards), and key-authorized provisioning before access is granted.*

---

## 🏢 Business Model & Enterprise Ecosystem

WipeX is architected specifically for corporate IT asset governance, enterprise decommissioning, and circular economy compliance:

```
                               ┌─────────────────────────────────────────┐
                               │   ENTERPRISE ONBOARDING & VERIFICATION  │
                               │  • Corporate & ITAD Accreditation Check │
                               │  • ISO 27001 / R2v3 / e-Stewards Audit  │
                               │  • Cryptographic Tenant Key Assignment  │
                               └────────────────────┬────────────────────┘
                                                    │
                                                    ▼
                               ┌─────────────────────────────────────────┐
                               │       WIPEX ENTERPRISE WORKSTATION      │
                               │  • Multi-Tier Physical Drive Sanitize   │
                               │  • Forensic Footprint & Undelete Audit  │
                               │  • Mathematical Shannon Entropy Engine  │
                               │  • Circular Economy Health Assessment   │
                               └────────────────────┬────────────────────┘
                                                    │
                                                    ▼
                               ┌─────────────────────────────────────────┐
                               │     COMPLIANCE & AUDIT TRAIL LEDGER     │
                               │  • NIST P-256 ECDSA Tamper-Proof Certs  │
                               │  • Historical Session & Log Archives    │
                               │  • Immutable PostgreSQL/SQLite Ledger   │
                               │  • Audit-Ready PDF / JSON Cert Exports  │
                               └─────────────────────────────────────────┘
```

---

## ⚡ Key Architecture & Core Workflow

WipeX utilizes a structured **5-Phase Hardware Sanitization Stepper**:

### 1. Phase 1: Select Storage Drive & Real Forensic Footprint Inspection
- **Hardware Discovery**: Direct physical disk topology probing via macOS `diskutil`, Linux `lsblk`, and Windows storage APIs.
- **Forensic Footprint & Undelete Analysis**: Scans active filesystem data, OS Trash bins, transaction journals (`.fseventsd`), and unallocated sectors. Shows organizations exactly which active files and permanently deleted unlinked files remain recoverable on unsanitized drives.
- **SMART Health Telemetry**: Live extraction of power-on hours, raw operating temperature, reallocated sector counts, and SSD wear percentages.

### 2. Phase 2: Curated ITAD Sanitization Tier Selection
- **Intelligent Media-Aware Matching**: Automatically evaluates disk controller architecture and recommends the exact regulatory erasure standard:
  - **Standard ITAD Tier**: NIST SP 800-88 Rev. 1 Clear (Single-Pass 0x00 Overwrite).
  - **NVMe Flash Tier**: NIST SP 800-88 Cryptographic Purge (Instant hardware encryption key destruction across all NAND channels).
  - **SATA Flash Tier**: NIST SP 800-88 Enhanced Security Erase (Firmware-level block voltage purge with HPA/DCO unfreezing).
  - **Magnetic Platter Tier**: DoD 5220.22-M 3-Pass Military Overwrite (`0x00`, `0xFF`, Cryptographic PRNG).
  - **High-Assurance / Defense Tier**: Peter Gutmann 35-Pass Forensic Magnetic Platter Purge.
  - **Mandatory Shred Tier**: NIST SP 800-88 Mechanical Disintegration (<2mm shred mandate for damaged media).

### 3. Phase 3: Hardware Sanitization & 256-Cluster Matrix Visualizer
- **Raw Block Streaming**: Unbuffered binary block I/O directly streaming to block devices (`/dev/rdiskX`, `/dev/sdX`, `\\.\PhysicalDriveX`).
- **Real-Time Matrix Visualizer**: 256-cell interactive canvas displaying active write sweeps, block completions, live throughput (MB/s), and real-time remaining ETA.
- **Anti-Corruption Safety Lockout (`🔒`)**: Irrevocably seals Phase 1 and 2 parameters once wiping begins, preventing session hijacking or double-wipe state corruption.

### 4. Phase 4: Zero-Trust Verification & Circular Economy Safety Assessment
- **Mathematical Shannon Entropy Audit**: Independent post-wipe verification sampling 10,000 LBAs across physical geometry to prove absolute data destruction:
  $$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i) = 0.000000 \text{ bits/byte}$$
- **Circular Economy Triage Health Score**:
  - 🟢 **GREEN (Safe for Resale / Secondary Market)**: $H(X) = 0.000000$, 0 bad sectors, health $\ge 90\%$, lifetime $< 20,000\text{ hrs}$.
  - 🟡 **YELLOW (Internal Corporate Redeployment Only)**: $H(X) = 0.000000$, healthy cells, but elevated hours ($> 30,000\text{ hrs}$).
  - 🔴 **RED (Mandatory Physical Shred Order)**: Physical sector errors, SMART threshold tripping, or audit failure.

### 5. Phase 5: Hardware-Bound NIST P-256 ECDSA Certificate
- **Asymmetric Cryptographic Binding**: Binds physical drive Serial Number, Model, sanitization standard, timestamp, and 128-bit digital nonce into a canonical SHA-256 digest.
- **ECDSA Signature**: Digitally signed using a secure NIST P-256 (secp256r1) ECDSA private key.
- **Export & Verification**: Instant PDF generation, clean print stylesheets, and backend cryptographic validation.

---

## 📜 Audit Trail & Historical Ledger Tab

WipeX includes a centralized **History & Audit Hub**:
- **Wipe Sessions Registry**: Detailed audit trail of every past sanitization run (Device ID, model, method, operator timestamp, sector count, duration, final status).
- **Certificate Vault**: Searchable historical certificate repository with instant PDF / JSON redownloads.
- **Dual Database Persistence**: Seamless synchronization to PostgreSQL (port 5432) for enterprise data center logging with automatic local SQLite fallback (`wipex.db`).
- **One-Click Ledger Maintenance**: Granular audit trail clearing and database maintenance controls.

---

## 🔬 WipeX vs. ZeroTrace: Impactful Differences

| Feature Dimension | ZeroTrace | WipeX Enterprise Platform |
|---|---|---|
| **Access Model** | Unverified public utility (High risk of forensic evasion / evidence destruction abuse) | **Enterprise-Vetted B2B**: Strict business verification & compliance screening before deployment. |
| **Post-Wipe Verification** | Blind zero-byte check (samples a few bytes for `0x00` values) | **Mathematical Shannon Entropy Audit**: 10,000 LBA sampling proving $H(X) = 0.000000$, catching encrypted fragments, slack space, & metadata leaks. |
| **Pre-Wipe Forensic Visibility** | None (No visibility into drive content or recoverable files) | **Active Forensic Footprint & Undelete Engine**: Surfaces active files, unallocated clusters, transaction logs (`.fseventsd`), and OS trash remnants. |
| **Hardware Controller Purge** | Generic user-space file overwriting / basic `dd` commands | **True Hardware Controller Purge**: Native NVMe crypto sanitize (`nvme sanitize -a crypto`), ATA Enhanced Security Erase, and HPA/DCO boundary unfreezing. |
| **Circular Economy Triage** | No diagnostic health analysis | **Automated ITAD Triage**: Multi-metric SMART telemetry & wear analysis outputting Green (Resale), Yellow (Internal Reuse), or Red (Shred). |
| **Tamper-Proof Audit Certificates** | Unsigned simulated PDF certificates | **NIST P-256 ECDSA Digital Signatures**: Cryptographically binds hardware serial, nonce, and erasure digest with instant verification API. |
| **Historical Compliance Ledger** | Basic local session storage | **Enterprise Dual-Ledger Architecture**: Persistent PostgreSQL & SQLite historical records with downloadable compliance certs. |

---

## 🚀 Deployment & Installation

### Prerequisites
- Python 3.9+ with virtual environment support
- Node.js 18+ & npm
- macOS 12+, Ubuntu Linux 20.04+, or Windows 10/11 Enterprise

### 1. Launch FastAPI Backend
```bash
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

### 2. Launch Enterprise Frontend
```bash
npm install
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.

---

## ⚖️ Compliance Standards Implemented
- **NIST Special Publication 800-88 Revision 1**: Guidelines for Media Sanitization (Clear & Purge).
- **IEEE 2883-2022**: Standard for Sanitizing Storage.
- **DoD 5220.22-M (National Industrial Security Program Operating Manual)**.
- **Peter Gutmann 35-Pass Secure Magnetic Media Purge**.
- **TCG Opal 2.0 / Enterprise Self-Encrypting Drive (SED) Protocols**.

---

## 📄 License & Compliance Notice
Enterprise proprietary software. Unauthorized reproduction, unverified distribution, or malicious deployment is strictly prohibited under international cyber security statutes and enterprise licensing agreements.
