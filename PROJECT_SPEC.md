# WipeX — Enterprise System Specification & Technical Blueprint

> **System Mission**: WipeX is an Enterprise-Grade Zero-Trust Physical Data Sanitization, Mathematical Entropy Verification, and Tamper-Proof Certification Platform. Built exclusively for corporate IT asset governance, enterprise data centers, and accredited ITADs (IT Asset Disposition), WipeX guarantees that physical storage hardware (NVMe SSDs, SATA SSDs, Enterprise HDDs) is sanitized beyond forensic recovery according to **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**, validated through **Mathematical Shannon Entropy audits ($H(X) = 0.000000$)**, evaluated for reuse health via an automated **Circular Economy Triage engine**, and certified using **Hardware-Bound NIST P-256 ECDSA Cryptographic Proofs**.

---

## 🔒 Enterprise Access Governance & Business Model

### 1. Restricted Enterprise-Only Access Architecture
To prevent malicious misuse—such as criminal cyber-theft evidence destruction, forensics evasion, or unvetted data obliteration—WipeX is deliberately designed as a **Restricted B2B Compliance Platform**:
- **Zero Public Access**: The platform is not deployed as an open consumer tool.
- **Enterprise Identity Verification**: Prospective organizations (ITAD vendors, Enterprise IT asset teams, Defense & Telecom infrastructure teams) undergo formal corporate verification.
- **Accreditation Vetting**: Verification of industry credentials (e.g., ISO 27001, R2v3, e-Stewards, NAID AAA).
- **Cryptographic Tenant Provisioning**: Verified enterprise operators receive cryptographically signed workstation licenses tied to corporate hardware security keys.

---

## 🏛️ Master System Workflow Architecture (5-Phase Stepper)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      WIPEX ENTERPRISE WORKFLOW ENGINE                             │
└──────────────────────────────────────────────────────────────────────────────────┘

 [ Phase 1: Drive Discovery & Forensic Audit ]
   │
   ├─► Real Physical Topology (macOS diskutil / Linux lsblk / Windows IOCTL)
   ├─► SMART Telemetry (Reallocated Sectors, Power-On Hours, Wear %, Temp)
   └─► Forensic Footprint Engine (Active Files vs. Recoverable Deleted/Trash & FSEvents)
   │
   ▼
 [ Phase 2: Curated ITAD Sanitization Tier Selection ]
   │
   ├─► Standard ITAD Tier: NIST SP 800-88 Clear (0x00 Single-Pass)
   ├─► NVMe Flash Tier: NIST SP 800-88 Crypto Purge (Hardware Controller Key Destruction)
   ├─► SATA Flash Tier: NIST SP 800-88 Enhanced Security Erase (Voltage pulse + HPA/DCO unfreeze)
   ├─► Magnetic Tier: DoD 5220.22-M (3-Pass: 0x00, 0xFF, PRNG)
   ├─► Defense Tier: Peter Gutmann (35-Pass Overwrite)
   └─► Damaged Drive Tier: NIST SP 800-88 Physical Disintegration Mandate (<2mm)
   │
   ▼
 [ Phase 3: Hardware Sanitization & 256-Cluster Matrix ]
   │
   ├─► Raw Block Kernel Streaming (/dev/rdiskX, /dev/sdX, \\.\PhysicalDriveX)
   ├─► 256-Cell Dynamic Cluster Matrix Visualizer with Live Throughput (MB/s) & ETA
   └─► Anti-Corruption Lockout (🔒 Locks backward phases to prevent session tampering)
   │
   ▼
 [ Phase 4: Zero-Trust Verification & Circular Economy Safety Assessment ]
   │
   ├─► Mathematical Shannon Entropy Audit: H(X) = -sum(P(x) * log2(P(x))) across 10,000 LBAs
   │     • Target: H(X) == 0.000000 bits/byte (100% Certified Data Destruction)
   │     • Non-Zero / Slack Residue Detected -> Instant Audit Fail
   └─► Circular Economy Triage:
         • 🟢 GREEN (Safe for Secondary Market / Resale)
         • 🟡 YELLOW (Internal Corporate Redeployment Only)
         • 🔴 RED (Mandatory Physical Shred Destruction Order)
   │
   ▼
 [ Phase 5: Hardware-Bound NIST P-256 ECDSA Certificate ]
   │
   ├─► Hardware Binding: SHA-256(Serial || Model || Nonce || Method || Timestamp || Outcome)
   ├─► Digital Signature: NIST P-256 (secp256r1) ECDSA Private Key Signing
   └─► Delivery: Clean Print/PDF Export + Automatic Synchronization to Dual Audit Ledger
```

---

## 🔬 WipeX vs. ZeroTrace: Technical Comparison

| Technical Dimension | ZeroTrace | WipeX Enterprise Platform |
|---|---|---|
| **Access & Distribution** | Publicly accessible code/app with zero access controls | **Restricted Enterprise B2B**: Strict business verification & compliance screening to prevent malicious evidence destruction. |
| **Data Verification** | Naive zero-byte sampling (`0x00` check on a few sectors) | **Mathematical Shannon Entropy Audit**: Multiprocess verification of 10,000 LBAs proving $H(X) = 0.000000$, catching encrypted payload residue & filesystem metadata. |
| **Forensic Undelete Detection** | None (Blind disk wipe without analysis) | **Deep Forensic Footprint Engine**: Discovers active files, unallocated clusters, transaction journals (`.fseventsd`), and OS trash remnants. |
| **Hardware Controller Purge** | Generic user-space file overwriting / basic `dd` commands | **Native Controller Purge**: NVMe hardware crypto sanitize (`nvme sanitize -a crypto`), ATA Enhanced Security Erase, and HPA/DCO boundary unfreezing. |
| **Circular Economy Scoring** | None | **Automated ITAD Triage**: Multi-metric SMART telemetry & wear analysis outputting Green (Resale), Yellow (Internal Reuse), or Red (Shred). |
| **Cryptographic Provenance** | Unsigned simulated PDF certificates | **NIST P-256 ECDSA Digital Signatures**: Cryptographically binds hardware serial, nonce, and erasure digest with instant verification API. |
| **Audit Ledger** | Local non-persistent session state | **Enterprise Dual-Ledger Architecture**: Persistent PostgreSQL & SQLite historical records with downloadable compliance certs. |

---

## 💾 Centralized Historical Audit Ledger

WipeX provides an integrated **History & Audit Registry**:
1. **Wipe Sessions Ledger**: Complete chronological ledger of every sanitization operation:
   - Device ID & Hardware Serial Number
   - Media Architecture & Sanitization Standard Executed
   - Sector Count & Mathematical Audit Result
   - Operator Timestamp & Execution Duration
2. **Certificate Vault**:
   - Centralized searchable catalog of all issued compliance certificates.
   - On-demand PDF export and cryptographic verification.
   - Dual database synchronization (PostgreSQL data center cluster + local SQLite `wipex.db`).

---

## 🛡️ Security & Cryptographic Specifications

### 1. Shannon Entropy Formula
$$	ext{Entropy } H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
- **Purged/Zeroed State**: $H(X) = 0.000000 	ext{ bits/byte}$
- **Filesystem Remnants / Metadata**: $0.050000 - 1.200000 	ext{ bits/byte}$
- **Plaintext Data**: $3.500000 - 6.500000 	ext{ bits/byte}$
- **Encrypted / Random Data**: $7.990000 - 8.000000 	ext{ bits/byte}$

### 2. Digital Signature Specification
- **Algorithm**: ECDSA over NIST P-256 (secp256r1) with SHA-256
- **Encoding**: ASN.1 DER (Base64-encoded)
- **Canonical Digest**:
  $$	ext{Digest} = 	ext{SHA256}(	ext{Serial} \mathbin{\Vert} 	ext{Model} \mathbin{\Vert} 	ext{Nonce} \mathbin{\Vert} 	ext{Method} \mathbin{\Vert} 	ext{Timestamp} \mathbin{\Vert} 	ext{Outcome})$$
