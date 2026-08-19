# WipeX — Complete Project Architecture & Master Specification

> **System Mission**: WipeX is an Enterprise-Grade Zero-Trust Data Sanitization, Hardware-Bound Verification, and Tamper-Proof Drive Certification Platform. It guarantees that storage devices (NVMe SSDs, SATA SSDs, HDDs, and mobile flash media) and targeted files/folders are sanitized beyond forensic recovery according to **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**, validated through **Mathematical Shannon Entropy audits ($H(X) = 0.000000$)**, evaluated for reuse health via an automated **Circular Economy Triage engine**, and certified using **Hardware-Bound SHA-256 / NIST P-256 ECDSA Cryptographic Proofs**.

---

## System Blueprint & Workflow Architecture

```
CORE SYSTEM WORKFLOW:
1. PHASE 1: Storage Detection & Pre-Wipe Explorer
   - Discover all physical NVMe, SATA SSD, Magnetic HDD, and Android ADB mobile devices.
   - Read SMART telemetry (reallocated sectors, lifetime power-on hours, wear level, temperature).
   - Provide an OS-style File & Directory Tree Explorer calculating active vs. recoverable deleted storage footprints.
   - Support Wipe Scope Selection: Full Physical Drive Sanitization vs. Selective File/Folder Shredding.

2. PHASE 2: Curated ITAD Sanitization Tier Selection
   - Match media type to curated IT Asset Disposition (ITAD) recycling standards:
     * Standard ITAD Tier: Quick Single-Pass Zero Clear (NIST SP 800-88 Clear).
     * NVMe Flash Tier: NIST SP 800-88 Cryptographic Purge (Hardware Key Destruction across all NAND channels).
     * SATA Flash Tier: NIST SP 800-88 Enhanced Security Erase (Voltage pulse reset with HPA/DCO boundary unfreezing).
     * Magnetic Platter Tier: DoD 5220.22-M 3-Pass Overwrite (0x00, 0xFF, PRNG).
     * High-Assurance / Defense Tier: Peter Gutmann 35-Pass Forensic Magnetic Platter Purge.
     * Mandatory Shred Tier: NIST SP 800-88 Mechanical Disintegration (<2mm shredding) for damaged media.

3. PHASE 3: Active Sanitization Engine & 256-Cluster Visualizer
   - Execute kernel-level erasure commands (raw block streaming to /dev/rdiskX, /dev/sdX, \\.\PhysicalDriveX, nvme sanitize, hdparm).
   - Render real-time progress with write speed (MB/s), live ETA, and an interactive 256-cluster sector canvas illustrating active scan pulses and zeroed blocks.
   - Lock backwards navigation (Anti-Corruption Lockout 🔒) to prevent state tampering or double wipes.

4. PHASE 4: Zero-Trust Mathematical Shannon Entropy Engine
   - Perform an independent post-wipe audit reading 10,000+ random LBAs across physical disk geometry.
   - Calculate exact Shannon Entropy: H(X) = -sum(P(x_i) * log2(P(x_i))) in bits/byte.
   - Verify H(X) == 0.000000 across sampled sectors to mathematically prove zero residual data.
   - Trigger instant audit failure if entropy > 0.000000 or unreadable bad sectors are detected.

5. PHASE 5: Circular Economy Safety Assessment
   - 🟢 GREEN (Safe for Reuse/Resale): 100% Cleaned, 0 Bad Sectors, Healthy SMART lifetime (<20,000 hrs).
   - 🟡 YELLOW (Caution - Internal Reuse Only): 100% Cleaned, 0 Bad Sectors, but High Lifetime Hours (>30,000 hrs).
   - 🔴 RED (Mandatory Physical Destruction Order): Hardware bad sectors / read errors prevent 100% wipe.

6. PHASE 6: Hardware-Bound Cryptographic Certificate & Public Ledger
   - Bind drive Serial Number, Model, Unique Nonce (128-bit), Timestamp, and Erasure Digest via SHA-256.
   - Sign certificate with asymmetric NIST P-256 (secp256r1) ECDSA digital signature in Base64 ASN.1 DER format.
   - Render ISO/IEC 18004 compliant vector QR code with embedded decentralized offline verification parameters.
   - Provide a Public Verification Portal detecting counterfeit or altered certificates.
```

---

## Architectural Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          WIPEX FRONTEND WEB UI                              │
│  (Modern Dark Void & Cyber Glass Design System · Responsive · Zero Config)   │
│                                                                             │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌──────────────────┐ │
│  │ 1. Drive &    │ │ 2. Curated    │ │ 3. Real-time  │ │ 4. Entropy       │ │
│  │ File Explorer │ │ ITAD Tiers    │ │ Sector Canvas │ │ Audit Engine     │ │
│  └───────────────┘ └───────────────┘ └───────────────┘ └──────────────────┘ │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌──────────────────┐ │
│  │ 5. Circular   │ │ 6. ECDSA      │ │ 7. Scannable  │ │ Public Ledger &  │ │
│  │ Health Triage │ │ Cryptographic │ │ QR Portal     │ │ Anti-Tamper Hub  │ │
│  └───────────────┘ └───────────────┘ └───────────────┘ └──────────────────┘ │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / REST API (Port 8000)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      WIPEX FASTAPI BACKEND SERVICE                          │
│                                                                             │
│  ┌───────────────────────┐ ┌──────────────────────┐ ┌────────────────────┐  │
│  │ Device Discovery      │ │ Sanitization Engine  │ │ Entropy Auditor    │  │
│  │ (lsblk / diskutil /   │ │ (Raw Block Stream /  │ │ (Shannon H(X) Math │  │
│  │ PowerShell / ADB)     │ │ NVMe / ATA / Opal)   │ │ Multiprocessing)   │  │
│  └───────────────────────┘ └──────────────────────┘ └────────────────────┘  │
│  ┌───────────────────────┐ ┌──────────────────────┐ ┌────────────────────┐  │
│  │ ECDSA NIST P-256      │ │ Dual Database Ledger │ │ Verification API   │  │
│  │ Crypto Signer         │ │ (PostgreSQL / SQLite)│ │ (Tamper Detection) │  │
│  └───────────────────────┘ └──────────────────────┘ └────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Direct Controller & Raw Block I/O
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HOST STORAGE HARDWARE                              │
│  • NVMe PCIe Gen3/Gen4/Gen5 SSDs (/dev/nvmeXn1, /dev/rdiskX)                 │
│  • SATA & SAS Solid State Drives (/dev/sdX, \\.\PhysicalDriveX)              │
│  • Enterprise Magnetic Hard Disk Drives (/dev/sdX)                          │
│  • Android Mobile Flash Storage (ADB / Fastboot Recovery)                   │
│  • Hidden Boundaries (HPA / DCO / Host Protected Partitions)                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Technical Specifications

### 1. Mathematical Shannon Entropy Verification
To guarantee zero residual data beyond forensic reconstruction, WipeX computes Shannon Entropy $H(X)$ across 10,000 random sectors:

$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

- Target state: $H(X) = 0.000000 \text{ bits/byte}$ (pure $0x00$ null bytes).
- Plaintext documents / code: $3.500000 - 6.500000 \text{ bits/byte}$.
- High-entropy encrypted blocks: $7.990000 - 8.000000 \text{ bits/byte}$.

---

### 2. Hardware-Bound Asymmetric Cryptography
Every certificate is bound to the physical drive through a canonical digest and signed using a NIST P-256 ECDSA key pair:

$$\text{Digest} = \text{SHA256}(\text{Serial} \mathbin{\Vert} \text{Model} \mathbin{\Vert} \text{Nonce} \mathbin{\Vert} \text{Method} \mathbin{\Vert} \text{Timestamp} \mathbin{\Vert} \text{Outcome})$$

$$\text{Signature} = \text{ECDSA-Sign}_{K_{\text{private}}}(\text{Digest})$$

The signature is verified both locally in the browser via the Web Crypto API and server-side in Python.

---

### 3. QR Code & Decentralized Offline Verification
- Generated using the ISO/IEC 18004 compliant `qrcode-generator` engine with Reed-Solomon Error Correction (Level M) and 4-module quiet zones.
- Scanning the QR code opens the Public Verification Portal with embedded cryptographic parameters, instantly verifying the hardware-bound proof without requiring central server access.

---

### 4. False Alarm Diagnostics vs. Hardware Faults
- Distinguishes transient SATA/NVMe CRC communication bus errors (SMART Attribute 0xC7 / 0x05 false alarms) from physical NAND wear.
- Performs direct non-destructive LBA read passes across fault zones to verify if a drive can be safely sanitized or must be physically shredded per NIST SP 800-88 §4.4.
