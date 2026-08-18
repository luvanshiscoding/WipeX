# WipeX — Complete Project Architecture & Master Specification

> **System Mission**: WipeX is an Enterprise-Grade Zero-Trust Data Sanitization, Hardware-Bound Verification, and Tamper-Proof Drive Certification Platform. It guarantees that storage devices (NVMe SSDs, SATA SSDs, and HDDs) are sanitized beyond forensic recovery according to **NIST SP 800-88 Rev. 1**, validated through **Mathematical Shannon Entropy audits**, evaluated for reuse health via an automated **Traffic Light Rating engine**, and certified using **Hardware-Bound SHA-256 / ECDSA Cryptographic Tokens**.

---

## 📑 Master Project Prompt (System Blueprint)

```markdown
You are building WipeX: an enterprise-grade, zero-trust data sanitization and hardware-bound drive certification system.

CORE SYSTEM REQUIREMENTS & WORKFLOW:
1. PHASE 1: Storage Detection & Pre-Wipe Explorer
   - Discover all physical NVMe, SATA SSD, and Magnetic HDD devices.
   - Read SMART telemetry (reallocated sectors, lifetime power-on hours, wear level, temperature).
   - Provide an OS-style File & Directory Tree Explorer calculating active vs. recoverable deleted storage footprints.
   - Display a high-contrast traffic-light condition tag (Good, Aging, Damaged).

2. PHASE 2: Protected Area Unfreezing & HPA/DCO Removal
   - Detect ATA Security Freezelock, Host Protected Areas (HPA), and Device Configuration Overlays (DCO).
   - Issue controller commands (e.g. `hdparm -N`, `hdparm --dco-restore`, sleep-cycle unfreeze) to ensure hidden LBAs are exposed prior to erasure.

3. PHASE 3: NIST SP 800-88 Protocol Selection
   - Match media type to optimal sanitization standard:
     * NVMe SSD: NIST SP 800-88 Purge via Cryptographic Key Scramble (SES=2) + Flash block zeroing.
     * SATA SSD: NIST SP 800-88 Purge via ATA Enhanced Security Erase (voltage pulse across all NAND blocks).
     * Magnetic HDD: NIST SP 800-88 Clear via Single-Pass 0x00 Overwrite / DoD 5220.22-M Multi-pass.
     * Failing Hardware: NIST SP 800-88 Destroy Order (Mandatory Physical Disintegration <2mm).

4. PHASE 4: Active Sanitization Engine & 256-Cluster Visualizer
   - Execute kernel-level erasure commands (`nvme format`, `hdparm`, or direct LBA stream).
   - Render real-time progress with write speed (MB/s), live ETA, and an interactive 256-cluster sector canvas illustrating active scan pulses and zeroed blocks.

5. PHASE 5: Zero-Trust Dual-Auditor & Mathematical Shannon Entropy Engine
   - Perform an independent audit reading 10,000+ random LBAs across the drive.
   - Calculate exact Shannon Entropy: H(X) = -sum(P(x_i) * log2(P(x_i))) in bits/byte.
   - Verify H(X) == 0.000000 across sampled sectors to mathematically prove zero residual data.
   - Trigger instant audit failure if entropy > 0.000000 or unreadable bad sectors are detected.

6. PHASE 6: Hardware-Bound Health Assessment (Traffic Light Rating)
   - 🟢 GREEN (Safe for Reuse/Resale): 100% Cleaned, 0 Bad Sectors, Healthy SMART lifetime (<20,000 hrs).
   - 🟡 YELLOW (Caution - Internal Reuse Only): 100% Cleaned, 0 Bad Sectors, but High Lifetime Hours (>30,000 hrs).
   - 🔴 RED (Mandatory Physical Destruction Order): Hardware bad sectors / read errors prevent 100% wipe.

7. PHASE 7: Cryptographic Tamper-Proof Certificate & Public Ledger
   - Bind drive Serial Number, Model, Unique Nonce (128-bit), Timestamp, and Erasure Digest via SHA-256.
   - Sign certificate with ECDSA P-256 digital signature.
   - Generate official PDF-printable certificate with vector QR code and anti-tamper watermark.
   - Provide a Public Verification Portal detecting counterfeit or cloned certificates.
```

---

## 🏛️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          WIPEX FRONTEND WEB UI                              │
│  (Modern Dark Void & Cyber Glass Design System · Responsive · Zero Config)   │
│                                                                             │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌──────────────────┐ │
│  │ 1. Drive      │ │ 2. Protected  │ │ 3. Method     │ │ 4. Real-time     │ │
│  │ Explorer Tree │ │ Area Unlock   │ │ Selection     │ │ Sector Canvas    │ │
│  └───────────────┘ └───────────────┘ └───────────────┘ └──────────────────┘ │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌──────────────────┐ │
│  │ 5. Entropy    │ │ 6. Traffic    │ │ 7. Tamper     │ │ Demo Mode &      │ │
│  │ Auditor       │ │ Light Rating  │ │ Proof Cert    │ │ Verification Hub │ │
│  └───────────────┘ └───────────────┘ └───────────────┘ └──────────────────┘ │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / REST API (Port 8000)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      WIPEX FASTAPI BACKEND SERVICE                          │
│                                                                             │
│  ┌───────────────────────┐ ┌──────────────────────┐ ┌────────────────────┐  │
│  │ Device Scanner        │ │ Sanitization Driver  │ │ Entropy Auditor    │  │
│  │ (lsblk / udev / SMART)│ │ (nvme / hdparm / dd) │ │ (Shannon H(X) Math)│  │
│  └───────────────────────┘ └──────────────────────┘ └────────────────────┘  │
│  ┌───────────────────────┐ ┌──────────────────────┐ ┌────────────────────┐  │
│  │ Cryptographic Signer  │ │ PostgreSQL Ledger    │ │ Public Portal API  │  │
│  │ (SHA-256 / ECDSA)     │ │ (Audit Database)     │ │ (Anti-Tamper Auth) │  │
│  └───────────────────────┘ └──────────────────────┘ └────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Direct Controller & Raw Block I/O
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HOST STORAGE HARDWARE                              │
│  • NVMe PCIe Gen3/Gen4/Gen5 SSDs (/dev/nvmeXn1)                             │
│  • SATA & SAS Solid State Drives (/dev/sdX)                                 │
│  • Magnetic Hard Disk Drives (/dev/sdX)                                     │
│  • Hidden Storage Zones (HPA / DCO / Host Protected Partitions)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Deep Technical Specifications

### 1. Mathematical Shannon Entropy Verification

The independent dual-auditor reads raw Logical Block Addresses (LBAs) directly bypassing filesystem caches. For each sampled block of bytes $X$, the empirical probability distribution $P(x_i)$ is computed across all 256 possible byte values ($0x00$ to $0xFF$):

$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i) \quad \text{(bits per byte)}$$

- **Post-Sanitization Target**: $H(X) = 0.000000 \text{ bits/byte}$ ($100\%$ zero-bytes).
- **Residual Unwiped Data**: $3.000000 \le H(X) \le 6.500000 \text{ bits/byte}$ (text, files, binaries).
- **Encrypted / Random Data**: $H(X) \approx 7.999900+ \text{ bits/byte}$ (high randomness).

### 2. Cryptographic Hardware Binding & Tamper Detection

To prevent certificate cloning or forgery across drives:
1. Prior to sanitization, a cryptographically secure 128-bit random nonce is generated.
2. Upon verified sanitization, a canonical hardware-bound string is constructed:
   $$\text{Payload} = \text{SERIAL} \mathbin{\Vert} \text{MODEL} \mathbin{\Vert} \text{METHOD\_ID} \mathbin{\Vert} \text{NONCE} \mathbin{\Vert} \text{ENTROPY} \mathbin{\Vert} \text{TIMESTAMP}$$
3. The SHA-256 digest is generated and signed using ECDSA with curve SECP256R1 (P-256).
4. The public verification portal cross-checks the signature against the centralized immutable ledger. If a certificate ID or hash is cloned to another drive serial, a `FRAUD ALERT — SIGNATURE MISMATCH` warning is triggered.

---

## 🗄️ Database Schema (PostgreSQL DDL)

```sql
CREATE TABLE IF NOT EXISTS sanitization_devices (
    device_id VARCHAR(64) PRIMARY KEY,
    device_path VARCHAR(64) NOT NULL,
    model_name VARCHAR(128) NOT NULL,
    serial_number VARCHAR(128) UNIQUE NOT NULL,
    storage_type VARCHAR(32) NOT NULL,
    capacity_bytes BIGINT NOT NULL,
    reallocated_sectors INT DEFAULT 0,
    power_on_hours INT DEFAULT 0,
    hpa_detected BOOLEAN DEFAULT FALSE,
    dco_detected BOOLEAN DEFAULT FALSE,
    is_frozen BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS wipe_jobs (
    wipe_id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) REFERENCES sanitization_devices(device_id),
    method_id VARCHAR(64) NOT NULL,
    standard_name VARCHAR(128) NOT NULL,
    pre_wipe_nonce VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL, -- 'PENDING', 'RUNNING', 'COMPLETED', 'FAILED'
    progress_percent INT DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS entropy_audits (
    audit_id VARCHAR(64) PRIMARY KEY,
    wipe_id VARCHAR(64) REFERENCES wipe_jobs(wipe_id),
    sampled_sectors_count INT NOT NULL,
    measured_entropy NUMERIC(8,6) NOT NULL,
    audit_passed BOOLEAN NOT NULL,
    unreadable_sectors INT DEFAULT 0,
    audited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
    certificate_id VARCHAR(64) PRIMARY KEY, -- e.g. 'WIPEX-2026-980PRO-8F2B'
    wipe_id VARCHAR(64) REFERENCES wipe_jobs(wipe_id),
    trust_score VARCHAR(16) NOT NULL, -- 'GREEN', 'YELLOW', 'RED'
    sha256_digest CHAR(64) NOT NULL,
    ecdsa_signature TEXT NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

---

## 🛠️ Low-Level Sanitization Commands Reference

| Media Target | Protocol | Hardware Execution Command |
|---|---|---|
| **NVMe SSD** | NIST SP 800-88 Purge | `nvme format /dev/nvme0n1 --namespace-id=1 --ses=2 --force` |
| **SATA SSD** | NIST SP 800-88 Purge | `hdparm --user-master u --security-set-pass wipex /dev/sdX`<br>`hdparm --user-master u --security-erase-enhanced wipex /dev/sdX` |
| **Magnetic HDD** | NIST SP 800-88 Clear | `dd if=/dev/zero of=/dev/sdX bs=4M status=progress conv=fdatasync` |
| **HPA Unlock** | Protected Area Removal | `hdparm -N /dev/sdX` / `hdparm -N p<MAX_SECTORS> /dev/sdX` |
| **DCO Restore** | Configuration Overlay Reset | `hdparm --dco-restore /dev/sdX` |

---

## 🚀 Interactive Demo Mode

The UI includes a built-in **Demo Mode** switch in the top header that allows instant testing without physical root hardware:
- **Demo Presets**: 1-click loading for Healthy NVMe, Hidden Partition SSD, Aging HDD, and Damaged Drive.
- **Fast-Forward Wipe**: Instant 1-second simulation of the 256-cluster sector canvas.
- **Portal Query Chips**: Instant verification test samples (Valid, Caution, and Forged Fraudulent Certificates).
- **Production Toggle**: Toggle OFF Demo Mode anytime to present a clean, production-ready enterprise interface.

---

## 🎨 Frontend Design Integrity & Production Rules

To preserve formal presentation and production-grade polish:
1. **No Informal Developer Notices**: Never inject ad-hoc debug messages, informal status lines, or explanatory developer text into the UI (e.g. avoid adding notes like "Sanitization Completed · Step 1–3 Locked").
2. **Standard Native Controls**: Safety constraints (e.g. step lockouts, method selection before Step 3) must operate cleanly through standard button states (`disabled`), stepper indicator styling (`🔒`), or native toasts.
3. **Pristine Prototype Layout**: Keep all headers, cards, badges, and action footers aligned, properly spaced, and formatted without awkward word wrapping or overflowing badges.
4. **Clean, Decluttered Non-Technical Readability**: Present clear, intuitive metrics for regular and enterprise users. Avoid overwhelming users with raw low-level math or LBA sector counts in standard UI views; instead highlight practical values: Erasure Status, Speed (Instant/Fast), Security Level, and Verification Result.


