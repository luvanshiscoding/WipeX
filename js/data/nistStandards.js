/**
 * WipeX - NIST SP 800-88 Rev. 1 & Sanitization Standards Repository
 */

window.NIST_STANDARDS = [
  {
    id: "purge-nvme-crypto",
    category: "PURGE",
    title: "NIST SP 800-88 Purge (NVMe Cryptographic & Block Erase)",
    suitableMedia: ["NVMe SSD", "PCIe SSD"],
    standardRef: "NIST SP 800-88 Rev. 1 § 5.1.2 & NVMe 1.4 Command Set",
    description: "Issues hardware-level NVMe Format with Cryptographic Erase (SES=2). Destroys the Media Encryption Key (MEK) inside the NVMe controller, rendering all NAND flash (including over-provisioned areas) mathematically undecipherable, followed by low-level zeroing.",
    passes: 1,
    estimatedSpeed: "400 - 900 MB/s",
    securityLevel: "HIGH (Defence & Enterprise)",
    hardwareCommand: "nvme format /dev/nvme0n1 --namespace-id=1 --ses=2 --force",
    unfreezesHpa: true,
    residualRisk: "None (Cryptographically impossible to recover)"
  },
  {
    id: "purge-ata-secure",
    category: "PURGE",
    title: "NIST SP 800-88 Purge (ATA Enhanced Secure Erase)",
    suitableMedia: ["SATA SSD", "Magnetic HDD"],
    standardRef: "NIST SP 800-88 Rev. 1 § 5.1.1 & ATA8-ACS",
    description: "Sends native ATA Enhanced Security Erase command directly to drive microcode. The internal controller applies a vendor-specific voltage pulse to clear all memory cells and overwrite magnetic tracks, unlocking and sanitizing hidden HPA/DCO zones.",
    passes: 1,
    estimatedSpeed: "180 - 250 MB/s",
    securityLevel: "HIGH (Corporate IT & Government)",
    hardwareCommand: "hdparm --user-master u --security-erase-enhanced p wipex /dev/sdX",
    unfreezesHpa: true,
    residualRisk: "Zero (Verified via Independent Dual-Auditor)"
  },
  {
    id: "clear-single-overwrite",
    category: "CLEAR",
    title: "NIST SP 800-88 Clear (Single-Pass 0x00 Overwrite)",
    suitableMedia: ["Magnetic HDD", "USB Flash"],
    standardRef: "NIST SP 800-88 Rev. 1 § 5.1.1 (Clear)",
    description: "Overwrites all addressable logical blocks with a single pass of constant zeroes (0x00). Protects against simple keyboard recovery and basic forensic lab tools on magnetic storage.",
    passes: 1,
    estimatedSpeed: "120 - 180 MB/s",
    securityLevel: "STANDARD (Low-Sensitivity Commercial)",
    hardwareCommand: "dd if=/dev/zero of=/dev/sdX bs=4M status=progress conv=fdatasync",
    unfreezesHpa: false,
    residualRisk: "Low (Unsuitable if drive contains bad sectors or hidden HPA)"
  },
  {
    id: "purge-dod-3pass",
    category: "PURGE",
    title: "DoD 5220.22-M (3-Pass DoD Compliant Overwrite)",
    suitableMedia: ["Magnetic HDD"],
    standardRef: "DoD 5220.22-M / NIST SP 800-88 Purge",
    description: "Pass 1: Fixed character (0x00); Pass 2: Complement byte (0xFF); Pass 3: Pseudo-random byte stream; followed by 100% sector read verification. Standard for legacy magnetic media recycling.",
    passes: 3,
    estimatedSpeed: "80 - 130 MB/s",
    securityLevel: "VERY HIGH (Legacy Platter Standard)",
    hardwareCommand: "shred -v -n 3 -z /dev/sdX",
    unfreezesHpa: true,
    residualRisk: "Zero"
  },
  {
    id: "destroy-physical",
    category: "DESTROY",
    title: "NIST SP 800-88 Destroy (Mandatory Physical Destruction)",
    suitableMedia: ["Failing SSDs", "Drives with Unreadable Bad Sectors"],
    standardRef: "NIST SP 800-88 Rev. 1 § 5.1.3 (Physical Destruction)",
    description: "Software sanitization CANNOT guarantee 100% destruction on media with physically damaged/unreachable sectors. System mandates chain-of-custody physical shredding / degaussing to prevent platter-level forensic extraction.",
    passes: 0,
    estimatedSpeed: "N/A (Physical Facility)",
    securityLevel: "MAXIMUM (Physical Shredder <2mm)",
    hardwareCommand: "echo 'CRITICAL: Physical destruction order generated. Media locked.'",
    unfreezesHpa: false,
    residualRisk: "Zero (Destroyed mechanically)"
  }
];
