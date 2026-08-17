/**
 * Aegis Wipe - Physical Storage Device Presets
 * Realistic hardware diagnostics, SMART registers, and topology profiles.
 */

window.MOCK_DEVICES = [
  {
    id: "dev-nvme-samsung-980",
    model: "Samsung SSD 980 PRO 1TB",
    type: "NVMe SSD",
    interface: "NVMe 1.4 / PCIe Gen 4 x4",
    capacity: "1,000.2 GB (1,953,525,168 LBA Sectors)",
    capacityBytes: 1000204886016,
    serialNumber: "S6B0NF0R419823X",
    maskedSerial: "S6B0****19823X",
    firmware: "5B2QGXA7",
    healthStatus: "HEALTHY",
    healthScore: 98,
    reallocatedSectors: 0,
    wearLevel: "98% Remaining",
    powerOnHours: "1,420 Hours",
    temperature: "34°C",
    hpaDetected: false,
    hpaSize: "0 MB",
    dcoDetected: false,
    overProvisioning: "10.0% (93.1 GB NAND Reserve)",
    cryptoEraseSupported: true,
    ataSecurityFrozen: true,
    smartAttributes: [
      { id: "0x01", name: "Critical Warning", raw: "0x00", threshold: "0x00", status: "PASSED" },
      { id: "0x02", name: "Composite Temperature", raw: "34°C (307 Kelvin)", threshold: "70°C", status: "OPTIMAL" },
      { id: "0x03", name: "Available Spare Capacity", raw: "100%", threshold: "10%", status: "HEALTHY" },
      { id: "0x04", name: "Percentage Used (Wear)", raw: "2%", threshold: "100%", status: "OPTIMAL" },
      { id: "0x05", name: "Data Units Written", raw: "12.4 TBW", threshold: "600 TBW", status: "HEALTHY" },
      { id: "0x0E", name: "Media & Data Integrity Errors", raw: "0", threshold: "0", status: "VERIFIED" }
    ],
    recommendedMethod: "purge-nvme-crypto",
    expectedOutcome: "GREEN",
    capacityUsedBytes: 642000000000,
    capacityUsedPct: 64.2,
    isAlreadyClean: false,
    currentFiles: [
      { name: "Documents/Resume.pdf", size: "284 KB" },
      { name: "Photos/Vacation.zip", size: "3.8 GB" },
      { name: "Projects/source-code.tar.gz", size: "864 MB" },
      { name: "Backups/TimeMachine.sparseimage", size: "412 GB" },
      { name: "Downloads/installer.dmg", size: "14.2 GB" }
    ],
    deletedRecoverableFiles: [
      { name: "Documents/old-passwords.txt", size: "12 KB", recoverability: "High" },
      { name: "Photos/IMG_2044.jpg", size: "5.4 MB", recoverability: "Medium" },
      { name: "Trash/private-notes.docx", size: "96 KB", recoverability: "High" }
    ]
  },
  {
    id: "dev-hdd-seagate-barracuda",
    model: "Seagate Barracuda 2TB 3.5\" HDD",
    type: "Magnetic HDD",
    interface: "SATA 3.3 (6.0 Gb/s) / 7200 RPM",
    capacity: "2,000.4 GB (3,907,029,168 LBA Sectors)",
    capacityBytes: 2000398934016,
    serialNumber: "W9A2L88K901",
    maskedSerial: "W9A2****88K901",
    firmware: "CC43",
    healthStatus: "CAUTION_AGING",
    healthScore: 68,
    reallocatedSectors: 0,
    wearLevel: "N/A (Mechanical)",
    powerOnHours: "43,820 Hours (5.0 yrs continuous)",
    temperature: "41°C",
    hpaDetected: false,
    hpaSize: "0 MB",
    dcoDetected: false,
    overProvisioning: "N/A (Magnetic Platter)",
    cryptoEraseSupported: false,
    ataSecurityFrozen: false,
    smartAttributes: [
      { id: "0x05", name: "Reallocated Sectors Count", raw: "0", threshold: "36", status: "CLEAN" },
      { id: "0x09", name: "Power-On Hours Lifetime", raw: "43,820 Hrs", threshold: "0", status: "AGING" },
      { id: "0x0A", name: "Spin Retry Count", raw: "0", threshold: "97", status: "PASSED" },
      { id: "0xBB", name: "Reported Uncorrectable", raw: "0", threshold: "0", status: "HEALTHY" },
      { id: "0xC5", name: "Current Pending Sector Count", raw: "0", threshold: "0", status: "OPTIMAL" },
      { id: "0xC6", name: "Offline Uncorrectable Sectors", raw: "0", threshold: "0", status: "OPTIMAL" }
    ],
    recommendedMethod: "purge-ata-enhanced",
    expectedOutcome: "YELLOW",
    capacityUsedBytes: 1844000000000,
    capacityUsedPct: 92.2,
    isAlreadyClean: false,
    currentFiles: [
      { name: "Media/Movies/collection.mkv", size: "847 GB" },
      { name: "Backup/2023_full.bak", size: "612 GB" },
      { name: "Music/FLAC_Library.tar", size: "184 GB" },
      { name: "Documents/taxes-2022.pdf", size: "4.8 MB" }
    ],
    deletedRecoverableFiles: [
      { name: "Old_Projects/legacy_source.zip", size: "2.1 GB", recoverability: "Medium" },
      { name: "Personal/letters-archive.pst", size: "846 MB", recoverability: "High" },
      { name: "Photos/family-2019.raw", size: "340 MB", recoverability: "Medium" },
      { name: "Deleted/bank-statements.pdf", size: "12 MB", recoverability: "High" }
    ]
  },
  {
    id: "dev-ssd-kingston-damaged",
    model: "Kingston A400 480GB SATA SSD",
    type: "SATA SSD",
    interface: "SATA 3.0 (6.0 Gb/s)",
    capacity: "480.1 GB (937,703,088 LBA Sectors)",
    capacityBytes: 480103981056,
    serialNumber: "50026B7682910F4A",
    maskedSerial: "5002****82910F4A",
    firmware: "SBFKB1H5",
    healthStatus: "FAILING_BAD_SECTORS",
    healthScore: 22,
    reallocatedSectors: 48,
    wearLevel: "14% Remaining (Heavy Degradation)",
    powerOnHours: "29,410 Hours",
    temperature: "48°C",
    hpaDetected: false,
    hpaSize: "0 MB",
    dcoDetected: false,
    overProvisioning: "0% Exhausted",
    cryptoEraseSupported: false,
    ataSecurityFrozen: true,
    smartAttributes: [
      { id: "0x05", name: "Reallocated Sector Count", raw: "48 Blocks", threshold: "10", status: "FAILED" },
      { id: "0x09", name: "Power-On Hours", raw: "29,410 Hrs", threshold: "0", status: "WARNING" },
      { id: "0xBB", name: "Uncorrectable Read Errors", raw: "128", threshold: "0", status: "FAILED" },
      { id: "0xE7", name: "SSD Life Left", raw: "14%", threshold: "10%", status: "CRITICAL" },
      { id: "0xC5", name: "Current Pending Sectors", raw: "16 Blocks", threshold: "0", status: "FAILED" }
    ],
    recommendedMethod: "destroy-physical",
    expectedOutcome: "RED",
    capacityUsedBytes: 312000000000,
    capacityUsedPct: 65.0,
    isAlreadyClean: false,
    currentFiles: [
      { name: "Work/Customer-DB.mdb", size: "284 GB" },
      { name: "Private/keys.pem", size: "8 KB" }
    ],
    deletedRecoverableFiles: [
      { name: "Scrapped/old-customer-records.csv", size: "18 GB", recoverability: "High" },
      { name: "Trash/employee-ssn-sheet.xlsx", size: "6.2 MB", recoverability: "High" }
    ]
  },
  {
    id: "dev-sandisk-hpa-hidden",
    model: "SanDisk Ultra 3D 512GB (HPA Partition Locked)",
    type: "SATA SSD",
    interface: "SATA 3.2 (6.0 Gb/s)",
    capacity: "512.1 GB (1,000,215,216 LBA Sectors)",
    capacityBytes: 512110190592,
    serialNumber: "SD-99281-HPA02",
    maskedSerial: "SD-99****HPA02",
    firmware: "X61110RL",
    healthStatus: "HEALTHY_HPA_LOCKED",
    healthScore: 95,
    reallocatedSectors: 0,
    wearLevel: "92% Remaining",
    powerOnHours: "3,810 Hours",
    temperature: "31°C",
    hpaDetected: true,
    hpaSize: "32.0 GB (Host Protected Area)",
    dcoDetected: true,
    overProvisioning: "7.0% (35.8 GB)",
    cryptoEraseSupported: true,
    ataSecurityFrozen: true,
    smartAttributes: [
      { id: "0x05", name: "Reallocated Sector Count", raw: "0", threshold: "10", status: "OPTIMAL" },
      { id: "0x09", name: "Power-On Hours", raw: "3,810 Hrs", threshold: "0", status: "HEALTHY" },
      { id: "0xE7", name: "SSD Life Left", raw: "92%", threshold: "10%", status: "OPTIMAL" },
      { id: "0xBB", name: "Reported Uncorrectable", raw: "0", threshold: "0", status: "CLEAN" }
    ],
    recommendedMethod: "purge-ata-secure",
    expectedOutcome: "GREEN",
    capacityUsedBytes: 218000000000,
    capacityUsedPct: 42.6,
    isAlreadyClean: false,
    currentFiles: [
      { name: "Software/VMs/ubuntu.qcow2", size: "128 GB" },
      { name: "Projects/webapp/node_modules/", size: "44 GB" },
      { name: "Assets/brand-assets.psd", size: "1.2 GB" }
    ],
    deletedRecoverableFiles: [
      { name: "Hidden/old_vm_snapshot.img", size: "28 GB", recoverability: "High (in HPA)" }
    ]
  },
  {
    id: "dev-crucial-clean-256",
    model: "Crucial MX500 256GB (Already Wiped)",
    type: "SATA SSD",
    interface: "SATA 3.3 (6.0 Gb/s)",
    capacity: "256.1 GB (500,118,192 LBA Sectors)",
    capacityBytes: 256060514304,
    serialNumber: "CRUCIAL-500MX-CLEAN99",
    maskedSerial: "CRUC****LEAN99",
    firmware: "M3CR023",
    healthStatus: "HEALTHY_ALREADY_CLEAN",
    healthScore: 96,
    reallocatedSectors: 0,
    wearLevel: "94% Remaining",
    powerOnHours: "5,120 Hours",
    temperature: "29°C",
    hpaDetected: false,
    hpaSize: "0 MB",
    dcoDetected: false,
    overProvisioning: "7.0% (17.9 GB)",
    cryptoEraseSupported: true,
    ataSecurityFrozen: false,
    smartAttributes: [
      { id: "0x05", name: "Reallocated Sector Count", raw: "0", threshold: "10", status: "CLEAN" },
      { id: "0xE7", name: "SSD Life Left", raw: "94%", threshold: "10%", status: "OPTIMAL" }
    ],
    recommendedMethod: "purge-ata-secure",
    expectedOutcome: "GREEN",
    capacityUsedBytes: 0,
    capacityUsedPct: 0.0,
    isAlreadyClean: true,
    currentFiles: [],
    deletedRecoverableFiles: []
  }
];
