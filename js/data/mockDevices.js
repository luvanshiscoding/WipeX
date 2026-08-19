/**
 * WipeX - Enterprise Storage Device Presets
 * Pre-configured realistic hardware drives for interactive prototype preview.
 */

window.MOCK_DEVICES = [
  {
    id: "dev-nvme-samsung-980",
    model: "Samsung SSD 980 PRO 1TB",
    type: "NVMe SSD",
    interface: "NVMe 1.4 / PCIe Gen 4 x4",
    capacity: "1,000 GB",
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
    ataSecurityFrozen: false,
    smartAttributes: [
      { id: "0x01", name: "Critical Warning", raw: "0x00", threshold: "0x00", status: "PASSED" },
      { id: "0x02", name: "Composite Temperature", raw: "34°C", threshold: "70°C", status: "OPTIMAL" },
      { id: "0x03", name: "Available Spare Capacity", raw: "100%", threshold: "10%", status: "HEALTHY" },
      { id: "0x04", name: "Percentage Used (Wear)", raw: "2%", threshold: "100%", status: "OPTIMAL" },
      { id: "0x05", name: "Data Units Written", raw: "12.4 TBW", threshold: "600 TBW", status: "HEALTHY" },
      { id: "0x0E", name: "Media & Data Integrity Errors", raw: "0", threshold: "0", status: "VERIFIED" }
    ],
    recommendedMethod: "purge-nvme-crypto",
    expectedOutcome: "GREEN",
    capacityUsedBytes: 428000000000,
    capacityUsedPct: 42.8,
    isAlreadyClean: false,
    currentFiles: [
      { name: "Documents/Financial-Reports-2025.xlsx", size: "14.2 MB" },
      { name: "Documents/Corporate-Strategy-Confidential.pdf", size: "28.6 MB" },
      { name: "Databases/Customer_Database_Production.sql", size: "38.4 GB" },
      { name: "UserFiles/Employee_Tax_Forms/", size: "<dir>" },
      { name: "UserFiles/Employee_Tax_Forms/W2_Batch_2025.zip", size: "1.8 GB" },
      { name: "Backups/System_State_Backup.tar.gz", size: "185.0 GB" }
    ],
    deletedRecoverableFiles: [
      { name: "RecycleBin/Confidential-Audit-2024.docx", size: "6.4 MB", recoverability: "High" },
      { name: "Temp/customer_payment_tokens.csv", size: "140 MB", recoverability: "High" }
    ]
  },
  {
    id: "dev-sandisk-hpa-hidden",
    model: "SanDisk Ultra 3D 512GB (Hidden Area Detected)",
    type: "SATA SSD",
    interface: "SATA 3.2 (6.0 Gb/s)",
    capacity: "512 GB",
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
      { name: "Projects/Client_Portal_Source/", size: "<dir>" },
      { name: "Projects/Client_Portal_Source/database.sqlite", size: "4.2 GB" },
      { name: "Media/Executive_Keynote_Video.mp4", size: "18.5 GB" },
      { name: "Archive/Archived_Emails_2023.pst", size: "42.0 GB" }
    ],
    deletedRecoverableFiles: [
      { name: "ProtectedPartition/legacy_payroll_backup.bak", size: "32.0 GB", recoverability: "High (Hidden Area)" }
    ]
  },
  {
    id: "dev-hdd-seagate-barracuda",
    model: "Seagate Barracuda 2TB HDD",
    type: "Magnetic HDD",
    interface: "SATA 3.3 (6.0 Gb/s) / 7200 RPM",
    capacity: "2,000 GB",
    capacityBytes: 2000398934016,
    serialNumber: "W9A2L88K901",
    maskedSerial: "W9A2****88K901",
    firmware: "CC43",
    healthStatus: "HEALTHY",
    healthScore: 94,
    reallocatedSectors: 0,
    wearLevel: "N/A (Mechanical)",
    powerOnHours: "1,820 Hours",
    temperature: "36°C",
    hpaDetected: false,
    hpaSize: "0 MB",
    dcoDetected: false,
    overProvisioning: "N/A (Magnetic Platter)",
    cryptoEraseSupported: false,
    ataSecurityFrozen: false,
    smartAttributes: [
      { id: "0x05", name: "Reallocated Sectors Count", raw: "0", threshold: "36", status: "CLEAN" },
      { id: "0x09", name: "Power-On Hours Lifetime", raw: "1,820 Hrs", threshold: "0", status: "HEALTHY" },
      { id: "0x0A", name: "Spin Retry Count", raw: "0", threshold: "97", status: "PASSED" },
      { id: "0xBB", name: "Reported Uncorrectable", raw: "0", threshold: "0", status: "HEALTHY" }
    ],
    recommendedMethod: "dod-3pass",
    expectedOutcome: "GREEN",
    capacityUsedBytes: 1240000000000,
    capacityUsedPct: 62.0,
    isAlreadyClean: false,
    currentFiles: [
      { name: "LegacyStorage/Accounting_Archives_2018_2024/", size: "<dir>" },
      { name: "LegacyStorage/Accounting_Archives_2018_2024/ledger.accdb", size: "85 GB" },
      { name: "SecurityFootage/Archive_Q4_2024.mkv", size: "420 GB" }
    ],
    deletedRecoverableFiles: [
      { name: "Scrapped/old-customer-records.csv", size: "18 GB", recoverability: "High" },
      { name: "Trash/employee-ssn-sheet.xlsx", size: "6.2 MB", recoverability: "High" }
    ]
  },
  {
    id: "dev-ssd-kingston-damaged",
    model: "Kingston A400 480GB (Hardware Faults)",
    type: "SATA SSD",
    interface: "SATA 3.0 (6.0 Gb/s)",
    capacity: "480 GB",
    capacityBytes: 480103981056,
    serialNumber: "50026B7682910F4A",
    maskedSerial: "5002****82910F4A",
    firmware: "SBFKB1H5",
    healthStatus: "FAILING_BAD_SECTORS",
    healthScore: 22,
    reallocatedSectors: 48,
    wearLevel: "14% Remaining (Degraded)",
    powerOnHours: "29,410 Hours",
    temperature: "48°C",
    hpaDetected: false,
    hpaSize: "0 MB",
    dcoDetected: false,
    overProvisioning: "0% Exhausted",
    cryptoEraseSupported: false,
    ataSecurityFrozen: false,
    smartAttributes: [
      { id: "0x05", name: "Reallocated Sector Count", raw: "48 Blocks", threshold: "10", status: "FAILED" },
      { id: "0x09", name: "Power-On Hours", raw: "29,410 Hrs", threshold: "0", status: "WARNING" },
      { id: "0xBB", name: "Uncorrectable Read Errors", raw: "128", threshold: "0", status: "FAILED" },
      { id: "0xE7", name: "SSD Life Left", raw: "14%", threshold: "10%", status: "CRITICAL" }
    ],
    recommendedMethod: "destroy-physical",
    expectedOutcome: "RED",
    capacityUsedBytes: 310000000000,
    capacityUsedPct: 64.5,
    isAlreadyClean: false,
    currentFiles: [
      { name: "Workstations/User_Home_Directory/", size: "<dir>" },
      { name: "Workstations/User_Home_Directory/browser_profiles.zip", size: "12.4 GB" },
      { name: "UnreadableSectors/bad_blocks_data.bin", size: "48 MB (Unsanitizable)" }
    ],
    deletedRecoverableFiles: [
      { name: "DamagedZone/vpn_certificates.pfx", size: "4.2 KB", recoverability: "Partial (Physical Block)" }
    ]
  },
  {
    id: "dev-crucial-clean-256",
    model: "Crucial MX500 256GB (Sanitized & Verified)",
    type: "SATA SSD",
    interface: "SATA 3.3 (6.0 Gb/s)",
    capacity: "256 GB",
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
