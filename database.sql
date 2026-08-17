-- ============================================================================
-- WipeX / Aegis Wipe — PostgreSQL Central Ledger DDL
-- Zero-Trust Data Sanitization & Hardware-Bound Verification Platform
-- ============================================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Devices Table: Target physical storage units
CREATE TABLE IF NOT EXISTS devices (
    device_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model VARCHAR(255) NOT NULL,
    serial_number VARCHAR(128) NOT NULL UNIQUE,
    storage_type VARCHAR(64) NOT NULL, -- 'NVMe SSD', 'SATA SSD', 'Magnetic HDD'
    interface VARCHAR(64) NOT NULL,    -- 'PCIe Gen 4 x4', 'SATA 3.3'
    capacity_bytes BIGINT NOT NULL,
    capacity_display VARCHAR(64) NOT NULL,
    firmware_rev VARCHAR(64),
    health_status VARCHAR(64) DEFAULT 'HEALTHY',
    health_score INT DEFAULT 100,
    hpa_detected BOOLEAN DEFAULT FALSE,
    hpa_size VARCHAR(64) DEFAULT '0 MB',
    dco_detected BOOLEAN DEFAULT FALSE,
    reallocated_sectors INT DEFAULT 0,
    power_on_hours INT DEFAULT 0,
    temperature VARCHAR(32) DEFAULT '35°C',
    expected_outcome VARCHAR(16) DEFAULT 'GREEN', -- 'GREEN', 'YELLOW', 'RED'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Wipe Operations Record
CREATE TABLE IF NOT EXISTS wipe_records (
    wipe_id VARCHAR(64) PRIMARY KEY,
    device_id UUID REFERENCES devices(device_id) ON DELETE CASCADE,
    sanitization_standard VARCHAR(128) NOT NULL, -- 'NIST_SP_800_88_PURGE', 'NIST_CLEAR'
    low_level_command TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'IN_PROGRESS', -- 'IN_PROGRESS', 'COMPLETED', 'FAILED'
    progress INT NOT NULL DEFAULT 0,
    pre_wipe_nonce VARCHAR(64) NOT NULL,
    duration_seconds INT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- 3. Independent Audit Results
CREATE TABLE IF NOT EXISTS audit_results (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wipe_id VARCHAR(64) REFERENCES wipe_records(wipe_id) ON DELETE CASCADE,
    sectors_sampled INT NOT NULL DEFAULT 10000,
    shannon_entropy NUMERIC(8, 6) NOT NULL DEFAULT 0.000000, -- 0.000000 for pure zero
    zero_byte_compliance_pct NUMERIC(5, 2) NOT NULL DEFAULT 100.00,
    bad_sectors_found INT DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'PASSED', -- 'PASSED', 'FAILED'
    audited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Sanitization Trust Scores
CREATE TABLE IF NOT EXISTS trust_scores (
    score_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wipe_id VARCHAR(64) REFERENCES wipe_records(wipe_id) ON DELETE CASCADE,
    health_score INT NOT NULL, -- 0 - 100
    rating VARCHAR(16) NOT NULL, -- 'GREEN', 'YELLOW', 'RED'
    recommendation TEXT NOT NULL,
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Hardware-Bound Compliance Certificates
CREATE TABLE IF NOT EXISTS certificates (
    certificate_id VARCHAR(64) PRIMARY KEY, -- e.g. 'WIPEX-2026-980PRO-8F2B'
    wipe_id VARCHAR(64) REFERENCES wipe_records(wipe_id) ON DELETE SET NULL,
    device_serial VARCHAR(128) NOT NULL,
    device_model VARCHAR(255) NOT NULL,
    storage_type VARCHAR(64) NOT NULL,
    capacity_display VARCHAR(64) NOT NULL,
    sanitization_method VARCHAR(255) NOT NULL,
    cleaned_status VARCHAR(128) NOT NULL,
    trust_score VARCHAR(64) NOT NULL,
    audit_result VARCHAR(255) NOT NULL,
    pre_wipe_nonce VARCHAR(64) NOT NULL,
    sha256_digest VARCHAR(64) NOT NULL,
    digital_signature TEXT NOT NULL,
    qr_payload TEXT NOT NULL,
    tamper_detected BOOLEAN DEFAULT FALSE,
    verdict TEXT NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for lightning fast lookups
CREATE INDEX IF NOT EXISTS idx_devices_serial ON devices(serial_number);
CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(device_serial);
CREATE INDEX IF NOT EXISTS idx_cert_id ON certificates(certificate_id);
CREATE INDEX IF NOT EXISTS idx_wipe_device ON wipe_records(device_id);

-- Seed Initial Reference Devices
INSERT INTO devices (model, serial_number, storage_type, interface, capacity_bytes, capacity_display, firmware_rev, health_status, health_score, hpa_detected, hpa_size, dco_detected, reallocated_sectors, power_on_hours, temperature, expected_outcome)
VALUES 
    ('Samsung SSD 980 PRO 1TB', 'S6B0NF0R419823X', 'NVMe SSD', 'NVMe 1.4 / PCIe Gen 4 x4', 1000204886016, '1,000.2 GB', '5B2QGXA7', 'HEALTHY', 98, FALSE, '0 MB', FALSE, 0, 1420, '34°C', 'GREEN'),
    ('Seagate Barracuda 2TB 3.5" HDD', 'W9A2L88K901', 'Magnetic HDD', 'SATA 3.3 (6.0 Gb/s) / 7200 RPM', 2000398934016, '2,000.4 GB', 'CC43', 'CAUTION_AGING', 68, FALSE, '0 MB', FALSE, 0, 43820, '41°C', 'YELLOW'),
    ('Kingston A400 480GB SATA SSD', '50026B7682910F4A', 'SATA SSD', 'SATA 3.0 (6.0 Gb/s)', 480103981056, '480.1 GB', 'SBFKB1H5', 'FAILING_BAD_SECTORS', 22, FALSE, '0 MB', FALSE, 48, 29410, '48°C', 'RED'),
    ('SanDisk Ultra 3D 512GB (HPA Partition Locked)', 'SD-99281-HPA02', 'SATA SSD', 'SATA 3.2 (6.0 Gb/s)', 512110190592, '512.1 GB', 'X61110RL', 'HEALTHY_HPA_LOCKED', 95, TRUE, '32.0 GB (Host Protected Area)', TRUE, 0, 3810, '31°C', 'GREEN')
ON CONFLICT (serial_number) DO NOTHING;
