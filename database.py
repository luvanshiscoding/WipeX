"""
WipeX - Database Persistence Engine
Seamlessly connects to PostgreSQL (port 5432) or local SQLite (wipex.db) ledger.
"""

import sqlite3
import os
import time
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), "wipex.db")
PG_HOST = os.getenv("PGHOST", "localhost")
PG_PORT = int(os.getenv("PGPORT", 5432))
PG_DB = os.getenv("PGDATABASE", "wipex")
PG_USER = os.getenv("PGUSER", os.getenv("USER", "postgres"))
PG_PASSWORD = os.getenv("PGPASSWORD", "")

USE_POSTGRES = False


def check_postgres_available() -> bool:
    """Checks if PostgreSQL is accessible on localhost:5432."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DB,
            user=PG_USER,
            password=PG_PASSWORD,
            connect_timeout=2
        )
        conn.close()
        return True
    except Exception:
        return False


USE_POSTGRES = check_postgres_available()


def get_db_connection():
    """Returns PostgreSQL connection if available, otherwise SQLite."""
    if USE_POSTGRES:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DB,
            user=PG_USER,
            password=PG_PASSWORD
        )
        return conn
    else:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn


def init_db():
    """Initializes database tables and seeds initial ledger records."""
    global USE_POSTGRES
    USE_POSTGRES = check_postgres_available()

    if USE_POSTGRES:
        import psycopg2
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load PostgreSQL Schema from database.sql if needed
        sql_path = os.path.join(os.path.dirname(__file__), "database.sql")
        if os.path.exists(sql_path):
            with open(sql_path, "r") as f:
                schema_sql = f.read()
            try:
                cursor.execute(schema_sql)
                conn.commit()
            except Exception as e:
                conn.rollback()
        
        # Seed reference certificates in Postgres if empty
        cursor.execute("SELECT COUNT(*) FROM certificates")
        if cursor.fetchone()[0] == 0:
            seed_certs = [
                ("AEGIS-2026-980PRO-8F2B", None, "Samsung SSD 980 PRO 1TB", "S6B0NF0R419823X", "NVMe PCIe 4.0 SSD", "1,000.2 GB", "Deep Hardware Purge (NIST SP 800-88 Crypto Erase)", "CLEANED (100% Zero Data)", "GREEN", "PASSED (100% Zero Confirmation)", "7e8b9f02c418a36d912", "a4f91d8e6c73b021a884f0923b7e12908c6a7e5f1d9c02b3e4f5a6b7c8d9e0f1", "3045022100a4f91d8e6c73b021a884f0923b7e129002208c6a7e5f1d9c02b3e4f5a6b7c8d9e0f1VALID", "https://wipex.app/verify?cert=AEGIS-2026-980PRO-8F2B", False, "Authentic & Hardware-Bound. This certificate has not been altered or reused."),
                ("AEGIS-2026-BARRACUDA-3C1A", None, "Seagate Barracuda 2TB 3.5\" HDD", "W9A2L88K901", "Magnetic HDD", "2,000.4 GB", "Standard Clear (NIST SP 800-88 Overwrite)", "CLEANED (100% Zero Data)", "YELLOW", "PASSED (Zero Residual Data)", "4a1c89f30b91e772d11", "f01c891e3271ba67209148cba0129845ef92a83b1029c78491823901bcae8129", "3045022100f01c891e3271ba67209148cba01298450220ef92a83b1029c78491823901bcae8129VALID", "https://wipex.app/verify?cert=AEGIS-2026-BARRACUDA-3C1A", False, "Authentic Wipe Certificate. Note: Drive has high operational lifetime (43,820 hrs); safe from data leak but component reliability is degraded."),
                ("AEGIS-2026-KINGSTON-RED-99", None, "Kingston A400 480GB SATA SSD", "50026B7682910F4A", "SATA SSD", "480.1 GB", "Mandatory Mechanical Disintegration (<2mm)", "NOT CLEANED (48 Bad Sectors)", "RED", "FAILED — 48 Bad Sectors Unwiped (Data Risk)", "98ab21034f81c990234", "9823ca019842bf901c82410a8837190248bf0912c01824761093847a192837bc", "30450221009823ca019842bf901c82410a88371902022048bf0912c01824761093847a192837bcVALID", "https://wipex.app/verify?cert=AEGIS-2026-KINGSTON-RED-99", False, "Mandated Physical Destruction Manifest Issued. This media is prohibited from resale or circular reuse due to unerasable hardware sectors."),
                ("AEGIS-FORGED-FAKE-CERT-00", None, "Samsung SSD 980 PRO 1TB [Forged Copy]", "S6B0NF0R419823X", "NVMe SSD", "1,000.2 GB", "Forged Certificate Attempt", "FAILED INTEGRITY", "FRAUD", "FAILED CRYPTOGRAPHIC INTEGRITY", "INVALID_NONCE_000", "0000000000000000000000000000000000000000000000000000000000000000", "INVALID_SIGNATURE", "https://wipex.app/verify?cert=AEGIS-FORGED-FAKE-CERT-00", True, "SECURITY ALERT: The digital signature and hardware binding hash do not match the central ledger. This certificate has been modified, forged, or transferred to an unauthorized drive.")
            ]
            cursor.executemany("""
                INSERT INTO certificates (certificate_id, wipe_id, device_model, device_serial, storage_type, capacity_display, sanitization_method, cleaned_status, trust_score, audit_result, pre_wipe_nonce, sha256_digest, digital_signature, qr_payload, tamper_detected, verdict)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (certificate_id) DO NOTHING
            """, seed_certs)
            conn.commit()
        conn.close()
        return

    # Fallback to SQLite
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            model TEXT NOT NULL,
            serial_number TEXT NOT NULL UNIQUE,
            storage_type TEXT NOT NULL,
            interface TEXT NOT NULL,
            capacity TEXT NOT NULL,
            capacity_bytes INTEGER NOT NULL,
            masked_serial TEXT,
            firmware TEXT,
            health_status TEXT DEFAULT 'HEALTHY',
            health_score INTEGER DEFAULT 100,
            hpa_detected INTEGER DEFAULT 0,
            hpa_size TEXT DEFAULT '0 MB',
            dco_detected INTEGER DEFAULT 0,
            reallocated_sectors INTEGER DEFAULT 0,
            power_on_hours TEXT DEFAULT '0 Hours',
            temperature TEXT DEFAULT '35°C',
            wear_level TEXT DEFAULT '100% Remaining',
            crypto_erase_supported INTEGER DEFAULT 1,
            ata_security_frozen INTEGER DEFAULT 0,
            recommended_method TEXT DEFAULT 'purge-nvme-crypto',
            expected_outcome TEXT DEFAULT 'GREEN',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wipe_records (
            wipe_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            method TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'IN_PROGRESS',
            progress INTEGER NOT NULL DEFAULT 0,
            pre_wipe_nonce TEXT NOT NULL,
            command TEXT,
            speed TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            certificate_id TEXT PRIMARY KEY,
            wipe_id TEXT,
            device_model TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            storage_type TEXT NOT NULL,
            capacity TEXT NOT NULL,
            standard TEXT NOT NULL,
            method_name TEXT NOT NULL,
            cleaned_status TEXT NOT NULL,
            trust_score TEXT NOT NULL,
            trust_score_label TEXT,
            audit_result TEXT NOT NULL,
            pre_wipe_nonce TEXT NOT NULL,
            sha256_digest TEXT NOT NULL,
            digital_signature TEXT NOT NULL,
            qr_payload TEXT NOT NULL,
            tamper_detected INTEGER DEFAULT 0,
            verdict TEXT NOT NULL,
            issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(serial_number)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cert_id ON certificates(certificate_id)")

    cursor.execute("SELECT COUNT(*) FROM devices")
    if cursor.fetchone()[0] == 0:
        seed_devices = [
            ("dev-nvme-samsung-980", "Samsung SSD 980 PRO 1TB", "S6B0NF0R419823X", "NVMe SSD", "NVMe 1.4 / PCIe Gen 4 x4", "1,000.2 GB (1,953,525,168 LBA Sectors)", 1000204886016, "S6B0****19823X", "5B2QGXA7", "HEALTHY", 98, 0, "0 MB", 0, 0, "1,420 Hours", "34°C", "98% Remaining", 1, 1, "purge-nvme-crypto", "GREEN"),
            ("dev-hdd-seagate-barracuda", "Seagate Barracuda 2TB 3.5\" HDD", "W9A2L88K901", "Magnetic HDD", "SATA 3.3 (6.0 Gb/s) / 7200 RPM", "2,000.4 GB (3,907,029,168 LBA Sectors)", 2000398934016, "W9A2****88K901", "CC43", "CAUTION_AGING", 68, 0, "0 MB", 0, 0, "43,820 Hours", "41°C", "N/A (Mechanical)", 0, 0, "clear-single", "YELLOW"),
            ("dev-ssd-kingston-damaged", "Kingston A400 480GB SATA SSD", "50026B7682910F4A", "SATA SSD", "SATA 3.0 (6.0 Gb/s)", "480.1 GB (937,703,088 LBA Sectors)", 480103981056, "5002****82910F4A", "SBFKB1H5", "FAILING_BAD_SECTORS", 22, 0, "0 MB", 0, 48, "29,410 Hours", "48°C", "14% Remaining", 0, 1, "destroy-physical", "RED"),
            ("dev-sandisk-hpa-hidden", "SanDisk Ultra 3D 512GB (HPA Partition Locked)", "SD-99281-HPA02", "SATA SSD", "SATA 3.2 (6.0 Gb/s)", "512.1 GB (1,000,215,216 LBA Sectors)", 512110190592, "SD-99****HPA02", "X61110RL", "HEALTHY_HPA_LOCKED", 95, 1, "32.0 GB (Host Protected Area)", 1, 0, "3,810 Hours", "31°C", "92% Remaining", 1, 1, "purge-ata-secure", "GREEN")
        ]
        cursor.executemany("""
            INSERT INTO devices (id, model, serial_number, storage_type, interface, capacity, capacity_bytes, masked_serial, firmware, health_status, health_score, hpa_detected, hpa_size, dco_detected, reallocated_sectors, power_on_hours, temperature, wear_level, crypto_erase_supported, ata_security_frozen, recommended_method, expected_outcome)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, seed_devices)

    cursor.execute("SELECT COUNT(*) FROM certificates")
    if cursor.fetchone()[0] == 0:
        seed_certs = [
            ("AEGIS-2026-980PRO-8F2B", "WIPE-REF-01", "Samsung SSD 980 PRO 1TB", "S6B0NF0R419823X", "NVMe PCIe 4.0 SSD", "1,000.2 GB", "Deep Hardware Purge (NIST SP 800-88 Crypto Erase)", "NVMe Cryptographic & Block Erase (SES=2)", "CLEANED (100% Zero Data)", "GREEN", "SAFE TO REUSE OR RESELL", "PASSED (100% Zero Confirmation)", "7e8b9f02c418a36d912", "a4f91d8e6c73b021a884f0923b7e12908c6a7e5f1d9c02b3e4f5a6b7c8d9e0f1", "3045022100a4f91d8e6c73b021a884f0923b7e129002208c6a7e5f1d9c02b3e4f5a6b7c8d9e0f1VALID", "https://wipex.app/verify?cert=AEGIS-2026-980PRO-8F2B", 0, "Authentic & Hardware-Bound. This certificate has not been altered or reused.", "2026-08-16 23:33:00 UTC"),
            ("AEGIS-2026-BARRACUDA-3C1A", "WIPE-REF-02", "Seagate Barracuda 2TB 3.5\" HDD", "W9A2L88K901", "Magnetic HDD", "2,000.4 GB", "Standard Clear (NIST SP 800-88 Overwrite)", "ATA Enhanced Security Erase", "CLEANED (100% Zero Data)", "YELLOW", "CAUTION (AGED HARDWARE)", "PASSED (Zero Residual Data)", "4a1c89f30b91e772d11", "f01c891e3271ba67209148cba0129845ef92a83b1029c78491823901bcae8129", "3045022100f01c891e3271ba67209148cba01298450220ef92a83b1029c78491823901bcae8129VALID", "https://wipex.app/verify?cert=AEGIS-2026-BARRACUDA-3C1A", 0, "Authentic Wipe Certificate. Note: Drive has high operational lifetime (43,820 hrs); safe from data leak but component reliability is degraded.", "2026-08-15 14:12:00 UTC"),
            ("AEGIS-2026-KINGSTON-RED-99", "WIPE-REF-03", "Kingston A400 480GB SATA SSD", "50026B7682910F4A", "SATA SSD", "480.1 GB", "Mandatory Mechanical Disintegration (<2mm)", "Chain-of-Custody Mechanical Shredding", "NOT CLEANED (48 Bad Sectors)", "RED", "MANDATORY PHYSICAL DESTRUCTION ORDER", "FAILED — 48 Bad Sectors Unwiped (Data Risk)", "98ab21034f81c990234", "9823ca019842bf901c82410a8837190248bf0912c01824761093847a192837bc", "30450221009823ca019842bf901c82410a88371902022048bf0912c01824761093847a192837bcVALID", "https://wipex.app/verify?cert=AEGIS-2026-KINGSTON-RED-99", 0, "Mandated Physical Destruction Manifest Issued. This media is prohibited from resale or circular reuse due to unerasable hardware sectors.", "2026-08-16 18:45:00 UTC"),
            ("AEGIS-FORGED-FAKE-CERT-00", "WIPE-REF-04", "Samsung SSD 980 PRO 1TB [Forged Copy]", "S6B0NF0R419823X", "NVMe SSD", "1,000.2 GB", "Forged Certificate Attempt", "Forged Certificate Attempt", "FAILED INTEGRITY", "FRAUD", "🚨 FRAUD ALERT — SIGNATURE MISMATCH", "FAILED CRYPTOGRAPHIC INTEGRITY", "INVALID_NONCE_000", "0000000000000000000000000000000000000000000000000000000000000000", "INVALID_SIGNATURE", "https://wipex.app/verify?cert=AEGIS-FORGED-FAKE-CERT-00", 1, "SECURITY ALERT: The digital signature and hardware binding hash do not match the central ledger. This certificate has been modified, forged, or transferred to an unauthorized drive.", "2026-08-16 11:00:00 UTC")
        ]
        cursor.executemany("""
            INSERT INTO certificates (certificate_id, wipe_id, device_model, serial_number, storage_type, capacity, standard, method_name, cleaned_status, trust_score, trust_score_label, audit_result, pre_wipe_nonce, sha256_digest, digital_signature, qr_payload, tamper_detected, verdict, issue_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, seed_certs)

    conn.commit()
    conn.close()


def get_all_devices() -> List[Dict[str, Any]]:
    """Retrieves all registered storage devices."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if USE_POSTGRES:
        cursor.execute("SELECT * FROM devices")
        columns = [desc[0] for desc in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        devices = []
        for r in rows:
            devices.append({
                "id": str(r.get("device_id") or r.get("id")),
                "model": r["model"],
                "serialNumber": r["serial_number"],
                "type": r["storage_type"],
                "interface": r["interface"],
                "capacity": r.get("capacity_display", "1,000 GB"),
                "capacityBytes": r["capacity_bytes"],
                "maskedSerial": r["serial_number"][:4] + "****" + r["serial_number"][-4:],
                "firmware": r.get("firmware_rev", "REV1"),
                "healthStatus": r.get("health_status", "HEALTHY"),
                "healthScore": r.get("health_score", 100),
                "hpaDetected": bool(r.get("hpa_detected")),
                "hpaSize": r.get("hpa_size", "0 MB"),
                "dcoDetected": bool(r.get("dco_detected")),
                "reallocatedSectors": r.get("reallocated_sectors", 0),
                "powerOnHours": f"{r.get('power_on_hours', 0)} Hours",
                "temperature": r.get("temperature", "35°C"),
                "wearLevel": "98% Remaining",
                "cryptoEraseSupported": True,
                "ataSecurityFrozen": False,
                "recommendedMethod": "purge-nvme-crypto" if "NVMe" in r["storage_type"] else "clear-single",
                "expectedOutcome": r.get("expected_outcome", "GREEN")
            })
        return devices
    else:
        cursor.execute("SELECT * FROM devices")
        rows = cursor.fetchall()
        conn.close()
        devices = []
        for r in rows:
            devices.append({
                "id": r["id"],
                "model": r["model"],
                "serialNumber": r["serial_number"],
                "type": r["storage_type"],
                "interface": r["interface"],
                "capacity": r["capacity"],
                "capacityBytes": r["capacity_bytes"],
                "maskedSerial": r["masked_serial"],
                "firmware": r["firmware"],
                "healthStatus": r["health_status"],
                "healthScore": r["health_score"],
                "hpaDetected": bool(r["hpa_detected"]),
                "hpaSize": r["hpa_size"],
                "dcoDetected": bool(r["dco_detected"]),
                "reallocatedSectors": r["reallocated_sectors"],
                "powerOnHours": r["power_on_hours"],
                "temperature": r["temperature"],
                "wearLevel": r["wear_level"],
                "cryptoEraseSupported": bool(r["crypto_erase_supported"]),
                "ataSecurityFrozen": bool(r["ata_security_frozen"]),
                "recommendedMethod": r["recommended_method"],
                "expectedOutcome": r["expected_outcome"]
            })
        return devices


def save_wipe_record(wipe_id: str, device_id: str, method: str, nonce: str) -> None:
    """Inserts a new sanitization record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if USE_POSTGRES:
        cursor.execute("SELECT device_id FROM devices WHERE device_id::text = %s OR serial_number = %s LIMIT 1", (device_id, device_id))
        row = cursor.fetchone()
        db_dev_id = row[0] if row else None
        cursor.execute("""
            INSERT INTO wipe_records (wipe_id, device_id, sanitization_standard, low_level_command, pre_wipe_nonce, status, progress)
            VALUES (%s, %s, %s, %s, %s, 'IN_PROGRESS', 0)
            ON CONFLICT (wipe_id) DO NOTHING
        """, (wipe_id, db_dev_id, method, "Initializing wipe", nonce))
    else:
        cursor.execute("""
            INSERT OR REPLACE INTO wipe_records (wipe_id, device_id, method, pre_wipe_nonce, status, progress)
            VALUES (?, ?, ?, ?, 'IN_PROGRESS', 0)
        """, (wipe_id, device_id, method, nonce))
    conn.commit()
    conn.close()


def update_wipe_progress(wipe_id: str, progress: int, status: str, speed: str = "450 MB/s", command: str = None) -> None:
    """Updates live progress for a wipe operation."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if USE_POSTGRES:
        cursor.execute("""
            UPDATE wipe_records
            SET progress = %s, status = %s, low_level_command = COALESCE(%s, low_level_command)
            WHERE wipe_id = %s
        """, (progress, status, command, wipe_id))
    else:
        completed_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) if status == "COMPLETED" else None
        cursor.execute("""
            UPDATE wipe_records
            SET progress = ?, status = ?, speed = ?, command = COALESCE(?, command), completed_at = ?
            WHERE wipe_id = ?
        """, (progress, status, speed, command, completed_at, wipe_id))
    conn.commit()
    conn.close()


def get_wipe_record(wipe_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves wipe record by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if USE_POSTGRES:
        cursor.execute("SELECT * FROM wipe_records WHERE wipe_id = %s", (wipe_id,))
        columns = [desc[0] for desc in cursor.description]
        row = cursor.fetchone()
        conn.close()
        if row:
            d = dict(zip(columns, row))
            return {
                "wipe_id": d["wipe_id"],
                "device_id": str(d["device_id"]),
                "method": d.get("sanitization_standard", "purge-nvme-crypto"),
                "status": d["status"],
                "progress": d["progress"],
                "nonce": d["pre_wipe_nonce"]
            }
        return None
    else:
        cursor.execute("SELECT * FROM wipe_records WHERE wipe_id = ?", (wipe_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None


def save_certificate(cert: Dict[str, Any]) -> None:
    """Persists a compliance certificate to database ledger."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if USE_POSTGRES:
        wipe_id = cert.get("wipe_id") or f"WIPE-{int(time.time())}"
        cursor.execute("""
            INSERT INTO certificates (
                certificate_id, wipe_id, device_model, device_serial, storage_type,
                capacity_display, sanitization_method, cleaned_status, trust_score,
                audit_result, pre_wipe_nonce, sha256_digest, digital_signature,
                qr_payload, tamper_detected, verdict
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (certificate_id) DO NOTHING
        """, (
            cert["certificateId"],
            wipe_id,
            cert["deviceModel"],
            cert["serialNumber"],
            cert["storageType"],
            cert["capacity"],
            cert.get("standard", cert.get("methodName", "Deep Hardware Purge")),
            cert["cleanedStatus"],
            cert["trustScore"],
            cert["auditResult"],
            cert["preWipeNonce"],
            cert["sha256Digest"],
            cert["digitalSignature"],
            cert["qrPayload"],
            bool(cert.get("tamperDetected")),
            cert["verdict"]
        ))
    else:
        cursor.execute("""
            INSERT OR REPLACE INTO certificates (
                certificate_id, wipe_id, device_model, serial_number, storage_type,
                capacity, standard, method_name, cleaned_status, trust_score,
                trust_score_label, audit_result, pre_wipe_nonce, sha256_digest,
                digital_signature, qr_payload, tamper_detected, verdict, issue_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cert["certificateId"],
            cert.get("wipe_id"),
            cert["deviceModel"],
            cert["serialNumber"],
            cert["storageType"],
            cert["capacity"],
            cert.get("standard", cert.get("methodName", "Deep Hardware Purge")),
            cert.get("methodName", cert.get("standard", "Deep Hardware Purge")),
            cert["cleanedStatus"],
            cert["trustScore"],
            cert.get("trustScoreLabel"),
            cert["auditResult"],
            cert["preWipeNonce"],
            cert["sha256Digest"],
            cert["digitalSignature"],
            cert["qrPayload"],
            1 if cert.get("tamperDetected") else 0,
            cert["verdict"],
            cert["issueDate"]
        ))
    conn.commit()
    conn.close()


def get_certificate_by_query(query: str) -> Optional[Dict[str, Any]]:
    """Looks up certificate by ID or drive serial number."""
    conn = get_db_connection()
    cursor = conn.cursor()
    q = query.strip()
    
    if USE_POSTGRES:
        cursor.execute("""
            SELECT * FROM certificates 
            WHERE certificate_id = %s OR device_serial = %s OR certificate_id ILIKE %s OR device_serial ILIKE %s
            LIMIT 1
        """, (q, q, f"%{q}%", f"%{q}%"))
        columns = [desc[0] for desc in cursor.description]
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        r = dict(zip(columns, row))
        return {
            "certificateId": r["certificate_id"],
            "wipeId": r["wipe_id"],
            "deviceModel": r["device_model"],
            "serialNumber": r["device_serial"],
            "storageType": r["storage_type"],
            "capacity": r["capacity_display"],
            "standard": r["sanitization_method"],
            "methodName": r["sanitization_method"],
            "cleanedStatus": r["cleaned_status"],
            "trustScore": r["trust_score"],
            "trustScoreLabel": "SAFE TO REUSE OR RESELL" if r["trust_score"] == "GREEN" else r["trust_score"],
            "auditResult": r["audit_result"],
            "preWipeNonce": r["pre_wipe_nonce"],
            "sha256Digest": r["sha256_digest"],
            "digitalSignature": r["digital_signature"],
            "qrPayload": r["qr_payload"],
            "tamperDetected": bool(r["tamper_detected"]),
            "verdict": r["verdict"],
            "issueDate": str(r.get("issued_at", "2026-08-16 23:33:00 UTC"))
        }
    else:
        cursor.execute("""
            SELECT * FROM certificates 
            WHERE certificate_id = ? OR serial_number = ? OR certificate_id LIKE ? OR serial_number LIKE ?
            LIMIT 1
        """, (q, q, f"%{q}%", f"%{q}%"))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        return {
            "certificateId": row["certificate_id"],
            "wipeId": row["wipe_id"],
            "deviceModel": row["device_model"],
            "serialNumber": row["serial_number"],
            "storageType": row["storage_type"],
            "capacity": row["capacity"],
            "standard": row["standard"],
            "methodName": row["method_name"],
            "cleanedStatus": row["cleaned_status"],
            "trustScore": row["trust_score"],
            "trustScoreLabel": row["trust_score_label"],
            "auditResult": row["audit_result"],
            "preWipeNonce": row["pre_wipe_nonce"],
            "sha256Digest": row["sha256_digest"],
            "digitalSignature": row["digital_signature"],
            "qrPayload": row["qr_payload"],
            "tamperDetected": bool(row["tamper_detected"]),
            "verdict": row["verdict"],
            "issueDate": row["issue_date"]
        }


# Automatically initialize on module import
init_db()
