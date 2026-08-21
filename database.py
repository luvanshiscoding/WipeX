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
        
        # NO SEED DATA EVER — devices and certificates only come from real
        # hardware probes and real wipe operations.
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
            qr_payload TEXT DEFAULT '',
            tamper_detected INTEGER DEFAULT 0,
            verdict TEXT NOT NULL,
            issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(serial_number)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cert_id ON certificates(certificate_id)")

    # NO SEED DATA EVER — devices and certificates only come from real
    # hardware probes and real wipe operations.

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
        db_dev_id = str(row[0]) if row else str(device_id)
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


def get_all_wipe_records() -> List[Dict[str, Any]]:
    """Returns all wipe records ordered by most recent first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if USE_POSTGRES:
            cursor.execute("SELECT * FROM wipe_records ORDER BY started_at DESC LIMIT 100")
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            return [dict(zip(columns, r)) for r in rows]
        else:
            cursor.execute("SELECT * FROM wipe_records ORDER BY started_at DESC LIMIT 100")
            rows = cursor.fetchall()
            records = []
            for row in rows:
                records.append({
                    "wipeId": row["wipe_id"],
                    "deviceId": row["device_id"],
                    "method": row["method"],
                    "status": row["status"],
                    "progress": row["progress"],
                    "command": row["command"],
                    "speed": row["speed"],
                    "startedAt": row["started_at"],
                    "completedAt": row["completed_at"]
                })
            return records
    except Exception:
        return []
    finally:
        conn.close()


def get_all_certificates() -> List[Dict[str, Any]]:
    """Returns all certificates ordered by most recent first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if USE_POSTGRES:
            cursor.execute("SELECT * FROM certificates ORDER BY issued_at DESC LIMIT 100")
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            return [dict(zip(columns, r)) for r in rows]
        else:
            cursor.execute("SELECT * FROM certificates ORDER BY issue_date DESC LIMIT 100")
            rows = cursor.fetchall()
            certs = []
            for row in rows:
                certs.append({
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
                    "tamperDetected": bool(row["tamper_detected"]),
                    "verdict": row["verdict"],
                    "issueDate": row["issue_date"]
                })
            return certs
    except Exception:
        return []
    finally:
        conn.close()


def clear_all_history() -> bool:
    """Clears all historical wipe records and certificates from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if USE_POSTGRES:
            cursor.execute("TRUNCATE TABLE certificates, wipe_records")
        else:
            cursor.execute("DELETE FROM certificates")
            cursor.execute("DELETE FROM wipe_records")
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


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
            cert.get("qrPayload", ""),
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
            cert.get("qrPayload", ""),
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
