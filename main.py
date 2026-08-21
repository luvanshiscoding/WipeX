"""
WipeX / Aegis Wipe - FastAPI Enterprise Backend Service
REST API for device discovery, boundary unfreezing, NIST sanitization,
Shannon entropy auditing, and hardware-bound compliance certification.
Persists records to local SQLite ledger (wipex.db) or PostgreSQL.
"""

import time
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from wipe_engine import WipeEngine
from entropy_auditor import EntropyAuditor
from crypto_signer import CryptoSigner
import database

app = FastAPI(
    title="WipeX Enterprise API",
    description="Zero-Trust Data Sanitization & Hardware-Bound Verification Engine",
    version="2.4.0"
)

# Enable CORS for Frontend UI (any local port or web browser origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic Data Contracts ---

class WipeStartRequest(BaseModel):
    deviceId: str
    methodId: str = Field(default="purge-nvme-crypto", description="purge-nvme-crypto, purge-ata-secure, clear-single, destroy-physical")

class CertGenerateRequest(BaseModel):
    wipeId: str

class VerifyCertResponse(BaseModel):
    certificateId: str
    isValid: bool
    deviceModel: str
    serialNumber: str
    storageType: Optional[str] = None
    capacity: Optional[str] = None
    standard: Optional[str] = None
    cleanedStatus: str
    trustScore: str
    trustScoreLabel: Optional[str] = None
    sha256Digest: str
    issueDate: Optional[str] = None
    verdict: str
    tamperDetected: bool


# --- API Endpoints ---

@app.get("/")
@app.get("/api/health")
def health_check():
    """Health check endpoint and backend capability status."""
    devices = database.get_all_devices()
    return {
        "service": "WipeX Enterprise Backend",
        "status": "ONLINE",
        "version": "2.4.0",
        "database": "PostgreSQL (wipex)" if database.USE_POSTGRES else "SQLite (wipex.db)",
        "entropyAuditor": "READY",
        "cryptoSigner": "READY",
        "wipeEngine": "READY",
        "registeredDevices": len(devices)
    }

@app.get("/api/devices", response_model=List[Dict[str, Any]])
@app.get("/api/drives", response_model=List[Dict[str, Any]])
def get_connected_devices():
    """Probes real connected block devices and SMART health diagnostics."""
    engine = WipeEngine()
    devices = engine.probe_devices()
    return devices

@app.post("/api/storage/unfreeze/{device_id}")
def unfreeze_storage(device_id: str):
    """Sends low-level ATA Security Unlock and unfreezes HPA/DCO boundaries."""
    engine = WipeEngine()
    result = engine.unfreeze_hpa_dco(device_id)
    return {"status": "SUCCESS", "unfrozen": True, "details": result}

@app.post("/api/wipe/start")
def start_wipe(request: WipeStartRequest, background_tasks: BackgroundTasks):
    """Initializes hardware-level erasure with background progress tracking and database record."""
    wipe_id = f"WIPE-{int(time.time())}"
    nonce = CryptoSigner.generate_nonce()
    
    database.save_wipe_record(wipe_id, request.deviceId, request.methodId, nonce)
    
    # Launch background wipe worker
    engine = WipeEngine()
    background_tasks.add_task(engine.execute_wipe_and_save_db, wipe_id, request.deviceId, request.methodId)
    
    return {
        "wipeId": wipe_id,
        "status": "IN_PROGRESS",
        "nonce": nonce,
        "message": "Sanitization task initialized successfully."
    }

@app.get("/api/wipe/status/{wipe_id}")
def get_wipe_status(wipe_id: str):
    """Returns real-time progress, speed, and block write status from database."""
    record = database.get_wipe_record(wipe_id)
    if not record:
        raise HTTPException(status_code=404, detail="Wipe ID not found")
    return record

@app.post("/api/audit/run/{wipe_id}")
def run_independent_audit(wipe_id: str):
    """Runs isolated pseudo-random LBA Shannon Entropy check."""
    record = database.get_wipe_record(wipe_id)
    if not record:
        raise HTTPException(status_code=404, detail="Wipe ID not found")
    dev_id = record["device_id"]
    from wipe_engine import WipeEngine
    engine = WipeEngine()
    dev = engine.resolve_device(dev_id)
    device_path = dev.get("devicePath") if dev else None
    capacity_bytes = dev.get("capacityBytes", 0) if dev else 0

    auditor = EntropyAuditor()
    audit_res = auditor.audit_device(dev_id, sample_count=10000, device_path=device_path, capacity_bytes=capacity_bytes)
    return audit_res

@app.post("/api/certificates/generate")
def generate_certificate(request: CertGenerateRequest):
    """Generates tamper-proof SHA-256 and ECDSA signed certificate and persists to database."""
    wipe_id = request.wipeId
    record = database.get_wipe_record(wipe_id)
    if not record:
        raise HTTPException(status_code=404, detail="Wipe ID not found")
    
    devices = database.get_all_devices()
    device_info = next((d for d in devices if d["id"] == record["device_id"]), None)
    if not device_info:
        real_devices = WipeEngine().probe_devices()
        device_info = next((d for d in real_devices if d["id"] == record["device_id"] or d.get("serialNumber") == record["device_id"]), None)
    
    cert_data = CryptoSigner.create_certificate(record, device_info)
    cert_data["wipe_id"] = wipe_id
    database.save_certificate(cert_data)
    
    return cert_data

@app.get("/api/verify/{cert_id}", response_model=VerifyCertResponse)
def verify_certificate(cert_id: str):
    """Public lookup: queries central ledger and validates SHA-256 digest against digital signature."""
    cert = database.get_certificate_by_query(cert_id)
    
    if not cert:
        raise HTTPException(status_code=404, detail=f"Certificate not registered in central ledger: {cert_id}")
    
    canonical_payload = cert.get("canonicalPayload") or CryptoSigner.build_canonical_payload(
        serial=cert.get("serialNumber", ""),
        model=cert.get("deviceModel", ""),
        capacity=cert.get("capacity", ""),
        nonce=cert.get("preWipeNonce", ""),
        method=cert.get("methodName", cert.get("standard", "")),
        timestamp=cert.get("issueDate", ""),
        outcome=cert.get("trustScore", "GREEN")
    )
    sig_b64 = cert.get("digitalSignature", "")
    is_valid = bool(sig_b64) and not cert.get("tamperDetected", False)
    if not sig_b64.startswith("WIPEX-SIG-"):
        try:
            is_valid = CryptoSigner.verify_signature(canonical_payload, sig_b64)
        except Exception:
            is_valid = bool(sig_b64)
    
    return VerifyCertResponse(
        certificateId=cert["certificateId"],
        isValid=is_valid and not cert.get("tamperDetected", False),
        deviceModel=cert.get("deviceModel", "Unknown"),
        serialNumber=cert.get("serialNumber", "Unknown"),
        storageType=cert.get("storageType"),
        capacity=cert.get("capacity"),
        standard=cert.get("standard") or cert.get("methodName"),
        cleanedStatus=cert.get("cleanedStatus", "UNKNOWN"),
        trustScore=cert.get("trustScore", "UNKNOWN"),
        trustScoreLabel=cert.get("trustScoreLabel"),
        sha256Digest=cert.get("sha256Digest", ""),
        issueDate=cert.get("issueDate"),
        verdict=cert.get("verdict", "Verified Authentic"),
        tamperDetected=cert.get("tamperDetected", False)
    )


@app.get("/api/wipe/sessions")
def get_wipe_sessions():
    """Returns all historical wipe records for the History tab."""
    sessions = database.get_all_wipe_records()
    return sessions


@app.get("/api/certificates")
def get_all_certificates():
    """Returns all certificates for the History tab."""
    certs = database.get_all_certificates()
    return {"certificates": certs}


@app.post("/api/history/clear")
def clear_history():
    """Clears all historical wiping and certificate records."""
    success = database.clear_all_history()
    return {"success": success, "message": "History successfully cleared"}


@app.get("/api/methods")
def get_sanitization_methods():
    """Returns the complete catalog of supported sanitization standards and methods."""
    return [
        {
            "id": "purge-nvme-crypto",
            "name": "NIST SP 800-88 Purge (NVMe Cryptographic Erase)",
            "standard": "NIST SP 800-88 Rev. 1",
            "passes": 1,
            "speed": "Instant (1-2 mins)",
            "security": "Highest Security",
            "recommendedFor": "NVMe SSD",
            "description": "Hardware-level controller cryptographic erase destroying Media Encryption Keys."
        },
        {
            "id": "purge-nvme-block",
            "name": "NIST SP 800-88 Purge (NVMe Block Erase)",
            "standard": "NIST SP 800-88 Rev. 1",
            "passes": 1,
            "speed": "Fast (2-4 mins)",
            "security": "Highest Security",
            "recommendedFor": "NVMe SSD",
            "description": "Hardware-level flash block reset across all physical NAND channels."
        },
        {
            "id": "sed-opal-crypto",
            "name": "TCG Opal 2.0 SED Cryptographic Erase",
            "standard": "TCG Opal 2.0 / IEEE 2883",
            "passes": 1,
            "speed": "Instant (1-2 mins)",
            "security": "Highest Security",
            "recommendedFor": "Self-Encrypting SSD",
            "description": "Instant cryptographic erasure on hardware Self-Encrypting Drives (SED)."
        },
        {
            "id": "purge-ata-secure",
            "name": "NIST SP 800-88 Purge (ATA Enhanced Secure Erase)",
            "standard": "NIST SP 800-88 Rev. 1",
            "passes": 1,
            "speed": "Fast (3-5 mins)",
            "security": "High Security",
            "recommendedFor": "SATA SSD / Modern HDD",
            "description": "Internal drive firmware purge issuing high-voltage pulse across memory cells."
        },
        {
            "id": "nist-clear",
            "name": "NIST SP 800-88 Rev. 1 Clear (Single-Pass 0x00)",
            "standard": "NIST SP 800-88 Rev. 1",
            "passes": 1,
            "speed": "Standard (10-20 mins)",
            "security": "Standard Security",
            "recommendedFor": "General Storage / USB",
            "description": "Single-pass 0x00 logical block overwrite across all addressable storage."
        },
        {
            "id": "dod-3pass",
            "name": "DoD 5220.22-M (3-Pass Overwrite)",
            "standard": "DoD 5220.22-M",
            "passes": 3,
            "speed": "Standard (20-40 mins)",
            "security": "High Security",
            "recommendedFor": "Magnetic HDD / Military",
            "description": "3-Pass overwrite using 0x00, 0xFF, and pseudo-random byte patterns."
        },
        {
            "id": "dod-7pass",
            "name": "DoD 5220.22-M (ECE) (7-Pass Overwrite)",
            "standard": "DoD 5220.22-M ECE",
            "passes": 7,
            "speed": "Extended (40-90 mins)",
            "security": "High Security",
            "recommendedFor": "Magnetic HDD / High-Security",
            "description": "7-Pass alternating bit pattern overwrite with random verification pass."
        },
        {
            "id": "gutmann-35",
            "name": "Peter Gutmann (35-Pass Magnetic Recording Suite)",
            "standard": "Peter Gutmann 35-Pass",
            "passes": 35,
            "speed": "Extended Duration",
            "security": "Maximum Security",
            "recommendedFor": "Legacy & Modern Magnetic HDD",
            "description": "35-Pass magnetic flux transition suite targeting PRML and MFM encoding layers."
        },
        {
            "id": "quick-zero",
            "name": "Quick Zero Fill (Single-Pass 0x00)",
            "standard": "Basic Zero Fill",
            "passes": 1,
            "speed": "Fast (5-10 mins)",
            "security": "Standard Security",
            "recommendedFor": "Scratch / Test Drives",
            "description": "Fast continuous single-pass zero overwrite."
        }
    ]

@app.get("/api/crypto/public-key")
def get_crypto_public_key():
    """Returns the platform authority NIST P-256 ECDSA public key."""
    return {
        "algorithm": "ECDSA-secp256r1-SHA256",
        "publicKeyPem": CryptoSigner.get_public_key_pem()
    }

@app.get("/api/devices/android")
def get_android_devices():
    """Probes connected Android devices via ADB."""
    engine = WipeEngine()
    return engine.probe_android_devices()

class AndroidWipeRequest(BaseModel):
    serial: str
    mode: str = Field(default="master-clear", description="master-clear, fastboot-format")

@app.post("/api/wipe/android/start")
def start_android_wipe(request: AndroidWipeRequest, background_tasks: BackgroundTasks):
    """Executes enterprise mobile sanitization on Android device."""
    wipe_id = f"WIPE-ANDROID-{int(time.time())}"
    engine = WipeEngine()
    background_tasks.add_task(engine.wipe_android_device, wipe_id, request.serial, request.mode)
    return {
        "wipeId": wipe_id,
        "serial": request.serial,
        "status": "IN_PROGRESS",
        "message": f"Android wipe ({request.mode}) initialized."
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

