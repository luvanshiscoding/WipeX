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
    
    is_valid = CryptoSigner.verify_signature(cert)
    
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
