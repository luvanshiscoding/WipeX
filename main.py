"""
WipeX - FastAPI backend.

Modules:
  M1 Drive Eraser        /api/devices, /api/wipe/*, /api/certificates/*, /api/verify/*
  M2 File & Folder Eraser /api/files/*
  M3 Carving & Recovery  /api/recovery/*, /api/benchmark
  Case management        /api/cases/*, /api/evidence/*, /api/holds/*
  Audit                  /api/audit/*
  Lab disk images        /api/lab/images/*
"""

import ctypes
import os
import platform
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

import audit_log
import benchmark
import cases
import database
import erasure
import file_eraser
import jobs
import lab_images
import recovery
import reports
import store
from crypto_signer import HAS_CRYPTOGRAPHY, CryptoSigner
from recovery import fs_recovery
from wipe_engine import WipeEngine

app = FastAPI(title="WipeX API", version="0.3.0",
              description="Integrated secure data erasure and forensic file recovery (SIH26149)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

store.init()
erasure._init_tables()


def _startup_images():
    try:
        lab_images.ensure_default_images()
    except Exception as exc:  # noqa: BLE001
        print("Lab image setup failed:", exc)


threading.Thread(target=_startup_images, daemon=True).start()


def _fail(exc: Exception):
    """Map domain exceptions to HTTP errors."""
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, (LookupError, FileNotFoundError)):
        raise HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (ValueError, FileExistsError)):
        raise HTTPException(status_code=400, detail=str(exc))
    raise HTTPException(status_code=500, detail=str(exc))


def _is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/")
@app.get("/api/health")
def health_check():
    return {
        "service": "WipeX", "status": "ONLINE", "version": app.version,
        "database": "PostgreSQL" if database.USE_POSTGRES else "SQLite (wipex.db)",
        "platform": platform.system(), "elevated": _is_admin(),
        "capabilities": {
            "signing": HAS_CRYPTOGRAPHY, "sleuthKit": fs_recovery.available(),
            "pdfReports": True, "formats": [f["ext"] for f in recovery.supported_formats()],
            "hardwarePurge": platform.system() == "Linux",
        },
        "counts": {"auditEntries": audit_log.count(), "cases": len(cases.list_cases()),
                   "labImages": len(lab_images.list_images(with_files=False))},
        "dualApproval": cases.dual_approval_required(),
    }


# ── Devices (M1) ─────────────────────────────────────────────────────────────

_device_cache: Dict[str, Any] = {"devices": [], "timestamp": 0.0, "lock": threading.Lock()}
DEVICE_CACHE_TTL = 30


def _physical_devices(refresh: bool = False) -> List[Dict[str, Any]]:
    now = time.time()
    with _device_cache["lock"]:
        if not refresh and now - _device_cache["timestamp"] < DEVICE_CACHE_TTL and _device_cache["devices"]:
            return list(_device_cache["devices"])
        try:
            fresh = WipeEngine().probe_devices()
        except Exception:  # noqa: BLE001
            fresh = []
        if fresh or not _device_cache["devices"]:
            _device_cache["devices"] = fresh
        _device_cache["timestamp"] = now
        return list(_device_cache["devices"])


@app.get("/api/devices")
@app.get("/api/drives")
def get_connected_devices(images: bool = True, refresh: bool = False):
    """Physical storage devices plus lab disk images (safe, file-backed erasure targets)."""
    devs = _physical_devices(refresh)
    if images:
        devs = devs + lab_images.list_images()
    for d in devs:
        hold = cases.find_blocking_hold(d.get("serialNumber", ""), d.get("devicePath", ""))
        d["legalHold"] = {"id": hold["id"], "caseId": hold["case_id"]} if hold else None
    return devs


@app.post("/api/storage/unfreeze/{device_id}")
def unfreeze_storage(device_id: str):
    if platform.system() != "Linux":
        return {"status": "UNSUPPORTED", "message": "HPA/DCO inspection uses hdparm on Linux"}
    return {"status": "ATTEMPTED", "details": WipeEngine().unfreeze_hpa_dco(device_id)}


@app.get("/api/methods")
def get_sanitization_methods():
    return erasure.method_catalog()


class WipeStartRequest(BaseModel):
    deviceId: str
    methodId: str
    operator: str = ""
    approver: str = ""
    caseId: Optional[str] = None


@app.post("/api/wipe/start")
def start_wipe(req: WipeStartRequest, background_tasks: BackgroundTasks):
    try:
        started = erasure.start(req.deviceId, req.methodId, req.operator, req.approver, req.caseId)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    background_tasks.add_task(erasure.run, started["wipeId"])
    return {**started, "status": "IN_PROGRESS"}


@app.get("/api/wipe/status/{wipe_id}")
def get_wipe_status(wipe_id: str):
    rec = database.get_wipe_record(wipe_id)
    if not rec:
        raise HTTPException(404, "Wipe ID not found")
    er = erasure.get(wipe_id)
    if er:
        rec["execution"] = er["execution"]
        rec["verification"] = er["verification"]
        rec["device"] = er["device"]
    return rec


@app.post("/api/audit/run/{wipe_id}")
def get_verification(wipe_id: str):
    """Verification results recorded by the erasure job (read-back, canaries, recovery attempt)."""
    er = erasure.get(wipe_id)
    if not er or not er.get("verification"):
        raise HTTPException(404, "No verification recorded for this job yet")
    v = er["verification"]
    pattern = next((c for c in v.get("checks", []) if c["name"] == "Pattern read-back"), {})
    return {**v, "status": "PASSED" if v.get("verdict") == "PASS" else "FAILED", "message": v.get("summary"),
            "sectorsSampled": v.get("samples"), "shannonEntropy": v.get("meanEntropy"), "coverage": pattern.get("coverage")}


class CertGenerateRequest(BaseModel):
    wipeId: str
    actor: str = "system"


@app.post("/api/certificates/generate")
def generate_certificate(req: CertGenerateRequest):
    try:
        return erasure.issue_certificate(req.wipeId, req.actor)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.get("/api/verify/{query}")
def verify_certificate(query: str):
    cert = erasure.lookup_certificate(query)
    if not cert:
        raise HTTPException(404, f"No certificate with ID or serial number '{query}'")
    return cert


@app.get("/api/certificates/{cert_id}/pdf")
def certificate_pdf(cert_id: str):
    cert = erasure.lookup_certificate(cert_id)
    if not cert:
        raise HTTPException(404, "Certificate not found")
    return Response(reports.certificate_pdf(cert), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{cert_id}.pdf"'})


@app.get("/api/wipe/sessions")
def get_wipe_sessions():
    return database.get_all_wipe_records()


@app.get("/api/certificates")
def get_all_certificates():
    return {"certificates": database.get_all_certificates()}


@app.post("/api/history/clear")
def clear_history(actor: str = "system"):
    ok = database.clear_all_history()
    audit_log.append("history.cleared", actor, details={"note": "Session and certificate tables cleared; audit log retained"})
    return {"success": ok}


@app.get("/api/crypto/public-key")
def get_crypto_public_key():
    return {"algorithm": "ECDSA P-256 / SHA-256", "publicKeyPem": CryptoSigner.get_public_key_pem()}


@app.get("/api/devices/android")
def get_android_devices():
    return WipeEngine().probe_android_devices()


class AndroidWipeRequest(BaseModel):
    serial: str
    mode: str = Field(default="master-clear", description="master-clear, fastboot-format")


@app.post("/api/wipe/android/start")
def start_android_wipe(req: AndroidWipeRequest, background_tasks: BackgroundTasks):
    wipe_id = f"WIPE-ANDROID-{int(time.time())}"
    background_tasks.add_task(WipeEngine().wipe_android_device, wipe_id, req.serial, req.mode)
    audit_log.append("erasure.android_started", "system", target=req.serial, details={"mode": req.mode, "wipeId": wipe_id})
    return {"wipeId": wipe_id, "serial": req.serial, "status": "IN_PROGRESS"}


# ── Lab images ───────────────────────────────────────────────────────────────

class LabImageRequest(BaseModel):
    name: str
    kind: str = "sample"
    sizeMb: int = 64


@app.get("/api/lab/images")
def list_lab_images():
    return lab_images.list_images()


@app.post("/api/lab/images")
def create_lab_image(req: LabImageRequest):
    try:
        img = lab_images.create_image(req.name, req.kind, req.sizeMb)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    audit_log.append("lab_image.created", "system", target=img["devicePath"], details={"kind": req.kind})
    return img


@app.post("/api/lab/images/{image_id}/reset")
def reset_lab_image(image_id: str):
    try:
        img = lab_images.reset_image(image_id)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    audit_log.append("lab_image.reset", "system", target=img["devicePath"])
    return img


@app.delete("/api/lab/images/{image_id}")
def delete_lab_image(image_id: str):
    try:
        lab_images.delete_image(image_id)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    return {"deleted": image_id}


# ── Recovery (M3) ────────────────────────────────────────────────────────────

class RecoverySource(BaseModel):
    type: str = Field(description="lab | evidence | path")
    id: Optional[str] = None
    path: Optional[str] = None


class RecoveryRequest(BaseModel):
    source: RecoverySource
    useFs: bool = True
    useCarving: bool = True
    types: Optional[List[str]] = None
    includePartial: bool = False
    caseId: Optional[str] = None
    actor: str = "system"


def _resolve_source(src: RecoverySource) -> Dict[str, Any]:
    if src.type == "lab":
        path = lab_images.path_for_id(src.id or "")
        if not path:
            raise LookupError("Lab image not found")
        return {"path": path, "label": os.path.basename(path)}
    if src.type == "evidence":
        ev = cases.get_evidence(src.id or "")
        if not ev:
            raise LookupError("Evidence item not found")
        return {"path": ev["image_path"], "label": f"{ev['id']} ({ev['label']})", "evidence": ev}
    if src.type == "path" and src.path:
        if not os.path.exists(src.path) and not src.path.startswith("\\\\.\\"):
            raise FileNotFoundError(src.path)
        return {"path": src.path, "label": src.path}
    raise ValueError("Unknown recovery source")


@app.post("/api/recovery/scan")
def start_recovery(req: RecoveryRequest):
    try:
        src = _resolve_source(req.source)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    case_id = req.caseId or (src.get("evidence") or {}).get("case_id")

    def work(ctx):
        out_dir = store.workspace_path("recovery", ctx.id)
        audit_log.append("recovery.started", req.actor, target=src["path"], case_id=case_id,
                         details={"jobId": ctx.id, "fs": req.useFs, "carving": req.useCarving})
        res = recovery.scan(src["path"], out_dir, use_fs=req.useFs, use_carving=req.useCarving, types=req.types,
                            include_partial=req.includePartial, progress=ctx.progress)
        res["outDir"] = out_dir
        res["sourceLabel"] = src["label"]
        res["evidenceId"] = (src.get("evidence") or {}).get("id")
        audit_log.append("recovery.finished", req.actor, target=src["path"], case_id=case_id,
                         details={"jobId": ctx.id, "summary": res["summary"]})
        return res

    job_id = jobs.submit("recovery", work, params={"source": req.source.model_dump(), "label": src["label"]}, case_id=case_id)
    return {"jobId": job_id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@app.get("/api/jobs")
def list_all_jobs(kind: Optional[str] = None):
    return jobs.list_jobs(kind)


def _safe_workspace_file(path: str) -> str:
    ap = os.path.abspath(path)
    ws = os.path.abspath(store.WORKSPACE)
    if not (ap.startswith(ws + os.sep) and os.path.isfile(ap)):
        raise HTTPException(403, "File is outside the WipeX workspace")
    return ap


@app.get("/api/recovery/file")
def get_recovered_file(path: str, download: bool = False):
    ap = _safe_workspace_file(path)
    return FileResponse(ap, filename=os.path.basename(ap) if download else None)


@app.get("/api/recovery/{job_id}/report.pdf")
def recovery_report(job_id: str):
    job = jobs.get(job_id)
    if not job or job["status"] != "COMPLETED":
        raise HTTPException(404, "Completed recovery job not found")
    case = cases.get_case(job["case_id"]) if job.get("case_id") else None
    ev = cases.get_evidence(job["result"].get("evidenceId")) if job["result"].get("evidenceId") else None
    return Response(reports.recovery_pdf(job, case, ev), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{job_id}.pdf"'})


@app.get("/api/recovery/formats")
def recovery_formats():
    return recovery.supported_formats()


class BenchmarkRequest(BaseModel):
    imageId: str


@app.post("/api/benchmark")
def run_benchmark(req: BenchmarkRequest):
    path = lab_images.path_for_id(req.imageId)
    if not path or not os.path.exists(path + ".truth.json"):
        raise HTTPException(400, "Benchmark needs a sample lab image with ground truth (create or reset one first)")
    return {"jobId": jobs.submit("benchmark", lambda ctx: benchmark.run(path, progress=ctx.progress), params={"imageId": req.imageId})}


# ── File & folder erasure (M2) ───────────────────────────────────────────────

class PathsRequest(BaseModel):
    paths: List[str]


class FileEraseRequest(BaseModel):
    paths: List[str]
    method: str = "zero"
    cleanTraces: bool = True
    operator: str = ""
    approver: str = ""


@app.get("/api/fs/list")
def list_directory(path: str = ""):
    """Read-only directory listing for the file picker."""
    if not path:
        if platform.system() == "Windows":
            drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
            return {"path": "", "parent": None, "entries": [{"name": d, "path": d, "isDir": True} for d in drives]}
        path = "/"
    ap = os.path.abspath(path)
    if not os.path.isdir(ap):
        raise HTTPException(404, "Not a directory")
    entries = []
    try:
        for name in sorted(os.listdir(ap), key=str.lower)[:2000]:
            fp = os.path.join(ap, name)
            try:
                is_dir = os.path.isdir(fp)
                entries.append({"name": name, "path": fp, "isDir": is_dir,
                                "size": 0 if is_dir else os.path.getsize(fp),
                                "protected": bool(file_eraser.check_path_allowed(fp))})
            except OSError:
                continue
    except PermissionError:
        raise HTTPException(403, "Permission denied")
    parent = os.path.dirname(ap.rstrip("\\/")) if ap.rstrip("\\/") != ap[:3].rstrip("\\/") else ""
    return {"path": ap, "parent": parent if parent != ap else "", "entries": entries,
            "workspace": os.path.abspath(store.WORKSPACE)}


@app.post("/api/files/analyze")
def analyze_files(req: PathsRequest):
    try:
        return file_eraser.analyze(req.paths)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.post("/api/files/erase")
def erase_files(req: FileEraseRequest):
    try:
        cases.check_authorization(req.operator, req.approver)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)

    def work(ctx):
        return file_eraser.erase(req.paths, req.method, req.cleanTraces, req.operator, req.approver, progress=ctx.progress)

    return {"jobId": jobs.submit("file_erasure", work, params={"paths": req.paths, "method": req.method})}


@app.post("/api/files/sandbox")
def create_file_sandbox():
    return file_eraser.create_sandbox(True)


@app.get("/api/files/report/{job_id}.pdf")
def file_erasure_report(job_id: str):
    job = jobs.get(job_id)
    if not job or job["status"] != "COMPLETED":
        raise HTTPException(404, "Completed file erasure job not found")
    return Response(reports.file_erasure_pdf(job["result"]), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{job["result"]["jobId"]}.pdf"'})


# ── Cases, evidence, legal holds ─────────────────────────────────────────────

class CaseRequest(BaseModel):
    title: str
    investigator: str
    description: str = ""


class EvidenceRequest(BaseModel):
    label: str = ""
    labImageId: Optional[str] = None
    sourcePath: Optional[str] = None
    actor: str = "system"


class HoldRequest(BaseModel):
    target: str
    targetKind: str
    reason: str = ""
    actor: str = "system"


class ActorRequest(BaseModel):
    actor: str = "system"


class StatusRequest(BaseModel):
    status: str
    actor: str = "system"


class DualApprovalRequest(BaseModel):
    enabled: bool
    actor: str = "system"


@app.get("/api/cases")
def list_cases():
    return cases.list_cases()


@app.post("/api/cases")
def create_case(req: CaseRequest):
    try:
        return cases.create_case(req.title, req.investigator, req.description)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    case = cases.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    case["jobs"] = [j for j in jobs.list_jobs(limit=200) if j.get("case_id") == case_id]
    return case


@app.post("/api/cases/{case_id}/status")
def set_case_status(case_id: str, req: StatusRequest):
    try:
        cases.set_case_status(case_id, req.status, req.actor)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    return cases.get_case(case_id)


@app.post("/api/cases/{case_id}/evidence")
def acquire_evidence(case_id: str, req: EvidenceRequest):
    source = lab_images.path_for_id(req.labImageId) if req.labImageId else req.sourcePath
    if not source:
        raise HTTPException(400, "Choose a lab image or enter a source path")
    if not os.path.exists(source) and not source.startswith("\\\\.\\"):
        raise HTTPException(404, f"Source not found: {source}")
    label = req.label or os.path.basename(source)
    job_id = jobs.submit("acquisition", lambda ctx: {**cases.acquire_evidence(case_id, source, label, req.actor, ctx.progress),
                                                    "summary": f"Acquired {label}"},
                         params={"source": source}, case_id=case_id)
    return {"jobId": job_id}


@app.post("/api/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str, req: ActorRequest):
    try:
        return cases.verify_evidence(evidence_id, req.actor)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.post("/api/cases/{case_id}/holds")
def add_hold(case_id: str, req: HoldRequest):
    try:
        return cases.add_hold(case_id, req.target, req.targetKind, req.reason, req.actor)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.post("/api/holds/{hold_id}/release")
def release_hold(hold_id: str, req: ActorRequest):
    try:
        cases.release_hold(hold_id, req.actor)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    return {"released": hold_id}


@app.get("/api/holds")
def list_holds():
    return cases.active_holds()


@app.get("/api/settings/dual-approval")
def get_dual_approval():
    return {"enabled": cases.dual_approval_required()}


@app.post("/api/settings/dual-approval")
def set_dual_approval(req: DualApprovalRequest):
    cases.set_dual_approval(req.enabled, req.actor)
    return {"enabled": req.enabled}


# ── Audit log ────────────────────────────────────────────────────────────────

@app.get("/api/audit/log")
def get_audit_log(limit: int = Query(200, le=2000), offset: int = 0, caseId: Optional[str] = None):
    return {"entries": audit_log.entries(limit, offset, caseId), "total": audit_log.count()}


@app.get("/api/audit/verify")
def verify_audit_chain():
    return audit_log.verify_chain()


@app.get("/api/audit/export")
def export_audit_log():
    data = {"exportedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "publicKeyPem": CryptoSigner.get_public_key_pem(),
            "verification": audit_log.verify_chain(),
            "entries": list(reversed(audit_log.entries(limit=100000)))}
    import json as _json
    return Response(_json.dumps(data, indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="wipex-audit-log.json"'})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
