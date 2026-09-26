"""
WipeX - FastAPI backend (local, offline).

Modules:
  M1 Drive Eraser         /api/devices, /api/wipe/*, /api/certificates/*, /api/verify/*
  M2 File & Folder Eraser /api/files/*
  M3 Carving & Recovery   /api/recovery/*, /api/benchmark
  Case management         /api/cases/*, /api/evidence/*, /api/holds/*
  Users and roles         /api/auth/*, /api/users
  Audit                   /api/audit/*
  Lab disk images         /api/lab/images/*

Every route except health, sign-in and certificate verification needs a signed-in user
whose role grants the route's permission (see users.ROLES). The built web UI (dist/) is
served from / so the whole application runs as one local process with no network access.
"""

import ctypes
import json
import os
import platform
import shutil
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

import audit_log
import benchmark
import cases
import database
import erasure
import ewf
import file_eraser
import hw_sanitize
import jobs
import lab_images
import paths
import recovery
import reports
import store
import users
from crypto_signer import HAS_CRYPTOGRAPHY, CryptoSigner
from recovery import fs_recovery
from wipe_engine import WipeEngine

app = FastAPI(title="WipeX API", version="0.4.0",
              description="Integrated secure data erasure and forensic file recovery")
# Only local clients: blocks DNS-rebinding pages from reaching the API through the browser
_hosts = os.environ.get("WIPEX_ALLOWED_HOSTS", "localhost,127.0.0.1,::1,testserver").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in _hosts if h.strip()])
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])

store.init()
database.init_db()
erasure._init_tables()
users.init()


def _startup_images():
    try:
        lab_images.ensure_default_images()
    except Exception as exc:  # noqa: BLE001
        print("Lab image setup failed:", exc)


threading.Thread(target=_startup_images, daemon=True).start()


def _fail(exc: Exception):
    """Map domain exceptions to HTTP errors."""
    if isinstance(exc, HTTPException):
        raise exc
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


# ── Authentication ───────────────────────────────────────────────────────────

async def signed_in(request: Request) -> Dict[str, Any]:
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else request.query_params.get("token", "")
    sess = users.session_for(token)
    if not sess:
        raise HTTPException(401, "Sign in required")
    users.current_session.set(sess)          # audit entries made for this request are signed by this user
    return sess


def need(perm: str):
    async def check(sess: Dict[str, Any] = Depends(signed_in)) -> Dict[str, Any]:
        if not users.has_perm(sess["role"], perm):
            label = users.ROLES.get(sess["role"], {}).get("label", sess["role"])
            raise HTTPException(403, f"The {label} role is not permitted to do this ({perm})")
        return sess
    return check


def _approval(operator: str, approver: str, password: str, action: str, target: str) -> Optional[Dict[str, Any]]:
    """Two-person rule: required when enabled, verified whenever an approver is supplied."""
    if not approver:
        if cases.dual_approval_required():
            raise PermissionError("Two-person rule is on: an approver must sign in to approve this erasure")
        return None
    return users.approve(approver, password, operator, action, target)


class SetupRequest(BaseModel):
    username: str
    password: str
    displayName: str = ""


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordRequest(BaseModel):
    oldPassword: str
    newPassword: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str
    displayName: str = ""


class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    active: Optional[bool] = None
    newPassword: Optional[str] = None


@app.get("/api/auth/state")
def auth_state(request: Request):
    header = request.headers.get("authorization", "")
    sess = users.session_for(header[7:].strip()) if header.lower().startswith("bearer ") else None
    user = next((u for u in users.list_users() if sess and u["id"] == sess["userId"]), None)
    return {"setupRequired": users.setup_required(), "user": user}


@app.post("/api/auth/setup")
def auth_setup(req: SetupRequest):
    """First run only: create the administrator account."""
    if not users.setup_required():
        raise HTTPException(409, "Setup has already been completed")
    try:
        users.create_user(req.username, req.password, "admin", req.displayName, actor=req.username)
        return users.login(req.username, req.password)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.post("/api/auth/login")
def auth_login(req: LoginRequest):
    try:
        return users.login(req.username, req.password)
    except PermissionError as exc:
        audit_log.append("user.login_failed", req.username or "unknown", target=req.username)
        raise HTTPException(401, str(exc))


@app.post("/api/auth/logout")
def auth_logout(sess=Depends(signed_in)):
    users.logout(sess["token"])
    return {"signedOut": True}


@app.post("/api/auth/password")
def auth_password(req: PasswordRequest, sess=Depends(signed_in)):
    try:
        users.change_password(sess["username"], req.oldPassword, req.newPassword)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    return {"changed": True}


@app.get("/api/roles")
def list_roles(sess=Depends(signed_in)):
    return [{"id": k, "label": v["label"], "permissions": sorted(v["perms"])} for k, v in users.ROLES.items()]


@app.get("/api/users")
def list_users(sess=Depends(need("users.manage"))):
    return users.list_users()


@app.post("/api/users")
def create_user(req: UserCreateRequest, sess=Depends(need("users.manage"))):
    try:
        return users.create_user(req.username, req.password, req.role, req.displayName, actor=sess["username"])
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.patch("/api/users/{username}")
def update_user(username: str, req: UserUpdateRequest, sess=Depends(need("users.manage"))):
    if username.lower() == sess["username"].lower() and (req.active is False or (req.role and req.role != "admin")):
        raise HTTPException(400, "You cannot disable or demote your own account")
    try:
        return users.update_user(username, sess["username"], role=req.role, active=req.active,
                                 new_password=req.newPassword)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health_check():
    system = platform.system()
    return {
        "service": "WipeX", "status": "ONLINE", "version": app.version,
        "database": "SQLite (local file)", "platform": system, "elevated": _is_admin(),
        "capabilities": {
            "signing": HAS_CRYPTOGRAPHY, "sleuthKit": fs_recovery.available(), "e01": True,
            "pdfReports": True, "formats": [f["ext"] for f in recovery.supported_formats()],
            "hardwarePurge": {"Linux": "nvme-cli / hdparm / sedutil-cli", "Windows": "NVMe via storage driver"}.get(system),
            "android": bool(shutil.which("adb")),
        },
        "counts": {"auditEntries": audit_log.count(), "cases": len(cases.list_cases()),
                   "labImages": len(lab_images.list_images(with_files=False))},
        "dualApproval": cases.dual_approval_required(),
        "setupRequired": users.setup_required(),
    }


# ── Devices (M1) ─────────────────────────────────────────────────────────────

_device_cache: Dict[str, Any] = {"devices": [], "timestamp": 0.0, "lock": threading.Lock()}
DEVICE_CACHE_TTL = 30


def _physical_devices(refresh: bool = False) -> List[Dict[str, Any]]:
    now = time.time()
    with _device_cache["lock"]:
        if not refresh and now - _device_cache["timestamp"] < DEVICE_CACHE_TTL and _device_cache["devices"]:
            return [dict(d) for d in _device_cache["devices"]]
        try:
            fresh = WipeEngine().probe_devices()
        except Exception:  # noqa: BLE001
            fresh = []
        for d in fresh:
            d["hardwareMethods"] = hw_sanitize.capabilities(d)
            d["recommendedMethod"] = "destroy" if d.get("expectedOutcome") == "RED" else hw_sanitize.recommend(d)
        if fresh or not _device_cache["devices"]:
            _device_cache["devices"] = fresh
        _device_cache["timestamp"] = now
        return [dict(d) for d in _device_cache["devices"]]


@app.get("/api/devices")
def get_connected_devices(images: bool = True, refresh: bool = False, sess=Depends(need("device.read"))):
    """Physical storage devices plus lab disk images (safe, file-backed erasure targets)."""
    devs = _physical_devices(refresh)
    if images:
        devs = devs + lab_images.list_images()
    for d in devs:
        hold = cases.find_blocking_hold(d.get("serialNumber", ""), d.get("devicePath", ""))
        d["legalHold"] = {"id": hold["id"], "caseId": hold["case_id"]} if hold else None
    return devs


@app.post("/api/storage/unfreeze/{device_id}")
def unfreeze_storage(device_id: str, sess=Depends(need("erasure.run"))):
    if platform.system() != "Linux":
        return {"status": "UNSUPPORTED", "message": "HPA/DCO inspection uses hdparm on Linux"}
    return {"status": "ATTEMPTED", "details": WipeEngine().unfreeze_hpa_dco(device_id)}


@app.get("/api/methods")
def get_sanitization_methods(sess=Depends(signed_in)):
    return erasure.method_catalog()


class WipeStartRequest(BaseModel):
    deviceId: str
    methodId: str
    caseId: Optional[str] = None
    approver: str = ""
    approverPassword: str = ""
    psid: str = ""


@app.post("/api/wipe/start")
def start_wipe(req: WipeStartRequest, background_tasks: BackgroundTasks, sess=Depends(need("erasure.run"))):
    operator = sess["username"]
    try:
        approval = _approval(operator, req.approver, req.approverPassword, f"erase-device:{req.methodId}", req.deviceId)
        started = erasure.start(req.deviceId, req.methodId, operator, (approval or {}).get("approver", ""),
                                req.caseId, approval=approval, options={"psid": req.psid} if req.psid else None)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    background_tasks.add_task(erasure.run, started["wipeId"])
    return {**started, "status": "IN_PROGRESS"}


@app.get("/api/wipe/status/{wipe_id}")
def get_wipe_status(wipe_id: str, sess=Depends(need("device.read"))):
    rec = database.get_wipe_record(wipe_id)
    if not rec:
        raise HTTPException(404, "Wipe ID not found")
    er = erasure.get(wipe_id)
    if er:
        rec["execution"] = er["execution"]
        rec["verification"] = er["verification"]
        rec["device"] = er["device"]
        rec["approval"] = er.get("approval")
    return rec


@app.post("/api/audit/run/{wipe_id}")
def get_verification(wipe_id: str, sess=Depends(need("device.read"))):
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


@app.post("/api/certificates/generate")
def generate_certificate(req: CertGenerateRequest, sess=Depends(need("certificate.issue"))):
    try:
        return erasure.issue_certificate(req.wipeId, sess["username"])
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.get("/api/verify/{query}")
def verify_certificate(query: str):
    """Public: anyone holding a certificate (or its QR code) can check it."""
    cert = erasure.lookup_certificate(query)
    if not cert:
        raise HTTPException(404, f"No certificate with ID or serial number '{query}'")
    return cert


@app.get("/api/certificates/{cert_id}/pdf")
def certificate_pdf(cert_id: str, request: Request, sess=Depends(need("report.read"))):
    cert = erasure.lookup_certificate(cert_id)
    if not cert:
        raise HTTPException(404, "Certificate not found")
    verify_url = f"{str(request.base_url).rstrip('/')}/#/verify?q={cert['certificateId']}"
    return Response(reports.certificate_pdf(cert, verify_url), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{cert_id}.pdf"'})


@app.get("/api/wipe/sessions")
def get_wipe_sessions(sess=Depends(need("report.read"))):
    return database.get_all_wipe_records()


@app.get("/api/certificates")
def get_all_certificates(sess=Depends(need("report.read"))):
    return {"certificates": database.get_all_certificates()}


@app.post("/api/history/clear")
def clear_history(sess=Depends(need("settings.manage"))):
    ok = database.clear_all_history()
    audit_log.append("history.cleared", sess["username"],
                     details={"note": "Session and certificate ledger cleared; signed proofs and audit log retained"})
    return {"success": ok}


@app.get("/api/crypto/public-key")
def get_crypto_public_key():
    return {"algorithm": "ECDSA P-256 / SHA-256", "publicKeyPem": CryptoSigner.get_public_key_pem()}


@app.get("/api/devices/android")
def get_android_devices(sess=Depends(need("device.read"))):
    return WipeEngine().probe_android_devices()


class AndroidWipeRequest(BaseModel):
    serial: str
    mode: str = Field(default="guided-reset", description="guided-reset | fastboot-wipe")
    approver: str = ""
    approverPassword: str = ""


@app.post("/api/wipe/android/start")
def start_android_wipe(req: AndroidWipeRequest, sess=Depends(need("erasure.run"))):
    operator = sess["username"]
    try:
        approval = _approval(operator, req.approver, req.approverPassword, f"erase-android:{req.mode}", req.serial)
        hold = cases.find_blocking_hold(req.serial)
        if hold:
            raise PermissionError(f"Device is under legal hold {hold['id']} (case {hold['case_id']})")
    except Exception as exc:  # noqa: BLE001
        _fail(exc)

    def work(ctx):
        audit_log.append("erasure.android_started", operator, target=req.serial,
                         details={"mode": req.mode, "jobId": ctx.id, "approver": (approval or {}).get("approver")})
        try:
            res = WipeEngine().wipe_android_device(req.serial, req.mode, progress=ctx.progress)
        except Exception as exc:
            audit_log.append("erasure.android_failed", operator, target=req.serial, details={"error": str(exc)})
            raise
        audit_log.append("erasure.android_finished", operator, target=req.serial,
                         details={"status": res["status"], "verified": res["verified"]})
        return {**res, "approval": approval}

    return {"jobId": jobs.submit("android_wipe", work, params={"serial": req.serial, "mode": req.mode})}


# ── Lab images ───────────────────────────────────────────────────────────────

class LabImageRequest(BaseModel):
    name: str
    kind: str = "sample"
    sizeMb: int = 64


@app.get("/api/lab/images")
def list_lab_images(sess=Depends(need("device.read"))):
    return lab_images.list_images()


@app.post("/api/lab/images")
def create_lab_image(req: LabImageRequest, sess=Depends(need("lab.manage"))):
    try:
        img = lab_images.create_image(req.name, req.kind, req.sizeMb)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    audit_log.append("lab_image.created", sess["username"], target=img["devicePath"], details={"kind": req.kind})
    return img


@app.post("/api/lab/images/{image_id}/reset")
def reset_lab_image(image_id: str, sess=Depends(need("lab.manage"))):
    try:
        img = lab_images.reset_image(image_id)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    audit_log.append("lab_image.reset", sess["username"], target=img["devicePath"])
    return img


@app.delete("/api/lab/images/{image_id}")
def delete_lab_image(image_id: str, sess=Depends(need("lab.manage"))):
    try:
        lab_images.delete_image(image_id)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    audit_log.append("lab_image.deleted", sess["username"], target=image_id)
    return {"deleted": image_id}


# ── Recovery (M3) ────────────────────────────────────────────────────────────

class RecoverySource(BaseModel):
    type: str = Field(description="drive | lab | evidence | path")
    id: Optional[str] = None
    path: Optional[str] = None
    folder: Optional[str] = None


class RecoveryRequest(BaseModel):
    source: RecoverySource
    useFs: bool = True
    useCarving: bool = True
    types: Optional[List[str]] = None
    includePartial: bool = False
    caseId: Optional[str] = None


_DRIVES_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
@(Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
  [pscustomobject]@{ Letter = [string]$_.DriveLetter; Label = $_.FileSystemLabel; Fs = [string]$_.FileSystemType;
                     Size = $_.Size; Free = $_.SizeRemaining; Type = [string]$_.DriveType } }) | ConvertTo-Json -Compress
"""


def _windows_drives() -> List[Dict[str, Any]]:
    import subprocess
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", _DRIVES_PS], capture_output=True, timeout=30)
        data = json.loads(out.stdout.decode("utf-8", "ignore") or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    data = [data] if isinstance(data, dict) else data
    system = os.environ.get("SystemDrive", "C:")[0].upper()
    drives = []
    for v in data:
        letter = (v.get("Letter") or "").upper()
        if not letter or not v.get("Size") or v.get("Type") == "CD-ROM":
            continue
        media = file_eraser._media_info(f"{letter}:\\")
        drives.append({"id": letter, "letter": letter, "label": v.get("Label") or "", "fileSystem": v.get("Fs") or "Unknown",
                       "size": int(v.get("Size") or 0), "free": int(v.get("Free") or 0),
                       "removable": v.get("Type") == "Removable" or media.get("busType") in ("USB", "SD", "MMC"),
                       "mediaType": media.get("mediaType"), "trim": media.get("trim"), "isSystem": letter == system,
                       "sameAsWorkspace": os.path.splitdrive(os.path.abspath(store.WORKSPACE))[0].upper() == f"{letter}:"})
    return drives


@app.get("/api/recovery/sources")
def recovery_sources(sess=Depends(need("recovery.run"))):
    """Drives (Windows volumes), lab images and acquired evidence that can be scanned."""
    evidence = [e for c in cases.list_cases() for e in (cases.get_case(c["id"]) or {}).get("evidence", [])]
    return {"drives": _windows_drives() if platform.system() == "Windows" else [],
            "labImages": lab_images.list_images(with_files=False),
            "evidence": [{"id": e["id"], "label": e["label"], "caseId": e["case_id"], "size": e["size_bytes"],
                          "format": "E01" if "E01" in (e.get("kind") or "") else "raw"} for e in evidence],
            "elevated": _is_admin(), "platform": platform.system()}


def _resolve_source(src: RecoverySource) -> Dict[str, Any]:
    if src.type == "drive":
        letter = (src.id or "").strip().rstrip(":\\").upper()
        if len(letter) != 1 or not letter.isalpha():
            raise ValueError("Choose a drive letter")
        if platform.system() != "Windows":
            raise ValueError("Scanning drives by letter is available on Windows")
        if not _is_admin():
            raise PermissionError("Reading a drive directly needs Administrator rights: start WipeX as Administrator")
        folder = ""
        if src.folder:
            drive, rest = os.path.splitdrive(os.path.abspath(src.folder))
            if drive.upper() != f"{letter}:":
                raise ValueError(f"The folder must be on drive {letter}:")
            folder = rest.replace("\\", "/")
        return {"path": "\\\\.\\" + f"{letter}:", "label": f"Drive {letter}:" + (f" (folder {src.folder})" if folder else ""),
                "folder": folder, "letter": letter}
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
def start_recovery(req: RecoveryRequest, sess=Depends(need("recovery.run"))):
    try:
        src = _resolve_source(req.source)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    case_id = req.caseId or (src.get("evidence") or {}).get("case_id")
    actor = sess["username"]

    def work(ctx):
        out_dir = store.workspace_path("recovery", ctx.id)
        audit_log.append("recovery.started", actor, target=src["path"], case_id=case_id,
                         details={"jobId": ctx.id, "fs": req.useFs, "carving": req.useCarving})
        res = recovery.scan(src["path"], out_dir, use_fs=req.useFs, use_carving=req.useCarving, types=req.types,
                            include_partial=req.includePartial, progress=ctx.progress, start_path=src.get("folder", ""))
        ws_drive = os.path.splitdrive(os.path.abspath(store.WORKSPACE))[0].upper()
        if src.get("letter") and ws_drive == f"{src['letter']}:":
            res["warning"] = (f"Recovered files are saved on drive {src['letter']}:, the same drive that was scanned. "
                              "For real evidence, scan from a copy or keep the WipeX data folder on another drive.")
        res["outDir"] = out_dir
        res["sourceLabel"] = src["label"]
        res["evidenceId"] = (src.get("evidence") or {}).get("id")
        res["examiner"] = actor
        audit_log.append("recovery.finished", actor, target=src["path"], case_id=case_id,
                         details={"jobId": ctx.id, "summary": res["summary"]})
        return res

    job_id = jobs.submit("recovery", work, params={"source": req.source.model_dump(), "label": src["label"]}, case_id=case_id)
    return {"jobId": job_id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, sess=Depends(signed_in)):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@app.get("/api/jobs")
def list_all_jobs(kind: Optional[str] = None, sess=Depends(signed_in)):
    return jobs.list_jobs(kind)


def _safe_workspace_file(path: str) -> str:
    ap = os.path.abspath(path)
    ws = os.path.abspath(store.WORKSPACE)
    if not (ap.startswith(ws + os.sep) and os.path.isfile(ap)):
        raise HTTPException(403, "File is outside the WipeX workspace")
    return ap


@app.get("/api/recovery/file")
def get_recovered_file(path: str, download: bool = False, sess=Depends(need("report.read"))):
    ap = _safe_workspace_file(path)
    return FileResponse(ap, filename=os.path.basename(ap) if download else None)


@app.post("/api/recovery/{job_id}/open")
def open_recovered_folder(job_id: str, sess=Depends(need("report.read"))):
    """Open the folder holding a job's recovered files in the file manager (desktop use)."""
    job = jobs.get(job_id)
    if not job or job["status"] != "COMPLETED" or not job["result"].get("outDir"):
        raise HTTPException(404, "Completed recovery job not found")
    folder = job["result"]["outDir"]
    if platform.system() == "Windows":
        os.startfile(folder)  # noqa: S606 - opens Explorer on the local desktop
    else:
        import subprocess
        subprocess.Popen(["open" if platform.system() == "Darwin" else "xdg-open", folder])
    return {"opened": folder}


@app.get("/api/recovery/{job_id}/report.pdf")
def recovery_report(job_id: str, sess=Depends(need("report.read"))):
    job = jobs.get(job_id)
    if not job or job["status"] != "COMPLETED":
        raise HTTPException(404, "Completed recovery job not found")
    case = cases.get_case(job["case_id"]) if job.get("case_id") else None
    ev = cases.get_evidence(job["result"].get("evidenceId")) if job["result"].get("evidenceId") else None
    return Response(reports.recovery_pdf(job, case, ev), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{job_id}.pdf"'})


@app.get("/api/recovery/formats")
def recovery_formats(sess=Depends(signed_in)):
    return recovery.supported_formats()


class BenchmarkRequest(BaseModel):
    imageId: Optional[str] = None
    imagePath: Optional[str] = None
    truthPath: Optional[str] = None


@app.post("/api/benchmark")
def run_benchmark(req: BenchmarkRequest, sess=Depends(need("recovery.run"))):
    """Lab image with its generated ground truth, or any raw/E01 image plus a truth JSON file."""
    path = lab_images.path_for_id(req.imageId) if req.imageId else req.imagePath
    truth = req.truthPath or (path + ".truth.json" if path else None)
    if not path or not os.path.exists(path):
        raise HTTPException(400, "Choose a lab image or enter the path of an image file")
    if not truth or not os.path.exists(truth):
        raise HTTPException(400, "No ground truth found: reset the lab image, or give the path of a truth JSON file")
    return {"jobId": jobs.submit("benchmark", lambda ctx: benchmark.run(path, truth, progress=ctx.progress),
                                 params={"image": os.path.basename(path)})}


# ── File & folder erasure (M2) ───────────────────────────────────────────────

class PathsRequest(BaseModel):
    paths: List[str]


class FileEraseRequest(BaseModel):
    paths: List[str]
    method: str = "zero"
    cleanTraces: bool = True
    clearJournal: bool = True
    approver: str = ""
    approverPassword: str = ""


@app.get("/api/fs/list")
def list_directory(path: str = "", sess=Depends(signed_in)):
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
def analyze_files(req: PathsRequest, sess=Depends(need("files.erase"))):
    try:
        return file_eraser.analyze(req.paths)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.post("/api/files/erase")
def erase_files(req: FileEraseRequest, sess=Depends(need("files.erase"))):
    operator = sess["username"]
    try:
        approval = _approval(operator, req.approver, req.approverPassword, f"erase-files:{req.method}",
                             ";".join(req.paths)[:500])
        cases.check_authorization(operator, (approval or {}).get("approver", ""))
    except Exception as exc:  # noqa: BLE001
        _fail(exc)

    def work(ctx):
        return file_eraser.erase(req.paths, req.method, req.cleanTraces, operator,
                                 (approval or {}).get("approver", ""), progress=ctx.progress, approval=approval,
                                 clear_journal_opt=req.clearJournal)

    return {"jobId": jobs.submit("file_erasure", work, params={"paths": req.paths, "method": req.method})}


@app.post("/api/files/sandbox")
def create_file_sandbox(sess=Depends(need("files.erase"))):
    return file_eraser.create_sandbox(True)


@app.get("/api/files/report/{job_id}.pdf")
def file_erasure_report(job_id: str, sess=Depends(need("report.read"))):
    job = jobs.get(job_id)
    if not job or job["status"] != "COMPLETED":
        raise HTTPException(404, "Completed file erasure job not found")
    return Response(reports.file_erasure_pdf(job["result"]), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{job["result"]["jobId"]}.pdf"'})


# ── Cases, evidence, legal holds ─────────────────────────────────────────────

class CaseRequest(BaseModel):
    title: str
    description: str = ""


class EvidenceRequest(BaseModel):
    label: str = ""
    labImageId: Optional[str] = None
    sourcePath: Optional[str] = None
    format: str = "raw"


class HoldRequest(BaseModel):
    target: str
    targetKind: str
    reason: str = ""


class StatusRequest(BaseModel):
    status: str


class DualApprovalRequest(BaseModel):
    enabled: bool


@app.get("/api/cases")
def list_cases(sess=Depends(need("case.read"))):
    return cases.list_cases()


@app.post("/api/cases")
def create_case(req: CaseRequest, sess=Depends(need("case.manage"))):
    try:
        return cases.create_case(req.title, sess["username"], req.description)
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.get("/api/cases/{case_id}")
def get_case(case_id: str, sess=Depends(need("case.read"))):
    case = cases.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    case["jobs"] = [j for j in jobs.list_jobs(limit=200) if j.get("case_id") == case_id]
    return case


@app.post("/api/cases/{case_id}/status")
def set_case_status(case_id: str, req: StatusRequest, sess=Depends(need("case.manage"))):
    try:
        cases.set_case_status(case_id, req.status, sess["username"])
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    return cases.get_case(case_id)


@app.post("/api/cases/{case_id}/evidence")
def acquire_evidence(case_id: str, req: EvidenceRequest, sess=Depends(need("evidence.acquire"))):
    source = lab_images.path_for_id(req.labImageId) if req.labImageId else req.sourcePath
    if not source:
        raise HTTPException(400, "Choose a lab image or enter a source path")
    if not os.path.exists(source) and not source.startswith("\\\\.\\"):
        raise HTTPException(404, f"Source not found: {source}")
    if req.format not in ("raw", "e01"):
        raise HTTPException(400, "Format must be raw or e01")
    label = req.label or os.path.basename(source)
    actor = sess["username"]
    job_id = jobs.submit("acquisition", lambda ctx: {**cases.acquire_evidence(case_id, source, label, actor, ctx.progress,
                                                                               fmt=req.format),
                                                    "summary": f"Acquired {label} as {req.format.upper()}"},
                         params={"source": source, "format": req.format}, case_id=case_id)
    return {"jobId": job_id}


@app.post("/api/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str, sess=Depends(need("case.read"))):
    try:
        return cases.verify_evidence(evidence_id, sess["username"])
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.get("/api/evidence/{evidence_id}/info")
def evidence_info(evidence_id: str, sess=Depends(need("case.read"))):
    ev = cases.get_evidence(evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence item not found")
    if ewf.is_ewf(ev["image_path"]):
        r = ewf.EwfReader(ev["image_path"])
        try:
            return {**ev, "container": r.info()}
        finally:
            r.close()
    return {**ev, "container": {"format": "raw (dd)"}}


@app.post("/api/cases/{case_id}/holds")
def add_hold(case_id: str, req: HoldRequest, sess=Depends(need("hold.manage"))):
    try:
        return cases.add_hold(case_id, req.target, req.targetKind, req.reason, sess["username"])
    except Exception as exc:  # noqa: BLE001
        _fail(exc)


@app.post("/api/holds/{hold_id}/release")
def release_hold(hold_id: str, sess=Depends(need("hold.manage"))):
    try:
        cases.release_hold(hold_id, sess["username"])
    except Exception as exc:  # noqa: BLE001
        _fail(exc)
    return {"released": hold_id}


@app.get("/api/holds")
def list_holds(sess=Depends(need("case.read"))):
    return cases.active_holds()


@app.get("/api/settings/dual-approval")
def get_dual_approval(sess=Depends(signed_in)):
    return {"enabled": cases.dual_approval_required()}


@app.post("/api/settings/dual-approval")
def set_dual_approval(req: DualApprovalRequest, sess=Depends(need("settings.manage"))):
    cases.set_dual_approval(req.enabled, sess["username"])
    return {"enabled": req.enabled}


# ── Audit log ────────────────────────────────────────────────────────────────

@app.get("/api/audit/log")
def get_audit_log(limit: int = Query(200, le=2000), offset: int = 0, caseId: Optional[str] = None,
                  sess=Depends(need("audit.read"))):
    return {"entries": audit_log.entries(limit, offset, caseId), "total": audit_log.count()}


@app.get("/api/audit/verify")
def verify_audit_chain(sess=Depends(need("audit.read"))):
    return audit_log.verify_chain()


@app.get("/api/audit/export")
def export_audit_log(sess=Depends(need("audit.read"))):
    data = {"exportedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "workstationPublicKeyPem": CryptoSigner.get_public_key_pem(),
            "userKeys": [{"keyId": k["key_id"], "username": k["username"], "publicKeyPem": k["public_key"],
                          "createdAt": k["created_at"], "retiredAt": k["retired_at"]}
                         for k in store.query("SELECT * FROM user_keys ORDER BY created_at")],
            "verification": audit_log.verify_chain(),
            "entries": list(reversed(audit_log.entries(limit=100000)))}
    audit_log.append("audit.exported", sess["username"], details={"entries": len(data["entries"])})
    return Response(json.dumps(data, indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="wipex-audit-log.json"'})


# ── Built web UI (offline, single process) ───────────────────────────────────

_UI = paths.ui_dir()
if os.path.isdir(os.path.join(_UI, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(_UI, "assets")), name="assets")


@app.get("/", include_in_schema=False)
def index():
    page = os.path.join(_UI, "index.html")
    if os.path.isfile(page):
        return FileResponse(page, headers={"Cache-Control": "no-cache"})
    return JSONResponse({"service": "WipeX", "status": "ONLINE",
                         "ui": "UI not built: run `npm run build`, or use `npm run dev` on port 5173"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
