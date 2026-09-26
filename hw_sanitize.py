"""
WipeX - firmware-level sanitize (NIST SP 800-88 "Purge") and drive health, per OS.

Linux    NVMe: nvme-cli Sanitize (crypto / block erase) polled through the sanitize log,
               falling back to Format NVM with Secure Erase Settings.
         SATA: hdparm ATA Security Erase (enhanced when supported), unfrozen drives only.
         Opal: sedutil-cli PSID revert (PSID printed on the drive label).
Windows  NVMe: IOCTL_STORAGE_REINITIALIZE_MEDIA, which the inbox NVMe driver turns into an
               NVMe Sanitize (Windows 10 1903+). Capabilities come from the controller's
               Identify data (SANICAP) read with IOCTL_STORAGE_QUERY_PROPERTY.
         Opal: sedutil-cli PSID revert when sedutil-cli.exe is installed.
         SATA: not offered - firmware freezes ATA security at boot and Windows blocks it;
               use the Linux live USB.
macOS    No supported firmware sanitize path; overwrite methods only.

Every purge is followed by the independent read-back verification in erasure.py.
"""

import ctypes
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import time
from typing import Any, Callable, Dict, Optional, Tuple

SYSTEM = platform.system()
ProgressFn = Optional[Callable[[int, str], None]]

# ── Windows storage IOCTLs ───────────────────────────────────────────────────

IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_STORAGE_REINITIALIZE_MEDIA = 0x002D9640
STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY = 49
STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY = 50
PROTOCOL_TYPE_NVME = 3
NVME_DATA_TYPE_IDENTIFY = 1
NVME_DATA_TYPE_LOG_PAGE = 2
SANITIZE_METHOD = {"block": 1, "crypto": 2}


def _win_disk_number(path: str) -> Optional[int]:
    m = re.match(r"^\\\\\.\\PhysicalDrive(\d+)$", path or "", re.I)
    return int(m.group(1)) if m else None


def _win_open(path: str, write: bool):
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.c_void_p
    access = (0x80000000 | 0x40000000) if write else 0          # GENERIC_READ|GENERIC_WRITE, or query-only
    h = k32.CreateFileW(ctypes.c_wchar_p(path), access, 0x1 | 0x2, None, 3, 0, None)
    if h in (None, ctypes.c_void_p(-1).value):
        raise PermissionError(f"Cannot open {path} (error {ctypes.GetLastError()}); run WipeX as Administrator")
    return h


def _win_ioctl(handle, code: int, inbuf: bytes, outlen: int) -> bytes:
    k32 = ctypes.windll.kernel32
    k32.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                                    ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    ib = ctypes.create_string_buffer(inbuf, len(inbuf)) if inbuf else None
    ob = ctypes.create_string_buffer(outlen) if outlen else None
    returned = ctypes.c_uint32(0)
    ok = k32.DeviceIoControl(handle, code, ib, len(inbuf), ob, outlen, ctypes.byref(returned), None)
    if not ok:
        raise OSError(ctypes.GetLastError(), f"DeviceIoControl 0x{code:08X} failed (error {ctypes.GetLastError()})")
    return ob.raw[:returned.value] if ob is not None else b""


def _win_nvme_query(path: str, data_type: int, request: int, sub: int = 0, length: int = 4096,
                    property_id: int = STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY, sub4: int = 0) -> bytes:
    """STORAGE_PROPERTY_QUERY + STORAGE_PROTOCOL_SPECIFIC_DATA -> raw NVMe payload."""
    header = struct.pack("<II", property_id, 0)                   # PropertyId, PropertyStandardQuery
    proto = struct.pack("<10I", PROTOCOL_TYPE_NVME, data_type, request, sub, 40, length, 0, 0, 0, sub4)
    inbuf = header + proto + b"\x00" * length
    h = _win_open(path, write=False)
    try:
        out = _win_ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, inbuf, len(inbuf))
    finally:
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(h))
    if len(out) < 48:
        raise OSError("Short protocol-specific reply")
    data_offset = struct.unpack_from("<I", out, 8 + 16)[0]       # ProtocolDataOffset (relative to the 40-byte block)
    data_len = struct.unpack_from("<I", out, 8 + 20)[0]
    return out[8 + data_offset:8 + data_offset + data_len]


def parse_identify_controller(data: bytes) -> Dict[str, Any]:
    """Fields of the NVMe Identify Controller structure that matter for sanitization."""
    if len(data) < 528:
        raise ValueError("Identify data too short")
    sanicap = struct.unpack_from("<I", data, 328)[0]
    oacs = struct.unpack_from("<H", data, 256)[0]
    fna = data[524]
    return {
        "serial": data[4:24].decode("ascii", "replace").strip(),
        "model": data[24:64].decode("ascii", "replace").strip(),
        "firmware": data[64:72].decode("ascii", "replace").strip(),
        "sanitizeCrypto": bool(sanicap & 0x1),
        "sanitizeBlock": bool(sanicap & 0x2),
        "sanitizeOverwrite": bool(sanicap & 0x4),
        "formatSupported": bool(oacs & 0x2),
        "formatCryptoErase": bool(fna & 0x4),
    }


def parse_nvme_health(data: bytes) -> Dict[str, Any]:
    """NVMe SMART / Health Information log page (LID 02h)."""
    if len(data) < 176:
        raise ValueError("Health log too short")
    kelvin = struct.unpack_from("<H", data, 1)[0]
    le128 = lambda off: int.from_bytes(data[off:off + 16], "little")  # noqa: E731
    return {
        "criticalWarning": data[0], "temperatureC": kelvin - 273 if kelvin else None,
        "availableSparePct": data[3], "percentageUsed": data[5],
        "dataUnitsWritten": le128(48), "powerCycles": le128(112), "powerOnHours": le128(128),
        "unsafeShutdowns": le128(144), "mediaErrors": le128(160),
    }


def windows_nvme_info(path: str) -> Dict[str, Any]:
    """Identify Controller + health log for an NVMe disk on Windows (read-only)."""
    info: Dict[str, Any] = {}
    try:
        # Controller data is only available through the adapter-level property; the
        # device-level property returns namespace data and must not be used here.
        ident = parse_identify_controller(_win_nvme_query(path, NVME_DATA_TYPE_IDENTIFY, 1))
        if not ident["model"] or not all(32 <= ord(ch) < 127 for ch in ident["model"]):
            raise ValueError("Identify Controller returned unexpected data")
        info.update(ident)
    except OSError as exc:
        info["identifyError"] = ("The storage driver does not support NVMe pass-through (for example Intel RST/VMD); "
                                 "use the Linux live USB for firmware sanitize" if exc.args and exc.args[0] == 1 else str(exc))
    except (ValueError, PermissionError) as exc:
        info["identifyError"] = str(exc)
    try:
        info["health"] = parse_nvme_health(_win_nvme_query(path, NVME_DATA_TYPE_LOG_PAGE, 2, length=512,
                                                           property_id=STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY,
                                                           sub4=0xFFFFFFFF))
    except (OSError, ValueError, PermissionError) as exc:
        info["healthError"] = str(exc)
    return info


def _win_reinitialize(path: str, method: str, timeout_s: int) -> Tuple[bool, str]:
    struct_in = struct.pack("<IIII", 16, 16, timeout_s, SANITIZE_METHOD[method] & 0xF)
    h = _win_open(path, write=True)
    try:
        _win_ioctl(h, IOCTL_STORAGE_REINITIALIZE_MEDIA, struct_in, 0)
        return True, f"NVMe Sanitize ({method} erase) completed via IOCTL_STORAGE_REINITIALIZE_MEDIA"
    except OSError as exc:
        return False, f"Windows rejected the sanitize request: {exc}"
    finally:
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(h))


# ── Linux helpers ────────────────────────────────────────────────────────────

def _run(cmd, timeout=60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _find_key(obj: Any, key: str) -> Any:
    """nvme-cli JSON layouts differ between versions; find a field wherever it is."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() == key:
                return v
            got = _find_key(v, key)
            if got is not None:
                return got
    elif isinstance(obj, list):
        for v in obj:
            got = _find_key(v, key)
            if got is not None:
                return got
    return None


def _linux_nvme_caps(path: str) -> Dict[str, Any]:
    res = _run(["nvme", "id-ctrl", path, "-o", "json"], timeout=15)
    data = json.loads(res.stdout) if res.returncode == 0 and res.stdout.strip() else {}
    sanicap = int(_find_key(data, "sanicap") or 0)
    fna = int(_find_key(data, "fna") or 0)
    return {"sanitizeCrypto": bool(sanicap & 1), "sanitizeBlock": bool(sanicap & 2),
            "formatCryptoErase": bool(fna & 4), "raw": bool(data)}


def _linux_nvme_sanitize(path: str, kind: str, progress: ProgressFn, timeout_s: int) -> Tuple[bool, str]:
    caps = _linux_nvme_caps(path)
    want = "sanitizeCrypto" if kind == "crypto" else "sanitizeBlock"
    if caps.get(want):
        sanact = "4" if kind == "crypto" else "2"                   # 4 = start crypto erase, 2 = block erase
        res = _run(["nvme", "sanitize", path, f"--sanact={sanact}"], timeout=60)
        if res.returncode != 0:
            return False, f"nvme sanitize failed: {(res.stderr or res.stdout).strip()[:300]}"
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            log = _run(["nvme", "sanitize-log", path, "-o", "json"], timeout=30)
            try:
                data = json.loads(log.stdout)
            except ValueError:
                data = {}
            sstat = int(_find_key(data, "sstat") or 0) & 0x7
            sprog = int(_find_key(data, "sprog") or 0)
            if sstat in (1, 4):
                return True, f"NVMe Sanitize ({kind} erase) completed (sanitize log status {sstat})"
            if sstat == 3:
                return False, "NVMe Sanitize reported failure (sanitize log status 3)"
            if progress:
                progress(min(89, 5 + sprog * 84 // 65536), f"NVMe sanitize in progress ({sprog * 100 // 65536}%)")
            time.sleep(2)
        return False, "Timed out waiting for NVMe Sanitize to finish"
    if kind == "crypto" and caps.get("formatCryptoErase"):
        res = _run(["nvme", "format", path, "--ses=2", "--force"], timeout=timeout_s)
        if res.returncode == 0:
            return True, "NVMe Format with Cryptographic Erase (SES=2) completed"
        return False, f"nvme format failed: {(res.stderr or res.stdout).strip()[:300]}"
    return False, f"Controller does not report {kind} erase support (SANICAP/FNA)"


def _linux_ata_info(path: str) -> Dict[str, Any]:
    out = _run(["hdparm", "-I", path], timeout=15).stdout
    sec = out.split("Security:", 1)[1] if "Security:" in out else ""
    minutes = [int(m) for m in re.findall(r"(\d+)min for", sec)]
    return {
        "securitySupported": "supported" in sec and "not\tsupported" not in sec,
        "frozen": bool(re.search(r"^\s*frozen", sec, re.M)) and not re.search(r"not\s+frozen", sec),
        "enhanced": bool(re.search(r"supported: enhanced erase", sec)),
        "estimateMinutes": max(minutes) if minutes else None,
    }


def _linux_ata_erase(path: str) -> Tuple[bool, str]:
    info = _linux_ata_info(path)
    if not info["securitySupported"]:
        return False, "Drive does not support the ATA Security feature set"
    if info["frozen"]:
        return False, "ATA security is frozen by the firmware; suspend/resume or hot-plug the drive, then retry"
    timeout = int((info["estimateMinutes"] or 120) * 60 * 1.5) + 600
    pw = "wipex"
    res = _run(["hdparm", "--user-master", "u", "--security-set-pass", pw, path], timeout=60)
    if res.returncode != 0:
        return False, f"Could not set the temporary ATA password: {res.stderr.strip()[:200]}"
    flag = "--security-erase-enhanced" if info["enhanced"] else "--security-erase"
    res = _run(["hdparm", "--user-master", "u", flag, pw, path], timeout=timeout)
    if res.returncode == 0:
        return True, f"ATA {'Enhanced ' if info['enhanced'] else ''}Security Erase completed"
    # Never leave the drive locked with our temporary password
    _run(["hdparm", "--user-master", "u", "--security-disable", pw, path], timeout=60)
    return False, f"ATA Security Erase failed: {res.stderr.strip()[:200]} (temporary password removed)"


def _opal_psid_revert(path: str, psid: str) -> Tuple[bool, str]:
    psid = re.sub(r"[^A-Za-z0-9]", "", psid or "")
    if len(psid) != 32:
        return False, "Enter the 32-character PSID printed on the drive label"
    res = _run(["sedutil-cli", "--PSIDrevert", psid, path], timeout=600)
    if res.returncode == 0:
        return True, "TCG Opal PSID revert completed: media encryption key regenerated (cryptographic erase)"
    return False, f"sedutil-cli PSID revert failed: {(res.stderr or res.stdout).strip()[:200]}"


# ── Public API ───────────────────────────────────────────────────────────────

_caps_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def capabilities(dev: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Which firmware purge methods can run on this device from this OS, with reasons."""
    path = dev.get("devicePath") or ""
    if dev.get("isImage"):
        reason = "Disk images have no controller; use an overwrite method"
        return {k: {"available": False, "reason": reason} for k in ("crypto", "block", "ata", "opal")}
    cached = _caps_cache.get(path)
    if cached and time.time() - cached[0] < 300:
        return cached[1]
    is_nvme = "nvme" in path.lower() or "NVME" in str(dev.get("interface", "")).upper() or "NVMe" in str(dev.get("type", ""))
    caps: Dict[str, Dict[str, Any]] = {}
    opal_tool = shutil.which("sedutil-cli")
    caps["opal"] = ({"available": True, "via": "sedutil-cli PSID revert", "needs": "psid"} if opal_tool else
                    {"available": False, "reason": "sedutil-cli is not installed"})
    try:
        if SYSTEM == "Linux":
            if is_nvme and shutil.which("nvme"):
                c = _linux_nvme_caps(path)
                caps["crypto"] = {"available": c["sanitizeCrypto"] or c["formatCryptoErase"], "via": "nvme-cli",
                                  "reason": None if (c["sanitizeCrypto"] or c["formatCryptoErase"]) else "Controller reports no crypto erase"}
                caps["block"] = {"available": c["sanitizeBlock"], "via": "nvme-cli",
                                 "reason": None if c["sanitizeBlock"] else "Controller reports no block erase"}
            else:
                why = "nvme-cli is not installed" if is_nvme else "Not an NVMe device"
                caps["crypto"] = caps["block"] = {"available": False, "reason": why}
            if not is_nvme and shutil.which("hdparm"):
                a = _linux_ata_info(path)
                ok = a["securitySupported"] and not a["frozen"]
                caps["ata"] = {"available": ok, "via": "hdparm", "frozen": a["frozen"],
                               "reason": None if ok else ("Security frozen by firmware" if a["frozen"] else "ATA Security not supported")}
            else:
                caps["ata"] = {"available": False, "reason": "hdparm is not installed" if not is_nvme else "NVMe drives use NVMe Sanitize"}
        elif SYSTEM == "Windows":
            if is_nvme:
                info = windows_nvme_info(path)
                if "model" in info:
                    caps["crypto"] = {"available": info["sanitizeCrypto"], "via": "Windows NVMe driver",
                                      "reason": None if info["sanitizeCrypto"] else "Controller reports no Sanitize crypto erase"}
                    caps["block"] = {"available": info["sanitizeBlock"], "via": "Windows NVMe driver",
                                     "reason": None if info["sanitizeBlock"] else "Controller reports no Sanitize block erase"}
                else:
                    why = info.get("identifyError", "Identify Controller failed")
                    caps["crypto"] = caps["block"] = {"available": False, "reason": why}
            else:
                caps["crypto"] = caps["block"] = {"available": False, "reason": "Not an NVMe device"}
            caps["ata"] = {"available": False, "reason": "ATA Security Erase is frozen/blocked under Windows; use the Linux live USB"}
        else:
            reason = "macOS has no supported firmware sanitize interface; use an overwrite method or the Linux live USB"
            caps["crypto"] = caps["block"] = caps["ata"] = {"available": False, "reason": reason}
    except Exception as exc:  # noqa: BLE001 - capability probing must never break device listing
        for k in ("crypto", "block", "ata"):
            caps.setdefault(k, {"available": False, "reason": f"Capability check failed: {exc}"})
    _caps_cache[path] = (time.time(), caps)
    return caps


def purge(dev: Dict[str, Any], kind: str, params: Optional[Dict[str, Any]] = None,
          progress: ProgressFn = None, timeout_s: int = 4 * 3600) -> Tuple[bool, str]:
    """Run a firmware purge. kind: crypto | block | ata. Returns (ok, message)."""
    params = params or {}
    path = dev["devicePath"]
    caps = capabilities(dev)
    if kind == "crypto" and not caps.get("crypto", {}).get("available") and params.get("psid"):
        kind = "opal"
    cap = caps.get(kind, {})
    if not cap.get("available"):
        return False, cap.get("reason") or f"{kind} purge is not available for this device"
    if kind == "opal":
        return _opal_psid_revert(path, params.get("psid", ""))
    if SYSTEM == "Windows":
        if kind in ("crypto", "block"):
            if progress:
                progress(10, f"NVMe Sanitize ({kind} erase) issued; the drive is working")
            return _win_reinitialize(path, kind, timeout_s)
        return False, cap.get("reason", "Not supported on Windows")
    if SYSTEM == "Linux":
        if kind in ("crypto", "block"):
            return _linux_nvme_sanitize(path, kind, progress, timeout_s)
        if kind == "ata":
            return _linux_ata_erase(path)
    return False, "No firmware sanitize path on this operating system"


def recommend(dev: Dict[str, Any]) -> str:
    """Strongest verified method available for the device on this OS."""
    if dev.get("isImage"):
        return "nist_800_88"
    caps = capabilities(dev)
    if caps.get("crypto", {}).get("available"):
        return "crypto_erase"
    if caps.get("block", {}).get("available"):
        return "block_erase"
    if caps.get("ata", {}).get("available"):
        return "ata_sanitize"
    return "nist_800_88"
