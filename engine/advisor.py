"""
Method advisor: ranks every sanitization method for the selected device and says why.

The ranking follows NIST SP 800-88: the kind of media decides whether one overwrite reaches
every block (Clear), whether only the drive's own sanitize command reaches spare and remapped
blocks (Purge), and when destruction is the only safe choice. Firmware methods are offered only
when the probe found them usable on this device from this operating system.
"""
from typing import Any, Dict, List

import erasure

FITS = ("best", "good", "fair", "avoid", "unavailable")


def media_class(dev: Dict[str, Any]) -> str:
    """image | usb | nvme | ssd | hdd | unknown"""
    if dev.get("isImage"):
        return "image"
    kind = str(dev.get("type") or "").lower()
    bus = str(dev.get("interface") or "").upper()
    if dev.get("removable") or "usb" in kind or bus.startswith(("USB", "SD", "MMC")):
        return "usb"
    if "nvme" in kind:
        return "nvme"
    if "ssd" in kind:
        return "ssd"
    if "hdd" in kind or "magnetic" in kind:
        return "hdd"
    return "unknown"


# Typical sustained write / read speeds (bytes per second) used for time estimates. USB sticks vary
# the most (roughly 5-100 MB/s), so their estimate is deliberately conservative.
SPEED = {"image": (300e6, 800e6), "usb": (20e6, 30e6), "nvme": (1000e6, 1500e6), "ssd": (350e6, 450e6),
         "hdd": (120e6, 150e6), "unknown": (60e6, 80e6)}
FIRMWARE_TIME = {"crypto": "under a minute (the drive's own command)", "block": "a few minutes (the drive's own command)",
                 "ata": "set by the drive (minutes on SSDs, hours on hard disks)"}


def duration(seconds: float) -> str:
    if seconds < 60:
        return "under a minute"
    if seconds < 90:
        return "about a minute"
    if seconds < 3600:
        return f"about {round(seconds / 60)} min"
    return f"about {seconds / 3600:.1f} h"


def estimate(dev: Dict[str, Any], passes: int) -> float:
    """Seconds for an overwrite with this many passes plus WipeX's verification (full read-back up to 8 GiB)."""
    capacity = float(dev.get("capacityBytes") or 0)
    write, read = SPEED[media_class(dev)]
    check = capacity / read if capacity <= erasure.FULL_VERIFY_LIMIT else 60.0
    return passes * capacity / write + check + 10


MEDIA_LABEL = {"image": "Disk image", "usb": "USB flash drive / memory card", "nvme": "NVMe SSD",
               "ssd": "SATA SSD", "hdd": "Hard disk", "unknown": "Drive of unknown type"}


def _failing(dev: Dict[str, Any]) -> bool:
    return dev.get("expectedOutcome") == "RED" or str(dev.get("healthStatus") or "").startswith("FAILING")


def _hw_available(dev: Dict[str, Any], kind: str) -> bool:
    caps = dev.get("hardwareMethods") or {}
    if caps.get(kind, {}).get("available"):
        return True
    return kind == "crypto" and bool(caps.get("opal", {}).get("available"))


def _hw_reason(dev: Dict[str, Any], kind: str) -> str:
    return (dev.get("hardwareMethods") or {}).get(kind, {}).get("reason") or "Not available for this drive here"


def advise(dev: Dict[str, Any]) -> Dict[str, Any]:
    """Recommended method, why, and a fit + one-line reason for every method."""
    mc = media_class(dev)
    flash = mc in ("usb", "nvme", "ssd")
    methods: Dict[str, Dict[str, Any]] = {}

    def put(mid: str, fit: str, reason: str) -> None:
        method = erasure.METHODS[mid]
        passes = len(method.get("passes", []))
        took = duration(estimate(dev, passes)) if passes else FIRMWARE_TIME[method["hardware"]]
        methods[mid] = {"fit": fit, "reason": reason, "writes": passes or None, "time": took}

    # Overwrite methods (Clear): the same everywhere except for the wording on flash
    put("nist_800_88", "good", "One pass of zeros over every block, then a full read-back.")
    put("single_pass", "fair", "The same single zero pass as NIST Clear; choose it only if a policy names it.")
    put("random_pass", "good", "One keyed random pass, checked by regenerating the exact stream."
        + (" Random data cannot be compressed or skipped by the flash controller." if flash else ""))
    put("dod_5220_22_m", "fair", "Three passes: three times the time of NIST Clear for no extra assurance on "
        "modern drives. Use only where a policy requires DoD 5220.22-M.")
    put("gutmann", "avoid", "35 passes designed for 1990s disk encodings: 35 times the writes"
        + (" and flash wear" if flash else "") + " with no benefit.")

    # Firmware methods (Purge)
    for mid, kind in (("crypto_erase", "crypto"), ("block_erase", "block"), ("ata_sanitize", "ata")):
        if mc == "image":
            put(mid, "unavailable", "A disk image is a file; firmware commands need a physical drive.")
        elif mc == "usb" and not _hw_available(dev, kind):
            put(mid, "unavailable", "USB sticks and memory cards do not pass NVMe or ATA sanitize commands through the USB bridge.")
        elif not _hw_available(dev, kind):
            put(mid, "unavailable", _hw_reason(dev, kind))
        else:
            put(mid, "good", {
                "crypto": "Destroys the drive's encryption key: every block, including spare areas, becomes unreadable in seconds.",
                "block": "The controller erases every block, including spare and remapped ones.",
                "ata": "The drive's own erase also reaches remapped sectors and hidden areas.",
            }[kind])

    rec = "nist_800_88"
    why: List[str] = []
    if mc == "image":
        why = ["A disk image is an ordinary file: every byte can be addressed, so one overwrite and a full read-back remove everything.",
               "Firmware erase commands apply only to physical drives."]
    elif mc == "usb":
        why = ["NIST SP 800-88 Clear for USB flash media is one overwrite of every block, followed by verification.",
               "USB sticks cannot run a firmware Purge, so extra passes only add time and wear.",
               "Hidden spare blocks cannot be reached by any overwrite: if the data needs Purge, destroy the stick after erasing."]
    elif mc == "nvme" and _hw_available(dev, "crypto"):
        rec = "crypto_erase"
        why = ["NVMe Sanitize crypto erase is a NIST Purge: it covers spare and remapped blocks that no overwrite reaches.",
               "It finishes in seconds instead of hours."]
    elif mc == "nvme" and _hw_available(dev, "block"):
        rec = "block_erase"
        why = ["NVMe Sanitize block erase is a NIST Purge: the controller erases every block, including spare ones."]
    elif mc == "ssd" and _hw_available(dev, "ata"):
        rec = "ata_sanitize"
        why = ["SSDs keep spare and remapped blocks; only the drive's own erase reaches them (NIST Purge)."]
    elif mc in ("nvme", "ssd"):
        why = ["Overwriting an SSD is a NIST Clear: spare and remapped blocks may keep old data.",
               "The drive's own erase command is not usable here" + (" (run WipeX on Linux for ATA Security Erase)." if mc == "ssd" else ".")]
    elif mc == "hdd" and _hw_available(dev, "ata"):
        rec = "ata_sanitize"
        why = ["The drive's Security Erase also overwrites remapped sectors and hidden areas (NIST Purge).",
               "On hard disks one pass is enough; NIST SP 800-88 does not ask for more."]
    elif mc == "hdd":
        why = ["On hard disks one verified overwrite is the NIST SP 800-88 Clear; more passes add no assurance.",
               "ATA Security Erase (Purge) needs Linux with hdparm."]
    else:
        why = ["One verified overwrite of every block is the NIST SP 800-88 Clear for any rewritable drive."]

    methods[rec]["fit"] = "best"
    warning = ""
    if _failing(dev):
        warning = ("This drive reports failing health: blocks that cannot be written cannot be verified. "
                   "Erase it, then destroy it physically.")
    write_mb = int(SPEED[mc][0] / 1e6)
    return {"mediaClass": mc, "mediaLabel": MEDIA_LABEL[mc], "recommended": rec, "why": why,
            "warning": warning, "methods": methods,
            "timeNote": (f"Times assume about {write_mb} MB/s writing"
                         + (" (USB sticks range from about 5 to 100 MB/s)" if mc == "usb" else "")
                         + "; the job shows the real speed and time left.")}


FILE_PATTERN_REASON = {
    "HDD": "One pass is enough on a hard disk (NIST SP 800-88); random data leaves no pattern behind.",
    "SSD": "One pass: more passes only wear the flash. Random data cannot be compressed or skipped by the controller.",
    "Flash": "One pass: more passes only wear the stick. Random data cannot be compressed or skipped by the controller.",
}


def advise_file_pattern(volumes: List[Dict[str, Any]]) -> Dict[str, str]:
    """Overwrite pattern for file deletion on the given volumes, and why."""
    kinds = {v.get("mediaType") for v in volumes}
    for k in ("Flash", "SSD", "HDD"):
        if k in kinds:
            return {"recommended": "random", "reason": FILE_PATTERN_REASON[k]}
    return {"recommended": "random", "reason": "One random pass overwrites the content completely; more passes add time, not assurance."}
