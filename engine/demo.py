"""
Demo mode: a safe, guided run through all three modules on the built-in sample data.

While demo mode is on the engine erases only sample disks and deletes only files that WipeX
created as samples, so an evaluator can try every step without risking a real drive. Progress
through the walkthrough is read back from the audit log, so it reflects what really ran.
"""
import os
import time
from typing import Any, Dict, List

import audit_log
import file_eraser
import lab_images
import store

STEPS = [
    ("recover", "Recover deleted files from a sample disk", "#/recovery"),
    ("delete", "Permanently delete the sample files", "#/erase?mode=files"),
    ("erase", "Erase a whole sample disk", "#/erase?mode=drive"),
    ("certificate", "Issue the signed certificate", "#/erase?mode=drive"),
    ("verify", "Check the certificate in Verify Certificate", "#/verify"),
    ("audit", "Verify the audit log chain", "#/audit"),
]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def enabled() -> bool:
    return bool(store.get_setting("demo_mode", False))


def state() -> Dict[str, Any]:
    return {"enabled": enabled(), "since": store.get_setting("demo_since", "")}


def set_enabled(on: bool, actor: str) -> Dict[str, Any]:
    store.set_setting("demo_mode", bool(on))
    if on:
        store.set_setting("demo_since", _now())
    audit_log.append("settings.demo_mode", actor, details={"enabled": bool(on)})
    return state()


def _inside(path: str, root: str) -> bool:
    ap, root = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(root))
    return ap == root or ap.startswith(root.rstrip("\\/") + os.sep)


def check_device(dev: Dict[str, Any]) -> None:
    if enabled() and not dev.get("isImage"):
        raise PermissionError("Demo mode is on: only sample disks can be erased. "
                              "Turn demo mode off to erase a real drive.")


def check_paths(paths: List[str]) -> None:
    if not enabled():
        return
    roots = file_eraser.sandbox_roots()
    outside = [p for p in paths if not any(_inside(p, r) for r in roots)]
    if outside:
        raise PermissionError("Demo mode is on: only WipeX sample files can be deleted "
                              f"(not {outside[0]}). Turn demo mode off to delete your own files.")


def mark(step: str) -> None:
    """Record a walkthrough step that leaves no audit entry of its own (certificate check, chain check)."""
    if enabled():
        store.set_setting(f"demo_step_{step}", _now())


def progress() -> Dict[str, Any]:
    since = store.get_setting("demo_since", "") or ""
    images = os.path.normcase(os.path.abspath(lab_images.images_dir()))
    rows = store.query("SELECT action, target, details FROM audit_log WHERE ts >= ? AND action IN "
                       "('recovery.finished','file_erasure.finished','erasure.finished','certificate.issued')",
                       (since,))
    on_image = lambda r: os.path.normcase(os.path.abspath(r["target"] or "")).startswith(images)  # noqa: E731
    done = {
        "recover": any(r["action"] == "recovery.finished" and on_image(r) for r in rows),
        "delete": any(r["action"] == "file_erasure.finished" for r in rows),
        "erase": any(r["action"] == "erasure.finished" and on_image(r) and '"COMPLETED"' in r["details"] for r in rows),
        "certificate": any(r["action"] == "certificate.issued" for r in rows),
        "verify": (store.get_setting("demo_step_verify", "") or "") >= since > "",
        "audit": (store.get_setting("demo_step_audit", "") or "") >= since > "",
    }
    steps = [{"id": s, "title": t, "href": h, "done": done[s]} for s, t, h in STEPS]
    return {"enabled": enabled(), "since": since, "steps": steps, "completed": sum(done.values()), "total": len(steps)}


def reset(actor: str) -> Dict[str, Any]:
    """Refill every sample disk with sample data and start the walkthrough again."""
    rebuilt = []
    for img in lab_images.list_images(with_files=False):
        lab_images.reset_image(img["id"])
        rebuilt.append(img["id"])
    store.set_setting("demo_since", _now())
    audit_log.append("demo.reset", actor, details={"sampleDisks": rebuilt})
    return {**progress(), "sampleDisks": rebuilt}
