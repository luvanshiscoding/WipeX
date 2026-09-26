"""
WipeX tests for users/roles, the authenticated API, E01 images and platform helpers.
Run from the project root:  python -m unittest discover -s tests -v
"""

import hashlib
import os
import platform
import struct
import sys
import tempfile
import time
import unittest

_TMP = tempfile.mkdtemp(prefix="wipex-tests-platform-")
os.environ.setdefault("WIPEX_WORKSPACE", os.path.join(_TMP, "ws"))
os.environ.setdefault("WIPEX_DB", os.path.join(_TMP, "wipex.db"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_log  # noqa: E402
import cases  # noqa: E402
import database  # noqa: E402
import ewf  # noqa: E402
import file_eraser  # noqa: E402
import hw_sanitize  # noqa: E402
import lab_images  # noqa: E402
import recovery  # noqa: E402
import store  # noqa: E402
import users  # noqa: E402

database.init_db()
PW = "correct-horse-1"


def _user(name: str, role: str) -> str:
    if not users.get_user(name):
        users.create_user(name, PW, role)
    return name


class UsersAndSignatures(unittest.TestCase):
    def test_password_hash_and_roles(self):
        _user("alice", "sanitizer")
        self.assertRaises(PermissionError, users.authenticate, "alice", "wrong-password")
        self.assertTrue(users.has_perm("sanitizer", "erasure.run"))
        self.assertFalse(users.has_perm("sanitizer", "erasure.approve"))
        self.assertFalse(users.has_perm("auditor", "files.erase"))
        self.assertTrue(users.has_perm("admin", "anything.at.all"))
        row = store.query_one("SELECT pw_hash, enc_private_key FROM users WHERE username='alice'")
        self.assertNotIn(PW, row["pw_hash"])
        self.assertIn("ENCRYPTED PRIVATE KEY", row["enc_private_key"])

    def test_personal_signature_in_audit_chain(self):
        _user("bob", "investigator")
        sess = users.login("bob", PW)
        s = users.session_for(sess["token"])
        tok = users.current_session.set(s)
        try:
            entry = audit_log.append("test.personal", "bob", details={"x": 1})
        finally:
            users.current_session.reset(tok)
        self.assertTrue(entry["actor_sig"])
        result = audit_log.verify_chain()
        self.assertTrue(result["valid"], result)
        self.assertGreaterEqual(result["userSigned"], 1)
        # Forge: another user's name on bob's signature must fail
        with store.tx() as conn:
            conn.execute("UPDATE audit_log SET actor_key_id=(SELECT key_id FROM user_keys WHERE username='alice' LIMIT 1) "
                         "WHERE seq=?", (entry["seq"],))
        _user("alice", "sanitizer")
        self.assertFalse(audit_log.verify_chain()["valid"])
        with store.tx() as conn:
            conn.execute("UPDATE audit_log SET actor_key_id=? WHERE seq=?", (entry["actor_key_id"], entry["seq"]))
        self.assertTrue(audit_log.verify_chain()["valid"])

    def test_password_reset_rotates_key_and_old_signatures_still_verify(self):
        _user("carol", "investigator")
        s = users.session_for(users.login("carol", PW)["token"])
        signed = users.sign_as(s, "payload")
        users.update_user("carol", "admin-test", new_password="another-pass-2")
        self.assertTrue(users.verify_user_signature(signed["keyId"], "payload", signed["signature"], "carol"))
        self.assertNotEqual(users.get_user("carol")["key_id"], signed["keyId"])
        self.assertIsNone(users.session_for(s["token"]))          # sessions dropped on reset
        users.change_password("carol", "another-pass-2", PW)     # self-service keeps the key
        self.assertEqual(users.authenticate("carol", PW)["key_id"], users.get_user("carol")["key_id"])

    def test_approval_rules(self):
        _user("dave", "sanitizer")
        _user("erin", "investigator")
        self.assertRaises(PermissionError, users.approve, "dave", PW, "dave", "erase", "t")      # same person
        self.assertRaises(PermissionError, users.approve, "dave", PW, "alice", "erase", "t")     # role lacks approve
        self.assertRaises(PermissionError, users.approve, "erin", "bad-password", "dave", "erase", "t")
        rec = users.approve("erin", PW, "dave", "erase", "t")
        self.assertTrue(users.verify_user_signature(rec["keyId"], rec["payload"], rec["signature"], "erin"))


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        import main
        cls.c = TestClient(main.app)
        if users.setup_required():
            r = cls.c.post("/api/auth/setup", json={"username": "root", "password": PW})
            assert r.status_code == 200, r.text
        cls.admin = {"Authorization": "Bearer " + cls.c.post("/api/auth/login", json={"username": "root", "password": PW}).json()["token"]}
        for name, role in (("san", "sanitizer"), ("inv", "investigator"), ("aud", "auditor")):
            cls.c.post("/api/users", json={"username": name, "password": PW, "role": role}, headers=cls.admin)
        cls.tok = {n: {"Authorization": "Bearer " + cls.c.post("/api/auth/login", json={"username": n, "password": PW}).json()["token"]}
                   for n in ("san", "inv", "aud")}

    def test_auth_required_and_roles_enforced(self):
        self.assertEqual(self.c.get("/api/cases").status_code, 401)
        self.assertEqual(self.c.get("/api/health").status_code, 200)
        self.assertEqual(self.c.post("/api/auth/setup", json={"username": "x", "password": PW}).status_code, 409)
        self.assertEqual(self.c.post("/api/cases", json={"title": "t"}, headers=self.tok["aud"]).status_code, 403)
        self.assertEqual(self.c.post("/api/files/analyze", json={"paths": []}, headers=self.tok["inv"]).status_code, 403)
        self.assertEqual(self.c.get("/api/users", headers=self.tok["san"]).status_code, 403)
        self.assertEqual(self.c.get("/api/audit/verify", headers=self.tok["aud"]).status_code, 200)
        self.assertEqual(self.c.get("/api/cases", headers={"Host": "evil.example"}).status_code, 400)

    def test_case_created_by_signed_in_user_is_personally_signed(self):
        r = self.c.post("/api/cases", json={"title": "API case"}, headers=self.tok["inv"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["investigator"], "inv")
        entry = next(e for e in audit_log.entries(50) if e["action"] == "case.created" and e["target"] == r.json()["id"])
        self.assertTrue(entry["actor_sig"])
        self.assertTrue(audit_log.verify_chain()["valid"])

    def test_two_person_rule_with_passwords_and_signed_certificate(self):
        lab_images.create_image(f"api-{int(time.time())}", "blank", 16)
        img = [i for i in lab_images.list_images() if i["devicePath"].endswith(".img")][-1]
        cases.set_dual_approval(True, "root")
        try:
            r = self.c.post("/api/wipe/start", json={"deviceId": img["id"], "methodId": "single_pass"}, headers=self.tok["san"])
            self.assertEqual(r.status_code, 403)
            r = self.c.post("/api/wipe/start", json={"deviceId": img["id"], "methodId": "single_pass", "approver": "inv",
                                                     "approverPassword": "nope-nope"}, headers=self.tok["san"])
            self.assertEqual(r.status_code, 403)
            r = self.c.post("/api/wipe/start", json={"deviceId": img["id"], "methodId": "single_pass", "approver": "inv",
                                                     "approverPassword": PW}, headers=self.tok["san"])
            self.assertEqual(r.status_code, 200, r.text)
        finally:
            cases.set_dual_approval(False, "root")
        wipe_id = r.json()["wipeId"]
        for _ in range(120):
            st = self.c.get(f"/api/wipe/status/{wipe_id}", headers=self.tok["san"]).json()
            if st["status"] != "IN_PROGRESS":
                break
            time.sleep(0.5)
        self.assertEqual(st["status"], "COMPLETED", st)
        cert = self.c.post("/api/certificates/generate", json={"wipeId": wipe_id}, headers=self.tok["san"]).json()
        self.assertTrue(cert["isValid"], cert)
        self.assertEqual(cert["issuerSignature"]["user"], "san")
        self.assertTrue(cert["approvalSignature"]["valid"])
        self.assertEqual(self.c.get(f"/api/verify/{cert['certificateId']}").status_code, 200)   # public


class E01Images(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = os.path.join(lab_images.images_dir(), "e01src.img")
        cls.truth = lab_images.build_sample_image(cls.img, size_mb=24)

    def test_roundtrip_multi_segment(self):
        raw = os.urandom(9 * 1024 * 1024 + 512 * 3)
        base = os.path.join(_TMP, "rt")
        w = ewf.EwfWriter(base, len(raw), {"case_number": "C-1"}, segment_size=4 * 1024 * 1024)
        w.write(raw)
        info = w.close()
        self.assertGreater(len(info["segments"]), 1)
        r = ewf.EwfReader(info["segments"][0])
        try:
            self.assertEqual(r.read(0, len(raw)), raw)
            self.assertEqual(r.stored_md5, hashlib.md5(raw).hexdigest())
            self.assertEqual(r.header.get("c"), "C-1")
        finally:
            r.close()

    def test_acquire_as_e01_then_recover_and_verify(self):
        case = cases.create_case("E01 case", "tester")
        ev = cases.acquire_evidence(case["id"], self.img, "lab", "tester", fmt="e01")
        self.assertTrue(ev["image_path"].endswith(".E01"))
        with open(self.img, "rb") as f:
            self.assertEqual(ev["sha256"], hashlib.sha256(f.read()).hexdigest())
        self.assertLess(os.path.getsize(ev["image_path"]), os.path.getsize(self.img))
        self.assertTrue(cases.verify_evidence(ev["id"], "tester")["match"])
        res = recovery.scan(ev["image_path"], os.path.join(_TMP, "e01-out"))
        deleted = {e["path"] for e in res["filesystem"]["entries"] if e["deleted"]}
        self.assertIn("/Evidence/Site_Photo_02.jpg", deleted)
        carved = {f["sha256"] for f in res["carving"]["files"]}
        orphan = next(f for f in self.truth["files"] if f["name"] == "orphan_invoice.pdf")
        self.assertIn(orphan["sha256"], carved)

    def test_corrupted_chunk_detected(self):
        raw = os.urandom(256 * 1024)                       # incompressible: stored with Adler-32
        base = os.path.join(_TMP, "bad")
        w = ewf.EwfWriter(base, len(raw))
        w.write(raw)
        path = w.close()["segments"][0]
        r = ewf.EwfReader(path)
        seg, off, _size, comp = r.chunks[1]
        r.close()
        self.assertFalse(comp)
        with open(path, "r+b") as f:
            f.seek(off + 100)
            f.write(b"\xAA")
        r = ewf.EwfReader(path)
        try:
            self.assertRaises(IOError, r.read, r.chunk_size, 1000)
        finally:
            r.close()


class RecoveryOnRealVolumes(unittest.TestCase):
    """Folder-scoped scans, TRIM-zeroed files and the post-erasure trace check (image-backed)."""

    @classmethod
    def setUpClass(cls):
        from recovery import fs_recovery
        cls.fsr = fs_recovery
        cls.img = os.path.join(lab_images.images_dir(), "vol.img")
        cls.truth = lab_images.build_sample_image(cls.img, size_mb=24)

    def test_scan_limited_to_one_folder(self):
        res = self.fsr.scan(self.img, os.path.join(_TMP, "scoped"), start_path="/Evidence")
        self.assertTrue(res["entries"])
        self.assertTrue(all(e["path"].startswith("/Evidence/") for e in res["entries"]))

    def test_zeroed_blocks_reported_as_erased_by_drive(self):
        f = next(x for x in self.truth["files"] if x["name"] == "Quarterly_Report.pdf")
        copy = os.path.join(_TMP, "trimmed.img")
        with open(self.img, "rb") as src, open(copy, "wb") as dst:
            dst.write(src.read())
        with open(copy, "r+b") as dst:                      # what TRIM does to freed blocks
            for off, length in f["runs"]:
                dst.seek(off)
                dst.write(b"\x00" * length)
        res = self.fsr.scan(copy, os.path.join(_TMP, "trimmed-out"))
        entry = next(e for e in res["entries"] if e["path"] == "/Documents/Quarterly_Report.pdf")
        self.assertEqual(entry["contentStatus"], "zeroed")
        self.assertNotIn("recoveredPath", entry)

    def test_trace_check_sees_ordinary_deletion(self):
        f = next(x for x in self.truth["files"] if x["name"] == "Site_Photo_02.jpg")
        res = self.fsr.dir_traces(self.img, "/Evidence", ["Site_Photo_02.jpg"], {f["sha256"]})
        self.assertEqual(res["namesFound"], ["Site_Photo_02.jpg"])       # a normal delete leaves the name
        self.assertEqual(res["contentFound"], ["Site_Photo_02.jpg"])     # ...and the content
        clean = self.fsr.dir_traces(self.img, "/Evidence", ["Never_Existed.jpg"], {"0" * 64})
        self.assertEqual((clean["namesFound"], clean["contentFound"]), ([], []))


class PlatformHelpers(unittest.TestCase):
    def test_nvme_identify_parsing(self):
        data = bytearray(4096)
        data[4:24] = b"SERIAL123".ljust(20)
        data[24:64] = b"Test NVMe Controller".ljust(40)
        struct.pack_into("<I", data, 328, 0b011)          # SANICAP: crypto + block
        data[524] = 0x04                                   # FNA: crypto erase via format
        info = hw_sanitize.parse_identify_controller(bytes(data))
        self.assertEqual(info["model"], "Test NVMe Controller")
        self.assertTrue(info["sanitizeCrypto"] and info["sanitizeBlock"] and info["formatCryptoErase"])
        self.assertFalse(info["sanitizeOverwrite"])

    def test_nvme_health_parsing(self):
        log = bytearray(512)
        struct.pack_into("<H", log, 1, 273 + 41)
        log[5] = 7
        log[128:144] = (1234).to_bytes(16, "little")
        h = hw_sanitize.parse_nvme_health(bytes(log))
        self.assertEqual((h["temperatureC"], h["percentageUsed"], h["powerOnHours"]), (41, 7, 1234))

    def test_images_have_no_hardware_purge(self):
        caps = hw_sanitize.capabilities({"devicePath": "x.img", "isImage": True})
        self.assertFalse(any(c["available"] for c in caps.values()))

    @unittest.skipUnless(platform.system() in ("Linux", "Darwin"), "extended attributes: Linux/macOS")
    def test_xattrs_erased(self):
        sandbox = file_eraser.create_sandbox(False)
        target = os.path.join(sandbox["path"], "tiny_note.txt")
        name = "user.xdg.origin.url" if platform.system() == "Linux" else "com.apple.quarantine"
        try:
            if platform.system() == "Linux":
                os.setxattr(target, name, b"https://example.org/secret")
            else:
                file_eraser._maclibc().setxattr(target.encode(), name.encode(), b"0081;0;Test;", 12, 0, 0)
        except OSError as exc:
            self.skipTest(f"file system has no user xattrs: {exc}")
        self.assertEqual(file_eraser.analyze([target])["items"][0]["xattrs"], 1)
        rep = file_eraser.erase([target], "zero", False, "tester")
        self.assertEqual(rep["xattrsErased"], 1)
        self.assertFalse(os.path.exists(target))


if __name__ == "__main__":
    unittest.main()
