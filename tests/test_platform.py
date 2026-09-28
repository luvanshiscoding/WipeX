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
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "engine"))

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
        cls.admin = {"Authorization": "Bearer " + cls.c.post("/api/auth/profile", json={"profile": "admin"}).json()["token"]}
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

    def test_access_profiles_open_without_password_and_keep_roles(self):
        profiles = self.c.get("/api/auth/profiles").json()
        self.assertEqual([p["id"] for p in profiles], ["admin", "investigator", "sanitizer", "auditor"])
        tok = {p["id"]: {"Authorization": "Bearer " + self.c.post("/api/auth/profile", json={"profile": p["id"]}).json()["token"]}
               for p in profiles}
        self.assertEqual(self.c.get("/api/cases", headers=tok["auditor"]).status_code, 200)
        self.assertEqual(self.c.post("/api/cases", json={"title": "t"}, headers=tok["auditor"]).status_code, 403)
        self.assertEqual(self.c.post("/api/files/analyze", json={"paths": []}, headers=tok["investigator"]).status_code, 403)
        self.assertEqual(self.c.post("/api/auth/profile", json={"profile": "root"}).status_code, 404)
        self.assertEqual(self.c.post("/api/auth/profile", json={"profile": "admin"}, headers={"Host": "evil.example"}).status_code, 400)
        r = self.c.post("/api/cases", json={"title": "Profile case"}, headers=tok["investigator"])
        self.assertEqual(r.json()["investigator"], "ntro.investigator")
        entry = next(e for e in audit_log.entries(50) if e["action"] == "case.created" and e["target"] == r.json()["id"])
        self.assertTrue(entry["actor_sig"])                              # still signed by the profile's own key
        rec = users.approve("investigator", "", "ntro.sanitizer", "erase", "t")   # a second profile approves
        self.assertTrue(users.verify_user_signature(rec["keyId"], rec["payload"], rec["signature"], "ntro.investigator"))
        self.assertRaises(PermissionError, users.approve, "auditor", "", "ntro.sanitizer", "erase", "t")

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


    def test_demo_mode_allows_only_sample_targets_and_tracks_the_walkthrough(self):
        tok = {"Authorization": "Bearer " + self.c.post("/api/auth/profile", json={"profile": "sanitizer"}).json()["token"]}
        r = self.c.post("/api/demo", json={"enabled": True}, headers=tok)
        self.assertEqual(r.status_code, 200, r.text)
        try:
            self.assertTrue(self.c.get("/api/health").json()["demoMode"])
            r = self.c.post("/api/wipe/start", json={"deviceId": "dev-disk-0", "methodId": "nist_800_88"}, headers=tok)
            self.assertEqual(r.status_code, 403)
            self.assertIn("Demo mode", r.json()["detail"])
            own = tempfile.mkdtemp(prefix="wipex-own-")
            r = self.c.post("/api/files/erase", json={"paths": [own], "method": "zero"}, headers=tok)
            self.assertEqual(r.status_code, 403)
            self.assertTrue(os.path.isdir(own))                            # untouched
            sandbox = self.c.post("/api/files/sandbox", headers=tok).json()["path"]
            r = self.c.post("/api/files/erase", json={"paths": [sandbox], "method": "random", "cleanTraces": False}, headers=tok)
            self.assertEqual(r.status_code, 200, r.text)
            for _ in range(600):                   # the drive check reads the whole folder tree back
                job = self.c.get(f"/api/jobs/{r.json()['jobId']}", headers=tok).json()
                if job["status"] != "RUNNING":
                    break
                time.sleep(0.5)
            self.assertEqual(job["status"], "COMPLETED", job.get("message"))
            steps = {s["id"]: s["done"] for s in self.c.get("/api/demo", headers=tok).json()["steps"]}
            self.assertTrue(steps["delete"])
            self.assertFalse(steps["erase"])
        finally:
            self.c.post("/api/demo", json={"enabled": False}, headers=tok)
        self.assertFalse(self.c.get("/api/health").json()["demoMode"])

    def test_method_advisor_ranks_every_method_with_a_reason(self):
        import advisor
        import erasure
        usb = advisor.advise({"type": "USB / removable", "interface": "USB", "removable": True, "hardwareMethods": {}})
        self.assertEqual(usb["recommended"], "nist_800_88")
        self.assertEqual(set(usb["methods"]), set(erasure.METHODS) - {"destroy"})
        self.assertTrue(all(m["reason"] for m in usb["methods"].values()))
        self.assertEqual(usb["methods"]["gutmann"]["fit"], "avoid")
        self.assertEqual(usb["methods"]["crypto_erase"]["fit"], "unavailable")
        nvme = advisor.advise({"type": "NVMe SSD", "interface": "NVME", "hardwareMethods": {"crypto": {"available": True}}})
        self.assertEqual(nvme["recommended"], "crypto_erase")
        failing = advisor.advise({"type": "Magnetic HDD", "healthStatus": "FAILING", "hardwareMethods": {}})
        self.assertIn("destroy", failing["warning"])
        devices = self.c.get("/api/devices", headers=self.admin).json()
        img = next(d for d in devices if d.get("isImage"))
        self.assertEqual(img["advice"]["recommended"], img["recommendedMethod"])
        self.assertEqual(img["advice"]["mediaClass"], "image")

    def test_whole_usb_drive_without_a_drive_letter_can_be_scanned(self):
        """Recover Files lists whole USB drives (a stick erased, formatted or damaged has no usable letter)
        and reads them raw; the system disk and fixed disks are not offered."""
        from unittest import mock
        import main
        img = os.path.join(lab_images.images_dir(), "usbstick.img")
        lab_images.build_sample_image(img, size_mb=24)
        fake = [{"id": "dev-disk-7", "devicePath": img, "model": "SanDisk Cruzer (test)", "capacityBytes": os.path.getsize(img),
                 "removable": True, "isBootDrive": False, "mountedPaths": [], "type": "USB / removable"},
                {"id": "dev-disk-0", "devicePath": "\\\\.\\PhysicalDrive0", "model": "System NVMe", "capacityBytes": 1,
                 "removable": False, "isBootDrive": True, "mountedPaths": ["C:\\"]}]
        with mock.patch.object(main, "_physical_devices", return_value=fake), mock.patch.object(main, "_is_admin", return_value=True):
            disks = self.c.get("/api/recovery/disks?refresh=true", headers=self.admin).json()
            self.assertEqual([d["id"] for d in disks], ["dev-disk-7"])
            r = self.c.post("/api/recovery/scan", json={"source": {"type": "disk", "id": "dev-disk-7"}, "useFs": True, "useCarving": True},
                            headers=self.admin)
            self.assertEqual(r.status_code, 200, r.text)
            for _ in range(240):
                job = self.c.get(f"/api/jobs/{r.json()['jobId']}", headers=self.admin).json()
                if job["status"] != "RUNNING":
                    break
                time.sleep(0.5)
            self.assertEqual(job["status"], "COMPLETED", job.get("message"))
            self.assertGreaterEqual(len(job["result"]["carving"]["files"]), 10)
            r = self.c.post("/api/recovery/scan", json={"source": {"type": "disk", "id": "dev-disk-0"}}, headers=self.admin)
            self.assertEqual(r.status_code, 404, r.text)                     # the system disk is not a recovery source here
        os.remove(img)



class WorksOffline(unittest.TestCase):
    """Every module runs with the network blocked: only loopback connections and lookups are allowed."""

    def test_every_module_runs_without_network(self):
        import socket
        from fastapi.testclient import TestClient
        import main
        attempts = []
        real_connect, real_lookup = socket.socket.connect, socket.getaddrinfo
        local = ("127.0.0.1", "::1", "localhost", None)

        def guarded_connect(sock, address):
            if (address[0] if isinstance(address, tuple) else address) not in local:
                attempts.append(address)
                raise OSError("network blocked by the test")
            return real_connect(sock, address)

        def guarded_lookup(host, *args, **kwargs):
            if host not in local:
                attempts.append(host)
                raise OSError("DNS blocked by the test")
            return real_lookup(host, *args, **kwargs)

        socket.socket.connect, socket.getaddrinfo = guarded_connect, guarded_lookup
        try:
            c = TestClient(main.app)
            h = {"Authorization": "Bearer " + c.post("/api/auth/profile", json={"profile": "admin"}).json()["token"]}

            def job(r):
                self.assertEqual(r.status_code, 200, r.text)
                for _ in range(600):
                    j = c.get(f"/api/jobs/{r.json()['jobId']}", headers=h).json()
                    if j["status"] != "RUNNING":
                        return j
                    time.sleep(0.5)

            name = f"offline-{int(time.time())}"
            lab_images.create_image(name, "sample", 16)
            rec = job(c.post("/api/recovery/scan", json={"source": {"type": "lab", "id": f"img-{name}"}, "useCarving": True}, headers=h))
            self.assertEqual(rec["status"], "COMPLETED")
            self.assertEqual(c.get(f"/api/recovery/{rec['id']}/report.pdf", headers=h).status_code, 200)
            sandbox = c.post("/api/files/sandbox", headers=h).json()["path"]
            dele = job(c.post("/api/files/erase", json={"paths": [sandbox], "method": "random", "cleanTraces": False}, headers=h))
            self.assertEqual(dele["status"], "COMPLETED")
            wipe = c.post("/api/wipe/start", json={"deviceId": f"img-{name}", "methodId": "nist_800_88"}, headers=h).json()
            for _ in range(240):
                st = c.get(f"/api/wipe/status/{wipe['wipeId']}", headers=h).json()
                if st["status"] != "IN_PROGRESS":
                    break
                time.sleep(0.5)
            self.assertEqual(st["status"], "COMPLETED", st)
            cert = c.post("/api/certificates/generate", json={"wipeId": wipe["wipeId"]}, headers=h).json()
            self.assertEqual(c.get(f"/api/certificates/{cert['certificateId']}/pdf", headers=h).status_code, 200)
            self.assertEqual(c.get(f"/api/verify/{cert['certificateId']}").status_code, 200)
            self.assertTrue(c.get("/api/audit/verify", headers=h).json()["valid"])
            self.assertEqual(c.get("/api/devices", headers=h).status_code, 200)
        finally:
            socket.socket.connect, socket.getaddrinfo = real_connect, real_lookup
        self.assertEqual(attempts, [], "WipeX tried to reach the network")

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

    def test_files_inside_a_deleted_folder_are_recovered_by_name(self):
        with open(self.img, "rb") as src:
            data = bytearray(src.read())
        i = data.find(b"EVIDENCE   ")                  # the folder's 8.3 entry in the root directory
        self.assertGreater(i, 0)
        data[i] = 0xE5                                     # what deleting the whole folder does to its entry,
        j = i - 32
        while j >= 0 and data[j + 11] == 0x0F:             # ...to its long-name entries
            data[j] = 0xE5
            j -= 32
        bps, reserved, fats, fat_sectors = (struct.unpack_from("<H", data, 11)[0], struct.unpack_from("<H", data, 14)[0],
                                            data[16], struct.unpack_from("<H", data, 22)[0])
        cluster = struct.unpack_from("<H", data, i + 26)[0]
        while 2 <= cluster < 0xFFF8:                       # ...and to its cluster chain in every FAT
            nxt = struct.unpack_from("<H", data, reserved * bps + 2 * cluster)[0]
            for k in range(fats):
                struct.pack_into("<H", data, (reserved + k * fat_sectors) * bps + 2 * cluster, 0)
            cluster = nxt
        copy = os.path.join(_TMP, "deleted-folder.img")
        with open(copy, "wb") as dst:
            dst.write(data)
        res = self.fsr.scan(copy, os.path.join(_TMP, "deleted-folder-out"))
        photo = next(e for e in res["entries"] if e["name"] == "Site_Photo_02.jpg")   # deleted inside it earlier
        self.assertEqual(photo["path"], "/Evidence/Site_Photo_02.jpg")
        self.assertTrue(photo["deleted"])
        self.assertEqual(photo["contentStatus"], "intact")
        self.assertTrue(next(e for e in res["entries"] if e["name"] == "Site_Photo_01.jpg")["deleted"])


class PlatformHelpers(unittest.TestCase):
    def test_macos_and_linux_drive_lists(self):
        """Recover Files lists USB volumes on macOS (diskutil) and Linux (lsblk) as well as Windows."""
        import json as _json
        import plistlib
        from unittest import mock
        import main
        usb = plistlib.dumps({"DeviceNode": "/dev/disk4s1", "VolumeName": "KINGSTON", "FilesystemName": "MS-DOS (FAT32)",
                              "TotalSize": 16_000_000_000, "FreeSpace": 9_000_000_000, "Internal": False,
                              "BusProtocol": "USB", "SolidState": False})
        run = mock.Mock(return_value=mock.Mock(stdout=usb))
        with mock.patch.object(main.platform, "system", return_value="Darwin"),                 mock.patch("os.path.isdir", return_value=True), mock.patch("os.listdir", return_value=["KINGSTON", "Macintosh HD"]),                 mock.patch("os.path.ismount", return_value=True),                 mock.patch("os.path.realpath", side_effect=lambda p: "/" if p.endswith("Macintosh HD") else p),                 mock.patch("subprocess.run", run):
            drives = main._unix_drives()
        self.assertEqual([(d["id"], d["device"], d["removable"]) for d in drives], [("/dev/disk4s1", "/dev/rdisk4s1", True)])
        lsblk = _json.dumps({"blockdevices": [
            {"path": "/dev/nvme0n1", "type": "disk", "tran": "nvme", "hotplug": False, "rm": False, "children": [
                {"path": "/dev/nvme0n1p2", "type": "part", "fstype": "ext4", "mountpoint": "/", "size": 500_000_000_000}]},
            {"path": "/dev/sdb", "type": "disk", "tran": "usb", "hotplug": True, "rm": True, "rota": True, "children": [
                {"path": "/dev/sdb1", "type": "part", "fstype": "exfat", "label": "STICK", "mountpoint": "/media/u/STICK",
                 "size": 32_000_000_000}]}]}).encode()
        with mock.patch.object(main.platform, "system", return_value="Linux"),                 mock.patch("subprocess.run", mock.Mock(return_value=mock.Mock(stdout=lsblk))):
            drives = main._unix_drives()
        self.assertEqual([(d["id"], d["fileSystem"], d["removable"], d["mediaType"]) for d in drives],
                         [("/dev/sdb1", "EXFAT", True, "Flash")])

    def test_usb_drives_recognised_on_every_os(self):
        """Whole USB drives are recognised from each OS's own wording; old lsblk's "0" is not true."""
        import main
        self.assertTrue(main._is_usb({"removable": True, "type": "USB / removable"}))                  # Windows
        self.assertTrue(main._is_usb({"removable": True, "type": "External drive", "interface": "USB"}))  # macOS
        self.assertTrue(main._is_usb({"removable": "1", "type": "HDD", "interface": "sata"}))           # Linux, old lsblk
        self.assertFalse(main._is_usb({"removable": "0", "type": "SATA SSD", "interface": "sata"}))
        self.assertFalse(main._is_usb({"removable": False, "type": "NVMe SSD", "interface": "NVME"}))
        import json as _json
        from unittest import mock
        lsblk = _json.dumps({"blockdevices": [
            {"path": "/dev/sda", "type": "disk", "tran": "sata", "hotplug": "0", "rm": "0", "children": [
                {"path": "/dev/sda2", "type": "part", "fstype": "ext4", "mountpoint": "/data", "size": "500000000000",
                 "hotplug": "0", "rm": "0"}]}]}).encode()
        with mock.patch.object(main.platform, "system", return_value="Linux"), \
                mock.patch("subprocess.run", mock.Mock(return_value=mock.Mock(stdout=lsblk))):
            self.assertEqual([d["removable"] for d in main._unix_drives()], [False])

    def test_device_size_on_macos_and_linux(self):
        """macOS reports 0 when seeking to the end of a disk node: the size comes from the driver."""
        import types
        from unittest import mock
        calls = []

        def ioctl(fd, req, buf):
            calls.append(req)
            return {0x40046418: struct.pack("=I", 512), 0x40086419: struct.pack("=Q", 62_521_344),
                    0x80081272: struct.pack("=Q", 32_010_928_128)}[req]

        class Dev:
            def fileno(self):
                return 3

            def seek(self, *_):
                return 0                                    # what a macOS /dev/rdiskN reports
        fake = types.SimpleNamespace(ioctl=ioctl)
        with mock.patch.dict(sys.modules, {"fcntl": fake}):
            with mock.patch("platform.system", return_value="Darwin"):
                self.assertEqual(ewf._posix_device_size(Dev()), 512 * 62_521_344)
            with mock.patch("platform.system", return_value="Linux"):
                self.assertEqual(ewf._posix_device_size(Dev()), 32_010_928_128)
        self.assertEqual(calls, [0x40046418, 0x40086419, 0x80081272])

    def test_restart_with_admin_rights_on_every_os(self):
        """Restart as Administrator / root builds the right request for each OS and hands over the port."""
        from unittest import mock
        import elevation
        with mock.patch.object(elevation, "SYSTEM", "Darwin"), mock.patch("subprocess.Popen") as popen:
            res = elevation.relaunch(["--no-browser", "--port", "8000"], wait_for_port=True)
        self.assertTrue(res["started"])
        args = popen.call_args[0][0]
        self.assertEqual(args[:2], ["osascript", "-e"])
        self.assertIn("with administrator privileges", args[2])
        self.assertIn("--replace", args[2])
        with mock.patch.object(elevation, "SYSTEM", "Linux"), mock.patch("shutil.which", return_value="/usr/bin/pkexec"), \
                mock.patch("subprocess.Popen") as popen:
            self.assertTrue(elevation.relaunch(["--port", "8000"], wait_for_port=True)["started"])
        args = popen.call_args[0][0]
        self.assertEqual(args[0], "pkexec")
        self.assertIn("--replace", args)
        with mock.patch.object(elevation, "SYSTEM", "Linux"), mock.patch("shutil.which", return_value=None):
            self.assertFalse(elevation.relaunch(["--port", "8000"])["started"])      # no GUI prompt: says use sudo
        self.assertTrue(elevation.takeover_marker(8000).endswith("wipex-takeover-8000"))

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
