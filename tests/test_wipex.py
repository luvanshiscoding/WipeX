"""
WipeX regression tests. Run from the project root:  python -m unittest discover -s tests -v
Each run uses a throwaway workspace and database.
"""

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="wipex-tests-")
os.environ.setdefault("WIPEX_WORKSPACE", os.path.join(_TMP, "ws"))
os.environ.setdefault("WIPEX_DB", os.path.join(_TMP, "wipex.db"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
database.init_db()

import audit_log  # noqa: E402
import benchmark  # noqa: E402
import cases  # noqa: E402
import erasure  # noqa: E402
import file_eraser  # noqa: E402
import lab_images  # noqa: E402
import recovery  # noqa: E402
import store  # noqa: E402
from recovery import carver, formats  # noqa: E402


class LabImageAndRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = os.path.join(lab_images.images_dir(), "rec.img")
        cls.truth = lab_images.build_sample_image(cls.path)
        cls.result = recovery.scan(cls.path, os.path.join(_TMP, "rec-out"))

    def test_sleuthkit_reads_generated_fat16(self):
        vols = self.result["filesystem"]["volumes"]
        self.assertEqual(vols[0]["fsType"], "FAT16")
        names = {e["path"] for e in self.result["filesystem"]["entries"]}
        self.assertIn("/Evidence/Site_Photo_01.jpg", names)        # long file name survives

    def test_deleted_files_listed_and_recovered(self):
        deleted = {e["path"]: e for e in self.result["filesystem"]["entries"] if e["deleted"]}
        expected = {f["path"] for f in self.truth["files"] if f["state"] == "deleted"}
        self.assertEqual(set(deleted), expected)
        self.assertEqual(deleted["/Evidence/Site_Photo_02.jpg"]["contentStatus"], "intact")
        # Fragment gap is unallocated garbage: contiguous FS recovery is detected as damaged
        self.assertEqual(deleted["/Evidence/Network_Diagram.png"]["contentStatus"], "damaged")

    def test_carving_is_byte_exact_including_fragments_and_orphans(self):
        carved = {f["sha256"]: f for f in self.result["carving"]["files"]}
        by_name = {f["name"]: f for f in self.truth["files"]}
        for name in ("orphan_photo.jpg", "orphan_invoice.pdf", "Quarterly_Report.pdf", "contacts.db", "Scan_0042.bmp"):
            self.assertIn(by_name[name]["sha256"], carved, name)
        for name in ("Network_Diagram.png", "Backup_Old.zip"):
            f = carved.get(by_name[name]["sha256"])
            self.assertIsNotNone(f, f"{name} not reassembled")
            self.assertEqual(f["status"], "repaired")
            self.assertEqual(len(f["fragments"]), 2)

    def test_no_false_positives(self):
        truth_hashes = {f["sha256"] for f in self.truth["files"]}
        for f in self.result["carving"]["files"]:
            self.assertIn(f["sha256"], truth_hashes, f"false positive {f['id']}")

    def test_docx_detected_inside_zip(self):
        exts = {f["ext"] for f in self.result["carving"]["files"]}
        self.assertIn("docx", exts)


class FormatValidators(unittest.TestCase):
    def test_png_crc_corruption_rejected(self):
        blob = bytearray(lab_images._diagram_png(1, 200, 120))
        self.assertTrue(formats.parse_png(bytes(blob)).valid)
        blob[200] ^= 0xFF
        self.assertFalse(formats.parse_png(bytes(blob)).valid)

    def test_truncated_jpeg_rejected(self):
        blob = lab_images._photo_jpeg(3, 160, 120)
        self.assertTrue(formats.parse_jpeg(blob).valid)
        self.assertFalse(formats.parse_jpeg(blob[:len(blob) // 2]).valid)

    def test_zip_member_crc_checked(self):
        blob = bytearray(lab_images._zip(5, 2))
        self.assertTrue(formats.parse_zip(bytes(blob)).valid)
        blob[200] ^= 0x01
        self.assertFalse(formats.parse_zip(bytes(blob)).valid)


class Erasure(unittest.TestCase):
    def _img(self, name):
        return lab_images.create_image(name, "sample")

    def test_overwrite_methods_verify(self):
        for mid in ("nist_800_88", "dod_5220_22_m"):
            img = self._img(f"e-{mid.replace('_', '-')}")
            s = erasure.start(img["id"], mid, "Tester")
            r = erasure.run(s["wipeId"])
            self.assertEqual(r["status"], "COMPLETED", r["verification"])
            checks = {c["name"]: c for c in r["verification"]["checks"]}
            self.assertEqual(checks["Canary blocks"]["recovered"], 0)
            self.assertTrue(checks["Recovery attempt (M3)"]["passed"])

    def test_incomplete_erasure_fails_verification(self):
        """Simulate a wipe that missed the region holding the files: verification must fail."""
        img = self._img("e-incomplete")
        path, cap = img["devicePath"], img["capacityBytes"]
        key = b"k" * 32
        with open(path, "r+b") as f:
            f.seek(4 * 1024 * 1024)                   # files live in the first ~2 MB
            f.write(b"\x00" * (cap - 4 * 1024 * 1024))
        v = erasure.verify(path, cap, b"\x00", key, erasure._sample_offsets(cap, 64, 1), {}, [], True)
        self.assertEqual(v["verdict"], "FAIL")
        checks = {c["name"]: c for c in v["checks"]}
        self.assertGreater(checks["Pattern read-back"]["mismatchedRegions"], 0)
        self.assertFalse(checks["Recovery attempt (M3)"]["passed"])   # files still recoverable

    def test_random_wipe_high_entropy_still_verifies(self):
        """A correct random wipe reads ~8 bits/byte; verification must pass on the expected pattern, not on entropy."""
        img = self._img("e-random")
        s = erasure.start(img["id"], "random_pass", "Tester")
        r = erasure.run(s["wipeId"])
        self.assertEqual(r["status"], "COMPLETED")
        self.assertGreater(r["verification"]["meanEntropy"], 7.9)

    def test_keyed_stream_is_reproducible(self):
        key = os.urandom(32)
        whole = erasure.prng_bytes(key, 0, 8192)
        self.assertEqual(erasure.prng_bytes(key, 4096, 4096), whole[4096:])
        self.assertEqual(erasure.prng_bytes(key, 4101, 17), whole[4101:4118])

    def test_boot_drive_and_hardware_on_image_refused(self):
        img = self._img("e-hw")
        with self.assertRaises(ValueError):
            erasure.start(img["id"], "crypto_erase", "Tester")

    def test_certificate_signature_and_ledger_tamper(self):
        img = self._img("e-cert")
        s = erasure.start(img["id"], "single_pass", "Tester")
        erasure.run(s["wipeId"])
        cert = erasure.issue_certificate(s["wipeId"])
        self.assertTrue(cert["isValid"])
        con = sqlite3.connect(store.DB_FILE)
        con.execute("UPDATE certificates SET trust_score='GREEN', device_model='Forged' WHERE certificate_id=?",
                    (cert["certificateId"],))
        con.commit()
        con.close()
        again = erasure.lookup_certificate(cert["certificateId"])
        self.assertFalse(again["isValid"])
        self.assertIn("model", again["tamperedFields"])

    def test_partial_id_does_not_match(self):
        self.assertIsNone(erasure.lookup_certificate("WIPEX"))


class CasesAndAudit(unittest.TestCase):
    def test_legal_hold_blocks_device_and_paths(self):
        c = cases.create_case("Hold test", "Insp. A")
        img = lab_images.create_image("held-disk", "sample")
        hold = cases.add_hold(c["id"], img["serialNumber"], "device_serial", "evidence", "Insp. A")
        with self.assertRaises(PermissionError):
            erasure.start(img["id"], "single_pass", "Tester")
        cases.release_hold(hold["id"], "Insp. A")
        erasure.start(img["id"], "single_pass", "Tester")          # allowed again

        folder = store.workspace_path("held-folder")
        cases.add_hold(c["id"], folder, "path", "", "Insp. A")
        self.assertIsNotNone(cases.find_blocking_hold(paths=[os.path.join(folder, "x.txt")]))

    def test_two_person_rule(self):
        cases.set_dual_approval(True, "admin")
        try:
            with self.assertRaises(PermissionError):
                cases.check_authorization("Asha", "")
            with self.assertRaises(PermissionError):
                cases.check_authorization("Asha", "asha")
            cases.check_authorization("Asha", "Ravi")
        finally:
            cases.set_dual_approval(False, "admin")

    def test_acquisition_hashes_match(self):
        c = cases.create_case("Acq", "Insp. B")
        img = lab_images.create_image("acq-src", "sample")
        ev = cases.acquire_evidence(c["id"], img["devicePath"], "Lab disk", "Insp. B")
        self.assertTrue(cases.verify_evidence(ev["id"], "Insp. B")["match"])

    def test_audit_chain_detects_edit_and_deletion(self):
        audit_log.append("test.one", "t")
        audit_log.append("test.two", "t")
        self.assertTrue(audit_log.verify_chain()["valid"])
        con = sqlite3.connect(store.DB_FILE)
        last = con.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
        con.execute("UPDATE audit_log SET actor='mallory' WHERE seq=?", (last - 1,))
        con.commit()
        res = audit_log.verify_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["brokenAt"], last - 1)
        con.execute("UPDATE audit_log SET actor='t' WHERE seq=?", (last - 1,))
        con.execute("DELETE FROM audit_log WHERE seq=?", (last - 1,))
        con.commit()
        con.close()
        self.assertFalse(audit_log.verify_chain()["valid"])


class FileEraser(unittest.TestCase):
    def test_guards(self):
        self.assertIsNotNone(file_eraser.check_path_allowed(os.path.expanduser("~")))
        self.assertIsNotNone(file_eraser.check_path_allowed(os.path.abspath(__file__)))

    def test_erase_sandbox(self):
        sb = file_eraser.create_sandbox(with_trace_demo=False)
        report = file_eraser.erase([sb["path"]], "random", True, "Tester")
        # The system drive's change journal may still name the files (clearing it is opt-in),
        # but nothing may be left in the folders themselves.
        self.assertIn(report["verdict"], ("PASS", "TRACES_REMAIN"))
        tc = report["traceCheck"]
        if tc.get("checked"):
            self.assertEqual(tc["namesFound"], [])
            self.assertEqual(tc["contentFound"], [])
        self.assertFalse(os.path.exists(sb["path"]))
        if os.name == "nt":
            self.assertGreaterEqual(report["streamsErased"], 1)


class Benchmark(unittest.TestCase):
    def test_benchmark_on_sample(self):
        img = lab_images.create_image("bench", "sample")
        res = benchmark.run(img["devicePath"])
        self.assertEqual(res["combined"]["recall"], 1.0, res["missed"])
        self.assertEqual(res["carving"]["precision"], 1.0)


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
