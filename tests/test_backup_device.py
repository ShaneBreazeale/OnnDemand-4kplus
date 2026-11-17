"""Per-unit device backup: planning, pins, resume and hash verification."""
import argparse
import hashlib
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import backup_device as bd

ROOT = Path(__file__).resolve().parents[1]
COFFEY = ROOT / "profile.coffey.json"
BINDING = {"serial": "CUSACOFFEYTEST01", "fingerprint": "onn/coffey/coffey:14/URO4",
           "bootloader": "01.01.260305.112513", "slot": "_b",
           "boot_id": "11111111-2222-3333-4444-555555555555"}


def payload(node):
    base = node.rsplit("mmcblk0p", 1)[-1]
    seed = hashlib.sha256(("init_boot" if base in ("22", "23") else base).encode()).digest()
    return (seed * 64)[:1024]


class FakeSession:
    def __init__(self):
        self.queries = []

    def text(self, script, timeout=60):
        self.queries.append(script.splitlines()[0])
        if "readlink -f /dev/block/by-name" in script:
            return {"text": "\n".join((
                "init_boot_a /dev/block/mmcblk0p22", "init_boot_b /dev/block/mmcblk0p23",
                "boot_a /dev/block/mmcblk0p20", "userdata /dev/block/mmcblk0p40",
                "super /dev/block/mmcblk0p30")), "returncode": 0}
        if "/sys/class/block/" in script:
            return {"text": "mmcblk0p20 2\nmmcblk0p22 2\nmmcblk0p23 2\nmmcblk0p30 8\n"
                            "mmcblk0p40 8\n", "returncode": 0}
        if script.startswith("df -k /data"):
            return {"text": "Filesystem 1K-blocks Used Available Use% Mounted on\n"
                            "/dev/block/dm-57 1000 500 400 55% /data", "returncode": 0}
        if script == "sync" or script == ":":
            return {"text": "", "returncode": 0}
        if "getprop" in script:
            return {"text": "ro.product.device=coffey", "returncode": 0}
        return {"text": "inventory-" + script.split()[0], "returncode": 0}

    def read_exact(self, command, size, timeout=900):
        assert command.startswith("cat /dev/block/")
        return payload(command.split()[-1])

    def stream_to(self, stream, command, timeout=3600):
        stream.write(b"TAR-OF-DATA")
        return len(b"TAR-OF-DATA")


@contextmanager
def fake_session(*args, **kwargs):
    yield FakeSession(), None, {"uid": 0}


def args(output, **overrides):
    values = dict(target="serial", adb="adb", profile=COFFEY, loader=None,
                  loader_sha256=None, direct=True, output=output, resume=False,
                  force=False, data=True, include_super=False,
                  require_fingerprint=None, verify_only=None)
    values.update(overrides)
    return argparse.Namespace(**values)


class PlanningTests(unittest.TestCase):
    def test_userdata_and_super_are_skipped_until_asked_for(self):
        mapping = {"init_boot_b": "/dev/block/mmcblk0p23", "boot_a": "/dev/block/mmcblk0p20",
                   "userdata": "/dev/block/mmcblk0p40", "super": "/dev/block/mmcblk0p30"}
        sizes = {"mmcblk0p23": 8 << 20, "mmcblk0p20": 64 << 20, "mmcblk0p40": 1 << 30,
                 "mmcblk0p30": 2 << 30}
        plan = bd.plan_partitions(mapping, sizes)
        self.assertEqual([name for name, _, _ in plan], ["init_boot_b", "boot_a"])
        plan = bd.plan_partitions(mapping, sizes, include_super=True)
        self.assertIn("super", [name for name, _, _ in plan])
        self.assertNotIn("userdata", [name for name, _, _ in plan])


class BackupTests(unittest.TestCase):
    def run_backup(self, directory, **overrides):
        with patch.object(bd.temp_root, "direct_session", fake_session), \
             patch.object(bd.temp_root, "binding", return_value=BINDING), \
             patch.object(bd, "stock_pins",
                          return_value={"init_boot": hashlib.sha256(payload(
                              "/dev/block/mmcblk0p22")).hexdigest(), "boot": "0" * 64}):
            return bd.backup(args(directory, **overrides), "adb")

    def test_backup_records_device_bytes_pins_and_cross_slot_equality(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            self.assertEqual(self.run_backup(output), 0)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertTrue(manifest["device_dump"])
            self.assertTrue(manifest["user_data_included"])
            self.assertFalse(manifest["crash_consistent"])
            self.assertEqual(manifest["slot"], "_b")
            self.assertTrue(manifest["verified_ok"])
            self.assertEqual(set(manifest["partitions"]), {"init_boot_a", "init_boot_b", "boot_a"})
            self.assertTrue(manifest["partitions"]["init_boot_a"]["matches_stock_pin"])
            self.assertFalse(manifest["partitions"]["boot_a"]["matches_stock_pin"])
            self.assertTrue(manifest["partitions"]["init_boot_a"]["equals_other_slot"])
            self.assertEqual(manifest["data"]["bytes"], len(b"TAR-OF-DATA"))
            self.assertTrue((output / "data.tar").is_file())
            self.assertIn("sha256sums.txt", [path.name for path in output.iterdir()])
            self.assertTrue(bd.verify_existing(output, manifest)[0])

    def test_verify_only_detects_a_tampered_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            self.assertEqual(self.run_backup(output), 0)
            manifest = json.loads((output / "manifest.json").read_text())
            (output / "partitions/boot_a.img").write_bytes(b"changed")
            ok, problems = bd.verify_existing(output, manifest)
            self.assertFalse(ok)
            self.assertTrue(any("boot_a" in problem for problem in problems))

    def test_refuses_a_non_empty_directory_without_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            output.mkdir()
            (output / "notes.txt").write_text("x")
            with self.assertRaises(bd.Stop):
                self.run_backup(output)

    def test_resume_reuses_a_verified_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            self.assertEqual(self.run_backup(output), 0)
            first = json.loads((output / "manifest.json").read_text())
            self.assertEqual(self.run_backup(output, resume=True), 0)
            second = json.loads((output / "manifest.json").read_text())
            self.assertEqual(first["partitions"], second["partitions"])

    def test_missing_data_flag_produces_a_partition_only_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            self.assertEqual(self.run_backup(output, data=False), 0)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertFalse(manifest["user_data_included"])
            self.assertIsNone(manifest["data"])

    def test_resume_rejects_other_device_firmware_slot_boot_and_legacy_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            self.run_backup(output)
            original = (output / "manifest.json").read_text()
            for field in ("serial_sha256", "fingerprint", "bootloader", "slot", "boot_id", None):
                with self.subTest(field=field):
                    manifest = json.loads(original)
                    if field:
                        manifest["backup_binding"][field] = "different"
                    else:
                        del manifest["backup_binding"]
                    (output / "manifest.json").write_text(json.dumps(manifest))
                    with patch.object(FakeSession, "read_exact", side_effect=AssertionError("read")), \
                         self.assertRaisesRegex(bd.Stop, "not bound"):
                        self.run_backup(output, resume=True, force=True)

    def test_interrupted_partition_backup_checkpoints_and_resumes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            original_read = FakeSession.read_exact
            calls = []

            def interrupted(session, command, size, timeout=900):
                calls.append(command)
                if len(calls) == 2:
                    raise bd.temp_root.Stop("connection lost")
                return original_read(session, command, size, timeout)

            with patch.object(FakeSession, "read_exact", interrupted), \
                 self.assertRaisesRegex(bd.temp_root.Stop, "connection lost"):
                self.run_backup(output)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertFalse(manifest["complete"])
            self.assertFalse(bd.verify_existing(output, manifest)[0])
            self.assertEqual(set(manifest["partitions"]), {"init_boot_a"})
            calls.clear()

            def resumed(session, command, size, timeout=900):
                self.assertNotIn("mmcblk0p22", command)
                calls.append(command)
                return original_read(session, command, size, timeout)

            with patch.object(FakeSession, "read_exact", resumed):
                self.assertEqual(self.run_backup(output, resume=True), 0)
            self.assertEqual(len(calls), 2)
            self.assertTrue(json.loads((output / "manifest.json").read_text())["complete"])

    def test_failed_tar_is_not_published_and_backup_can_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"

            def failed_tar(session, stream, command, timeout=3600):
                stream.write(b"partial tar")
                raise bd.temp_root.Stop("streamed command failed (exit 2)")

            with patch.object(FakeSession, "stream_to", failed_tar), \
                 self.assertRaisesRegex(bd.temp_root.Stop, "streamed command failed"):
                self.run_backup(output)
            self.assertFalse((output / "data.tar").exists())
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertIsNone(manifest["data"])
            self.assertFalse(manifest["verified_ok"])
            with patch.object(FakeSession, "read_exact", side_effect=AssertionError("reread")):
                self.assertEqual(self.run_backup(output, resume=True), 0)

    def test_interruption_immediately_after_partition_publication_can_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            original_replace = bd.os.replace

            def interrupted(source, target):
                original_replace(source, target)
                if Path(target).name == "init_boot_a.img":
                    raise OSError("interrupted after rename")

            with patch.object(bd.os, "replace", interrupted), \
                 self.assertRaisesRegex(OSError, "interrupted after rename"):
                self.run_backup(output)
            manifest = json.loads((output / "manifest.json").read_text())
            entry = manifest["partitions"]["init_boot_a"]
            with (output / entry["file"]).open("rb") as stream:
                self.assertEqual(bd.digest_stream(stream), entry["sha256"])
            self.assertEqual(self.run_backup(output, resume=True), 0)

    def test_manifest_is_bound_before_the_first_partition_read(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            with patch.object(FakeSession, "read_exact", side_effect=bd.Stop("interrupted")), \
                 self.assertRaisesRegex(bd.Stop, "interrupted"):
                self.run_backup(output)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["backup_binding"]["boot_id"], BINDING["boot_id"])
            self.assertEqual(manifest["partitions"], {})
            self.assertFalse(manifest["complete"])
            self.assertEqual(self.run_backup(output, resume=True), 0)

    def test_empty_tar_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            with patch.object(FakeSession, "stream_to", return_value=0), \
                 self.assertRaisesRegex(bd.Stop, "archive is empty"):
                self.run_backup(output)
            self.assertFalse((output / "data.tar").exists())

    def test_resume_rejects_changed_mapping_and_options(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backup"
            self.run_backup(output)
            with self.assertRaisesRegex(bd.Stop, "backup options changed"):
                self.run_backup(output, resume=True, data=False)
            with self.assertRaisesRegex(bd.Stop, "backup options changed"):
                self.run_backup(output, resume=True, include_super=True)


if __name__ == "__main__":
    unittest.main()
