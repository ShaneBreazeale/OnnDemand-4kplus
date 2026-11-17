"""Offline stock-OTA archive, verification and profile pinning."""
import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import archive_stock as ar


def sha(data, algorithm="sha256"):
    return hashlib.new(algorithm, data).hexdigest()


class FakeResponse:
    def __init__(self, data, chunk=7):
        self.data, self.chunk, self.pos = data, chunk, 0

    def read(self, size):
        size = min(size, self.chunk)
        piece = self.data[self.pos:self.pos + size]
        self.pos += len(piece)
        return piece

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class DownloadTests(unittest.TestCase):
    def test_streams_once_and_leaves_no_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            data = b"stock-ota" * 1000
            destination = Path(temp) / "ota.zip"
            with patch.object(ar.urllib.request, "urlopen", return_value=FakeResponse(data)):
                actual = ar.download("https://example.invalid/ota.zip", destination,
                                     len(data), sha(data), progress=lambda _: None)
            self.assertEqual(actual, sha(data))
            self.assertEqual(destination.read_bytes(), data)
            self.assertEqual(list(Path(temp).iterdir()), [destination])

    def test_hash_mismatch_keeps_partial_and_never_renames(self):
        with tempfile.TemporaryDirectory() as temp:
            data = b"stock-ota"
            destination = Path(temp) / "ota.zip"
            with patch.object(ar.urllib.request, "urlopen", return_value=FakeResponse(data)):
                with self.assertRaises(ar.Stop):
                    ar.download("https://example.invalid/ota.zip", destination,
                                len(data), "0" * 64, progress=lambda _: None)
            self.assertFalse(destination.exists())
            partials = list(Path(temp).glob("ota.zip.partial-*"))
            self.assertEqual(len(partials), 1)
            self.assertEqual(partials[0].read_bytes(), data)

    def test_existing_archive_is_verified_not_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "ota.zip"
            destination.write_bytes(b"already-here")
            with patch.object(ar.urllib.request, "urlopen",
                              side_effect=AssertionError("must not download")):
                actual = ar.download("https://example.invalid/ota.zip", destination,
                                     len(b"already-here"), sha(b"already-here"))
            self.assertEqual(actual, sha(b"already-here"))


class PartitionTests(unittest.TestCase):
    def test_reference_pins_are_checked_and_unpinned_files_are_only_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "init_boot.img").write_bytes(b"boot")
            (folder / "system.img").write_bytes(b"sys")
            (folder / "vbmeta.img").write_bytes(b"vb")
            profile = {"init_boot_size": 4, "init_boot_sha256": sha(b"boot"),
                       "dsu_partitions": {"system": {"size": 3, "sha256": sha(b"sys")}}}
            rows = ar.verify_partitions(profile, folder, ["init_boot", "system", "vbmeta"])
        self.assertTrue(rows["init_boot"]["matches_reference_pin"])
        self.assertTrue(rows["system"]["matches_reference_pin"])
        self.assertFalse(rows["vbmeta"]["matches_reference_pin"])
        self.assertEqual(rows["vbmeta"]["sha256"], sha(b"vb"))

    def test_a_changed_pinned_partition_stops(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "init_boot.img").write_bytes(b"tampered")
            profile = {"init_boot_size": 4, "init_boot_sha256": sha(b"boot"),
                       "dsu_partitions": {}}
            with self.assertRaises(ar.Stop):
                ar.verify_partitions(profile, folder, ["init_boot"])

    def test_profile_pinning_fills_empty_fields_and_refuses_a_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "profile.json"
            path.write_text(json.dumps({"ota_sha256": None, "root_stock_sha1": None}))
            ar.update_profile(path, "a" * 64, "b" * 40)
            self.assertEqual(json.loads(path.read_text()),
                             {"ota_sha256": "a" * 64, "root_stock_sha1": "b" * 40})
            with self.assertRaises(ar.Stop):
                ar.update_profile(path, "c" * 64, "b" * 40)


class VerifyOnlyTests(unittest.TestCase):
    def build(self, temp, write_profile=False):
        folder = Path(temp)
        cache = folder / "cache"
        cache.mkdir()
        output = folder / "archive"
        partitions_dir = output / "partitions"
        partitions_dir.mkdir(parents=True)
        ota_data = b"full-ota-archive"
        (cache / "test-full-ota.zip").write_bytes(ota_data)
        files = {"init_boot": b"boot-image", "system": b"system-image"}
        for name, data in files.items():
            (partitions_dir / (name + ".img")).write_bytes(data)
        (partitions_dir / "extraction-receipt.json").write_text("{}\n")
        profile = {
            "id": "test", "device": "coffey",
            "fingerprint": "onn/coffey/coffey:14/TEST/1:user/release-keys",
            "security_patch": "2026-03-01",
            "ota_url": "https://example.invalid/ota.zip", "ota_size": len(ota_data),
            "ota_sha256": sha(ota_data),
            "init_boot_size": len(files["init_boot"]),
            "init_boot_sha256": sha(files["init_boot"]),
            "dsu_partitions": {"system": {"size": len(files["system"]),
                                          "sha256": sha(files["system"])}},
            "root_stock_sha1": None,
        }
        profile_path = folder / "profile.json"
        profile_path.write_text(json.dumps(profile))
        args = ["--profile", str(profile_path), "--cache", str(cache), "--output", str(output),
                "--partitions", "init_boot", "system", "--verify-only"]
        if write_profile:
            args.append("--write-profile")
        return profile_path, args, output

    def test_verify_only_writes_a_manifest_without_network_or_device_access(self):
        with tempfile.TemporaryDirectory() as temp:
            _, args, output = self.build(temp)
            with patch.object(ar.urllib.request, "urlopen",
                              side_effect=AssertionError("must not download")), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(ar.main(args), 0)
            manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["archive_kind"], "vendor_full_ota")
        self.assertFalse(manifest["device_dump"])
        self.assertFalse(manifest["user_data_included"])
        self.assertTrue(manifest["ota"]["matches_reference_pin"])
        self.assertEqual(manifest["init_boot_sha1"], sha(b"boot-image", "sha1"))
        self.assertTrue(manifest["partitions"]["init_boot"]["matches_reference_pin"])

    def test_verify_only_uses_the_first_manifest_when_the_profile_is_unpinned(self):
        with tempfile.TemporaryDirectory() as temp:
            profile_path, args, output = self.build(temp)
            profile = json.loads(profile_path.read_text())
            expected = profile["ota_sha256"]
            profile["ota_sha256"] = None
            profile_path.write_text(json.dumps(profile))
            with patch.object(ar.urllib.request, "urlopen",
                              side_effect=AssertionError("must not download")), \
                    redirect_stdout(io.StringIO()):
                with self.assertRaises(ar.Stop):
                    ar.main(args)
                (output / "manifest.json").write_text(
                    json.dumps({"ota": {"sha256": expected}}))
                self.assertEqual(ar.main(args), 0)

    def test_write_profile_pins_the_verified_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            profile_path, args, output = self.build(temp, write_profile=True)
            profile = json.loads(profile_path.read_text())
            expected = profile["ota_sha256"]
            profile["ota_sha256"] = None
            profile_path.write_text(json.dumps(profile))
            (output / "manifest.json").write_text(json.dumps({"ota": {"sha256": expected}}))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(ar.main(args), 0)
            updated = json.loads(profile_path.read_text())
            expected = sha((Path(temp) / "cache" / "test-full-ota.zip").read_bytes())
        self.assertEqual(updated["ota_sha256"], expected)
        self.assertEqual(updated["root_stock_sha1"], sha(b"boot-image", "sha1"))


if __name__ == "__main__":
    unittest.main()
