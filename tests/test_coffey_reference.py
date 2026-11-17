"""Coffey reference pins and the read-only trusted-state probe."""
import json
from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import slot_report as sr
from tools import trusted_state_probe as tsp

ROOT = Path(__file__).resolve().parents[1]
COFFEY = json.loads((ROOT / "profile.coffey.json").read_text())
SERIAL = "CUSACOFFEYTEST01"
BOOT = "11111111-2222-3333-4444-555555555555"
TARGET = "192.0.2.55:5555"
NODES = dict(zip(sr.PARTITIONS, (22, 23, 20, 21, 5, 6, 12, 13, 25, 26, 27, 28)))


class FakeCoffey:
    def __init__(self, slot="_a"):
        self.values = {key: "" for key in sr.PROPERTIES}
        self.values.update({
            "ro.serialno": SERIAL, "boot_id": BOOT, "ro.product.device": "coffey",
            "ro.product.model": "onn 4K Plus Streaming", "ro.build.fingerprint": COFFEY["fingerprint"],
            "ro.bootloader": "01.01.260305.112513", "ro.boot.slot_suffix": slot,
            "ro.product.cpu.abilist": COFFEY["abi"], "ro.boot.flash.locked": "1",
            "ro.boot.vbmeta.device_state": "locked", "ro.boot.verifiedbootstate": "green",
            "sys.boot_completed": "1",
        })
        self.queries = []

    def __call__(self, argv, **kwargs):
        if argv[:2] == ["fake-adb", "connect"]:
            return subprocess.CompletedProcess(argv, 0, "connected\n", "")
        if argv[4] == sr.IDENTITY_COMMAND:
            return subprocess.CompletedProcess(
                argv, 0, "\n".join(k + "=" + v for k, v in self.values.items()) + "\n", "")
        command = argv[4].rsplit("\n", 1)[1]
        query = tuple(command.split())
        self.queries.append(query)
        if query == ("id", "-u"):
            return subprocess.CompletedProcess(argv, 0, "2000\n", "")
        if query == ("getenforce",):
            return subprocess.CompletedProcess(argv, 0, "Enforcing\n", "")
        if query == ("uname", "-r"):
            return subprocess.CompletedProcess(argv, 0, "5.15.180-android14-8-g1234567890ab\n", "")
        if query == ("uname", "-v"):
            return subprocess.CompletedProcess(argv, 0, "#1 SMP PREEMPT Thu Mar 5 2026\n", "")
        if query == ("cat", "/proc/partitions"):
            return subprocess.CompletedProcess(
                argv, 0, "179 22 16384 mmcblk0p22\n179 23 16384 mmcblk0p23\n", "")
        if query[0] == "readlink":
            name = query[2].removeprefix("/dev/block/by-name/")
            return subprocess.CompletedProcess(
                argv, 0, "/dev/block/mmcblk0p" + str(NODES[name]) + "\n", "")
        if query[0] == "cat" and query[1].startswith("/sys/class/block/"):
            return subprocess.CompletedProcess(argv, 0, "16384\n", "")
        if query[0] == "sha256sum":
            return subprocess.CompletedProcess(
                argv, 0, COFFEY["init_boot_sha256"] + "  " + query[1] + "\n", "")
        if query == ("bootctl", "get-number-slots"):
            return subprocess.CompletedProcess(argv, 0, "2\n", "")
        if query[:1] == ("bootctl",):
            return subprocess.CompletedProcess(argv, 0, "0\n", "")
        if query == ("gsi_tool", "status"):
            return subprocess.CompletedProcess(argv, 0, "normal\n", "")
        if query == ("update_engine_client", "--status"):
            return subprocess.CompletedProcess(argv, 0, "CURRENT_OP=UPDATE_STATUS_IDLE\n", "")
        raise AssertionError("Unexpected probe: " + repr(query))


class CoffeyReferenceTests(unittest.TestCase):
    def collect(self, fake):
        collector = sr.Collector("fake-adb", TARGET, COFFEY)
        with patch.object(sr.subprocess, "run", side_effect=fake):
            return collector, collector.collect()

    def test_reference_pins_match_the_official_payload_metadata(self):
        self.assertEqual(COFFEY["device"], "coffey")
        self.assertEqual(COFFEY["fingerprint"],
                         "onn/coffey/coffey:14/URO4.260304.011.B1/15051976:user/release-keys")
        self.assertEqual(COFFEY["init_boot_size"], 8388608)
        self.assertEqual(COFFEY["init_boot_sha256"],
                         "bc2112c2531acbd375ed67eb31fcbaa7412232fce777e49ba025d2b34d30dc61")
        self.assertEqual(sum(p["size"] for p in COFFEY["dsu_partitions"].values()), 1197735936)
        self.assertEqual(COFFEY["ota_size"], 906283326)
        self.assertTrue(COFFEY["reference_only"])
        self.assertFalse(COFFEY["install_supported"])
        self.assertFalse(COFFEY["hardware_verified"])
        self.assertIsNone(COFFEY["ota_sha256"])
        self.assertEqual(COFFEY["bootloader"], "01.01.260305.112513")
        self.assertEqual(COFFEY["slots"], {})

    def test_collector_reports_coffey_pins_without_claiming_install_support(self):
        fake = FakeCoffey()
        _, report = self.collect(fake)
        self.assertEqual(report["collection_status"], "complete")
        self.assertEqual(report["reference_profile"]["device"], "coffey")
        self.assertTrue(report["reference_profile"]["reference_only"])
        comparison = report["profile_comparison"]
        self.assertTrue(comparison["firmware_matches"])
        self.assertTrue(comparison["abi_matches"])
        self.assertTrue(comparison["bootloader_pinned"])
        self.assertTrue(comparison["bootloader_matches"])
        self.assertEqual(comparison["installer_supported_slots"], [])
        self.assertFalse(comparison["unlock_hardware_verified"])
        self.assertFalse(comparison["root_method_hardware_verified"])
        self.assertFalse(report["installation_support_established"])
        self.assertEqual(report["kernel_release"]["value"], "5.15.180-android14-8-g1234567890ab")
        entry = report["partitions"]["init_boot_a"]
        self.assertEqual(entry["size"]["bytes"], 8388608)
        self.assertTrue(entry["sha256"]["matches_reference_stock_image"])

    def test_a_jarvis2_device_is_rejected_by_the_coffey_reference(self):
        fake = FakeCoffey()
        fake.values["ro.product.device"] = "jarvis2"
        _, report = self.collect(fake)
        self.assertEqual(report["collection_status"], "stopped")
        self.assertEqual(fake.queries, [])


class TrustedStateProbeTests(unittest.TestCase):
    def test_read_only_probe_reports_locked_and_never_sends_an_unlock(self):
        commands = []

        def fake(argv, **kwargs):
            commands.append(argv)
            if argv[:2] == ["fake-adb", "connect"]:
                return subprocess.CompletedProcess(argv, 0, "connected\n", "")
            if argv[-1] == "getprop":
                props = {"ro.serialno": SERIAL, "ro.product.device": "coffey",
                         "ro.build.fingerprint": COFFEY["fingerprint"],
                         "ro.bootloader": "01.01.260305.112513", "ro.boot.slot_suffix": "_a",
                         "ro.product.cpu.abilist": COFFEY["abi"], "ro.boot.flash.locked": "1",
                         "ro.boot.vbmeta.device_state": "locked",
                         "ro.boot.verifiedbootstate": "green", "sys.boot_completed": "1"}
                text = "".join("[" + k + "]: [" + v + "]\n" for k, v in props.items())
                return subprocess.CompletedProcess(argv, 0, text, "")
            if argv[-1].endswith("/read_state") and argv[3] == "shell":
                return subprocess.CompletedProcess(
                    argv, 0, '{"stage":"lock_state","rc":0,"errno":0,"ret":"0x00000000",'
                             '"origin":0,"a":1,"b":0,"c":0}\n', "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as temp, \
                patch.object(tsp.shutil, "which", return_value="fake-adb"), \
                patch.object(tsp.subprocess, "run", side_effect=fake):
            output = Path(temp) / "probe"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(tsp.main(["--target", TARGET, "--output-dir", str(output)]), 0)
            receipt = json.loads((output / "trusted-state.json").read_text())
        self.assertEqual(receipt["secure_lock_state"], 1)
        self.assertEqual(receipt["interpretation"], "locked")
        self.assertTrue(receipt["trusted_app_reachable_as_shell"])
        self.assertEqual(receipt["write_invocations"], 0)
        self.assertFalse(receipt["unlock_attempted"])
        self.assertNotIn(SERIAL, json.dumps(receipt))
        flat = " ".join(" ".join(command) for command in commands)
        for forbidden in ("--unlock-once", "unlock_once", "flashing", "reboot", "settings put"):
            self.assertNotIn(forbidden, flat)
        self.assertTrue(any("/read_state" in command[-1] for command in commands))

    def test_wrong_firmware_stops_before_staging_anything(self):
        commands = []

        def fake(argv, **kwargs):
            commands.append(argv)
            if argv[:2] == ["fake-adb", "connect"]:
                return subprocess.CompletedProcess(argv, 0, "connected\n", "")
            text = "[ro.serialno]: [" + SERIAL + "]\n[ro.product.device]: [coffey]\n" \
                   "[ro.build.fingerprint]: [onn/coffey/coffey:14/OTHER/1:user/release-keys]\n"
            return subprocess.CompletedProcess(argv, 0, text, "")

        with tempfile.TemporaryDirectory() as temp, \
                patch.object(tsp.shutil, "which", return_value="fake-adb"), \
                patch.object(tsp.subprocess, "run", side_effect=fake):
            with self.assertRaises(tsp.Stop):
                tsp.main(["--target", TARGET, "--output-dir", str(Path(temp) / "probe")])
        self.assertFalse(any(command[3] == "push" for command in commands if len(command) > 3))


if __name__ == "__main__":
    unittest.main()
