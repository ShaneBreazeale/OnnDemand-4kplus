"""Read-only root readiness and the guarded temporary-root session harness."""
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import root_readiness as rr
from tools import temp_root as tr

ROOT = Path(__file__).resolve().parents[1]
COFFEY = json.loads((ROOT / "profile.coffey.json").read_text())
SERIAL = "CUSACOFFEYTEST01"
BOOT = "11111111-2222-3333-4444-555555555555"


def elf(machine=40, payload=b"\x00" * 16):
    header = b"\x7fELF" + bytes((1, 1, 1)) + b"\x00" * 11
    return header + struct.pack("<H", machine) + payload


def sections(uid="2000", kernel="5.15.196-android14-11-g3d26c188ef7e-ab14657224"):
    props = [""] * len(rr.PROPS)
    values = {
        "ro.serialno": SERIAL, "ro.product.device": "coffey",
        "ro.product.model": "onn. 4K Plus Streaming", "ro.build.fingerprint": COFFEY["fingerprint"],
        "ro.build.id": "URO4.260304.011.B1", "ro.build.version.incremental": "15051976",
        "ro.build.version.sdk": "34", "ro.bootloader": "01.01.260305.112513",
        "ro.boot.slot_suffix": "_b", "ro.product.cpu.abilist": "armeabi-v7a,armeabi",
        "ro.boot.flash.locked": "1", "ro.boot.vbmeta.device_state": "locked",
        "ro.boot.verifiedbootstate": "green", "ro.boot.selinux": "enforcing",
        "sys.oem_unlock_allowed": "1",
    }
    for index, key in enumerate(rr.PROPS):
        props[index] = values.get(key, "")
    return {
        "identity": props,
        "uname": [kernel, "armv8l", "#1 SMP PREEMPT Sat Jan 3 21:52:40 UTC 2026"],
        "runtime": [uid, "Enforcing"],
        "sysctl": ["-1", "2", "1", "No such file or directory", "No such file or directory",
                   "No such file or directory"],
        "status": ["Seccomp:\t0", "CapInh:\t0000000000000000", "CapEff:\t0000000000000000"],
        "byname": ["boot_a init_boot_a init_boot_b userdata super"],
        "access": ["/dev/block/mmcblk0p23", "block_denied_as_shell", "kallsyms_denied"],
        "setuid": [""],
        "perf": ["  14.1(ms)  task-clock   # 0.8 cpus used"],
        "cpuinfo": ["Features\t: half thumb fastmult vfp edsp neon"],
    }


CONFIG = "\n".join((
    "CONFIG_FUTEX_PI=y", "CONFIG_USER_NS is not set", "CONFIG_NET_NS=y",
    "CONFIG_XFRM_USER=y", "CONFIG_INET_ESP=y", "# CONFIG_AF_RXRPC is not set",
    "CONFIG_STATIC_USERMODEHELPER=y", 'CONFIG_STATIC_USERMODEHELPER_PATH=""',
    "CONFIG_SECURITY_SELINUX=y", "CONFIG_SHADOW_CALL_STACK=y", "CONFIG_CFI_CLANG=y",
    "CONFIG_ARM64_PTR_AUTH_KERNEL=y", "# CONFIG_ARM64_BTI_KERNEL is not set",
    "CONFIG_ARM64_MTE=y", "CONFIG_KASAN=y", "CONFIG_KASAN_HW_TAGS=y",
)) .replace("CONFIG_USER_NS is not set", "# CONFIG_USER_NS is not set")


class ReadinessTests(unittest.TestCase):
    def test_release_scope_uses_the_first_fixed_release_above_the_version(self):
        self.assertTrue(rr.in_scope((5, 15, 196), "ghostlock"))
        self.assertFalse(rr.in_scope((5, 15, 212), "ghostlock"))
        self.assertTrue(rr.in_scope((5, 15, 204), "dirtyfrag"))
        self.assertFalse(rr.in_scope((5, 15, 205), "dirtyfrag"))
        self.assertTrue(rr.in_scope((6, 6, 100), "ghostlock"))
        self.assertFalse(rr.in_scope((2, 6, 38), "ghostlock"))
        self.assertTrue(rr.in_scope((4, 10, 9), "ghostlock"))
        self.assertEqual(rr.parse_release("5.15.196-android14-11-g3d26c188ef7e"),
                         (5, 15, 196))
        with self.assertRaises(rr.Stop):
            rr.parse_release("not-a-release")

    def test_vulnerable_kernel_is_not_reported_as_a_root_shell(self):
        report = rr.assess(sections(), CONFIG)
        self.assertEqual(report["verdict"], "temp_root_in_scope_needs_coffey_loader")
        self.assertTrue(report["cves"]["CVE-2026-43499"]["in_version_range"])
        self.assertTrue(report["cves"]["CVE-2026-43499"]["trigger_config_present"])
        self.assertFalse(report["cves"]["CVE-2026-43499"]["coffey_port_exists"])
        self.assertEqual(report["cves"]["CVE-2026-43284"]["status"], "trigger_unavailable")
        self.assertFalse(report["hardening"]["userns_allowed"])
        self.assertEqual(report["hardening"]["usermode_helper"], "disabled")
        self.assertFalse(report["hardening"]["mte_effective"])
        gates = {gate["gate"]: gate["pass"] for gate in report["gates"]}
        self.assertTrue(gates["kernel_bug_in_range"])
        self.assertFalse(gates["working_loader"])
        self.assertFalse(gates["root_proof"])

    def test_shareable_report_omits_the_serial(self):
        report = rr.assess(sections(), CONFIG)
        self.assertNotIn(SERIAL, json.dumps(report) + rr.text_report(report))

    def test_fixed_kernel_and_missing_trigger_are_reported_honestly(self):
        report = rr.assess(sections(kernel="5.15.212-android14"), CONFIG)
        self.assertEqual(report["verdict"], "temp_root_chain_blocked")
        self.assertFalse(report["cves"]["CVE-2026-43499"]["in_version_range"])


class LoaderTests(unittest.TestCase):
    def test_loader_must_be_a_pinned_arm_elf(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loader"
            path.write_bytes(elf(40))
            good = tr.verify_loader(path, tr.sha256_file(path))
            self.assertEqual(good["arch"], "arm")
            with self.assertRaises(tr.Stop):
                tr.verify_loader(path, "0" * 64)
            with self.assertRaises(tr.Stop):
                tr.verify_loader(path, "not-a-hash")
            path.write_bytes(elf(183))
            self.assertEqual(tr.verify_loader(path, tr.sha256_file(path))["arch"], "aarch64")
            path.write_bytes(elf(62))
            with self.assertRaises(tr.Stop):
                tr.verify_loader(path, tr.sha256_file(path))
            path.write_bytes(b"#!/bin/sh\necho root\n")
            with self.assertRaises(tr.Stop):
                tr.verify_loader(path, tr.sha256_file(path))


class FakeProc:
    """A process whose stdout is a real file so select()/os.read() behave."""

    def __init__(self, incoming):
        self.out = tempfile.TemporaryFile()
        self.out.write(incoming)
        self.out.seek(0)
        self.stdout = self.out
        self.stdin = tempfile.TemporaryFile()
        self.killed = False

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


class SessionTests(unittest.TestCase):
    def test_text_is_framed_by_the_return_status_and_not_the_loader_word(self):
        with patch.object(tr.secrets, "token_hex", return_value="ab" * 8):
            proc = FakeProc(b"0\n\nONN-TR-" + ("ab" * 8).encode() + b" 0\n")
            session = tr.RootSession(proc)
            result = session.text("id -u")
            self.assertEqual(result, {"text": "0", "returncode": 0})

    def test_read_exact_does_not_lose_bytes_after_the_payload(self):
        with patch.object(tr.secrets, "token_hex", return_value="cd" * 8):
            payload = bytes(range(256)) * 4
            proc = FakeProc(payload + b"ONN-TR-" + ("cd" * 8).encode() + b" 0\n")
            session = tr.RootSession(proc)
            self.assertEqual(session.read_exact("cat /dev/block/x", len(payload)), payload)

    def test_stream_to_is_bounded_and_stops_at_the_marker(self):
        with patch.object(tr.secrets, "token_hex", return_value="ef" * 12):
            marker = ("ONN-END-" + "ef" * 12).encode()
            payload = b"A" * 100000
            proc = FakeProc(payload + b"\n" + marker + b" 0\n")
            session = tr.RootSession(proc)
            sink = io.BytesIO()
            self.assertEqual(session.stream_to(sink, "tar -cf - -C /data ."), len(payload))
            self.assertEqual(sink.getvalue(), payload)

    def test_stream_rejects_command_failure_even_after_partial_output(self):
        for command in ("false", "printf partial; exit 7"):
            with self.subTest(command=command):
                proc = subprocess.Popen(["/bin/sh"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        bufsize=0)
                session = tr.RootSession(proc)
                try:
                    with self.assertRaisesRegex(tr.Stop, "streamed command failed"):
                        session.stream_to(io.BytesIO(), command, timeout=5)
                    self.assertEqual(session.text("printf still-alive"),
                                     {"text": "still-alive", "returncode": 0})
                finally:
                    session.close()
                    proc.stdout.close()

    def test_stream_preserves_binary_output_and_keeps_stderr_out(self):
        proc = subprocess.Popen(["/bin/sh"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        session = tr.RootSession(proc)
        try:
            sink = io.BytesIO()
            self.assertEqual(session.stream_to(sink, "printf '\\000\\377payload'; echo error >&2"), 9)
            self.assertEqual(sink.getvalue(), b"\x00\xffpayload")
        finally:
            session.close()
            proc.stdout.close()


class SessionRefusalTests(unittest.TestCase):
    def test_proof_rejects_a_nonzero_uid(self):
        with patch.object(tr.secrets, "token_hex", return_value="12" * 8):
            proc = FakeProc(b"2000\nshell\nu:r:shell:s0\nEnforcing\n" + BOOT.encode() +
                            b"\nONN-TR-" + ("12" * 8).encode() + b" 0\n")
            session = tr.RootSession(proc)
            with self.assertRaises(tr.Stop):
                tr.prove(session, "b")

    def test_proof_rejects_root_without_block_access(self):
        with patch.object(tr.secrets, "token_hex", return_value="34" * 8):
            marker = ("ONN-TR-" + "34" * 8).encode()
            incoming = (b"0\nu:r:root:s0\nEnforcing\n" + BOOT.encode() + b"\n" + marker +
                        b" 0\n" + b"denied\n" + marker + b" 0\n")
            session = tr.RootSession(FakeProc(incoming))
            with self.assertRaises(tr.Stop):
                tr.prove(session, "b")


if __name__ == "__main__":
    unittest.main()
