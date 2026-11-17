#!/usr/bin/env python3
"""Collect a read-only onn slot report against a pinned reference profile.

The default reference is profile.json (2026 onn 4K Pro, jarvis2). Use
--profile profile.coffey.json for the 2025 onn 4K Plus (coffey). A reference
profile never authorizes an unlock or firmware write by itself.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROPERTIES = (
    "ro.product.device", "ro.product.model", "ro.soc.model", "ro.board.platform",
    "ro.build.fingerprint", "ro.build.id", "ro.build.version.incremental",
    "ro.build.version.release", "ro.build.version.sdk", "ro.build.version.security_patch",
    "ro.bootloader", "ro.boot.slot_suffix", "ro.product.cpu.abilist",
    "ro.boot.flash.locked", "ro.boot.vbmeta.device_state", "ro.boot.verifiedbootstate",
    "ro.boot.veritymode", "ro.virtual_ab.enabled", "ro.boot.dynamic_partitions",
    "sys.boot_completed", "ro.gsid.image_running",
    "ro.boot.vbmeta.digest", "ro.boot.vbmeta.hash_alg", "ro.boot.vbmeta.size",
)
BINDING = ("ro.serialno", "ro.product.device", "ro.build.fingerprint",
           "ro.bootloader", "ro.boot.slot_suffix", "boot_id")
PARTITIONS = tuple(name + slot for name in
                   ("init_boot", "boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system")
                   for slot in ("_a", "_b"))
IDENTITY_COMMAND = "# slot-report identity\n" + "\n".join(
    "printf '%s=' " + shlex.quote(key) + "; getprop " + shlex.quote(key)
    for key in ("ro.serialno", *PROPERTIES)
) + "\nprintf 'boot_id='; cat /proc/sys/kernel/random/boot_id"


class Stop(Exception):
    """A static, shareable explanation; never include raw transport output."""


def network_target(value):
    match = re.fullmatch(r"([0-9.]+)(?::([0-9]{1,5}))?", value)
    if not match:
        raise argparse.ArgumentTypeError("Use the onn's IPv4 address, optionally with :port")
    try:
        address = ipaddress.IPv4Address(match[1])
    except ipaddress.AddressValueError as error:
        raise argparse.ArgumentTypeError("Invalid IPv4 address") from error
    port = int(match[2] or "5555")
    if address.is_unspecified or address.is_multicast or not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Invalid ADB address or port")
    return f"{address}:{port}"


def hardware_serial(value):
    if not re.fullmatch(r"[A-Za-z0-9]{4,64}", value):
        raise argparse.ArgumentTypeError("Use the onn's hardware serial")
    return value


def result_status(result):
    if result["timed_out"]:
        return "timeout"
    if result["returncode"] == 0:
        return "ok"
    error = (result["stdout"] + "\n" + result["stderr"]).lower()
    if "unauthorized" in error or "failed to authenticate" in error:
        return "unauthorized"
    if "permission denied" in error or "operation not permitted" in error:
        return "permission_denied"
    if result["returncode"] == 127 or "not found" in error or "no such file" in error:
        return "unavailable"
    return "query_failed"


def parsed(result, parser):
    item = {"status": result_status(result)}
    if item["status"] == "ok":
        value = parser(result["stdout"].strip())
        if value is None:
            item["status"] = "unrecognized_output"
        else:
            item["value"] = value
    return item


def integer(text):
    return int(text) if re.fullmatch(r"[0-9]{1,15}", text) else None


def one_of(*values):
    return lambda text: text if text in values else None


def partition_sizes(text):
    sizes = {}
    for line in text.splitlines():
        fields = line.split()
        if (len(fields) == 4 and all(integer(x) is not None for x in fields[:3])
                and re.fullmatch(r"mmcblk0p[0-9]+", fields[3])):
            sizes[fields[3]] = int(fields[2]) * 1024
    return sizes


def update_status(text):
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    operation = values.get("CURRENT_OP", "")
    if not re.fullmatch(r"UPDATE_STATUS_[A-Z_]{1,60}", operation):
        return None
    return {"operation": operation}


class Collector:
    def __init__(self, adb, target, profile, expected_serial=None, progress=None):
        self.adb, self.target, self.profile = adb, target, profile
        self.expected_serial = expected_serial
        self.progress = progress or (lambda message: None)
        self.records = []
        self.binding = None
        self.secrets = {target, target.rsplit(":", 1)[0]}
        if expected_serial:
            self.secrets.add(expected_serial)
        self.report = {
            "schema": "onn26-slot-report-v2",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collection_status": "incomplete",
            "diagnostic_only": True,
            "installation_support_established": False,
            "device_writes_requested": False,
            "properties": {}, "partitions": {}, "boot_control": {},
            "notes": [
                "Unavailable reads are unknown, not proof of incompatible or damaged partitions.",
                "An inactive slot's contents and bootability are not inferred from its name.",
                "This report does not authorize a slot switch, unlock or firmware installation.",
            ],
        }

    def run(self, label, arguments):
        argv = [self.adb, *arguments]
        try:
            response = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                                      shell=False)
            result = {"returncode": response.returncode, "stdout": response.stdout,
                      "stderr": response.stderr, "timed_out": False}
        except subprocess.TimeoutExpired as error:
            def decode(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            result = {"returncode": None, "stdout": decode(error.stdout),
                      "stderr": decode(error.stderr), "timed_out": True}
        except OSError:
            raise Stop("Cannot execute ADB; check --adb and the platform-tools installation.")
        self.records.append({"label": label, "argv": argv, **result})
        return result

    def snapshot(self):
        result = self.run("identity", ["-s", self.target, "shell", IDENTITY_COMMAND])
        status = result_status(result)
        if status == "unauthorized":
            raise Stop("Android requires debugging authorization. Accept it on the selected onn and rerun.")
        if status != "ok":
            raise Stop("Cannot read the selected onn's identity; check its ADB connection.")
        values = {}
        for line in result["stdout"].splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values or key not in (*PROPERTIES, "ro.serialno", "boot_id"):
                raise Stop("Malformed device identity response; collection stopped.")
            values[key] = value
        self.secrets.update(values.get(key, "") for key in ("ro.serialno", "boot_id"))
        serial_pattern = self.profile.get("serial_regex", r"JUSA[A-Za-z0-9]+")
        if (not re.fullmatch(serial_pattern, values.get("ro.serialno", ""))
                or values.get("ro.product.device") != self.profile["device"]):
            raise Stop("The selected device is not an identified " + self.profile["device"] + " onn.")
        if self.expected_serial and values["ro.serialno"] != self.expected_serial:
            raise Stop("The selected device does not match --expect-serial.")
        if (values.get("ro.boot.slot_suffix") not in ("_a", "_b")
                or not values.get("ro.build.fingerprint") or not values.get("ro.bootloader")
                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", values.get("boot_id", ""))):
            raise Stop("Device firmware, active slot or boot identity is unavailable.")
        binding = {key: values[key] for key in BINDING}
        if self.binding is not None and binding != self.binding:
            raise Stop("Device, firmware, active slot or boot changed during collection; report is incomplete.")
        self.binding = binding
        return values

    def query(self, label, *arguments):
        # Bind every query to the same physical unit, firmware, slot and boot.
        checks = []
        for key, value in self.binding.items():
            getter = "cat /proc/sys/kernel/random/boot_id" if key == "boot_id" else "getprop " + key
            checks.append('[ "$(' + getter + ')" = ' + shlex.quote(value) + ' ] || exit 90')
        command = "\n".join(checks) + "\n" + shlex.join(arguments)
        result = self.run(label, ["-s", self.target, "shell", command])
        if result["returncode"] == 90:
            raise Stop("Device, firmware, active slot or boot changed during collection; report is incomplete.")
        if result_status(result) == "unauthorized":
            raise Stop("ADB authorization was lost; report is incomplete.")
        return result

    def collect(self):
        try:
            self.progress("Connecting to the selected onn for read-only diagnostics...")
            result = self.run("connect", ["connect", self.target])
            if result_status(result) == "unauthorized" or "failed to authenticate" in result["stdout"].lower():
                raise Stop("Android requires debugging authorization. Accept it on the selected onn and rerun.")
            values = self.snapshot()
            self.report["reference_profile"] = {
                "id": self.profile.get("id"), "device": self.profile.get("device"),
                "reference_only": self.profile.get("reference_only", False),
                "install_supported": self.profile.get("install_supported", True),
            }
            self.report["properties"] = {key: values.get(key) or None for key in PROPERTIES}
            bootloader_pinned = self.profile.get("bootloader")
            slots = self.profile.get("slots", {})
            self.report["profile_comparison"] = {
                "firmware_matches": values["ro.build.fingerprint"] == self.profile["fingerprint"],
                "bootloader_matches": bootloader_pinned is None or values["ro.bootloader"] == bootloader_pinned,
                "bootloader_pinned": bootloader_pinned is not None,
                "abi_matches": self.profile["abi"] in values.get("ro.product.cpu.abilist", "").split(","),
                "installer_supported_slots": sorted(slots),
                "active_slot_matches_installer": values["ro.boot.slot_suffix"] in slots,
                "active_slot_a": values["ro.boot.slot_suffix"] == "_a",
            }
            comparison = self.report["profile_comparison"]
            matches = all(comparison[key] for key in
                          ("firmware_matches", "bootloader_matches", "abi_matches"))
            slot = slots.get(values["ro.boot.slot_suffix"], {})
            for kind in ("unlock", "root_method"):
                comparison[kind + "_hardware_verified"] = matches and slot.get(kind + "_hardware_verified") is True
            self.report["shell_uid"] = parsed(self.query("shell-uid", "id", "-u"), integer)
            self.report["selinux"] = parsed(self.query("selinux", "getenforce"),
                                             one_of("Enforcing", "Permissive", "Disabled"))
            self.report["kernel_release"] = parsed(
                self.query("kernel-release", "uname", "-r"),
                lambda text: text if re.fullmatch(r"[0-9A-Za-z._+-]{1,120}", text) else None)
            self.report["kernel_version"] = parsed(
                self.query("kernel-version", "uname", "-v"),
                lambda text: text if 0 < len(text) <= 300 and "\n" not in text else None)
            proc = self.query("proc-partitions", "cat", "/proc/partitions")
            sizes = partition_sizes(proc["stdout"]) if result_status(proc) == "ok" else {}
            self.report["proc_partitions_access"] = result_status(proc)
            for name in PARTITIONS:
                self.progress("Reading " + name + " metadata...")
                entry = self.read_partition(name, sizes)
                self.report["partitions"][name] = entry
            active = self.report["partitions"]["init_boot" + values["ro.boot.slot_suffix"]]
            active["avb_binding"] = avb_binding(values, self.profile)
            self.read_boot_control()
            self.report["update_engine"] = parsed(
                self.query("update-status", "update_engine_client", "--status"), update_status)
            self.report["dsu"] = parsed(self.query("dsu-status", "gsi_tool", "status"),
                lambda text: text.splitlines() if text and all(
                    line in ("normal", "running", "installed", "enabled", "disabled")
                    for line in text.splitlines()) else None)
            self.snapshot()
            self.report["collection_status"] = "complete"
        except Stop as error:
            self.report["collection_status"] = "stopped"
            self.report["stop_reason"] = str(error)
        return self.public_report()

    def read_partition(self, name, proc_sizes):
        path = "/dev/block/by-name/" + name
        mapping = parsed(self.query(name + "-mapping", "readlink", "-f", path),
                         lambda text: text if re.fullmatch(r"/dev/block/mmcblk0p[0-9]+", text) else None)
        entry = {"mapping": mapping, "size": {"status": "mapping_unavailable"}}
        if mapping["status"] == "ok":
            node = mapping["value"].rsplit("/", 1)[1]
            size = parsed(self.query(name + "-size", "cat", "/sys/class/block/" + node + "/size"), integer)
            if size["status"] == "ok":
                size = {"status": "ok", "bytes": size["value"] * 512, "source": "sysfs"}
            elif node in proc_sizes:
                size = {"status": "ok", "bytes": proc_sizes[node], "source": "proc_partitions"}
            entry["size"] = size
        if name.startswith("init_boot_"):
            size = entry["size"]
            if size["status"] != "ok":
                entry["sha256"] = {"status": "size_unverified"}
            elif size["bytes"] != self.profile["init_boot_size"]:
                entry["sha256"] = {"status": "unexpected_size"}
            else:
                # Only hash the named init_boot partition after checking its length.
                # No su, adb root, firmware copies or device-side temporary files.
                digest = parsed(self.query(name + "-sha256", "sha256sum", path),
                    lambda text: text.split()[0] if re.fullmatch(
                        r"[0-9a-f]{64}  " + re.escape(path), text) else None)
                if digest["status"] == "ok":
                    digest["matches_reference_stock_image"] = digest["value"] == self.profile["init_boot_sha256"]
                entry["sha256"] = digest
        return entry

    def read_boot_control(self):
        self.progress("Reading available boot-control and update status...")
        control = self.report["boot_control"]
        count = parsed(self.query("slot-count", "bootctl", "get-number-slots"), integer)
        control["number_slots"] = count
        if count["status"] != "ok" or count["value"] != 2:
            control["remaining_queries"] = "not_attempted_without_two_slot_boot_control"
            return
        for command in ("get-current-slot", "get-active-boot-slot"):
            control[command] = parsed(self.query(command, "bootctl", command),
                                      lambda text: int(text) if text in ("0", "1") else None)
        control["get-snapshot-merge-status"] = parsed(
            self.query("merge-status", "bootctl", "get-snapshot-merge-status"),
            lambda text: text.lower() if text.lower() in
            ("none", "unknown", "snapshotted", "merging", "cancelled") else None)
        for slot in ("0", "1"):
            for command in ("is-slot-bootable", "is-slot-marked-successful"):
                result = self.query(command + "-" + slot, "bootctl", command, slot)
                # AOSP bootctl uses a nonzero exit for both false and HAL errors.
                # Only success proves true; failures do not prove an unbootable slot.
                control[command + "-" + slot] = {"status": result_status(result)}
                if result["returncode"] == 0:
                    control[command + "-" + slot]["value"] = True

    def public_report(self):
        # Never publish argv, stderr, address, serial or boot ID. Also scrub any
        # accidental echoes of the private binding from allowed property values.
        def scrub(value):
            if isinstance(value, dict):
                return {key: scrub(item) for key, item in value.items()}
            if isinstance(value, list):
                return [scrub(item) for item in value]
            if isinstance(value, str):
                for secret in sorted(filter(None, self.secrets), key=len, reverse=True):
                    value = value.replace(secret, "[redacted]")
                return re.sub(self.profile.get("serial_regex", r"JUSA[A-Za-z0-9]+"), "[redacted]", value)
            return value
        return scrub(self.report)


def avb_binding(values, profile):
    """Indirect, active-slot-only evidence about init_boot; never a direct hash.

    A locked bootloader that boots green verified the active slot's vbmeta
    chain, and exported that chain's digest and size. tools/avb_pin.py derives
    both from the stock OTA and checks that the OTA init_boot satisfies its hash
    descriptor. A match proves the device's vbmeta chain is the stock one. It
    proves init_boot[:covered_bytes] was stock at boot only if the bootloader
    requested init_boot during verification, which libavb does not report.
    Nothing here covers the inactive slot or the partition's padding.
    """
    descriptor = profile.get("init_boot_avb") or {}
    base = {"method": "avb_vbmeta_digest", "direct_hash": False,
            "full_partition_hash_proven": False,
            "scope": "active_slot_vbmeta_chain_at_boot",
            "covered_bytes": descriptor.get("image_size"),
            "assumes": ["bootloader_requests_init_boot"]}
    pin = profile.get("vbmeta_digest")
    if not (isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin)) or not descriptor:
        return {**base, "status": "no_reference_pin"}
    digest = values.get("ro.boot.vbmeta.digest", "")
    if values.get("ro.boot.vbmeta.hash_alg") != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return {**base, "status": "unavailable"}
    if (values.get("ro.boot.flash.locked") != "1"
            or values.get("ro.boot.vbmeta.device_state") != "locked"
            or values.get("ro.boot.verifiedbootstate") != "green"):
        # Unlocked/orange boots still export a digest, but nothing enforced it.
        return {**base, "status": "not_enforced_by_locked_green_boot"}
    if values.get("ro.build.fingerprint") != profile.get("fingerprint"):
        # A different build has a different chain; that is not evidence of tampering.
        return {**base, "status": "different_build"}
    size_pin = profile.get("vbmeta_size")
    size_matches = size_pin is None or values.get("ro.boot.vbmeta.size") == str(size_pin)
    status = "match" if digest == pin and size_matches else "mismatch"
    return {**base, "status": status, "vbmeta_chain_matches_reference": status == "match",
            "vbmeta_size_matches_reference": size_matches if size_pin is not None else None}


def text_report(report):
    device = (report.get("reference_profile") or {}).get("device", "onn")
    return ("onn " + device + " — read-only slot diagnostic\n"
            "This diagnostic does not verify an unlock/root installation on either slot.\n"
            "Unavailable fields are unknown. Review this report before sharing.\n\n"
            + json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def write_file(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=network_target, required=True,
                        help="One onn IPv4 address, optionally :port; no network scan")
    parser.add_argument("--adb", default="adb", help="ADB executable or path")
    parser.add_argument("--profile", type=Path, default=ROOT / "profile.json",
                        help="Pinned reference profile; use profile.coffey.json for the 2025 4K Plus")
    parser.add_argument("--expect-serial", type=hardware_serial,
                        help="Optional physical serial check; kept out of the shareable report")
    parser.add_argument("--output-dir", type=Path, help="New report directory; default is under ignored work/slot-reports/")
    args = parser.parse_args(argv)
    adb = shutil.which(args.adb)
    if not adb:
        parser.error("ADB was not found; install Android platform-tools or use --adb")
    try:
        profile = json.loads(args.profile.read_text())
    except (OSError, ValueError):
        parser.error("Cannot read the reference profile; supply a valid --profile JSON file")
    for key in ("device", "fingerprint", "abi", "init_boot_size", "init_boot_sha256"):
        if not profile.get(key):
            parser.error("The reference profile is missing " + key)
    output = args.output_dir or (ROOT / "work/slot-reports" /
        (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]))
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError:
        parser.error("Cannot create the report directory; choose a new writable --output-dir")
    collector = Collector(adb, args.target, profile, args.expect_serial,
                          progress=lambda message: print(message, flush=True))
    try:
        report = collector.collect()
    except KeyboardInterrupt:
        collector.report.update(collection_status="stopped", stop_reason="Collection interrupted by operator.")
        report = collector.public_report()
    report["collector_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    private = {"target": args.target, "binding": collector.binding, "commands": collector.records}
    write_file(output / "private.json", json.dumps(private, indent=2) + "\n")
    write_file(output / "slot-report.json", json.dumps(report, indent=2) + "\n")
    write_file(output / "slot-report.txt", text_report(report))
    print("Report: " + str(output / "slot-report.txt"))
    print("Share slot-report.txt or slot-report.json after review. Keep private.json local.")
    if report["collection_status"] != "complete":
        print(report["stop_reason"], file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
