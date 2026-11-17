#!/usr/bin/env python3
"""Read-only trusted AVB lock-state probe for an onn over network ADB.

This pushes only the pinned read_state helper to /data/local/tmp, runs its
fixed read command, and removes it. It never sends an unlock command, flashes
firmware, changes settings, or reboots.

A successful read proves that the device's OPTEE AVB trusted application is
reachable from the ordinary shell UID. It does not prove that an unlock would
succeed on this model, and it does not authorize a write.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.slot_report import network_target  # noqa: E402

READER = ROOT / "bin/armeabi-v7a/read_state"
NATIVE_PINS = ROOT / "NATIVE_SHA256.json"
PROPS = ("ro.serialno", "ro.product.device", "ro.build.fingerprint", "ro.bootloader",
         "ro.boot.slot_suffix", "ro.product.cpu.abilist", "ro.boot.flash.locked",
         "ro.boot.vbmeta.device_state", "ro.boot.verifiedbootstate", "sys.boot_completed")


class Stop(Exception):
    """A static, shareable explanation; never include raw transport output."""


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, timeout=20):
    try:
        response = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                  shell=False)
        return {"returncode": response.returncode, "stdout": response.stdout,
                "stderr": response.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as error:
        decode = lambda value: value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        return {"returncode": None, "stdout": decode(error.stdout),
                "stderr": decode(error.stderr), "timed_out": True}
    except OSError as error:
        raise Stop("Cannot execute ADB: " + str(error)) from error


def parse_props(text):
    return dict(re.findall(r"^\[([^\]]+)\]: \[(.*)\]$", text, re.M))


def parse_lock_state(text):
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if (isinstance(event, dict) and event.get("stage") == "lock_state"
                and event.get("rc") == 0 and event.get("ret") == "0x00000000"
                and type(event.get("a")) is int and event["a"] in (0, 1)):
            return event["a"]
    return None


def require(condition, message):
    if not condition:
        raise Stop(message)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=network_target, required=True,
                        help="One onn IPv4 address, optionally :port; no network scan")
    parser.add_argument("--adb", default="adb", help="ADB executable or path")
    parser.add_argument("--profile", type=Path, default=ROOT / "profile.coffey.json",
                        help="Pinned reference profile; no default match is bypassed")
    parser.add_argument("--output-dir", type=Path,
                        help="New receipt directory; default is under ignored work/trusted-state/")
    args = parser.parse_args(argv)
    adb = shutil.which(args.adb)
    require(adb, "ADB was not found; install Android platform-tools or use --adb")
    require(READER.is_file(), "Packaged read_state helper is missing")
    pins = json.loads(NATIVE_PINS.read_text())
    require(pins.get("bin/armeabi-v7a/read_state") == digest(READER),
            "Packaged read_state helper differs from its pinned hash")
    try:
        profile = json.loads(args.profile.read_text())
    except (OSError, ValueError) as error:
        parser.error("Cannot read the reference profile: " + str(error))

    output = args.output_dir or (ROOT / "work/trusted-state" /
        (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]))
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError:
        parser.error("Cannot create the receipt directory; choose a new --output-dir")

    records = []
    remote = None
    try:
        records.append(run([adb, "connect", args.target]))
        identity = run([adb, "-s", args.target, "shell", "getprop"])
        require(identity["returncode"] == 0 and not identity["timed_out"],
                "Cannot read the selected onn; check its ADB connection and authorization")
        props = parse_props(identity["stdout"])
        require(props.get("ro.product.device") == profile.get("device"),
                "The selected device is not an identified " + str(profile.get("device")) + " onn")
        require(props.get("ro.build.fingerprint") == profile.get("fingerprint"),
                "The selected onn firmware differs from the pinned reference profile")
        require(re.fullmatch(profile.get("serial_regex", r"JUSA[A-Za-z0-9]+"),
                             props.get("ro.serialno", "")),
                "The selected onn hardware serial does not match the reference profile")
        require(profile.get("abi") in props.get("ro.product.cpu.abilist", "").split(","),
                "The selected onn userspace ABI differs from the reference profile")

        remote = "/data/local/tmp/oe26-lock-" + uuid.uuid4().hex[:12]
        require(run([adb, "-s", args.target, "shell", "mkdir", "-m", "700", remote])["returncode"] == 0,
                "Cannot create the temporary helper directory")
        require(run([adb, "-s", args.target, "push", str(READER), remote + "/read_state"])["returncode"] == 0,
                "Cannot stage the pinned read_state helper")
        require(run([adb, "-s", args.target, "shell", "chmod", "700", remote + "/read_state"])["returncode"] == 0,
                "Cannot make the staged helper executable")
        result = run([adb, "-s", args.target, "shell", remote + "/read_state"], timeout=15)
        state = parse_lock_state(result["stdout"]) if result["returncode"] == 0 else None
        require(state is not None,
                "The trusted AVB read did not return a lock state; no write was attempted")
        records.append(result)

        report = {
            "at": datetime.now(timezone.utc).isoformat(),
            "profile": profile.get("id"),
            "device": props.get("ro.product.device"),
            "fingerprint": props.get("ro.build.fingerprint"),
            "bootloader": props.get("ro.bootloader"),
            "slot": props.get("ro.boot.slot_suffix"),
            "abi": profile.get("abi"),
            "serial_sha256": hashlib.sha256(props.get("ro.serialno", "").encode()).hexdigest(),
            "flash_locked": props.get("ro.boot.flash.locked"),
            "vbmeta_device_state": props.get("ro.boot.vbmeta.device_state"),
            "verified_boot_state": props.get("ro.boot.verifiedbootstate"),
            "secure_lock_state": state,
            "interpretation": "unlocked" if state == 0 else "locked",
            "trusted_app_reachable_as_shell": True,
            "write_invocations": 0,
            "unlock_attempted": False,
            "reboot_requested": False,
            "settings_changed": False,
            "next": "Reconnaissance only. Do not unlock until the coffey pins and recovery plan are reviewed.",
        }
        report["receipt"] = str(output / "trusted-state.json")
        (output / "trusted-state.json").write_text(json.dumps(report, indent=2) + "\n")
        (output / "private.json").write_text(json.dumps(
            {"target": args.target, "device_serial": props.get("ro.serialno"),
             "commands": records}, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        print("Receipt:", report["receipt"])
        return 0
    finally:
        if remote and re.fullmatch(r"/data/local/tmp/oe26-lock-[0-9a-f]{12}", remote):
            try:
                run([adb, "-s", args.target, "shell", "rm", "-f", remote + "/read_state"], timeout=10)
                run([adb, "-s", args.target, "shell", "rmdir", remote], timeout=10)
            except Stop:
                pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Stop as error:
        print("STOP:", error, file=sys.stderr)
        sys.exit(2)
