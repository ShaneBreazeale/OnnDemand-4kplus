#!/usr/bin/env python3
"""Read-only temporary-root readiness report for a connected onn.

This answers one question: does this exact unit expose a *credible* path to a
temporary uid-0 shell before the bootloader is unlocked? It never exploits,
stages a binary, writes settings, reboots, or touches a partition.

The report separates three things that are easy to confuse:

1. Is the kernel in a known-vulnerable version range for a published bug?
2. Does the build have the kernel options that bug needs to trigger?
3. Do the *final* steps of the published exploit chain work on Android at all?

A "vulnerable" kernel is not a root shell. The last section records the gates
that a coffey-specific loader still has to pass.
"""
import argparse
from datetime import datetime, timezone
import gzip
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

# Kernel version history for the two published families. A version is affected
# when it is below the first fixed release on its own branch.
FIXED = {
    "ghostlock": [(5, 10, 261), (5, 15, 212), (6, 1, 175), (6, 6, 140),
                  (6, 12, 86), (6, 18, 27), (7, 0, 4)],
    "dirtyfrag": [(5, 10, 255), (5, 15, 205), (6, 1, 171), (6, 6, 138),
                  (6, 12, 87), (6, 18, 28), (7, 0, 5)],
}
FIRST = {"ghostlock": (2, 6, 39), "dirtyfrag": (4, 11, 0)}
CVE = {"ghostlock": "CVE-2026-43499", "dirtyfrag": "CVE-2026-43284"}

PROPS = (
    "ro.serialno", "ro.product.device", "ro.product.model", "ro.soc.model",
    "ro.board.platform", "ro.build.fingerprint", "ro.build.id",
    "ro.build.version.incremental", "ro.build.version.release", "ro.build.version.sdk",
    "ro.build.version.security_patch", "ro.bootloader", "ro.boot.slot_suffix",
    "ro.product.cpu.abilist", "ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
    "ro.boot.verifiedbootstate", "ro.boot.veritymode", "ro.virtual_ab.enabled",
    "ro.boot.dynamic_partitions", "ro.gsid.image_running", "ro.boot.vbmeta.digest",
    "ro.boot.vbmeta.size", "ro.boot.vbmeta.hash_alg", "ro.boot.rpmb_state",
    "ro.boot.production_mode", "ro.boot.avb_version", "ro.boot.rollback",
    "ro.boot.bootreason", "ro.boot.selinux", "sys.oem_unlock_allowed",
)
SYSCTLS = (
    "/proc/sys/kernel/perf_event_paranoid",
    "/proc/sys/kernel/kptr_restrict",
    "/proc/sys/kernel/dmesg_restrict",
    "/proc/sys/kernel/unprivileged_userns_clone",
    "/proc/sys/kernel/unprivileged_bpf_disabled",
    "/proc/sys/user/max_user_namespaces",
)
CONFIG_KEYS = (
    "CONFIG_FUTEX_PI", "CONFIG_USER_NS", "CONFIG_NET_NS", "CONFIG_AF_RXRPC",
    "CONFIG_XFRM_USER", "CONFIG_INET_ESP", "CONFIG_STATIC_USERMODEHELPER",
    "CONFIG_STATIC_USERMODEHELPER_PATH", "CONFIG_SECURITY_SELINUX",
    "CONFIG_SHADOW_CALL_STACK", "CONFIG_CFI_CLANG", "CONFIG_ARM64_PTR_AUTH_KERNEL",
    "CONFIG_ARM64_BTI_KERNEL", "CONFIG_ARM64_MTE", "CONFIG_RANDOMIZE_BASE",
    "CONFIG_KASAN", "CONFIG_KASAN_HW_TAGS", "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
    "CONFIG_SLAB_FREELIST_HARDENED", "CONFIG_HARDENED_USERCOPY",
    "CONFIG_VMAP_STACK", "CONFIG_MODULE_SIG_FORCE", "CONFIG_KALLSYMS_ALL",
    "CONFIG_SECCOMP", "CONFIG_BPF_SYSCALL",
)

COLLECT = "\n".join((
    "echo '##identity'",
    "\n".join("getprop " + key for key in PROPS),
    "echo '##uname'",
    "uname -r", "uname -m", "uname -v",
    "echo '##runtime'",
    "id -u", "getenforce",
    "echo '##sysctl'",
    "\n".join("cat " + key + " 2>&1" for key in SYSCTLS),
    "echo '##status'",
    "grep -E '^(Seccomp|NoNewPrivs):|^Cap(Inh|Prm|Eff|Bnd|Amb):' /proc/self/status 2>&1",
    "echo '##cpuinfo'",
    "grep -m1 -E '^(Features|CPU part|CPU architecture)' /proc/cpuinfo 2>&1",
    "echo '##byname'",
    "test -d /dev/block/by-name && ls /dev/block/by-name | tr '\\n' ' ' ; echo",
    "echo '##access'",
    "readlink -f /dev/block/by-name/init_boot_b 2>&1",
    "test -r /dev/block/by-name/init_boot_b && echo block_readable_as_shell || echo block_denied_as_shell",
    "head -c 1 /proc/kallsyms >/dev/null 2>&1 && echo kallsyms_readable || echo kallsyms_denied",
    "echo '##setuid'",
    "find /system/bin /system/xbin /vendor/bin -perm -4000 -type f 2>/dev/null | tr '\\n' ' ' ; echo",
    "echo '##perf'",
    "simpleperf stat -e task-clock -- true 2>&1 | tail -n 3",
    "echo '##end'",
))


class Stop(Exception):
    """A static, shareable explanation; never include raw transport output."""


def parse_release(text):
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", (text or "").strip())
    if not match:
        raise Stop("Cannot read a numeric kernel release from the device.")
    return tuple(int(part) for part in match.groups())


def in_scope(release, family):
    """True when the release predates the first fixed release above it."""
    if release < FIRST[family]:
        return False
    fixed = [version for version in FIXED[family] if version >= release]
    return bool(fixed) and release < min(fixed)


def parse_config(text):
    values = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:].split(" ", 1)[0]] = "n"
    return values


def parse_sections(text):
    sections, current = {}, None
    for line in text.splitlines():
        if line.startswith("##"):
            current = line[2:].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line.rstrip("\r"))
    return sections


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, timeout=30, binary=False):
    try:
        result = subprocess.run(argv, capture_output=True, text=not binary, timeout=timeout,
                                shell=False)
    except subprocess.TimeoutExpired as error:
        raise Stop("ADB did not answer within %d seconds." % timeout) from error
    except OSError as error:
        raise Stop("Cannot execute ADB: " + str(error)) from error
    return result


def collect(adb, serial):
    """Read only. Returns (sections, config_text, raw) without writing to the device."""
    result = run([adb, "-s", serial, "shell", COLLECT], timeout=60)
    if result.returncode != 0 and not result.stdout:
        raise Stop("The device did not answer the read-only probe.")
    sections = parse_sections(result.stdout)
    missing = {"identity", "uname", "runtime", "sysctl", "status", "byname", "access",
               "setuid", "perf", "cpuinfo"} - set(sections)
    if missing:
        raise Stop("The probe was incomplete: " + ", ".join(sorted(missing)))
    config = run([adb, "-s", serial, "exec-out", "cat /proc/config.gz"], timeout=60, binary=True)
    config_text = ""
    if config.returncode == 0 and config.stdout[:2] == b"\x1f\x8b":
        try:
            config_text = gzip.decompress(config.stdout).decode("utf-8", "replace")
        except OSError:
            config_text = ""
    return sections, config_text, {"probe": result.stdout, "config_gz_sha256":
                                   digest_bytes(config.stdout) if config.stdout else None}


def value(sections, name, index):
    lines = sections.get(name) or []
    return lines[index].strip() if index < len(lines) else ""


def assess(sections, config_text):
    """Pure function: sections + kernel config -> shareable readiness report."""
    props = dict(zip(PROPS, (sections["identity"] + [""] * len(PROPS))[:len(PROPS)]))
    release_text = value(sections, "uname", 0)
    release = parse_release(release_text)
    machine = value(sections, "uname", 1)
    config = parse_config(config_text)
    runtime_uid = value(sections, "runtime", 0)
    selinux = value(sections, "runtime", 1) or "unknown"
    sysctl = dict(zip(SYSCTLS, sections["sysctl"] + [""] * len(SYSCTLS)))
    status = "\n".join(sections["status"])
    setuid = [entry for entry in (sections["setuid"][0].split() if sections["setuid"] else [])]
    perf_output = "\n".join(sections["perf"])
    perf_works = "task-clock" in perf_output and "not permitted" not in perf_output.lower()

    def sysctl_number(path):
        try:
            return int((sysctl.get(path) or "").strip())
        except ValueError:
            return None

    config_flag = lambda key: config.get(key, "n")
    userns = (config_flag("CONFIG_USER_NS") != "n"
              and sysctl_number("/proc/sys/kernel/unprivileged_userns_clone") != 0
              and sysctl_number("/proc/sys/user/max_user_namespaces") != 0)
    cpuinfo = "\n".join(sections["cpuinfo"])
    mte_hardware = "mte" in cpuinfo.lower()
    # KASAN_HW_TAGS needs MTE. On a core without it the option is inert at boot.
    kasan_active = config_flag("CONFIG_KASAN") == "y" and (
        config_flag("CONFIG_KASAN_HW_TAGS") != "y" or mte_hardware)

    hardening = {
        "kernel_release": release_text,
        "kernel_arch": machine,
        "userspace_abi": props.get("ro.product.cpu.abilist"),
        "selinux": selinux,
        "seccomp": "disabled" if re.search(r"^Seccomp:\s*0$", status, re.M)
                   else ("enabled" if "Seccomp:" in status else "unknown"),
        "no_new_privs": bool(re.search(r"^NoNewPrivs:\s*1$", status, re.M)),
        "userns_allowed": userns,
        "unprivileged_perf": perf_works,
        "perf_event_paranoid": sysctl_number("/proc/sys/kernel/perf_event_paranoid"),
        "kptr_restrict": sysctl_number("/proc/sys/kernel/kptr_restrict"),
        "usermode_helper": ("disabled" if config_flag("CONFIG_STATIC_USERMODEHELPER") == "y"
                           and config_flag("CONFIG_STATIC_USERMODEHELPER_PATH") == ""
                           else "default"),
        "kallsyms_readable": "kallsyms_readable" in "\n".join(sections["access"]),
        "shadow_call_stack": config_flag("CONFIG_SHADOW_CALL_STACK") == "y",
        "cfi": config_flag("CONFIG_CFI_CLANG") == "y",
        "pac": config_flag("CONFIG_ARM64_PTR_AUTH_KERNEL") == "y",
        "bti_kernel": config_flag("CONFIG_ARM64_BTI_KERNEL") == "y",
        "mte": config_flag("CONFIG_ARM64_MTE") == "y",
        "mte_hardware": mte_hardware,
        "mte_effective": config_flag("CONFIG_ARM64_MTE") == "y" and mte_hardware,
        "kasan": config_flag("CONFIG_KASAN") == "y",
        "kasan_hw_tags": config_flag("CONFIG_KASAN_HW_TAGS") == "y",
        "kasan_effective": kasan_active,
        "setuid_root_binaries": setuid,
        "block_readable_as_shell": "block_readable_as_shell" in "\n".join(sections["access"]),
    }

    ghost_in_scope = in_scope(release, "ghostlock")
    dirty_in_scope = in_scope(release, "dirtyfrag")
    ghost_trigger = ghost_in_scope and config_flag("CONFIG_FUTEX_PI") == "y"
    esp_trigger = (dirty_in_scope and userns and config_flag("CONFIG_XFRM_USER") == "y"
                   and config_flag("CONFIG_INET_ESP") == "y")
    rxrpc_trigger = (dirty_in_scope and config_flag("CONFIG_AF_RXRPC") == "y")

    ghost_blockers = []
    if config_flag("CONFIG_STATIC_USERMODEHELPER_PATH") == "":
        ghost_blockers.append("usermode_helper_disabled: core_pattern and modprobe_path "
                              "final stages cannot run")
    if hardening["cfi"] or hardening["pac"] or hardening["shadow_call_stack"]:
        ghost_blockers.append("control_flow_hardened: CFI/PAC/shadow stack require a "
                              "data-only final stage instead of function-table overwrite")
    if selinux == "Enforcing":
        ghost_blockers.append("selinux_enforcing: uid-0 still needs a domain/permissive "
                              "step before block devices are readable")
    dirty_blockers = []
    if not userns:
        dirty_blockers.append("no_unprivileged_userns: ESP variant cannot register an SA")
    if config_flag("CONFIG_AF_RXRPC") == "n":
        dirty_blockers.append("rxrpc_not_built: RxRPC variant unavailable")
    if not setuid:
        dirty_blockers.append("no_setuid_root_binary: the published page-cache chain has "
                              "no execution target on this build")
    if config_flag("CONFIG_STATIC_USERMODEHELPER_PATH") == "":
        dirty_blockers.append("usermode_helper_disabled: no core_pattern escape")

    cves = {
        CVE["ghostlock"]: {
            "name": "GhostLock",
            "subsystem": "rtmutex/futex-PI stack use-after-free",
            "kernel_release": release_text,
            "in_version_range": ghost_in_scope,
            "trigger_config_present": config_flag("CONFIG_FUTEX_PI") == "y",
            "trigger_requires": "CONFIG_FUTEX_PI only; no capability, namespace or "
                                "remote access",
            "public_ports": ["armv7l 5.4.210 (Huawei Watch 4 Pro)",
                             "arm64 5.15.149 (OPPO Find X6 Pro)"],
            "coffey_port_exists": False,
            "final_stage_blockers": ghost_blockers if ghost_trigger else [],
            "status": ("in_scope_no_coffey_loader" if ghost_trigger else
                       ("out_of_version_range" if not ghost_in_scope else
                        "missing_trigger_config")),
        },
        CVE["dirtyfrag"]: {
            "name": "DirtyFrag",
            "subsystem": "xfrm-ESP / RxRPC page-cache write",
            "kernel_release": release_text,
            "in_version_range": dirty_in_scope,
            "esp_trigger_possible": esp_trigger,
            "rxrpc_trigger_possible": rxrpc_trigger,
            "coffey_port_exists": False,
            "final_stage_blockers": dirty_blockers,
            "status": ("in_scope_chain_blocked" if (esp_trigger or rxrpc_trigger)
                       else "trigger_unavailable"),
        },
    }

    if ghost_trigger:
        verdict = "temp_root_in_scope_needs_coffey_loader"
        summary = ("The kernel is inside the GhostLock range and FUTEX_PI is built in, so "
                   "an unprivileged trigger exists. No coffey loader exists yet; the "
                   "published Android ports target 5.4.210 (armv7l) and 5.15.149 (arm64).")
    elif dirty_in_scope:
        verdict = "temp_root_chain_blocked"
        summary = ("The kernel is inside the DirtyFrag range, but the trigger or the "
                   "execution target is missing on this build.")
    else:
        verdict = "temp_root_not_available"
        summary = "Neither published kernel bug applies to this release."

    gates = [
        {"gate": "firmware_identity", "pass": True,
         "detail": props.get("ro.build.fingerprint", "")},
        {"gate": "bootloader_locked", "pass": props.get("ro.boot.flash.locked") == "1",
         "detail": "flash.locked=" + str(props.get("ro.boot.flash.locked"))},
        {"gate": "oem_unlock_allowed", "pass": props.get("sys.oem_unlock_allowed") == "1",
         "detail": "sys.oem_unlock_allowed=" + str(props.get("sys.oem_unlock_allowed"))},
        {"gate": "kernel_bug_in_range", "pass": ghost_in_scope or dirty_in_scope,
         "detail": release_text},
        {"gate": "trigger_config_present", "pass": ghost_trigger or esp_trigger or rxrpc_trigger,
         "detail": "FUTEX_PI=" + config_flag("CONFIG_FUTEX_PI") +
                   " USER_NS=" + config_flag("CONFIG_USER_NS")},
        {"gate": "working_loader", "pass": False,
         "detail": "no coffey-compatible loader has been run on this unit"},
        {"gate": "root_proof", "pass": False,
         "detail": "waiting on a loader; id -u must become 0 before any backup"},
    ]

    return {
        "schema": "onn-root-readiness-v1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "diagnostic_only": True,
        "device_writes_requested": False,
        "exploit_attempted": False,
        "device": props.get("ro.product.device"),
        "model": props.get("ro.product.model"),
        "fingerprint": props.get("ro.build.fingerprint"),
        "build_id": props.get("ro.build.id"),
        "build_incremental": props.get("ro.build.version.incremental"),
        "security_patch": props.get("ro.build.version.security_patch"),
        "bootloader": props.get("ro.bootloader"),
        "slot": props.get("ro.boot.slot_suffix"),
        "abi": props.get("ro.product.cpu.abilist"),
        "shell_uid": runtime_uid,
        "hardening": hardening,
        "cves": cves,
        "gates": gates,
        "verdict": verdict,
        "summary": summary,
        "notes": [
            "A vulnerable kernel version is not a working root shell.",
            "A successful loader is proven only by id -u == 0 plus a block-device read.",
            "Nothing here authorizes a reboot, unlock, flash or settings change.",
        ],
    }


def text_report(report):
    lines = [
        "%s %s (%s) - read-only temporary-root readiness" % (
            report.get("device"), report.get("model"), report.get("build_incremental")),
        "Kernel %s  slot %s  shell uid %s" % (
            report["hardening"]["kernel_release"], report.get("slot"), report.get("shell_uid")),
        "",
        "Verdict: " + report["verdict"],
        report["summary"],
        "",
        "Gates:",
    ]
    for gate in report["gates"]:
        lines.append("  [%s] %-24s %s" % ("pass" if gate["pass"] else "----",
                                          gate["gate"], gate["detail"]))
    lines.append("")
    for cve, entry in report["cves"].items():
        lines.append("%s %s: %s" % (cve, entry["name"], entry["status"]))
        if entry["final_stage_blockers"]:
            for blocker in entry["final_stage_blockers"]:
                lines.append("    blocker: " + blocker)
    lines.append("")
    lines.append("Hardening: " + json.dumps(report["hardening"], indent=2))
    return "\n".join(lines) + "\n"


def write_file(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="ADB serial or IP:port of one onn")
    parser.add_argument("--adb", default="adb", help="ADB executable or path")
    parser.add_argument("--profile", type=Path, default=ROOT / "profile.coffey.json",
                        help="Reference profile used only to label the expected firmware")
    parser.add_argument("--config", type=Path,
                        help="Offline /proc/config.gz instead of reading it from the device")
    parser.add_argument("--output-dir", type=Path,
                        help="New report directory; default is under ignored work/root-readiness/")
    args = parser.parse_args(argv)
    adb = shutil.which(args.adb)
    if not adb:
        parser.error("ADB was not found; install Android platform-tools or use --adb")
    try:
        profile = json.loads(args.profile.read_text())
    except (OSError, ValueError):
        parser.error("Cannot read the reference profile; supply a valid --profile JSON file")
    output = args.output_dir or (ROOT / "work/root-readiness" /
        (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]))
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError:
        parser.error("Cannot create the report directory; choose a new writable --output-dir")
    try:
        sections, config_text, raw = collect(adb, args.target)
        if args.config:
            config_text = gzip.decompress(args.config.read_bytes()).decode("utf-8", "replace")
        report = assess(sections, config_text)
    except Stop as error:
        print(str(error), file=sys.stderr)
        return 2
    report["reference_profile"] = {
        "id": profile.get("id"), "device": profile.get("device"),
        "fingerprint_matches": profile.get("fingerprint") == report.get("fingerprint"),
        "install_supported": bool(profile.get("install_supported")),
    }
    report["collector_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    write_file(output / "private.json",
               json.dumps({"target": args.target, "raw": raw}, indent=2) + "\n")
    write_file(output / "root-readiness.json", json.dumps(report, indent=2) + "\n")
    write_file(output / "root-readiness.txt", text_report(report))
    print("Report: " + str(output / "root-readiness.txt"))
    print("Verdict: " + report["verdict"])
    print("Share root-readiness.txt; keep private.json local.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
