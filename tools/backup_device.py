#!/usr/bin/env python3
"""Per-unit onn backup that runs only when a uid-0 shell is already proven.

This is the backup the stock OTA archive cannot give you: the bytes actually on
this unit, both slots included, plus a tar of /data. It refuses to run as the
ordinary shell user, because a shell-owned "backup" cannot open block devices and
would silently produce an empty or partial archive.

It never writes to the device, never reboots, and never changes a setting. On the
host it only creates files inside the chosen output directory.

The tar of /data is a live filesystem snapshot: apps are running, so a file can
be captured mid-write. `sync` is issued first, and the manifest says
``crash_consistent: false``. For a consistent image, run this from the DSU guest
against a quiesced system, or after the permanent root is in place.

Progress is checkpointed on the host. Resume requires the same unit, firmware,
slot, boot and backup options; after a reboot use a new output directory. Older
manifests without a device binding can be verified but cannot be resumed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import temp_root  # noqa: E402

SCHEMA = "onn-device-backup-v1"
ALWAYS_SKIP = {"mmcblk0", "userdata"}
DEFAULT_SKIP = {"super"}
PRIORITY = ("init_boot", "boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system",
            "bootloader", "oem", "metadata", "misc", "param", "env", "frp", "factory",
            "cri_data", "logo", "tee", "rsv", "reserved", "mmcblk0boot0", "mmcblk0boot1")


class Stop(Exception):
    """A static, shareable explanation; never include raw transport output."""


def digest_stream(stream):
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(1 << 20)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def free_bytes(path):
    return shutil.disk_usage(path).free


def by_name(session):
    """Every /dev/block/by-name entry, with its resolved node.

    Names are matched strictly: the output of this shell call is device data, not
    a command, and anything that is not ``name -> node`` is discarded.
    """
    result = session.text(
        "for n in $(ls /dev/block/by-name); do "
        "printf '%s %s\\n' \"$n\" \"$(readlink -f /dev/block/by-name/$n 2>/dev/null)\"; done")
    mapping = {}
    for line in result["text"].splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].startswith("/dev/block/"):
            mapping[parts[0]] = parts[1]
    if not mapping:
        raise Stop("Cannot read /dev/block/by-name even as root; refusing to guess.")
    return mapping


def sizes(session, mapping):
    """Bytes per block node, from sysfs; block-device st_size is not reliable."""
    out = {}
    nodes = sorted(set(os.path.basename(node) for node in mapping.values()))
    script = "for n in " + " ".join(nodes) + "; do printf '%s %s\\n' \"$n\" " \
             "\"$(cat /sys/class/block/$n/size 2>/dev/null)\"; done"
    for line in session.text(script)["text"].splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = int(parts[1]) * 512
    return out


def plan_partitions(mapping, node_sizes, include_super=False):
    """Ordered (name, node, bytes) list, important boot partitions first."""
    skip = set(ALWAYS_SKIP) | (set() if include_super else DEFAULT_SKIP)
    entries = []
    for name, node in mapping.items():
        if name in skip:
            continue
        size = node_sizes.get(os.path.basename(node))
        if not size:
            continue
        entries.append((name, node, size))

    def order(entry):
        base = entry[0].rsplit("_", 1)[0] if entry[0][-2:] in ("_a", "_b") else entry[0]
        index = PRIORITY.index(base) if base in PRIORITY else len(PRIORITY)
        return (index, entry[0])

    return sorted(entries, key=order)


def stock_pins(profile_id):
    manifest = ROOT / "backups" / str(profile_id) / "manifest.json"
    try:
        data = json.loads(manifest.read_text())
    except (OSError, ValueError):
        return {}
    return {name: entry.get("sha256") for name, entry in (data.get("partitions") or {}).items()
            if entry.get("sha256")}


def inventory(session):
    commands = (
        ("getprop", "getprop"),
        ("df", "df -h"),
        ("mount", "mount"),
        ("by-name", "ls -l /dev/block/by-name"),
        ("proc-partitions", "cat /proc/partitions"),
        ("packages", "pm list packages -f"),
        ("packages-list", "cat /data/system/packages.list"),
    )
    blocks = []
    for title, command in commands:
        result = session.text(command, timeout=120)
        blocks.append("### " + title + "\n" + result["text"].rstrip() + "\n")
    return "\n".join(blocks)


def data_used_kib(session):
    text = session.text("df -k /data | tail -n 1")["text"].split()
    # Filesystem 1K-blocks Used Available Use% Mounted -> Used is the third field.
    if len(text) > 2 and text[2].isdigit():
        return int(text[2])
    return None


def write_manifest(directory, manifest):
    """Publish atomically; a resume replaces its own manifest, never a foreign one."""
    path = directory / "manifest.json"
    temporary = directory / ("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(json.dumps(manifest, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def load_manifest(directory):
    try:
        return json.loads((directory / "manifest.json").read_text())
    except (OSError, ValueError) as error:
        raise Stop("The existing backup has no readable manifest.") from error


def verify_existing(directory, manifest):
    """Re-hash every file the manifest names; return (ok, problems)."""
    problems = []
    if manifest.get("complete") is False:
        problems.append("backup: incomplete run")
    entries = list((manifest.get("partitions") or {}).items())
    if manifest.get("data"):
        entries.append(("data", manifest["data"]))
    if manifest.get("inventory"):
        entries.append(("inventory", manifest["inventory"]))
    for name, entry in entries:
        path = directory / entry["file"]
        if not path.is_file():
            problems.append("%s: missing" % name)
            continue
        size = path.stat().st_size
        if size != entry.get("bytes"):
            problems.append("%s: size %d != %d" % (name, size, entry.get("bytes")))
            continue
        with path.open("rb") as stream:
            actual = digest_stream(stream)
        if actual != entry.get("sha256"):
            problems.append("%s: sha256 mismatch" % name)
    return not problems, problems


def backup(args, adb):
    output = args.output
    resume = args.resume
    manifest_path = output / "manifest.json"
    if manifest_path.exists() and not resume:
        raise Stop("That directory already contains a manifest; use --resume or a new path.")
    if output.exists() and any(output.iterdir()) and not resume:
        raise Stop("That directory is not empty; use --resume or a new path.")
    prior = load_manifest(output) if manifest_path.exists() else None
    if prior and prior.get("schema") != SCHEMA:
        raise Stop("The existing manifest has a different schema; refusing to mix runs.")
    profile = json.loads(args.profile.read_text())
    state = {}
    session_context = (temp_root.open_session(adb, args.target, args.loader,
                                              args.loader_sha256, state=state)
                       if args.loader else temp_root.direct_session(adb, args.target))
    with session_context as (session, verified_loader, facts):
        if facts["uid"] != 0:
            raise Stop("Not root; refusing to write a backup that would be empty.")
        output.mkdir(mode=0o700, parents=True, exist_ok=True)
        (output / "partitions").mkdir(mode=0o700, exist_ok=True)
        before = temp_root.binding(adb, args.target)
        if not before.get("serial") or not before.get("boot_id"):
            raise Stop("Device identity is incomplete; refusing an unbound backup.")
        backup_binding = {key: before[key] for key in
                          ("fingerprint", "bootloader", "slot", "boot_id")}
        backup_binding["serial_sha256"] = hashlib.sha256(before["serial"].encode()).hexdigest()
        if prior and (prior.get("backup_binding") != backup_binding
                      or prior.get("profile") != profile.get("id")):
            raise Stop("The prior backup is not bound to this device, firmware, slot and boot; "
                       "use a new output directory. Legacy backups cannot be resumed safely.")
        if args.require_fingerprint and before["fingerprint"] != args.require_fingerprint:
            raise Stop("The firmware fingerprint does not match --require-fingerprint.")
        mapping = by_name(session)
        node_sizes = sizes(session, mapping)
        plan = plan_partitions(mapping, node_sizes, include_super=args.include_super)
        if not plan:
            raise Stop("No readable partitions were found; refusing to continue.")
        partition_plan = {name: {"node": node, "bytes": size} for name, node, size in plan}
        if prior and (prior.get("partition_plan") != partition_plan
                      or prior.get("data_requested") != bool(args.data)):
            raise Stop("Partition mapping, sizes or backup options changed; use a new output directory.")
        used_kib = data_used_kib(session) if args.data else 0
        needed = sum(size for _, _, size in plan) + (used_kib or 0) * 1024
        if free_bytes(output) < needed + (1 << 30):
            raise Stop("The host needs %.1f GiB more free space for this run." %
                       ((needed + (1 << 30) - free_bytes(output)) / (1 << 30)))
        checkpoint = {
            "schema": SCHEMA, "created_at": (prior or {}).get("created_at") or
                datetime.now(timezone.utc).isoformat(),
            "profile": profile.get("id"), "backup_binding": backup_binding,
            "partition_plan": partition_plan, "data_requested": bool(args.data),
            "complete": False, "verified_ok": False,
            "partitions": dict((prior or {}).get("partitions") or {}),
            "data": (prior or {}).get("data"), "inventory": (prior or {}).get("inventory"),
        }
        write_manifest(output, checkpoint)
        partitions, skipped = {}, []
        for name, node, size in plan:
            target = output / "partitions" / (name + ".img")
            entry = None
            if target.exists():
                known = (prior or {}).get("partitions", {}).get(name)
                if (resume and known and known.get("bytes") == size == target.stat().st_size
                        and known.get("node") == node):
                    with target.open("rb") as stream:
                        if digest_stream(stream) == known.get("sha256"):
                            entry = known
                if entry is None and not args.force:
                    raise Stop("Existing %s does not match the manifest; use --resume "
                               "with a verified file or a new output directory." % target.name)
            if entry is None:
                data = session.read_exact("cat " + node, size,
                                          timeout=max(300, size // (64 << 10)))
                temporary = target.with_name("." + target.name + ".part")
                with temporary.open("wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                entry = {"file": str(Path("partitions") / target.name), "node": node,
                         "bytes": size}
                with temporary.open("rb") as stream:
                    entry["sha256"] = digest_stream(stream)
                # Journal the expected hash before publishing the file. If interrupted
                # before rename, resume re-reads it; after rename, it can verify it.
                checkpoint["partitions"][name] = entry
                write_manifest(output, checkpoint)
                os.replace(temporary, target)
            partitions[name] = entry
            checkpoint["partitions"][name] = entry
            write_manifest(output, checkpoint)
        data_entry = None
        if args.data:
            session.text("sync", timeout=300)
            target = output / "data.tar"
            if target.exists() and resume and (prior or {}).get("data"):
                known = prior["data"]
                with target.open("rb") as stream:
                    if digest_stream(stream) == known.get("sha256"):
                        data_entry = known
            if data_entry is None:
                temporary = target.with_name(".data.tar.part")
                with temporary.open("wb") as stream:
                    written = session.stream_to(stream, "tar -cf - -C /data .")
                    if written <= 0:
                        raise Stop("The /data archive is empty; refusing to publish it.")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, target)
                with target.open("rb") as stream:
                    data_entry = {"file": "data.tar", "bytes": written,
                                  "sha256": digest_stream(stream),
                                  "method": "tar -cf - -C /data .",
                                  "live_snapshot": True, "crash_consistent": False}
            checkpoint["data"] = data_entry
            write_manifest(output, checkpoint)
        inventory_text = inventory(session)
        (output / "inventory.txt").write_text(inventory_text)
        inventory_entry = {"file": "inventory.txt",
                           "bytes": (output / "inventory.txt").stat().st_size,
                           "sha256": hashlib.sha256(inventory_text.encode()).hexdigest()}
        after = temp_root.binding(adb, args.target)
        if after["boot_id"] != before["boot_id"]:
            raise Stop("The onn rebooted during the backup; treat these files as a partial run.")
        if (after["fingerprint"], after["serial"]) != (before["fingerprint"], before["serial"]):
            raise Stop("The device identity changed during the backup.")

    pins = stock_pins(profile.get("id"))
    for name, entry in partitions.items():
        base = name[:-2] if name[-2:] in ("_a", "_b") else name
        pin = pins.get(base)
        entry["stock_pin_sha256"] = pin
        entry["matches_stock_pin"] = (pin == entry["sha256"]) if pin else None
    for base in {name[:-2] for name in partitions if name[-2:] in ("_a", "_b")}:
        first, second = partitions.get(base + "_a"), partitions.get(base + "_b")
        if first and second:
            same = first["sha256"] == second["sha256"]
            first["equals_other_slot"] = second["equals_other_slot"] = same
    manifest = {
        "schema": SCHEMA,
        "backup_binding": backup_binding,
        "partition_plan": partition_plan,
        "data_requested": bool(args.data),
        "complete": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile.get("id"),
        "device": profile.get("device"),
        "fingerprint": before["fingerprint"],
        "bootloader": before["bootloader"],
        "slot": before["slot"],
        "boot_id": before["boot_id"],
        "device_dump": True,
        "user_data_included": bool(args.data),
        "live_snapshot": True,
        "crash_consistent": False,
        "partitions": partitions,
        "data": data_entry,
        "inventory": inventory_entry,
        "loader": verified_loader,
        "stock_manifest": str(ROOT / "backups" / str(profile.get("id")) / "manifest.json")
                          if pins else None,
        "notes": [
            "These are this unit's bytes, not OTA images.",
            "The /data tar was taken from a running system; use it for files, not for a "
            "byte-identical restore.",
            "A verified hash proves the host file is intact, not that the device is healthy.",
        ],
    }
    ok, problems = verify_existing(output, manifest)
    manifest["verified_ok"] = ok
    manifest["verify_problems"] = problems
    write_manifest(output, manifest)
    sums = []
    for entry in list(partitions.values()) + [data_entry, inventory_entry]:
        if entry:
            sums.append("%s  %s" % (entry["sha256"], entry["file"]))
    (output / "sha256sums.txt").write_text("\n".join(sums) + "\n")
    print("Backup: " + str(output))
    print("Partitions: %d  /data: %s  verified: %s" %
          (len(partitions), "yes" if data_entry else "no", ok))
    for problem in problems:
        print("  " + problem, file=sys.stderr)
    return 0 if ok else 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="ADB serial or IP:port of one onn")
    parser.add_argument("--adb", default="adb", help="ADB executable or path")
    parser.add_argument("--profile", type=Path, default=ROOT / "profile.coffey.json")
    parser.add_argument("--loader", type=Path,
                        help="Temporary-root loader; omit only if the device is already rooted")
    parser.add_argument("--loader-sha256", help="Pinned SHA-256 of the loader")
    parser.add_argument("--direct", action="store_true",
                        help="Use an already-rooted device instead of a loader")
    parser.add_argument("--output", type=Path,
                        help="New backup directory; default under ignored backups/")
    parser.add_argument("--resume", action="store_true",
                        help="Continue on the same device/firmware/slot/boot after verifying finished files")
    parser.add_argument("--force", action="store_true",
                        help="Replace files that exist but are not in the manifest")
    parser.add_argument("--no-data", dest="data", action="store_false",
                        help="Skip the /data tar and back up partitions only")
    parser.add_argument("--include-super", action="store_true",
                        help="Also dump the multi-gigabyte super partition")
    parser.add_argument("--require-fingerprint",
                        help="Refuse unless ro.build.fingerprint equals this value")
    parser.set_defaults(data=True)
    parser.add_argument("--verify-only", type=Path,
                        help="Re-hash an existing backup directory and exit")
    args = parser.parse_args(argv)
    adb = shutil.which(args.adb)
    if not adb:
        parser.error("ADB was not found; install Android platform-tools or use --adb")
    if bool(args.loader) == bool(args.direct):
        parser.error("Choose exactly one of --loader (temporary root) or --direct (already root)")
    if args.loader and not args.loader_sha256:
        parser.error("--loader requires --loader-sha256")
    if args.verify_only:
        manifest = load_manifest(args.verify_only)
        ok, problems = verify_existing(args.verify_only, manifest)
        print(("Verified: " if ok else "Problems in: ") + str(args.verify_only))
        for problem in problems:
            print("  " + problem)
        return 0 if ok else 3
    args.output = args.output or (ROOT / "backups" /
        ("%s-device-%s" % (json.loads(args.profile.read_text()).get("id", "onn"),
                           datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))))
    try:
        return backup(args, adb)
    except (Stop, temp_root.Stop) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
