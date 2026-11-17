#!/usr/bin/env python3
"""Archive and verify the pinned stock OTA before any firmware write.

This is a vendor firmware archive, not a dump of the physical unit. It does
not include user data, calibration data, or partitions absent from the OTA.
A true pre-write partition dump still requires the temporary root guest.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = ROOT / "tools/extract_dsu_ota.py"
DEFAULT_PARTITIONS = (
    "boot", "bootloader", "dtbo", "init_boot", "odm", "odm_dlkm", "odm_ext",
    "oem", "product", "system", "system_dlkm", "system_ext", "vbmeta",
    "vbmeta_system", "vendor", "vendor_boot", "vendor_dlkm",
)


class Stop(Exception):
    """A static, shareable explanation."""


def digest(path, algorithm="sha256"):
    value = hashlib.new(algorithm)
    with Path(path).open("rb") as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def download(url, destination, expected_size, expected_sha, progress=print):
    """Stream once, hash while writing, and never replace an existing archive."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        require(destination.stat().st_size == expected_size, "Existing archive size mismatch")
        actual = digest(destination)
        if expected_sha:
            require(actual == expected_sha, "Existing archive hash mismatch")
        return actual
    partial = destination.with_name(destination.name + ".partial-" + uuid.uuid4().hex)
    value = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(url, timeout=60) as source, partial.open("xb") as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)
                value.update(chunk)
                size += len(chunk)
                if size // (64 * 1024 * 1024) != (size - len(chunk)) // (64 * 1024 * 1024):
                    progress(f"Downloaded {size // (1024 * 1024)} MiB...")
            output.flush()
            os.fsync(output.fileno())
        require(size == expected_size, "Download size mismatch; partial file retained")
        actual = value.hexdigest()
        if expected_sha:
            require(actual == expected_sha, "Download hash mismatch; partial file retained")
        require(not destination.exists(), "Archive destination appeared; refusing replacement")
        partial.rename(destination)
        return actual
    except BaseException:
        # Keep a partial download for diagnosis only; it is never renamed.
        raise


def require(condition, message):
    if not condition:
        raise Stop(message)


def extract(archive, directory, partitions):
    directory = Path(directory)
    if directory.exists():
        raise Stop("Extraction directory already exists; use --verify-only or a new --output")
    directory.mkdir(parents=True, mode=0o700)
    command = [sys.executable, str(EXTRACTOR), str(archive), str(directory),
               "--partitions", *partitions]
    response = subprocess.run(command, capture_output=True, text=True, timeout=900)
    if response.returncode != 0:
        raise Stop("Stock OTA extraction failed: " + response.stderr.strip()[-400:])
    return directory


def verify_partitions(profile, directory, partitions):
    directory = Path(directory)
    rows = {}
    for name in partitions:
        path = directory / (name + ".img")
        require(path.is_file(), "Extracted partition is missing: " + name)
        size = path.stat().st_size
        sha = digest(path)
        pin = None
        if name == "init_boot":
            pin = {"size": profile["init_boot_size"], "sha256": profile["init_boot_sha256"]}
        elif name in profile.get("dsu_partitions", {}):
            pin = profile["dsu_partitions"][name]
        if pin:
            require(size == pin["size"] and sha == pin["sha256"],
                    "Extracted partition differs from its reference pin: " + name)
        rows[name] = {"file": str(path.resolve()), "size": size, "sha256": sha,
                      "matches_reference_pin": pin is not None}
    return rows


def update_profile(path, ota_sha256, init_boot_sha1):
    """Fill only fields that are still empty; never overwrite a different pin."""
    path = Path(path)
    profile = json.loads(path.read_text())
    for key, value in (("ota_sha256", ota_sha256), ("root_stock_sha1", init_boot_sha1)):
        current = profile.get(key)
        if current is None:
            profile[key] = value
        elif current != value:
            raise Stop("Reference profile already pins a different " + key + "; not overwriting")
    temporary = path.with_name(path.name + ".partial-" + uuid.uuid4().hex)
    temporary.write_text(json.dumps(profile, indent=2) + "\n")
    os.replace(temporary, path)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=ROOT / "profile.coffey.json")
    parser.add_argument("--cache", type=Path, default=ROOT / "cache")
    parser.add_argument("--output", type=Path, required=True,
                        help="New archive directory; never overwritten")
    parser.add_argument("--partitions", nargs="+", default=list(DEFAULT_PARTITIONS))
    parser.add_argument("--verify-only", action="store_true",
                        help="Verify an existing OTA and extracted partition set; no download or extract")
    parser.add_argument("--write-profile", action="store_true",
                        help="Pin the verified OTA SHA-256 and stock init_boot SHA-1 into the profile")
    args = parser.parse_args(argv)
    for name in args.partitions:
        if not re.fullmatch(r"[a-zA-Z0-9_]+", name):
            parser.error("Invalid partition name: " + name)
    try:
        profile = json.loads(args.profile.read_text())
    except (OSError, ValueError) as error:
        parser.error("Cannot read the reference profile: " + str(error))
    for key in ("device", "fingerprint", "ota_url", "ota_size", "init_boot_size",
                "init_boot_sha256"):
        if not profile.get(key):
            parser.error("The reference profile is missing " + key)

    archive = args.cache / (profile["id"] + "-full-ota.zip")
    output = args.output.resolve()
    expected_ota = profile.get("ota_sha256")
    if args.verify_only:
        require(archive.is_file(), "No cached archive to verify at " + str(archive))
        require(output.is_dir(), "No archive output directory at " + str(output))
        if not expected_ota:
            # Fall back to the first run's own manifest; never invent a pin.
            prior = output / "manifest.json"
            require(prior.is_file(), "No profile pin or prior manifest to verify the archive against")
            expected_ota = json.loads(prior.read_text())["ota"]["sha256"]
            require(re.fullmatch(r"[0-9a-f]{64}", expected_ota or ""),
                    "Prior manifest has no valid OTA SHA-256")
    else:
        try:
            output.mkdir(parents=True, exist_ok=False)
        except OSError:
            parser.error("Cannot create the archive directory; choose a new --output")
        actual = download(profile["ota_url"], archive, profile["ota_size"], expected_ota)

    if args.verify_only:
        actual = digest(archive)
    require(archive.stat().st_size == profile["ota_size"], "Archived OTA size mismatch")
    if expected_ota:
        require(actual == expected_ota, "Archived OTA differs from the expected SHA-256")

    partitions_dir = output / "partitions"
    if not args.verify_only:
        try:
            extract(archive, partitions_dir, args.partitions)
        except OSError as error:
            raise Stop("Cannot run the stock OTA extractor: " + str(error)) from error
    rows = verify_partitions(profile, partitions_dir, args.partitions)
    init_boot_sha1 = digest(partitions_dir / "init_boot.img", "sha1")

    if args.write_profile:
        update_profile(args.profile, actual, init_boot_sha1)
        profile["ota_sha256"], profile["root_stock_sha1"] = actual, init_boot_sha1

    manifest = {
        "schema": "onn-stock-archive-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile.get("id"),
        "device": profile["device"],
        "fingerprint": profile["fingerprint"],
        "security_patch": profile.get("security_patch"),
        "archive_kind": "vendor_full_ota",
        "device_dump": False,
        "user_data_included": False,
        "ota": {"url": profile["ota_url"], "file": str(archive.resolve()),
                "bytes": archive.stat().st_size, "sha256": actual,
                "matches_reference_pin": profile.get("ota_sha256") == actual},
        "init_boot_sha1": init_boot_sha1,
        "partitions": rows,
        "extraction_receipt": str((partitions_dir / "extraction-receipt.json").resolve()),
        "limitations": [
            "This archive is the vendor OTA, not a dump of this physical unit.",
            "It does not include user data, accounts, settings, or calibration data.",
            "It is restore material only if a matching recovery path exists.",
            "A pre-write dump of the physical partitions still requires the temporary root guest.",
        ],
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    if args.write_profile:
        manifest["profile_updated"] = str(args.profile.resolve())
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({key: manifest[key] for key in
                      ("device", "fingerprint", "ota", "init_boot_sha1", "partitions")},
                     indent=2))
    print("Manifest:", manifest_path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Stop as error:
        print("STOP:", error, file=sys.stderr)
        sys.exit(2)
