#!/usr/bin/env python3
"""Derive the AVB pins that let a shell-only report bind init_boot to the OTA.

Shell UID 2000 cannot read /dev/block/* or sysfs partition sizes on coffey, so
the on-device init_boot cannot be hashed without root. A locked bootloader that
reports verifiedbootstate=green has, however, verified the active slot's
init_boot against a hash descriptor inside the vbmeta chain, and it exports the
digest of that whole chain as ro.boot.vbmeta.digest.

This tool runs on the host against partitions extracted from the pinned stock
OTA. It never touches a device. It proves, offline:

1. init_boot.img matches the profile's size and SHA-256 pin;
2. the vbmeta chain contains exactly one hash descriptor for init_boot, and
   H(salt || init_boot.img[:image_size]) equals that descriptor's digest;
3. the expected ro.boot.vbmeta.digest, computed the way libavb and
   ``avbtool calculate_vbmeta_digest`` do: one hash over the top-level vbmeta
   struct followed by each chained partition's vbmeta struct, in descriptor
   order.

It is a pure-stdlib parser; it does not execute a downloaded avbtool.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]

HEADER = struct.Struct("!4s2L2QL11QLL47sx80x")      # AvbVBMetaImageHeader, 256 bytes
FOOTER = struct.Struct("!4sLLQQQ28x")               # AvbFooter, 64 bytes
DESCRIPTOR = struct.Struct("!2Q")                   # tag, num_bytes_following
HASH_DESCRIPTOR = struct.Struct("!2QQ32sLLLL60x")   # AvbHashDescriptor, 132 bytes
CHAIN_DESCRIPTOR = struct.Struct("!2QLLLL60x")      # AvbChainPartitionDescriptor, 92 bytes
TAG_HASH, TAG_CHAIN = 2, 4
assert HEADER.size == 256 and FOOTER.size == 64
assert HASH_DESCRIPTOR.size == 132 and CHAIN_DESCRIPTOR.size == 92


class Stop(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Stop(message)


def vbmeta_struct(path):
    """Return (vbmeta struct bytes = header + auth + aux, descriptor bytes, header flags)."""
    data = Path(path).read_bytes()
    offset = 0
    if data[:4] != b"AVB0":
        require(len(data) >= FOOTER.size, path.name + " has no vbmeta header or AVB footer")
        magic, _, _, _, offset, size = FOOTER.unpack_from(data, len(data) - FOOTER.size)
        require(magic == b"AVBf", path.name + " has no vbmeta header or AVB footer")
        require(offset + size <= len(data), path.name + " AVB footer points outside the image")
    require(offset + HEADER.size <= len(data), path.name + " vbmeta header is truncated")
    fields = HEADER.unpack_from(data, offset)
    require(fields[0] == b"AVB0", path.name + " vbmeta magic mismatch")
    # libavb refuses an unsigned chained vbmeta; an unsigned top one only boots unlocked.
    require(fields[5] != 0, path.name + " vbmeta is unsigned (algorithm NONE)")
    auth_size, aux_size = fields[3], fields[4]
    # magic, major, minor, auth, aux, algorithm, hash(2), signature(2),
    # public_key(2), public_key_metadata(2), descriptors(2), ...
    descriptors_offset, descriptors_size = fields[14], fields[15]
    end = offset + HEADER.size + auth_size + aux_size
    require(end <= len(data), path.name + " vbmeta blocks are truncated")
    blob = data[offset:end]
    aux = blob[HEADER.size + auth_size:]
    require(descriptors_offset + descriptors_size <= len(aux), path.name + " descriptors overflow")
    return blob, aux[descriptors_offset:descriptors_offset + descriptors_size], fields[17]


def descriptors(raw):
    position = 0
    while position < len(raw):
        tag, following = DESCRIPTOR.unpack_from(raw, position)
        require(following % 8 == 0, "Malformed AVB descriptor length")
        chunk = raw[position:position + DESCRIPTOR.size + following]
        require(len(chunk) == DESCRIPTOR.size + following, "Truncated AVB descriptor")
        position += len(chunk)
        if tag == TAG_HASH:
            require(len(chunk) >= HASH_DESCRIPTOR.size, "Truncated AVB hash descriptor")
            _, _, image_size, algorithm, name_len, salt_len, digest_len, flags = \
                HASH_DESCRIPTOR.unpack_from(chunk)
            body = chunk[HASH_DESCRIPTOR.size:]
            require(name_len + salt_len + digest_len <= len(body), "AVB hash descriptor overflows")
            name = body[:name_len].decode()
            salt = body[name_len:name_len + salt_len]
            digest = body[name_len + salt_len:name_len + salt_len + digest_len]
            yield {"kind": "hash", "partition": name, "image_size": image_size,
                   "algorithm": algorithm.rstrip(b"\0").decode(), "salt": salt,
                   "digest": digest, "flags": flags}
        elif tag == TAG_CHAIN:
            require(len(chunk) >= CHAIN_DESCRIPTOR.size, "Truncated AVB chain descriptor")
            _, _, _, name_len, _, _ = CHAIN_DESCRIPTOR.unpack_from(chunk)
            require(CHAIN_DESCRIPTOR.size + name_len <= len(chunk), "AVB chain descriptor overflows")
            name = chunk[CHAIN_DESCRIPTOR.size:CHAIN_DESCRIPTOR.size + name_len].decode()
            yield {"kind": "chain", "partition": name}


def derive(directory, profile, top="vbmeta"):
    directory = Path(directory)
    init_boot = directory / "init_boot.img"
    require(init_boot.is_file(), "init_boot.img is missing from " + str(directory))
    image = init_boot.read_bytes()
    require(len(image) == profile["init_boot_size"]
            and hashlib.sha256(image).hexdigest() == profile["init_boot_sha256"],
            "init_boot.img differs from the profile's size/SHA-256 pin")

    top_path = directory / (top + ".img")
    require(top_path.is_file(), top + ".img is missing from " + str(directory))
    blob, raw, flags = vbmeta_struct(top_path)
    # HASHTREE_DISABLED (1) / VERIFICATION_DISABLED (2) would make "green" meaningless.
    require(flags == 0, top + ".img sets AVB verification-disable flags")
    chain_hasher = hashlib.sha256(blob)
    total_size = len(blob)
    sources = [(top, list(descriptors(raw)))]
    chained = []
    for item in sources[0][1]:
        if item["kind"] != "chain":
            continue
        path = directory / (item["partition"] + ".img")
        require(path.is_file(), "Chained image is missing; extract it too: " + item["partition"])
        child_blob, child_raw, _ = vbmeta_struct(path)
        child = list(descriptors(child_raw))
        # libavb refuses chain descriptors outside the top-level vbmeta.
        require(not any(d["kind"] == "chain" for d in child),
                "Nested chain descriptor in " + item["partition"] + "; libavb would reject it")
        chain_hasher.update(child_blob)
        total_size += len(child_blob)
        sources.append((item["partition"], child))
        chained.append(item["partition"])

    matches = [(where, d) for where, items in sources for d in items
               if d["kind"] == "hash" and d["partition"] == "init_boot"]
    require(len(matches) == 1, "Expected exactly one init_boot hash descriptor, found " + str(len(matches)))
    where, descriptor = matches[0]
    require(descriptor["algorithm"] == "sha256" and len(descriptor["digest"]) == 32,
            "init_boot descriptor is not SHA-256")
    require(descriptor["image_size"] <= len(image), "init_boot descriptor covers more than the image")
    computed = hashlib.sha256(descriptor["salt"] + image[:descriptor["image_size"]]).digest()
    require(computed == descriptor["digest"],
            "init_boot.img does not satisfy its AVB hash descriptor")
    return {
        "vbmeta_digest": chain_hasher.hexdigest(),
        "vbmeta_hash_alg": "sha256",
        "vbmeta_size": total_size,  # libavb exports the same sum as ro.boot.vbmeta.size
        "vbmeta_chain": [top, *chained],
        "init_boot_avb": {
            "descriptor_in": where,
            "image_size": descriptor["image_size"],
            "salt": descriptor["salt"].hex(),
            "digest": descriptor["digest"].hex(),
        },
    }


def update_profile(path, pins):
    """Fill only absent fields; never overwrite a different pin."""
    profile = json.loads(Path(path).read_text())
    for key, value in pins.items():
        current = profile.get(key)
        if current is None:
            profile[key] = value
        elif current != value:
            raise Stop("Reference profile already pins a different " + key + "; not overwriting")
    temporary = path.with_name(path.name + ".partial-" + uuid.uuid4().hex)
    temporary.write_text(json.dumps(profile, indent=2) + "\n")
    os.replace(temporary, path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("partitions", type=Path,
                        help="Directory of extracted stock OTA images (vbmeta.img, init_boot.img, chained images)")
    parser.add_argument("--profile", type=Path, default=ROOT / "profile.coffey.json")
    parser.add_argument("--write-profile", action="store_true",
                        help="Pin vbmeta_digest and init_boot_avb into the profile if still absent")
    args = parser.parse_args(argv)
    try:
        profile = json.loads(args.profile.read_text())
        pins = derive(args.partitions, profile)
        require(re.fullmatch(r"[0-9a-f]{64}", pins["vbmeta_digest"]), "Derived digest is malformed")
        if args.write_profile:
            update_profile(args.profile, pins)
    except (OSError, ValueError, UnicodeDecodeError, struct.error) as error:
        print("AVB pin derivation failed: " + str(error), file=sys.stderr)
        return 2
    except Stop as error:
        print("AVB pin derivation stopped: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(pins, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
