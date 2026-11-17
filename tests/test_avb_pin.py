import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import avb_pin as ap  # noqa: E402
from tools import slot_report as sr  # noqa: E402


def pad8(data):
    return data + b"\0" * (-len(data) % 8)


def hash_descriptor(name, image, salt=b"\x5a" * 32):
    body = name.encode() + salt + hashlib.sha256(salt + image).digest()
    size = pad8(ap.HASH_DESCRIPTOR.pack(0, 0, 0, b"", 0, 0, 0, 0) + body)
    head = ap.HASH_DESCRIPTOR.pack(ap.TAG_HASH, len(size) - 16, len(image), b"sha256",
                                   len(name), len(salt), 32, 0)
    return pad8(head + body)


def chain_descriptor(name, key=b"K" * 8):
    body = name.encode() + key
    total = pad8(ap.CHAIN_DESCRIPTOR.pack(0, 0, 0, 0, 0, 0) + body)
    head = ap.CHAIN_DESCRIPTOR.pack(ap.TAG_CHAIN, len(total) - 16, 1, len(name), len(key), 0)
    return pad8(head + body)


def vbmeta(descriptors, auth=b"\0" * 64, algorithm=1, flags=0, key=b"P" * 40):
    # A public key sits ahead of the descriptors so descriptors_offset is non-zero
    # and differs from every neighbouring header field.
    desc = b"".join(descriptors)
    aux = pad8(key) + desc
    aux += b"\0" * (-len(aux) % 64)
    header = ap.HEADER.pack(b"AVB0", 1, 2, len(auth), len(aux), algorithm,
                            0, 32, 32, 32, 0, len(key), 0, 0, len(pad8(key)), len(desc),
                            0, flags, 0, b"test")
    return header + auth + aux


def with_footer(payload, vbmeta_blob, partition_size=8192):
    offset = len(payload) + (-len(payload) % 4096)
    image = payload + b"\0" * (offset - len(payload)) + vbmeta_blob
    image += b"\0" * (partition_size - len(image) - ap.FOOTER.size)
    return image + ap.FOOTER.pack(b"AVBf", 1, 0, len(payload), offset, len(vbmeta_blob))


class AvbPinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.init_boot = b"\x11" * 4096
        self.profile = {"init_boot_size": len(self.init_boot),
                        "init_boot_sha256": hashlib.sha256(self.init_boot).hexdigest()}
        (self.dir / "init_boot.img").write_bytes(self.init_boot)

    def tearDown(self):
        self.tmp.cleanup()

    def test_descriptor_in_top_vbmeta_and_chain_digest_order(self):
        # Descriptor order, not file-name order, decides the digest.
        top = vbmeta([hash_descriptor("init_boot", self.init_boot),
                      chain_descriptor("vbmeta_system"), chain_descriptor("boot")])
        system, boot = vbmeta([], key=b"S" * 16), vbmeta([], key=b"B" * 24)
        (self.dir / "vbmeta.img").write_bytes(top + b"\0" * 1024)
        (self.dir / "vbmeta_system.img").write_bytes(system)
        (self.dir / "boot.img").write_bytes(with_footer(b"\x22" * 1000, boot))
        pins = ap.derive(self.dir, self.profile)
        self.assertEqual(pins["vbmeta_digest"], hashlib.sha256(top + system + boot).hexdigest())
        self.assertNotEqual(pins["vbmeta_digest"], hashlib.sha256(top + boot + system).hexdigest())
        self.assertEqual(pins["vbmeta_size"], len(top) + len(system) + len(boot))
        self.assertEqual(pins["vbmeta_chain"], ["vbmeta", "vbmeta_system", "boot"])
        self.assertEqual(pins["init_boot_avb"]["descriptor_in"], "vbmeta")

    def test_weakened_or_ambiguous_chains_are_rejected(self):
        good = hash_descriptor("init_boot", self.init_boot)
        cases = {
            "verification-disable": vbmeta([good], flags=2),
            "unsigned": vbmeta([good], algorithm=0),
            "exactly one": vbmeta([good, good]),
        }
        for reason, image in cases.items():
            with self.subTest(reason):
                (self.dir / "vbmeta.img").write_bytes(image)
                with self.assertRaisesRegex(ap.Stop, reason):
                    ap.derive(self.dir, self.profile)
        (self.dir / "vbmeta.img").write_bytes(vbmeta([good, chain_descriptor("vbmeta_system")]))
        (self.dir / "vbmeta_system.img").write_bytes(vbmeta([chain_descriptor("boot")]))
        with self.assertRaisesRegex(ap.Stop, "Nested chain"):
            ap.derive(self.dir, self.profile)
        broken = bytearray(good)
        broken[56:60] = (10_000).to_bytes(4, "big")   # partition_name_len
        (self.dir / "vbmeta.img").write_bytes(vbmeta([bytes(broken)]))
        with self.assertRaisesRegex(ap.Stop, "overflows"):
            ap.derive(self.dir, self.profile)

    def test_descriptor_in_chained_footer_image(self):
        boot_vbmeta = vbmeta([hash_descriptor("init_boot", self.init_boot)])
        top = vbmeta([chain_descriptor("boot")])
        (self.dir / "vbmeta.img").write_bytes(top)
        (self.dir / "boot.img").write_bytes(with_footer(b"\x22" * 1000, boot_vbmeta))
        pins = ap.derive(self.dir, self.profile)
        self.assertEqual(pins["vbmeta_digest"], hashlib.sha256(top + boot_vbmeta).hexdigest())
        self.assertEqual(pins["init_boot_avb"]["descriptor_in"], "boot")

    def test_tampered_init_boot_or_missing_chain_stops(self):
        (self.dir / "vbmeta.img").write_bytes(vbmeta([hash_descriptor("init_boot", b"\x99" * 4096)]))
        with self.assertRaisesRegex(ap.Stop, "does not satisfy"):
            ap.derive(self.dir, self.profile)
        (self.dir / "vbmeta.img").write_bytes(vbmeta([chain_descriptor("vbmeta_system")]))
        with self.assertRaisesRegex(ap.Stop, "Chained image is missing"):
            ap.derive(self.dir, self.profile)

    def test_profile_pin_mismatch_stops_before_parsing(self):
        (self.dir / "init_boot.img").write_bytes(b"\x00" * 4096)
        with self.assertRaisesRegex(ap.Stop, "differs from the profile"):
            ap.derive(self.dir, self.profile)

    def test_write_profile_never_overwrites_a_different_pin(self):
        path = self.dir / "profile.json"
        path.write_text(json.dumps({"vbmeta_digest": "a" * 64}))
        with self.assertRaisesRegex(ap.Stop, "different vbmeta_digest"):
            ap.update_profile(path, {"vbmeta_digest": "b" * 64})
        ap.update_profile(path, {"vbmeta_digest": "a" * 64, "init_boot_avb": {"x": 1}})
        self.assertEqual(json.loads(path.read_text())["init_boot_avb"], {"x": 1})


class AvbBindingTests(unittest.TestCase):
    PROFILE = {"fingerprint": "onn/coffey/coffey:14/X/1:user/release-keys",
               "vbmeta_digest": "c" * 64, "vbmeta_size": 17152,
               "init_boot_avb": {"image_size": 1851392, "digest": "d" * 64}}
    LOCKED = {"ro.boot.flash.locked": "1", "ro.boot.vbmeta.device_state": "locked",
              "ro.boot.verifiedbootstate": "green", "ro.boot.vbmeta.hash_alg": "sha256",
              "ro.boot.vbmeta.digest": "c" * 64, "ro.boot.vbmeta.size": "17152",
              "ro.build.fingerprint": "onn/coffey/coffey:14/X/1:user/release-keys"}

    def binding(self, profile=None, **changes):
        values = dict(self.LOCKED)
        values.update({key.replace("_", "."): value for key, value in changes.items()})
        return sr.avb_binding(values, self.PROFILE if profile is None else profile)

    def test_match_is_indirect_partial_and_states_its_assumption(self):
        result = self.binding()
        self.assertEqual(result["status"], "match")
        self.assertTrue(result["vbmeta_chain_matches_reference"])
        self.assertFalse(result["direct_hash"])
        self.assertFalse(result["full_partition_hash_proven"])
        self.assertEqual(result["covered_bytes"], 1851392)
        self.assertIn("bootloader_requests_init_boot", result["assumes"])
        self.assertIn("active_slot", result["scope"])
        self.assertNotIn("matches_reference_stock_image", result)

    def test_digest_or_size_difference_is_a_mismatch(self):
        self.assertEqual(self.binding(ro_boot_vbmeta_digest="e" * 64)["status"], "mismatch")
        result = self.binding(ro_boot_vbmeta_size="16384")
        self.assertEqual(result["status"], "mismatch")
        self.assertFalse(result["vbmeta_size_matches_reference"])

    def test_unenforced_unpinned_or_other_builds_never_claim_a_result(self):
        cases = {
            "not_enforced_by_locked_green_boot": self.binding(ro_boot_verifiedbootstate="orange"),
            "no_reference_pin": self.binding(profile={}),
            "unavailable": self.binding(ro_boot_vbmeta_digest=""),
            "different_build": self.binding(ro_build_fingerprint="onn/coffey/coffey:14/Y/2:user/release-keys"),
        }
        for status, result in cases.items():
            with self.subTest(status):
                self.assertEqual(result["status"], status)
                self.assertNotIn("vbmeta_chain_matches_reference", result)


if __name__ == "__main__":
    unittest.main()
