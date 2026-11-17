# Inputs and source references

Original OnnDemand contributions are licensed under Apache-2.0. See
[LICENSE](LICENSE), [NOTICE](NOTICE), and [LICENSE_SCOPE.md](LICENSE_SCOPE.md).
Third-party components keep their existing terms. The inherited 4K Pro material
described below is excluded from the original OnnDemand license grant.

Firmware is downloaded from the pinned Google OTA URL in `profile.json` and
is not included in Git. Magisk is downloaded from its official GitHub release;
its upstream license is [GPL-3.0](https://github.com/topjohnwu/Magisk/blob/master/LICENSE).
Magisk images and APKs are excluded from this repository.

The native helpers use Linux's TEE userspace ioctl interface and Android's
system property interface. They implement the AVB protocol described in the
[OP-TEE AVB header](https://github.com/OP-TEE/optee_os/blob/master/ta/avb/include/ta_avb.h).
No OP-TEE implementation is bundled. Android NDK and platform-tools are external
build/runtime requirements and are not redistributed here.

`tools/extract_full_ota.py` is our small standard-library full-OTA extractor.
Its protobuf fields follow AOSP's
[update metadata schema](https://android.googlesource.com/platform/system/update_engine/+/refs/heads/android14-release/update_metadata.proto).
The upstream 4K Pro project's original workflow, helper sources, and tests carry
no open-source license grant. That inherited material is not relicensed here;
its original rights and restrictions remain in place. See the legacy scope
inventory in [LICENSE_SCOPE.md](LICENSE_SCOPE.md).

`tools/extract_dsu_ota.py` applies the same verified full-payload extraction to
the larger system/product partitions. The EROFS metadata reader follows the
[erofs-utils v1.7.1 disk structures](https://kernel.googlesource.com/pub/scm/linux/kernel/git/xiang/erofs-utils/+/refs/tags/v1.7.1/include/erofs_fs.h).
The external `mkfs.erofs`, `fsck.erofs` and `secilc` executables are host
dependencies, not redistributed binaries in this repository.

The offline DSU builder downloads the pinned AOSP Android 14
[avbtool.py](https://android.googlesource.com/platform/external/avb/+/android-14.0.0_r1/avbtool.py)
into ignored cache storage. Its upstream source includes its Apache 2.0 license.
No production signing key is included or claimed. The DSU image uses an unsigned
AVB hash-tree footer on the unlocked, measured firmware.

The single-use DSU review follows the shipping first-stage init and AOSP
[DSU architecture](https://source.android.com/docs/core/ota/dynamic-system-updates).
The update-preference command uses Android's
[OTA_DISABLE_AUTOMATIC_UPDATE setting](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/provider/Settings.java).

The optional root SSH helper in `native/rootssh` uses
[gliderlabs/ssh](https://github.com/gliderlabs/ssh),
[creack/pty](https://github.com/creack/pty),
[Go x/crypto](https://go.googlesource.com/crypto),
[Go x/sys](https://go.googlesource.com/sys), and
[go-shlex](https://github.com/anmitsu/go-shlex). Exact versions and module
checksums are recorded in its `go.mod` and `go.sum`. Dependency license notices
are preserved in `native/rootssh/licenses`; include those notices when
redistributing a compiled SSH helper. Generated helpers and device credentials
are normally kept separate; the verified release helpers under
`src/onndemand/assets/ssh` are intentionally bundled in Git and distributions.
Device credentials remain excluded. See `docs/SSH.md` for usage and validation limits.

The coffey root payload source is vendored under `vendor/coffey`, derived from
GhostLock-H80GT revision `33541d1a852a926f782602aa34d79cfbffbd4bb6` with the local
coffey modifications described in its NOTICE.md. Its Apache-2.0 license and
notices accompany the bundled payload. The package manifest pins source and
binary hashes and records Android NDK 28.2.13676358 and Go 1.27.4 as the native
release toolchains. See `docs/RELEASING.md` for rebuild and verification steps.
