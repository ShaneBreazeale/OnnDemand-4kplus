# Temporary root before unlock — assessment and ordering

**Status: temporary root is credible on this exact unit, but no coffey loader
exists yet.** This document records what was measured on the connected
`coffey` on 2026-11-16, what each public kernel bug would need here, and the
order of operations that keeps a usable backup possible.

Nothing in this document, or in the tools it names, authorizes an unlock, a
flash or a reboot. The installer still refuses `coffey` because
`profile.coffey.json` is `reference_only`.

## Why temp root first

The supported permanent-root path needs an unlocked bootloader, and unlocking
normally performs a factory reset. The stock OTA archive in
`backups/coffey-15051976/` is a *firmware* archive: it is not a dump of this
unit and it contains no apps, accounts or settings
(`device_dump: false`, `user_data_included: false`).

On this build the ordinary shell cannot produce the missing half either:

| Read | Result as `shell` |
| --- | --- |
| `/dev/block/by-name/*` | `brw------- root root`, open denied |
| `/data/app`, `/data/data` | permission denied |
| `adb backup` | disabled (`backup_enabled=0`, `bmgr` off) |
| `/proc/kallsyms` | permission denied |
| `/proc/config.gz` | **readable** |
| `perf_event_open` | **allowed** (`perf_event_paranoid=-1`) |

So a pre-unlock backup of `/data` and of the physical partitions needs uid 0.
That is the only reason to do temporary root first; it is not a shortcut around
the reset.

## What was measured

`python3 tools/root_readiness.py --target <serial>` writes the full report. The
relevant values on this unit:

| Item | Value |
| --- | --- |
| Device / build | `coffey`, `URO4.260304.011.B1 / 15051976`, SDK 34 |
| Active slot | `_b` |
| Kernel | `5.15.196-android14-11-g3d26c188ef7e` (arm64 kernel, 32-bit userspace) |
| Lock state | `flash.locked=1`, `verifiedbootstate=green`, EFI/OPTEE secure boot |
| `CONFIG_FUTEX_PI` | `y` |
| `CONFIG_USER_NS` | **not set** |
| `CONFIG_AF_RXRPC` | not set |
| `CONFIG_STATIC_USERMODEHELPER_PATH` | `""` (all usermode helpers disabled) |
| `CONFIG_CFI_CLANG` / `SHADOW_CALL_STACK` / `PTR_AUTH_KERNEL` | `y` / `y` / `y` |
| `CONFIG_ARM64_BTI_KERNEL` | not set |
| `CONFIG_ARM64_MTE` | `y`, but the CPU has no MTE, so `KASAN_HW_TAGS` is inert |
| `perf_event_paranoid` | `-1`; kernel IPs appear in `simpleperf` samples |
| setuid-root binaries | none under `/system/bin`, `/system/xbin`, `/vendor/bin` |
| `sys.oem_unlock_allowed` | `1` |
| `ro.boot.rpmb_state` / `production_mode` | `1x1` / `1` |

## Paths ruled out before the kernel bugs

**Signed GSI through DSU.** DSU can boot a Google-signed image on a locked
device without wiping `/data`, and a userdebug GSI would give `adb root`. That
would be the cleanest temporary root of all. It is not available here:
`ro.zygote=zygote32` and `ro.product.cpu.abilist64` is empty, so this is a
32-bit-userspace device. Android 14 ships no 32-bit GSI, and the standard arm64
GSI cannot start without 64-bit userspace. The self-built DSU image used for
`jarvis2` needs an unlocked bootloader.

**Reachable vendor drivers.** These open successfully from the ordinary shell
domain: `/dev/mali0` (`mali_kbase`), `/dev/ion`, and `/dev/tee0` (the AVB trusted
app itself). `/dev/aml_dsm` is denied. Each is plausible future exploit surface,
but none has a public `coffey`-matched exploit, and the TEE one is the unlock
path this project already uses rather than a privilege boundary to break.

## The two published bugs, applied to this build

### GhostLock (`CVE-2026-43499`) — in version range, trigger available

The rtmutex/futex-PI stack use-after-free needs only `CONFIG_FUTEX_PI=y`; no
capability and no user namespace. `5.15.196` is below the `5.15.212` fix, so the
trigger exists. That is the good news.

The published final stages do **not** transfer:

- `core_pattern` / `modprobe_path` are dead: `STATIC_USERMODEHELPER_PATH=""`
  disables every usermode helper, so the usual "flip a mode bit, crash a helper"
  finish cannot run.
- The writeup's function-table overwrite assumes no CFI/PAC/shadow stack. All
  three are enabled here, so the finish has to be a **data-only** primitive
  (for example clearing `selinux_state.enforcing` and rewriting the current
  task's `cred`), not a control-flow hijack.
- SELinux stays `Enforcing`, so uid 0 alone is not enough to open a block
  device; the loader must also reach permissive or a privileged domain.
- The writeup's stack reclaim uses `PR_SET_MM_MAP`, which needs
  `CAP_SYS_RESOURCE`; with user namespaces off, a different reclaim syscall is
  required (the authors list `clone`, `setsockopt`, `pselect`, `keyctl`).
- The one part that *is* available is the KASLR leak: `perf_event_open` is
  unrestricted and `simpleperf` samples already contain kernel text addresses.

Known public Android ports: `5.4.210` armv7l (Huawei Watch 4 Pro) and `5.15.149`
arm64 (OPPO Find X6 Pro). Neither matches `5.15.196` arm64 with this config, so
offsets, stack layout and the final stage all have to be re-derived.

### DirtyFrag (`CVE-2026-43284` / `CVE-2026-43500`) — blocked here

`5.15.196` is inside the range, but this build removes every way the published
chain finishes:

- ESP variant needs unprivileged user namespaces: `CONFIG_USER_NS` is not set.
- RxRPC variant needs `rxrpc`: not built.
- The chain overwrites the page cache of a setuid-root binary and execs it.
  This build has **no setuid-root binary**, so there is no execution target.
- There is no usermode-helper finish either.

Verdict: not a usable path on `coffey`.

## Recovery and fastboot do not replace temp root

Before committing to a kernel exploit, the obvious "root shell without unlocking"
routes were checked against the stock images offline. None of them pan out:

- **Stock recovery exists.** The `vendor_boot` v4 table has a 15,180,601-byte
  fragment of type 2 named `recovery`, and its init starts
  `adbd --root_seclabel=u:r:su:s0` with no `user` line, so the daemon would be
  uid 0. But recovery's `prop.default` is `ro.build.type=user`,
  `ro.adb.secure=1`, `ro.debuggable=0`, and the ramdisk contains no `adb_keys`.
  `/data` is not mounted (FBE), so there is nowhere to read an authorized key
  from, and recovery has no authorization UI. The root daemon is unreachable.
- **fastbootd is in the same ramdisk**, but its binary contains
  `fetch not supported on user builds` and `Fetch is not allowed on user build`.
  `fetch` is the only read command; on a `user` build it is refused.
- **The bootloader image is Amlogic `@ML` signed/encrypted.** No read/dump
  command can be identified from the OTA, and it must not be guessed at.
- **A raw `userdata` dump is not a usable backup anyway.** `/data` is
  file-based-encrypted; a factory reset calls `deleteAllKeys` in KeyMint, so the
  keyblobs inside an old raw image are not reliably decryptable afterwards. Only
  a uid-0 shell in the *running* system can copy decrypted app files.

That leaves two options: a GhostLock loader, or accepting the loss of
app-private data and backing up only what the shell can read.

## Toward a coffey loader

This is the part that is still missing, and it is real exploit work rather than
a pin change.

**What already exists publicly.** The upstream PoC is
[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
(`IonStack/CVE-2026-43499`, Apache-2.0). The closest Android port is
[yakidango-official/GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT),
arm64 on a 5.10 kernel, and it already implements the finish this device needs:
UAF → KASLR → arbitrary read/write → `cred` rewrite → SELinux permissive →
`sig_enforce` → KernelSU. The `gitchw` armv7l port and the OPPO arm64 port show
two more reclaim strategies.

**What we can already prepare offline.** The archived stock `boot.img` is an
Android boot image v4; the kernel is LZ4-legacy at offset 4096. Decompressing it
gives a 43,559,424-byte arm64 `Image` with the `ARM\\x64` header at `0x38`, and
its kallsyms data contains `commit_creds`, `init_task`,
`prepare_kernel_cred`, `selinux_state` and `core_pattern`. That means the
per-symbol offsets a target table needs can be recovered from the OTA without a
rooted device. Local copies live in ignored `work/coffey-rootrecon/`.

**What a working loader still has to solve.**

1. Reclaim the freed waiter from 32-bit userspace. `PR_SET_MM_MAP` is out (no
   `CAP_SYS_RESOURCE`, no user namespaces); `PR_SET_NAME` / `pselect` /
   `keyctl`-style controlled kernel-stack copies are the candidates.
2. Drive a 64-bit kernel from an `armeabi-v7a` binary: all kernel pointers and
   `rt_mutex_waiter` fields are 64-bit even though the process is 32-bit.
3. Calibrate this build's stack layout; `do_futex` frame depth is
   compiler/profile dependent and differs from every published port.
4. Finish data-only: clear `selinux_state.enforcing`, then rewrite the current
   `cred` (or call `commit_creds` with a forged cred) without a usermode helper.
5. Keep the whole thing memory-only so a failed run is a reboot, not a write.

The first on-device run should be an explicit, single decision: it can panic the
box, and it cannot be validated by reading the source. The harness in
`tools/temp_root.py` reports a failure without retrying and records what
happened.

## Port progress (2026-11-17)

The first assumption to fall was the one about userspace. `ro.zygote=zygote32`
and an empty `abilist64` describe the Android runtime, not what the kernel will
run: a **statically linked aarch64** binary executes fine as uid 2000. That
removes the 32-bit refactor entirely; the arm64 exploit source builds and runs
against this kernel.

A static `armeabi-v7a` probe (built with `zig cc -target arm-linux-musleabi`)
and an aarch64 rebuild both ran on the unit and showed:

- `perf_event_open` hardware sampling works (`kaslr_kernel_ips=1657/2047`);
- `PERF_SAMPLE_PHYS_ADDR` page-fault sampling returns a real physical address
  (`phys_phys=0x6b38d000`) for an anon page — the value source the write
  primitive needs.

The kernel image is also mapped in the linear map, which is **not** slid. With
`P0_KERNEL_PHYS_LOAD=0x02080000` (`vendor_boot.kernel_addr`) and
`P0_PHYS_OFFSET=0` (`/proc/zoneinfo` `start_pfn: 0`), a port of the GhostLock
chain now builds for aarch64 and its `DRYRUN=1` path runs on the unit:

```
init_task=ffffff800491c200
ctl.data=ffffff800490fdd0           (target of the hijack write)
init_task.comm=ffffff800491ca10     (first validation read)
dm=ffffff8064514000                 (controlled page, bit16 set)
```

That dry-run exercises address computation and the physical-page oracle only.
It does **not** fire the futex UAF and does not write kernel memory.

Exact offsets came from the OTA image, not guesses:

| symbol | offset from `_text` |
| --- | --- |
| `init_task` | `0x0289c200` |
| `init_cred` | `0x0285e4e8` |
| `selinux_state` | `0x029e9078` |
| `commit_creds` | `0x00179804` |
| `sysctl_bootid` | `0x02a04931` |
| `boot_id` ctl entry / data field | `0x0288fdc8` / `0x0288fdd0` |

Struct layouts (BTF): `rt_mutex_waiter` has `wake_state@0x40` and `prio@0x44`
(the 5.10 ports use `prio@0x40`, so the 64-bit prio word is
`0x00000082_00000000` here); `task_struct` has `tasks@0x538`, `mm@0x588`,
`pid@0x640`, `real_cred@0x7f8`, `cred@0x800`, `comm@0x810`,
`pi_blocked_on@0x918`; `mm_struct.owner@0x348`; `cred.uid@0x4`;
`selinux_state.enforcing@0x0`.

Remaining before the first real run:

1. **Carrier calibration.** The `pselect` spray assumes 64-bit `unsigned long`
   fd_sets. The port uses the verbatim `MCAST_JOIN_SOURCE_GROUP` copy
   (33 words) instead; both the option (`SLIDE_MCAST_OPT`, 46 vs 44) and the
   landing shift (`SLIDE_MCAST_SHIFT`, default 23) are runtime-selectable and
   still have to be found for 5.15.196.
2. **First trigger.** A wrong landing panics the kernel. The port now has a
   `CALIBRATE=1` mode that fires the UAF but aims the write at a magic value
   inside our own dm page, so success is visible through `boot_id` and no
   kernel data except `ctl.data` is touched. It has not been run.
3. **Task walk.** H80GT uses `mm->owner` (found with kernelsnitch) because a
   `tasks`-list walk's secondary write corrupts the list head. The port keeps
   that route; kernelsnitch constants (`MM_STRUCT_SZ=1024`, order 3) still need
   calibration.
4. **Cred swap + SELinux.** One 16-byte UUID write at `task+0x7f8` sets
   `real_cred = cred = &init_cred`; the `selinux_state` pointer write needs
   byte0 zero and bit16 set, which the dm-page selector already enforces.

One input is still assumed: `P0_KERNEL_PHYS_LOAD=0x2080000`. Every address above
depends on it, and a wrong value means the first write corrupts an arbitrary
physical page. A second unit, or a read-back of `init_task.comm == "swapper"`
once the trigger lands, is the way to settle it.

## Order of operations

1. **Freeze the box.** No OTA, no factory reset, no `fastboot flash`. A new
   build invalidates the pins and may move the kernel out of range (or into it).
2. **Readiness gate.** `tools/root_readiness.py` must end at
   `temp_root_in_scope_needs_coffey_loader` or better. If it says
   `temp_root_not_available`, stop; the honest options are then "unlock now and
   lose `/data`" or "no root".
3. **Get a coffey loader.** It must implement the contract in
   `tools/temp_root.py`: run as shell, exploit, then `exec /system/bin/sh`. It
   must not write a partition, change a setting or reboot.
4. **Prove root, then back up — in that order.**
   `tools/temp_root.py --prove` accepts only `id -u == 0` plus a successful
   block-device read. `tools/backup_device.py` refuses to run without that
   proof and refuses to run over a session whose boot id changed.
5. **Keep the backup off-box.** The manifest is `device_dump: true`,
   `user_data_included: true`, `crash_consistent: false`. Verify with
   `--verify-only` before touching the bootloader.
6. **Then, and only then, the permanent path.** For this family that is still a
   single `init_boot` write after unlock — not a filesystem overwrite. If "prep
   root" means a custom system image instead, that is the DSU route and the
   reset is unavoidable; see [the no-reset options](NO_RESET.md).

## Using the temporary-root harness

The harness never contains an exploit. It stages one pinned ELF, verifies the
SHA-256, runs it, proves the resulting shell, and always removes the staged file.

```sh
# 1. read-only: is this unit even a candidate?
python3 tools/root_readiness.py --target CUSA...

# 2. prove a loader, change nothing else
python3 tools/temp_root.py --target CUSA... \
  --loader work/loader/coffey-ghostlock \
  --loader-sha256 <64 hex> --exec 'id; getenforce'

# 3. the actual pre-unlock backup
python3 tools/backup_device.py --target CUSA... \
  --loader work/loader/coffey-ghostlock --loader-sha256 <64 hex> \
  --output backups/coffey-15051976-device

# 4. re-check the archive later, without a device
python3 tools/backup_device.py --verify-only backups/coffey-15051976-device
```

A loader that exits without leaving a shell, leaves a non-root shell, leaves a
root shell that still cannot read `/dev/block/by-name/init_boot_b`, or lets the
boot id change is rejected with a durable receipt under `work/temp-root/`.

## Risk

A memory-only kernel exploit does not write to disk, so a crash is normally a
reboot, not a brick. That is not a guarantee: a loader that panics in a
persistent loop, or corrupts a partition it should not touch, can leave a box
that only vendor tools could recover, and no coffey recovery procedure is
published. `rpmb_state=1x1` means rollback protection is provisioned, so a
recovery attempt cannot simply flash an older signed image.

## What is still unproven

- No coffey loader has been run. `working_loader` and `root_proof` are recorded
  as failed gates until one is.
- Whether the OPTEE AVB trusted app's unlock forces a wipe is still unproven
  (see [COFFEY.md](COFFEY.md)); the reset is assumed.
- The `/data` tar is a live snapshot, not a crash-consistent image.

## Update 2026-11-17: temporary root and full backup are done

The coffey loader has now been run end-to-end from the tree:
`work/exploit/coffey/h80gt/src` with the knobs

```
KASLR_BASE_OVERRIDE=0xffffffc008000000 SKIP_HIJACK=1 SLIDE_SHIFT=6 \
P0_PHYS_LOAD=0x01800000 PSELECT_ENTER_DELAY=1000000 \
SYSCTL_WALK_ATTEMPTS=40 KS_MAX_TRIES=6 DM_SETTLE_MS=3000
```

The owner/verify/cred/selinux walks all landed on attempt 1; the anchor reported
`getuid()==0` and `enforce=0`. See `work/exploit/coffey/README.md` for the
verified load/geometry/timing explanation (0x1800000, pselect shift 6, 1 s
enter delay) and the `SKIP_HIJACK`/`KASLR_BASE_OVERRIDE` rationale.

Full pre-unlock backup (verified `SHA256SUMS`, 36 GB):
`gpubox:~/onn-backup/coffey-FULL-20261117T053008Z`

Still unproven: whether the OPTEE unlock forces a wipe. The reset is still
assumed, but it no longer gates the backup.

## Temp root on demand (no unlock)

If the goal is maintenance rather than permanent root, keep the bootloader
locked (Widevine L1 stays valid) and use the packaged scripts:

```sh
tools/coffey-root.sh --yes          # GhostLock run; leaves a uid-0 loop
tools/coffey-sudo.sh 'id; ls /data' # run one command through the loop
tools/coffey-root.sh --check        # is the loop alive?
```

The loop is memory-only and dies on reboot; re-run `coffey-root.sh`. It is a
uid-0 process with kernel SID, not a system-wide `su`: file/block/process
commands work, framework commands (`pm`, `am`, `cmd`, `dumpsys`) need the
normal adb shell. See `docs/RESTORE.md` for the no-unlock note and
`work/exploit/coffey/README.md` for the exploit knobs.
