# 2025 onn 4K Plus (`coffey`) retarget plan

This checkout started as the [2026 onn 4K Pro (`jarvis2`) installer](https://github.com/openensemble/onn-4k-pro-2026-unlock-root).
The `jarvis2` pins are **not valid** for the 2025 onn 4K Plus. This document
tracks the separate `coffey` work.

**Current stage: read-only reconnaissance only.** No coffey unlock, DSU boot or
firmware write has been tested. Unlocking erases all user data, and a bad
`init_boot` can brick the box with no proven recovery. The read-only readiness
gate and the temporary-root harness are in place; **no coffey loader exists yet**.
See [the temporary-root assessment](ROOT_PATH.md) for the measured kernel,
config and exploitability facts.

**Do not assume the DSU detour is the right path.** Read
[the no-reset decision guide](NO_RESET.md) first. If fastboot is available on
this unit, unlock + a direct Magisk `init_boot` patch is simpler than a DSU
guest. If a factory reset is unacceptable, the remaining options are temporary
kernel root (no `coffey` profile exists) or no root at all.

## Confirmed from the official OTA

Build **`URO4.260304.011.B1 / 15051976`** (Android 14, SDK 34, SPL 2026-03-01),
full OTA:

```
https://android.googleapis.com/packages/ota-api/package/db1ba0cd0b332be68b0488095966feeb6b39305a.zip
```

The pins below live in `profile.coffey.json`, which is marked
`reference_only: true` and cannot authorize an install.

| Item | Value |
| --- | --- |
| Device | `coffey` (Amlogic S905X5M, 32-bit userspace expected) |
| Fingerprint | `onn/coffey/coffey:14/URO4.260304.011.B1/15051976:user/release-keys` |
| OTA size | 906,283,326 bytes |
| `init_boot` | 8,388,608 bytes, sha256 `bc2112c2…dc61` |
| DSU inputs | system 473,403,392 · system_ext 96,186,368 · product 543,825,920 · vendor 83,812,352 · odm 507,904 |

The OTA's SHA-256, `bootloader`, active-slot block mapping, serial prefix and
ABI list are still open. They are read from the device in the next step.

## Unknowns that decide whether this approach is viable

1. **Trusted AVB application.** The unlock relies on the Amlogic OPTEE AVB
   trusted app used by `jarvis2`. If coffey does not expose it to UID 2000, the
   network-only unlock path stops here.
2. **Bootloader policy.** The unlock call may be present but refused by this
   bootloader. The read-only probe does not prove a write will succeed.
3. **Recovery.** There is no published coffey factory-image recovery procedure.
   The DSU stock rehearsal is a fallback for the guest system, not proof that a
   damaged `init_boot` can be recovered.

Do not let the box take an OTA before these checks. A different build needs its
own OTA metadata and pins.

## Step 1 — enable network ADB

On the TV:

1. **Settings** (gear) → **System** → **About**.
2. Select **Android TV OS build** seven times to enable developer options.
3. Back → **System** → **Developer options**.
4. Turn on **USB debugging**. On this firmware it opens ADB on port **5555**
   directly; wireless pairing is normally not needed.
5. Find the IP under **Settings → Network & Internet →** your network.

From the Linux x86-64 host:

```sh
sudo apt-get install adb
adb connect ONN_IP:5555
adb devices -l
```

Accept the debugging prompt on the TV. `adb devices` must show `device`, not
`unauthorized`.

## Step 2 — read-only slot and firmware report

From this checkout on the Linux host:

```sh
python3 tools/slot_report.py \
  --profile profile.coffey.json \
  --target ONN_IP \
  --output-dir work/coffey-recon
```

This selects only `ONN_IP`, checks the same unit/build/slot/boot throughout,
and writes `slot-report.txt` plus a private raw-command file. It does not
request root, write settings or firmware, reboot, or switch slots.

Expected facts to review:

- `ro.product.device` is `coffey`.
- The fingerprint matches `profile.coffey.json`.
- `init_boot_a` / `init_boot_b` map to physical block nodes and are 8 MiB.
- At least the active slot's `init_boot` hash matches the OTA pin.
- `ro.product.cpu.abilist` contains `armeabi-v7a`.

## Step 3 — read-only trusted-state probe

Only after Step 2 passes:

```sh
python3 tools/trusted_state_probe.py \
  --profile profile.coffey.json \
  --target ONN_IP
```

This stages only the pinned `read_state` helper in `/data/local/tmp`, runs its
single fixed read command, removes it, and reports `secure_lock_state`:

- `1` = locked (expected on a stock box)
- `0` = already unlocked

It never sends an unlock command, flashes, changes settings, or reboots. A
successful read is the go/no-go signal for designing a coffey unlock step. If
the probe fails, stop; the network-only path may not apply to this unit.

## Step 4 — archive the stock firmware before any write

A firmware archive is the only real brick protection available before root.
It is **not** a dump of your unit and it does **not** include apps, accounts or
settings. Run this on the Linux host (about 2.3 GB total):

```sh
python3 tools/archive_stock.py \
  --profile profile.coffey.json \
  --output backups/coffey-15051976 \
  --write-profile
```

It does five things:

1. Downloads the pinned full OTA to `cache/`.
2. Hashes it and refuses a size or hash mismatch.
3. Extracts the boot chain (`boot`, `init_boot`, `vendor_boot`, `dtbo`,
   `vbmeta`, `vbmeta_system`, `bootloader`) and the system partitions.
4. Verifies every extracted partition against the OTA payload and, where the
   profile pins one, against that pin.
5. Writes `manifest.json` with the OTA SHA-256, every partition hash, and the
   stock `init_boot` SHA-1 used for Magisk's backup directory.

`--write-profile` only fills an empty `ota_sha256` / `root_stock_sha1`; it
refuses to replace a different pin. Re-check later without downloading:

```sh
python3 tools/archive_stock.py --profile profile.coffey.json \
  --output backups/coffey-15051976 --verify-only
```

The manifest records `device_dump: false` and `user_data_included: false`.
Do not describe it as a full backup.

### What still needs the temporary root guest

Immediately before the single `init_boot` write, the installer must dump the
physical partitions from the DSU root guest and verify each hash off-device.
The `jarvis2` workflow already does this for the active `init_boot`; the coffey
retarget will extend it to `boot`, `vendor_boot`, `dtbo`, `vbmeta` and
`vbmeta_system`. That dump is the actual per-unit backup. It cannot be made
from a stock, locked box because ordinary ADB cannot read block devices.

### Your apps and settings

Unlocking performs a factory reset. Nothing in this repository can image
`/data` without root. Before unlocking, use Google account sync, each app's
own export, and a written note of accounts, Wi-Fi networks and installed apps.
Do not rely on `adb backup`; it is deprecated and often disabled on TV builds.

### Temporary root on stock, before unlock

There is a third option that keeps `/data` readable: obtain a temporary uid-0
shell on the stock, locked system, then dump the unit before touching the
bootloader. It is credible on this build (`5.15.196`, `CONFIG_FUTEX_PI=y`,
unprivileged `perf_event_open`), but it is **not ready**: no coffey loader has
been written or run, and the published Android finishes assume a usermode
helper, no CFI/PAC and a setuid-root target, none of which hold here.

The read-only gate and the backup are ready and tested:

```sh
python3 tools/root_readiness.py --target ONN_IP   # read-only verdict
python3 tools/temp_root.py --target ONN_IP \
  --loader work/loader/coffey-loader --loader-sha256 <64 hex>
python3 tools/backup_device.py --target ONN_IP \
  --loader work/loader/coffey-loader --loader-sha256 <64 hex>
```

`temp_root.py` accepts a loader only after `id -u == 0` *and* a successful
block-device read, and `backup_device.py` refuses to run without that proof.
Read [ROOT_PATH.md](ROOT_PATH.md) for the hardening list, the ordering and the
remaining gaps.

## Step 5 — only after review

If and only if Steps 2 and 3 pass, the remaining work is:

1. Add the coffey bootloader, slot mapping and serial prefix to the reference
   profile.
2. Build a coffey-specific `unlock_once` guard and repeat the same one-write
   and durable-attempt design used for `jarvis2`.
3. Re-pin the OTA SHA-256 and extract `init_boot` plus the DSU inputs.
4. Retarget `tools/build_dsu.py` and the identity checks.
5. Run the stock-DSU return rehearsal before any permanent write.

Each step needs its own review. Nothing here authorizes skipping a guard.
