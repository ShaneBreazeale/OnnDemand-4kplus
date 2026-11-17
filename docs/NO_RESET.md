# Rooting without a factory reset — what is actually possible

The short answer: **on a locked bootloader, persistent root normally requires an
unlock, and a normal unlock wipes userdata.** That is a platform security
property, not a bug in this repository. There are a few exceptions, but none is
a supported, device-matched path for `coffey` today.

This document exists so we do not pretend the DSU pipeline is the only option,
and so we do not promise a no-wipe result we cannot deliver.

## Why this repository is not a rootkit

A rootkit hides, persists without consent, and usually exploits a vulnerability.
This workflow does the opposite:

- It asks for explicit consent before the unlock and before the write.
- It writes exactly one partition (`init_boot`), once, and verifies the readback.
- It keeps durable receipts and refuses to repeat an uncertain action.
- It removes its temporary DSU guest and does not install a boot script.

It is, however, a **heavy** pipeline: a temporary 4 GB Android guest exists only
to run a root helper that performs a one-partition patch. We can probably remove
that detour. The factory reset is a separate question.

## The options, ranked by what they preserve

| Option | Persistent root? | Wipes data? | Needs | Status for `coffey` |
| --- | --- | --- | --- | --- |
| **Fastboot unlock + Magisk-patched `init_boot`** | Yes | Yes, normally | USB-C OTG, fastboot, OEM unlocking | **Unknown until tested**; simplest path if available |
| **AVB trusted-app unlock + `init_boot` patch** | Yes | The repository requires a recovery reset; whether the TA itself forces it is unproven | Network ADB only | The current design; reset assumed |
| **Custom DSU guest only** | No (guest-only root) | No | Already unlocked for an unsigned image | Not a permanent-root path |
| **Temporary kernel root (DirtyFrag / GhostLock / port)** | No, one boot | No | Exact vulnerable kernel + device profile | No `coffey` profile exists |
| **ADB debloat / custom launcher** | No root | No | ADB only | Works today |

## The DSU detour

Android's DSU can boot a **Google- or OEM-signed** GSI on a locked device. A
self-built, unsigned system image normally requires an unlocked bootloader. Our
root DSU is self-built, so it cannot be the no-unlock path.

If the bootloader is already unlocked, DSU is a nice fallback. Before unlock, it
is not a way around the reset.

## The only real no-wipe root route

Temporary root uses a kernel privilege-escalation bug and late-loads a
KernelSU-compatible module. It leaves the boot image and partitions untouched
and ends at the next full reboot.

Two public families matter here:

| Bug | Kernel branch | Fixed at or after |
| --- | --- | --- |
| DirtyFrag (CVE-2026-43284) | 5.15 | 5.15.205 |
| GhostLock (CVE-2026-43499) | 5.15 | 5.15.212 |

Coffey is an Android 14 Amlogic S905X5M device. Its kernel is probably 5.15.x,
but the exact release decides whether either bug is even present. The read-only
slot report now records `uname -r` and `uname -v` for this reason.

Even on a vulnerable kernel, a public loader still needs a **device profile**
(offsets, page layout, KMI module). The community index currently lists no
Amlogic TV box and no `coffey` target. Porting one is original exploit work with
a real chance of a kernel panic, and it is not persistent.

## A no-reset path that is often enough

If the goal is a custom launcher, fewer ads, or removing preinstalled apps, root
may be unnecessary. ADB `pm disable-user` and a sideloaded launcher do not touch
the bootloader, do not wipe data, and are reversible. That is a different goal
from permanent root, but it is worth naming before accepting a wipe.

## What to check before choosing

1. `uname -r` and `uname -v` from the read-only slot report.
2. Whether `fastboot` responds on this unit:
   ```sh
   adb reboot bootloader
   fastboot getvar unlocked
   fastboot getvar current-slot
   ```
   `fastboot reboot` returns to Android. These reads do not flash anything.
3. Whether Developer options shows **OEM unlocking** and whether it is on.
4. Whether you have a second unit or a full data backup, because the first
   unlock test is the one that can cost data.

If fastboot works and you accept a reset, the better engineering choice is the
short path: unlock once, patch `init_boot` with Magisk, flash it, verify. It has
far fewer moving parts than the DSU guest. If a reset is unacceptable, the only
honest next step is the temporary-root research path above — not a modified
installer that pretends the wipe does not exist.
