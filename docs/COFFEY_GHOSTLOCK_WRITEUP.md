# coffey (onn 4K Plus) — GhostLock root: technical write-up

**Date:** 2026-11-17
**Target:** onn 4K Plus ("coffey"), Android 14 / Google TV
`URO4.260304.011.B1`, kernel `5.15.196-android14-11-g3d26c188ef7e-ab14657224`, aarch64
**Goal:** temporary uid-0 root before bootloader unlock, to take a full `/data` +
both-slot backup.

---

## 1. TL;DR

- **No new CVE.** The bug is **GhostLock, CVE-2026-43499**, a use-after-free in
  the kernel rtmutex `remove_waiter()` path. It affects `CONFIG_FUTEX_PI=y`
  kernels below the 5.15.212 fix; coffey is 5.15.196.
- **No new memory-corruption primitive.** The arbitrary write is GhostLock's
  rbtree-erase write; the arbitrary read is the reference's `sysctl boot_id`
  `ctl.data` hijack. Both are data-only and therefore survive CFI/PAC/SCS.
- **What is actually new here** is the coffey port and the device-specific
  unknowns that had to be solved:
  1. aarch64/bionic build of the armv7l/arm64 reference for a 5.15.196 Android
     14 kernel (nearest public ports were 5.4.210 armv7l and 5.15.149 arm64).
  2. **Physical load discovery**: `P0_KERNEL_PHYS_LOAD = 0x01800000`, recovered
     from the vendor `page_trace` module's PFN annotations in an oops — not from
     the (staging) `vendor_boot` header, which says `0x02080000`.
  3. **Carrier timing fix**: the reference's 50 ms enter delay fired
     `sched_setattr` before `pselect` had copied the fd_sets, leaving the stale
     `waiter->lock` as 0 and panicking. 1 s makes the plant deterministic.
  4. **KASLR-off adaptation**: the perf IP leak is unreliable on coffey (it can
     sample a module and invent a bogus slide), KASLR is actually disabled, and
     the reference's `loggers[0][1]` slide read is zero on this build. A
     `SKIP_HIJACK` path pins the base instead.
  5. A persistent uid-0 loader loop used to stream the full backup out over a
     FIFO (no `/data` temp space).
- **Result:** `getuid()==0`, SELinux `enforce=0`, `sig_enforce=0`, full 36 GB
  backup on gpubox, `SHA256SUMS` verified.

---

## 2. Target and constraints

| Property | Value |
|---|---|
| Device | onn 4K Plus, `s7d_s905x5m_bm202` (Amlogic S905X5M) |
| Android | 14, `URO4.260304.011.B1`, build `15051976` |
| Kernel | `5.15.196-android14-11-g3d26c188ef7e-ab14657224` |
| ABI | arm64 (userspace shell is 32-bit toybox; the exploit binary is aarch64) |
| Bootloader | locked, verified boot green, `ro.debuggable=0` |
| Slot | `_b` |
| Crypto | FBE, `ro.crypto.state=encrypted`, `ro.crypto.type=file` |

Hardening relevant to the chain (from `/proc/config.gz`):

```
CONFIG_FUTEX=y  CONFIG_FUTEX_PI=y
CONFIG_CFI_CLANG=y  CONFIG_CFI_CLANG_SHADOW=y
CONFIG_ARM64_PTR_AUTH=y  CONFIG_ARM64_PTR_AUTH_KERNEL=y
CONFIG_SHADOW_CALL_STACK=y  CONFIG_STACKPROTECTOR=y
CONFIG_KASAN=y  CONFIG_KASAN_HW_TAGS=y        # MTE absent -> inert
CONFIG_USER_NS is not set
CONFIG_AF_RXRPC is not set
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH=""
CONFIG_RANDOMIZE_BASE=y                        # but no seed -> slide 0
CONFIG_SLAB_FREELIST_HARDENED=y  CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_HARDENED_USERCOPY=y  CONFIG_BUG_ON_DATA_CORRUPTION=y  CONFIG_DEBUG_LIST=y
CONFIG_RODATA_FULL_DEFAULT_ENABLED=y  CONFIG_STRICT_KERNEL_RWX=y
CONFIG_IO_URING=y  CONFIG_BPF_SYSCALL=y  CONFIG_USERFAULTFD=y
CONFIG_SECCOMP=y  CONFIG_SECCOMP_FILTER=y
```

Runtime: `perf_event_paranoid=-1`; the exploit process has
`Seccomp=0`/`NoNewPrivs=0` under the `shell` domain, so raw syscalls are
available.

Consequences:

- `modprobe_path`/`core_pattern` finishes are dead (`STATIC_USERMODEHELPER_PATH=""`).
- No userns, no `AF_RXRPC`, no setuid-root binary → the DirtyFrag variants
  (`CVE-2026-43284`/`CVE-2026-43500`) are not usable here.
- CFI + PAC + SCS rule out control-flow hijack finishes; the chain must be
  **data-only**.
- KASLR is "on" in config but has no seed, so the runtime text base equals the
  link-time base (`0xffffffc008000000`). Symbols are therefore directly usable.

---

## 3. The vulnerability: GhostLock (CVE-2026-43499)

**Class:** use-after-free / stale pointer in the rtmutex waiter removal path.
**Trigger:** `FUTEX_WAIT_REQUEUE_PI` + `FUTEX_CMP_REQUEUE_PI` closing a PI cycle
(the waiter is the owner of a lock the requeue needs), producing `EDEADLK`.
**Fix range:** 5.15.212+ (coffey: 5.15.196).

Mechanism, as used by the exploit:

1. A waiter thread calls `futex(FUTEX_WAIT_REQUEUE_PI)`; the kernel puts an
   `struct rt_mutex_waiter` **on that thread's kernel stack** and records it in
   `task->pi_blocked_on`.
2. Another thread closes the PI cycle. The deadlock path returns `EDEADLK`
   (`errno 35`) and unwinds the waiter, but the stale `pi_blocked_on` is left
   pointing at the now-dead stack slot.
3. The waiter thread returns from the syscall and later parks in an unrelated
   syscall. That syscall's stack frame reuses the same kernel-stack words, so
   **userspace-controlled data copied into that frame becomes the fake
   `rt_mutex_waiter`**.
4. A `sched_setattr()` on the waiter task runs `rt_mutex_adjust_pi()` →
   `rt_mutex_adjust_prio_chain()`, which follows `pi_blocked_on` and treats the
   planted words as a waiter attached to a fake `rt_mutex` in our own page.
5. The chain's rbtree erase of the fake waiter node performs the write.

The crash signature when the plant is missing (stale slot zeroed) is
diagnostic:

```
pc : rt_mutex_adjust_prio_chain+0x17c     (0xffffffc0095039a4)
    f9401f9b  ldr x27, [x28, #0x38]      ; x27 = waiter->lock
    b8bfc368  ldar w8, [x27]             ; fault, FAR = 0
x28 = stale rt_mutex_waiter on a kernel stack, [x28+0x38] = NULL
```

With `panic_on_oops=1` (Android user build) a miss reboots the box, so the
plant must be exact.

### 3.1 The write primitive

The rbtree erase of the fake node (`rb_erase` Case-2: one non-NULL child)
performs exactly two stores and returns:

```
PRIMARY   *(target)   = value
SECONDARY *(value+8)  = target
```

where `target` comes from waiter word 5 (`pi_left`) and `value` from word 3
(`pi_pc`). This gives an 8-byte arbitrary write plus a self-referential second
store. If `value` is a real writable kernel address, the secondary lands there
(usually in our own page, made harmless by construction).

### 3.2 The carrier / stack geometry

The stale waiter must be overwritten with ten 8-byte words:

| word | offset | field | planted value |
|---|---|---|---|
| 0 | 0x00 | tree parent/color | harmless (root-path erase) |
| 1 | 0x08 | tree right | 0 |
| 2 | 0x10 | tree left | 0 |
| 3 | 0x18 | pi_tree parent/color | **write value** |
| 4 | 0x20 | pi_tree right | 0 |
| 5 | 0x28 | pi_tree left | **write target** |
| 6 | 0x30 | task | `init_task` |
| 7 | 0x38 | lock | fake lock in our page |
| 8 | 0x40 | wake_state/prio | `0x82` |
| 9 | 0x48 | deadline | 0 |

On coffey the reachable carrier is **`pselect`**. `core_sys_select` puts
`bits = sp + 0x50`, and the three fd_sets are laid out as
`in = bits`, `out = bits + size`, `ex = bits + 2*size`, with
`size = FDS_BYTES(320) = 0x28`. The stale requeue waiter lives at
`do_futex x29 - 0xd0 = T - D - 0x1d0` (where `D` is the `el0_svc` entry depth),
and `ex` starts at `waiter + 0x20`. Therefore **global fd_set word 6 lands on
waiter word 0** → `SLIDE_SHIFT=6`.

The `el0_svc` depth `D` (~0x1f0) cancels because both the futex and pselect
syscalls enter through the same path; the relative shift is still 6. This was
the key reconciliation after the first oops looked "0x1f0 off".

The fd_set bits are also real fd masks, so `open_slide_selected_fds()` opens
every referenced fd number (duplicating a timerfd) so `pselect` blocks instead
of returning `EBADF`, and the stamp stays resident.

---

## 4. Recon: addresses and the physical load

### 4.1 Kernel image and symbols

- Extracted the arm64 `Image` from `boot.img` (LZ4 at offset 4096,
  43,559,424 bytes), symbolized it with `vmlinux-to-elf`, and used the embedded
  BTF (`Image+0x1cdb684`) for struct layouts.
- Link-time base `KIMAGE_TEXT_BASE = 0xffffffc008000000`; KASLR slide 0.
- `PAGE_OFFSET = 0xffffff8000000000`, `VA_BITS 39`, `vmemmap = 0xfffffffe00000000`.
- Linear alias of a kernel symbol: `PAGE_OFFSET + P0_PHYS_LOAD + (link - KIMAGE_TEXT_BASE)`.

Key offsets from `_text`:

```
init_task        0x0289c200     init_cred         0x0285e4e8
selinux_state    0x029e9078     boot_id ctl.data  0x0288fdd0
boot_id buffer   0x02a04938     loggers (nf)      0x027619b8
rt_sched_class   0x01b6a510
```

BTF layouts used:

```
task_struct: real_cred 0x7f8, cred 0x800, comm 0x810,
             pi_lock 0x8ec, pi_waiters 0x900, pi_top_task 0x910,
             pi_blocked_on 0x918
cred:         uid 0x4, caps 0x28..0x48, security 0x78, user 0x80, user_ns 0x88
rt_mutex_waiter: tree 0x0, pi_tree 0x18, task 0x30, lock 0x38,
             wake_state 0x40, prio 0x44
mm_struct:    owner 0x348
```

### 4.2 Physical load: 0x01800000, not 0x02080000

The exploit addresses kernel `.data`/`.bss` through the **linear map**, so it
must know where the Image was physically loaded. `vendor_boot`'s
`kernel_addr = 0x02080000` is the *staging* address; the Image is relocated.

The vendor `page_trace` module annotates every register in an oops with its PFN.
Four independent image addresses agree on the real load:

```
PC  0xffffffc0095039a4  pfn 2d03 -> 0x2d039a4 - 0x15039a4 = 0x1800000
R4  0xffffffc00a76d000  pfn 3f6d -> 0x3f6d000 - 0x276d000 = 0x1800000
R6  0xffffffc0098411bd  pfn 3041 -> 0x30411bd - 0x18411bd = 0x1800000
R15 0xffffffc00a788000  pfn 3f88 -> 0x3f88000 - 0x2788000 = 0x1800000
```

2 MiB aligned, four-way agreement. This turned the previous "load wrong" hangs
and panics into a solved variable. (An earlier `0x01080000`/`0x02000000` guess
panicked; `0x02080000` hung.)

---

## 5. The coffey exploit chain

Stages, each one GhostLock walk (one 8-byte write, sometimes two stores):

```
[0] CALIBRATE_PAGE      target = value inside our own dm page
                        proves load + carrier + trigger, no kernel target
[1] BSS scratch         write a dm pointer into boot_id buffer (0x2a04938)
                        proves a kernel .data write end-to-end
[2] SKIP_HIJACK         KASLR off: pin base 0xffffffc008000000
                        (reference's loggers[0][1] read is zero here)
[3] OWNER read          ctl.data := anchor_mm->owner (mm+0x348)
                        read 16 bytes via /proc/sys/kernel/random/boot_id
[4] VERIFY read         ctl.data := task+0x810 (comm), expect "ksanch0r"
[5] CRED write          *(task+0x800) = init_cred
                        anchor getuid() flips to 0
[6] SELINUX write       *(selinux_state) = dm-page value, byte0=0
                        enforce=0 (permissive)
[7] SIG_ENFORCE write   *(sig_enforce) = dm-page value, byte0=0
                        unsigned modules allowed
[8] ROOT LOADER         anchor forks uid-0 loader (KSU hook), leaving a
                        persistent command loop for the backup
```

### 5.1 Arbitrary read via `boot_id`

The reference's sysctl stage: `/proc/sys/kernel/random/boot_id` is a 16-byte
read whose source pointer is the `ctl_table.data` field at `0x28fdd0`. Writing
that field to any kernel address (through the GhostLock write) turns a boot_id
read into a 16-byte arbitrary read. `sysctl_read_step()` re-points and reads,
with a freshness check so a not-yet-landed write cannot feed stale bytes to the
next predicate.

This is enough to walk `mm->owner` from a KernelSnitch-leaked `mm_struct`, then
verify the task via `comm`, then write `cred`.

### 5.2 Cred swap

`*(task+0x800) = &init_cred`, leaving `real_cred` untouched. The anchor's
`getuid()` (cred->uid@+4) becomes 0 while `capget()` still reads `real_cred`, so
no `commit_creds`/`capset` BUG_ON is reachable. The secondary store lands at
`init_cred+8` (gid/suid), which is cosmetic (observed garbled gid) and does not
affect capabilities.

### 5.3 SELinux / sig_enforce

Both are 8-byte writes of a dm-page address whose low byte is 0:

- `selinux_state.enforcing` byte 0 → `0` (permissive). Byte 2 is forced odd by
  page selection so the `initialized` flag is not cleared.
- `sig_enforce` byte 0 → `0`, allowing unsigned module loads.

`lenforce=0` was confirmed by the next child's startup context
(`attr=u:r:shell:s0 enforce=0`) and by the anchor's successful `setenforce`.

---

## 6. Reliability work (the actual debugging)

### 6.1 The 50 ms race

The reference defaults to `PSELECT_ENTER_DELAY_USEC=50000`. On coffey the
consumer often fired `sched_setattr` before the waiter thread had entered
`pselect`/copied the `ex` set, so the stale waiter was still zero and the chain
oopsed at `rt_mutex_adjust_prio_chain+0x17c` with `waiter->lock == NULL`.

`STAMP_ONLY` proved the user fd_sets were correct (all ten words/global indices
matched), and both `core_sys_select` and `__arm64_sys_pselect6` disassembly
proved `exp` is the fourth argument and the `ex` copy lands at `bits+2*size`.
The remaining variable was purely *when* the fire landed.

`PSELECT_ENTER_DELAY=1000000` (1 s) makes the carrier deterministic: the waiter
is parked in `do_select` with the stamp resident. Calibration then landed on
attempt 1, and every subsequent walk landed on attempt 1.

### 6.2 The perf KASLR leak is a trap

`p0_aliases_init()` can leak the text base from perf IP samples. On coffey one
run reported `text_base=0xffffffc003200000` (a module-derived bogus slide),
which would have made `text_addr(INIT_CRED)` point at garbage. Since KASLR is
disabled, the chain now pins `KASLR_BASE_OVERRIDE=0xffffffc008000000` and does
not trust the leak.

### 6.3 `SKIP_HIJACK`

The reference's hijack reads a pointer at `loggers[0][1]` to recover the slide.
On coffey that slot is `0` at runtime (the ULOG logger is not registered), so
the predicate can never pass. The `SKIP_HIJACK` path skips that walk, sets
`kaslr_slide = 0`, and lets the OWNER read establish the read primitive. The
write primitive had already been proven by calibration and the BSS scratch
write.

### 6.4 Working invocation

```sh
KASLR_BASE_OVERRIDE=0xffffffc008000000 SKIP_HIJACK=1 SLIDE_SHIFT=6 \
P0_PHYS_LOAD=0x01800000 PSELECT_ENTER_DELAY=1000000 \
SYSCTL_WALK_ATTEMPTS=40 KS_MAX_TRIES=6 DM_SETTLE_MS=3000 \
/data/local/tmp/coffey
```

Observed:

```
sysctl walk owner       landed attempt=1
sysctl walk verify      landed attempt=1  (comm "ksanch0r")
sysctl walk cred        landed attempt=1  -> anchor getuid()==0
sysctl walk selinux     landed attempt=1  -> enforce=0
sysctl walk sig_enforce landed attempt=1
sysctl-route-ok slide=0000000000000000
exploit chain complete
```

---

## 7. What is new vs. prior art (explicit)

**Not new:**

- The bug, the CVE, the stale-`pi_blocked_on` idea, the rbtree-erase write, the
  `ctl.data`/boot_id read, the cred/`selinux_state`/`sig_enforce` finish, and
  the KernelSnitch `mm` leak all come from GhostLock / IonStack and the
  `GhostLock-H80GT` reference.
- No new kernel vulnerability was discovered.

**New / device-specific engineering:**

1. **First working coffey (5.15.196 / Android 14 / aarch64) port** of the
   reference. Public ports were 5.4.210 armv7l and 5.15.149 arm64.
2. **PFN-based load recovery**: using the vendor `page_trace` oops annotations
   to derive `P0_PHYS_LOAD=0x01800000` from four independent registers. This is
   a general forensic trick for vendor kernels that annotate oops PFNs.
3. **Carrier timing characterization**: the pselect fd_set copy race and the
   deterministic 1 s gate; the static proof that `exp` is arg 4 and `ex =
   bits+2*size`; the `el0_svc` depth cancellation that makes shift 6 correct.
4. **KASLR-off / empty-loggers adaptation** (`SKIP_HIJACK` + pinned base), and
   the observation that the perf IP leak can invent a module-based slide.
5. **Persistent uid-0 loader loop** from the anchored cred window, used to
   stream a full 36 GB backup over a FIFO without `/data` temp space.

If this is written up publicly, frame it as a **port + reliability study of
CVE-2026-43499 on a new target**, not as a new vulnerability.

---

## 8. Evidence

- Oops with PFNs (dropbox `SYSTEM_LAST_KMSG`), PC
  `rt_mutex_adjust_prio_chain+0x17c`, `FAR=0`, `R28` = stack waiter.
- `calib-page: LANDED [0xb00]=...` (safe, user page).
- `bss-test: LANDED target=ffffff8004204938 value=...` (kernel `.data`).
- `sysctl root proof (anchor): uid=0 euid=0 ... caps=0` and
  `SELINUX set PERMISSIVE`, `sig_enforce disabled`.
- Root loop: `uid=0(root) gid=0(root) context=u:r:kernel:s0`.
- Backup: `gpubox:~/onn-backup/coffey-FULL-20261117T053008Z`, 36 GB,
  `SHA256SUMS` verified (159 files), `tar -tf` clean.

---

## 9. Defensive guidance

- **Patch** to 5.15.212+ (the `remove_waiter` fix). The specific invariant is
  that `task->pi_blocked_on` must not survive a failed/aborted requeue-PI wait.
- **Detection**: `FUTEX_WAIT_REQUEUE_PI` followed by `FUTEX_CMP_REQUEUE_PI`
  returning `EDEADLK` (35), then `sched_setattr` on the same task, is the
  trigger shape. Oops signature: `rt_mutex_adjust_prio_chain+0x17c`,
  `waiter->lock == NULL`. Post-exploit: `selinux_state` byte 0 = 0 while the
  bootloader is locked, `sig_enforce=0`, boot_id reads containing kernel
  pointers.
- **Hardening that helped but was bypassed**: `panic_on_oops=1` makes a bad
  plant fatal (it reboots) but does not stop a correct plant; CFI/PAC/SCS force
  the data-only finish; `STATIC_USERMODEHELPER` kills the classic finish but
  not the cred/SELinux finish.
- **Hardening that would have helped more**: a KASLR seed; unprivileged perf
  restrictions (`perf_event_paranoid` > 1); no unprivileged `io_uring`;
  `CONFIG_BPF_UNPRIV_DEFAULT_OFF`; stricter SELinux on `shell`.

---

## 10. Reproduction / artifacts

- Source: `work/exploit/coffey/h80gt/src` (port), reference
  `work/exploit/GhostLock-H80GT` (Apache-2.0; IonStack/CyberMeowfia credits).
- Build: NDK r28c, `aarch64-linux-android34-clang`, static, `-DUSE_PSELECT`,
  `-DTARGET_CONFIG_H='"targets/coffey/target.h"'`.
- Target table: `src/targets/coffey/target.h`.
- Oops decode: `work/dropbox2.txt`, `work/dropbox.txt`.
- Kernel artifacts: `work/coffey-rootrecon/kernel.elf`, `kernel.Image`,
  `vmlinux.btf`.
- Backup manifest: `work/backup/MANIFEST.txt`; destination
  `gpubox:~/onn-backup/coffey-FULL-20261117T053008Z`.

## 11. Limitations / ethics

- This is a memory-only exploit: a failed attempt reboots; a reboot restores
  SELinux/sig_enforce/boot_id. Nothing is flashed.
- The temporary root leaves the device permissive and `sig_enforce=0`; do not
  run untrusted modules or leave it in that state longer than necessary.
- This work was performed on the owner's own device for backup before unlock.
  Do not reuse it on devices you do not own.

---

# Appendix A — Chronology of the coffey port

This is the order in which the unknowns were actually closed. It is included
because the final chain looks much simpler than the path that produced it.

### Phase 0 — route selection

- Read the repo and probed the live unit over USB (`CUSA2512000317`).
- GhostLock (`CVE-2026-43499`) was the only viable route:
  `CONFIG_FUTEX_PI=y`, kernel 5.15.196 (fix at 5.15.212), unprivileged trigger.
- DirtyFrag (`CVE-2026-43284`/`CVE-2026-43500`) was ruled out on every axis:
  no user namespaces, no `AF_RXRPC`, no setuid-root binary, and
  `STATIC_USERMODEHELPER_PATH=""` kills the usermode-helper finish.
- Also ruled out: a signed GSI via DSU (no 32-bit GSI on Android 14 and no
  64-bit userspace), and the stock recovery/fastbootd path (root `adbd` exists
  in the recovery ramdisk, but `ro.adb.secure=1`, no `adb_keys`, no prompt;
  `fastbootd` has `fetch not supported` on user builds).

### Phase 1 — safe tooling and the `/sdcard` pull

- `tools/root_readiness.py` (read-only gate) → verdict
  `temp_root_in_scope_needs_coffey_loader`.
- `tools/temp_root.py` (stages one pinned ELF, enforces `id -u == 0` plus a
  successful `/dev/block/by-name/init_boot_*` read, always removes the binary).
- `tools/backup_device.py` (both slots, partitions, `/data` tar, SHA-256,
  resume/verify).
- Pulled `/storage/emulated/0` (1.6 GB) straight to gpubox; SHA-256 verified.
  This is the fallback that survives even a full wipe.

### Phase 2 — offline kernel work

- Extracted the stock `Image` from `boot.img` (LZ4 at file offset 4096,
  43,559,424 bytes) and symbolized it with `vmlinux-to-elf`.
- Found the embedded BTF at `Image+0x1cdb684`; parsed exact 5.15 layouts
  (`rt_mutex_waiter` is not the 5.10 layout: `wake_state@0x40`,
  `prio@0x44`).
- Built the coffey symbol table from kallsyms + BTF; confirmed the symbols
  against the runtime (`init_mm` matched exactly, KASLR disabled).
- Discovered that a **static aarch64 binary runs** even though
  `ro.zygote=zygote32` and `abilist64` is empty — the 32-bit runtime props
  describe Android userspace, not the kernel ABI. This removed the entire
  32-bit refactor.

### Phase 3 — trigger and carrier

- Two perf primitives worked from uid 2000: kernel IP sampling
  (`perf_event_paranoid=-1`) and `PERF_SAMPLE_PHYS_ADDR` for a user page
  (the physical-address oracle).
- First builds: a musl/zag build died in the raw `clone()` child (TLS); the
  bionic/NDK r28c build fired the UAF. That is when the device started
  panicking on wrong landings.
- The MCAST carrier sweep (options 46/44, shifts 0–23) was stopped as
  **mathematically dead**: `ip6_mc_source`'s `group_source_req` copy is at
  `stack_top-0x3c0`, 42 words below the futex waiter, and only 33 words are
  copied. No shift in 0–23 can reach the waiter.
- pselect page calibration hit: `calib-page: LANDED [0xb00]=dm+0xa20` at
  `SLIDE_SHIFT=6`, with `CMP_REQUEUE_PI done errno=35` (EDEADLK = ghost
  formed). The write primitive was now proven without any kernel address.

### Phase 4 — the physical load

- Kernel-image targets (boot_id ctl.data, the boot_id buffer, `selinux_state`,
  `uuid.data`, `rt_sched_class`) all hung or panicked; the user-page target
  always landed.
- Candidate loads were tested with a harmless `.bss`/boot_id probe:
  `0x02080000` (vendor_boot) → hang; `0x01080000` → panic; `0x02000000` →
  panic.
- Static boot-path analysis could not settle it: boot v4 has no
  `kernel_addr`; vendor_boot's field is the only plaintext hint; the
  `@ML`/FIP bootloader is encrypted; `param`/`env` are not in the OTA.
- Codex (asked for a separate boot-format opinion) confirmed the field is the
  spec load address but that `text_offset=0` wants 2 MiB alignment;
  `0x02080000` is non-compliant but tolerated.
- The breakthrough was **in the oops itself**: the vendor `page_trace` module
  annotates every register with its PFN. Four independent image addresses
  agree on `0x01800000`:
  `PC 0x2d03`, `R4/R12/R13 0x3f6d`, `R6 0x3041`, `R15 0x3f88`.
  `vendor_boot`'s `0x02080000` was the staging address; the Image was
  relocated 8 MiB lower. No additional write was needed.

### Phase 5 — geometry and the NULL lock

- Even at the correct load, the BSS write still oopsed with
  `waiter->lock == NULL` (`rt_mutex_adjust_prio_chain+0x17c`,
  `ldr x27,[x28,#0x38]; ldar [x27]`, FAR=0). That isolated a second,
  independent problem.
- `STAMP_ONLY` proved the user fd_sets were correct (word 3 = value, word 5 =
  target, word 6 = init_task, word 7 = fake_lock, word 8 = prio), and
  `ulimit -n = 32768` ruled out `ex`-set truncation.
- Static reconciliation:
  - `exp` is the 4th argument; `core_sys_select` copies `ex` to `bits+2*size`.
  - `do_futex`'s requeue-PI waiter is at `x29-0xd0` = `T-D-0x1d0`.
  - The `el0_svc` entry depth `D` (~0x1f0) cancels between pselect and futex,
    so the relative shift is still 6. The initial "0x1f0 off" was not a
    geometry error.
- The remaining variable was **when** the consumer fired. The reference's
  50 ms `PSELECT_ENTER_DELAY_USEC` fired `sched_setattr` before `pselect`
  copied the fd_sets; the stale waiter was still zero. With
  `PSELECT_ENTER_DELAY=1000000` the calibration landed cleanly and the BSS
  scratch write landed at `0x1800000`.

### Phase 6 — KASLR and the slide stage

- The perf IP leak is unreliable on coffey (one run returned a module-based
  bogus base `0xffffffc003200000`). KASLR is actually disabled ("lack of
  seed"), so the base is pinned with
  `KASLR_BASE_OVERRIDE=0xffffffc008000000`.
- The reference's `loggers[0][1]` slide read is zero on this build (the ULOG
  logger is not registered), so `SKIP_HIJACK=1` skips it; the OWNER read
  establishes the `ctl.data` read primitive.

### Phase 7 — root and backup

- Owner / verify / cred / SELinux / sig_enforce walks all landed on attempt 1
  with the 1 s gate.
- The anchor flipped to `uid=0`; `enforce=0` and `sig_enforce=0`.
- A loader hook was used to leave a persistent uid-0 command loop.
- The full backup was streamed to gpubox through a FIFO (no `/data` temp
  space): whole eMMC, super, raw userdata, every by-name partition + GPT,
  `/data` tar, user-10 profile tar, and the APK set.

---

# Appendix B — Dead ends and why

| Route | Why it failed / was not used |
|---|---|
| DirtyFrag (CVE-2026-43284/43500) | No userns, no `AF_RXRPC`, no setuid-root binary, UMH disabled |
| `modprobe_path` / `core_pattern` finish | `STATIC_USERMODEHELPER_PATH=""` |
| Function-pointer hijack finish | CFI + PAC + SCS |
| `PR_SET_MM_MAP` stack reclaim | Needs `CAP_SYS_RESOURCE`; no userns |
| MCAST `group_source_req` carrier | Copy at `T-0x3c0`, 42 words below the waiter; only 33 words copied → no reachable shift |
| `readv` / `sendmsg` / `perf_event_attr` carriers | All land above or below the `T-D-0x1d0` waiter with too few full 64-bit words |
| Stock recovery `adbd` root | `ro.adb.secure=1`, no `adb_keys`, no prompt |
| `fastbootd fetch` | "fetch not supported" on user builds |
| DSU signed GSI | No 32-bit GSI on Android 14; no 64-bit userspace |
| `vendor_boot.kernel_addr = 0x02080000` | Staging address; real load `0x01800000` (PFNs) |
| Blind shift sweep | Unbounded in practice; the static shift is 6 |
| perf KASLR leak | Can return a module-derived bogus base; KASLR is off anyway |
| `loggers[0][1]` slide read | Zero at runtime on this build |
| pipe_buffer/vmemmap read route | Not needed once the write landed; also gated by the same chain |

---

# Appendix C — Claims and non-claims (for disclosure)

**Claims**

- GhostLock (CVE-2026-43499) is exploitable on coffey (Android 14,
  5.15.196, aarch64) to obtain uid 0 and SELinux permissive at runtime.
- The physical Image load is `0x01800000`, proven by four PFN-annotated
  image addresses in an oops.
- The pselect carrier's stack shift is 6; the `el0_svc` depth cancels.
- The 50 ms enter delay is a reliability bug on this target; 1 s is
  deterministic.
- The full pre-unlock backup is complete and verified.

**Non-claims**

- We did **not** discover CVE-2026-43499 or a new kernel vulnerability.
- We did **not** discover a new memory-corruption primitive. The write is
  GhostLock's rbtree erase; the read is the reference's `ctl.data`/boot_id
  hijack; the finish is the reference's cred/SELinux/sig_enforce data-only
  chain.
- We did **not** prove whether the OPTEE unlock forces a wipe; that remains
  the open question the backup is meant to de-risk.
- We did **not** achieve permanent root; the root is memory-only and a reboot
  restores the kernel state.

---

# Appendix D — Third-party review notes

- Claude Code (local CLI) refused the exploit-chain prompt with a cyber
  safeguard. That is recorded and was not worked around.
- Codex refused the exploit-chain prompt ("Daybreak access") but answered the
  separate boot-format question, which contributed the 2 MiB-alignment
  observation. That answer is in `work/codex-boot-opinion.txt`.
- A local `deepseek-v4-pro` agent produced the static vmemmap/slab fallback
  plan (pipe_buffer.page → `mm->owner` → fake cred). It was not needed once
  the standard chain landed, but it is the right fallback if the
  `ctl.data` stage ever breaks.
