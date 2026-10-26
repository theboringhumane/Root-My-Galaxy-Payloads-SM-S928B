# Port status: SM-S928B / S928BXXU6EZIF

**Status: not built, not run, not rooted.** The profile now carries symbol
offsets, struct offsets and a P0 fingerprint derived from the exact
`S928BXXU6EZIF` Image. The BL package that ships with it declares the kernel's
physical region at `0xa8000000`, but a declaration is not a reading from a
running boot, so `target.h` still refuses to compile.

Do not remove the gate to "try it". A profile with an unmeasured physical anchor
writes to a real address that is not the symbol; the failure mode is a panic,
not a wrong answer.

## Identity (measured on the reference unit)

| Field | Value | Status |
| --- | --- | --- |
| Model | `SM-S928B` | measured |
| Device | `e3q` | measured |
| Build | `CP2A.260605.016.S928BXXU6EZIF` | measured |
| Fingerprint | `samsung/e3qxins/e3q:17/CP2A.260605.016/S928BXXU6EZIF:user/release-keys` | measured |
| Android / SDK | 17 / 37 | measured |
| Kernel | `6.1.162-android14-11-34343818-abS928BXXU6EZIF` | measured |
| Security patch | `2026-09-05` | measured |
| KMI | `android14-6.1`, AArch64 | measured |

The identity macros are metadata. The shared payload sources do **not** read them
and do **not** verify the build at runtime; only the build-time gate uses them.
Whatever loads the payload is responsible for the identity check, which is why
the values are recorded here and in `target.h`.

## Image provenance

The Image was sliced out of page 1 of the `boot.img.lz4` in the AP tar of the
`S928BXXU6EZIF` FUS package (boot header v3, `kernel_size` 0x245fa00).

| Property | Value |
| --- | --- |
| File | `out/kernel` |
| Size | 38,140,416 bytes (`0x245fa00`) |
| SHA-256 | `a8c1638497ca1bff576c5a6d9426521ec545fd68da8ce5dfa47c40233391a179` |
| Container | PE/COFF arm64 EFI stub, no ELF symbol table |
| Sections | `.text` VA 0x10000, vsize 0x21f0000; `.data` VA 0x2200000 |
| `image_size` / `text_offset` | 0x2710000 / 0 |
| `KIMAGE_TEXT_BASE` | 0xffffffc008000000 (matches kallsyms relative base) |

Everything below is derived from this one file. No vmlinux, BTF file or symbol
table ships separately, so the tables were read out of the Image itself with
`tools/inspect_image.py`:

- **kallsyms** — base-relative layout: s32 offsets at 0x142f568, relative base
  0xffffffc008000000 at 0x1498628, 107568 symbols at 0x1498630, compressed names
  at 0x1498638, token table 0x1653078, token index 0x1653400.
- **BTF** — one valid blob at 0x1820e90 (`hdr_len` 24, `type_len` 0x3625fc,
  `str_len` 0x254814). The other `9f eb 01 00` hit in the file does not validate.

## Value ledger

| Value | Status | Evidence |
| --- | --- | --- |
| `P0_PHYS_OFFSET = 0x816e0000` | measured | `/proc/zoneinfo`, `start_pfn 530144` (`evidence/live-probes.md`) |
| `KIMAGE_TEXT_BASE = 0xffffffc008000000` | measured | kallsyms relative base in the Image; `CONFIG_ARM64_VA_BITS=39` |
| `SLIDE_TRACEFS_EVENT_ID = 106` | measured | tracefs `sched_blocked_reason/id` |
| 23 inherited symbol offsets | verified | 22 match exactly; `SLIDE_NFULNL_LOGGER_OFF` corrected by 14 bytes (below) |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF = 0xdb39c` | verified | `worker_thread+0xa0`; the blocking `bl schedule` returns to 0xdb39c, and the live caller is `worker_thread+0xa0/0x430` |
| `SLIDE_PSELECT_WORD_SHIFT = 3` | verified | frame arithmetic below |
| `rt_mutex_waiter`, `task_struct`, `file_operations`, page/slab, configfs, workqueue, pipe offsets | verified | BTF (`tools/inspect_image.py btf`) |
| `p0_fingerprint.h` | verified | generated from this Image at probe 0x1f0000; regeneration is byte-identical and the generator re-reads all 32 rows / 256 qwords |
| `P0_KERNEL_PHYS_LOAD = 0xa8000000` | **declared, pending** | the BL's `xbl_config.elf` `/soc/memorymap/memory@A8000000` is `MemLabel = "Kernel"`, `reg = <0xa8000000 0x10000000>`; the BL's `uefi.elf` carries the driver that looks up that entry and writes `KernelBaseAddr`/`KernelSize` from it; `UEFI_RESV` ends at the region base, the map's `NOMAP` region ends at the live `memstart`, and it collides with no DT carve-out (`evidence/xbl-memorymap.md`). Not yet read from a running boot. |

`P0_PHYS_OFFSET` is `memstart_addr`, not a DRAM base. The value matches the
reference profile exactly, which is expected on the same platform binary, and it
is readable without root, so it does not need the firmware download.

### Symbol offsets

All of these are `symbol_va - 0xffffffc008000000` in the Image above.

| Macro | Value | Symbol / target |
| --- | --- | --- |
| `ASHMEM_MISC_FOPS_OFF` | 0x023dc200 | `ashmem_miscs + 0x10` (miscdevice `.fops`), holds `base+0x013e2e30` |
| `ASHMEM_FOPS_OFF` | 0x013e2e30 | `ashmem_fops` |
| `ASHMEM_IOCTL_OFF` | 0x00d44e8c | `ashmem_ioctl` |
| `ASHMEM_COMPAT_IOCTL_OFF` | 0x00d457c4 | `compat_ashmem_ioctl` |
| `ASHMEM_MMAP_OFF` | 0x00d4581c | `ashmem_mmap` |
| `ASHMEM_OPEN_OFF` | 0x00d45a48 | `ashmem_open` |
| `ASHMEM_RELEASE_OFF` | 0x00d45ad0 | `ashmem_release` |
| `ASHMEM_SHOW_FDINFO_OFF` | 0x00d45bf0 | `ashmem_show_fdinfo` |
| `CONFIGFS_READ_ITER_OFF` | 0x00472b84 | `configfs_read_iter` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | 0x004730b4 | `configfs_bin_write_iter` |
| `COPY_SPLICE_READ_OFF` | 0x003f07c4 | `generic_file_splice_read` (legacy macro name) |
| `NOOP_LLSEEK_OFF` | 0x003a235c | `noop_llseek` |
| `INIT_TASK_OFF` | 0x0226f6c0 | `init_task` |
| `ROOT_TASK_GROUP_OFF` | 0x0246dd80 | `root_task_group` |
| `SELINUX_ENFORCING_OFF` | 0x02542618 | `selinux_state` (the enforcing byte is its first field) |
| `KMALLOC_CACHES_OFF` | 0x01781458 | `kmalloc_caches` |
| `ANON_PIPE_BUF_OPS_OFF` | 0x0122ad50 | `anon_pipe_buf_ops` |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x000d3be0 | `call_usermodehelper_exec_work` |
| `SYSTEM_UNBOUND_WQ_OFF` | 0x0225ac60 | `system_unbound_wq` |
| `SLIDE_NFULNL_LOGGER_OFF` | 0x016ba45d | `nfulnl_logger.name` target, `"nfnetlink_log"` |
| `SLIDE_LOGGERS_0_1_OFF` | 0x02262828 | `nfulnl_logger` |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | 0x02396a98 | `random_table[0x108].data`, holds `base+0x02625768` |
| `SLIDE_SYSCTL_BOOTID_OFF` | 0x02625768 | `sysctl_bootid` |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x000db39c | `worker_thread + 0xa0` |

One correction against the inherited table: `SLIDE_NFULNL_LOGGER_OFF` was
`0x016ba44f`, which lands 14 bytes early inside the preceding
`"packet message\n"` string. On this Image `nfulnl_logger.name` is
`base+0x016ba45d`, so the inherited value would have made `slide_read_stext`
return `real_stext + 14` and fail the 32 KiB slide alignment check. Every other
inherited symbol value matched exactly.

### Pselect frame arithmetic

The route rewrites the stale `rt_waiter` left by `futex_wait_requeue_pi` using
the fd-set buffer `core_sys_select` copies onto the same kernel stack.

| Frame | Offset in Image | Fact |
| --- | --- | --- |
| `__arm64_sys_futex` | 0x1a10ac | `sub sp, sp, #0x70` |
| `do_futex` | 0x1a0e30 | `sub sp, sp, #0x60`, calls `futex_wait_requeue_pi` |
| `futex_wait_requeue_pi` | 0x1a3b44 | `sub sp, sp, #0x1b0`; `rt_mutex_init_waiter` self-stores at `sp+0x98` and `sp+0xb0` |
| `__arm64_sys_pselect6` | 0x3c4b2c | `sub sp, sp, #0x90`, calls `core_sys_select` directly |
| `core_sys_select` | 0x3c3d64 | `sub sp, sp, #0x1c0`, zeroes a 0x100-byte `fd_set_bits` at `sp+0x50` |

With `pt_regs` at `kernel_entry-0x110`, the waiter sits at `pt_regs-0x1e8` and
the fd-set buffer at `pt_regs-0x200`; the waiter begins at global word 3.

### Struct offsets

BTF confirms `rt_mutex_waiter` is 0x58 bytes with `tree_entry` 0x0,
`pi_tree_entry` 0x18, `task` 0x30, `lock` 0x38, `wake_state` 0x40, `prio` 0x44,
`deadline` 0x48 and `ww_ctx` 0x50 — identical to the fake-waiter layout. The same
blob confirms the `task_struct` fields (`usage` 0x40, `prio` 0x84,
`normal_prio` 0x8c, `sched_task_group` 0x348, `pi_lock` 0x924, `pi_waiters`
0x938, `pi_top_task` 0x948, `pi_blocked_on` 0x950), `file_operations`,
`configfs_buffer`, `workqueue_struct`, `pool_workqueue`, `worker_pool`,
`work_struct`, `pipe_buffer`, `struct page` (0x40) and the `struct slab` overlay
(`slab_cache` at 0x18). `mm_struct` is 0x3c0 by BTF; `MM_STRUCT_SZ` remains
0x400 because that is the observed slab object stride.

Every member macro in `ezif_layout.h` was compared against these BTF entries
(bit offsets divided by 8), not eyeballed:

| Struct | Members checked |
| --- | --- |
| `rt_mutex_waiter` | 8 of 8; size 0x58 |
| `task_struct` | `usage`, `prio`, `normal_prio`, `sched_task_group`, `pi_lock`, `pi_waiters`, `pi_top_task`, `pi_blocked_on` |
| `file_operations` | `owner` 0x0, `llseek` 0x8, `read` 0x10, `write` 0x18, `read_iter` 0x20, `write_iter` 0x28, `unlocked_ioctl` 0x50, `compat_ioctl` 0x58, `mmap` 0x60, `open` 0x70, `release` 0x80, `splice_read` 0xc8, `show_fdinfo` 0xe0 |
| `configfs_buffer` | `page` 0x10, `needs_read_fill` 0x50, `bin_buffer` 0x58, `bin_buffer_size` 0x60, `cb_max_size` 0x64 |
| `workqueue_struct`, `pool_workqueue`, `worker_pool`, `work_struct` | `dfl_pwq` 0xb0; `pool` 0x0, `wq` 0x8, `work_color` 0x10, `refcnt` 0x18, `nr_in_flight` 0x1c, `nr_active` 0x5c, `max_active` 0x60; `worklist` 0x28, `nr_idle` 0x3c; `data` 0x0, `entry` 0x8, `func` 0x18 |
| `pipe_buffer` | `page` 0x0, `offset` 0x8, `len` 0xc, `ops` 0x10, `flags` 0x18, `private` 0x20; size 0x28 |
| `page` / `slab` | `compound_head` 0x8, `page_type` 0x30; `slab_cache` 0x18 |

Two profile macro names do not match the BTF member name they target, and both
were checked by offset rather than name: `FAKE_TASK_TASK_GROUP_OFF` targets
`sched_task_group`, and `FOPS_IOCTL_OFF` targets `unlocked_ioctl`.

`APP_EZIF_FOPS_TABLE_ALT_OFF` is inherited and unused in both profiles. It must
stay unused: a 0x110-byte table at absolute 0x2180 would run to 0x2290 and
overwrite the fake `rt_mutex` at 0x2210.

`tools/layout_check.c` turns the tables above into `_Static_assert`s: every
symbol offset inside the Image and aligned, the load address and the whole
Image span inside the BL's `Kernel` region, the physical delta inside the
direct map, every struct field inside its BTF size, every fake object inside
the reclaimed order-3 page, the bank/oracle slot arithmetic, and the
fingerprint probe covering all 32 rows. It needs only a host C11 compiler.

## Pending

`P0_KERNEL_PHYS_LOAD` is the only value that blocks the build.

It cannot be closed from `memstart`: DZF2 pairs `0xa8000000` with
`memstart 0x80000000` (+0x28000000), and this device's `memstart` is
`0x816e0000`, so the same delta would give `0xa96e0000`. The load address is a
property of the boot chain. `/proc/iomem` and `/proc/cmdline` are denied to the
shell, and the PE `ImageBase` is 0.

The boot chain itself now supplies a placement for this exact package. The BL
member carries `xbl_config.elf`, whose second FDT has `/soc/memorymap`:

```text
/soc/memorymap/memory@A8000000
  reg = <0x00000000 0xa8000000 0x00000000 0x10000000>
  MemLabel = "Kernel"
```

That is 256 MiB, 2 MiB aligned, beginning exactly where `UEFI_RESV` ends and
clear of every Linux-side carve-out.  The same map's `NOMAP` region ends at
0x816e0000, which is the live `memstart` to the byte.
`evidence/xbl-memorymap.md` records the extraction, the full map, and the
cross-checks against the live kernel, the UEFI image and the DTBO.

This is stronger than free space, but it is still not a runtime measurement.
The same BL member's `uefi.elf` carries the driver that publishes the entry:
it looks up the platform-config entry named `Kernel` (the map's `MemLabel`),
then calls `SetVariable` for `KernelBaseAddr` and `KernelSize` with that
entry's `MemBase` and `MemSize` under GUID
882f8c2b-9646-435f-8de5-f208ff80c1bd.  LinuxLoader reads those variables back
and adds the Image's `text_offset` (0 here), or 0x8000 / 0x80000 when the arm64
header is not recognised.  `evidence/xbl-memorymap.md` records the driver, the
calls, and the gzip-nested firmware volume they live in.  The shell still
cannot read the variables, so the value is boot-chain authored end to end but
unmeasured; the row stays pending until a running boot confirms it.

What the shipped DT says is recorded in `evidence/dtbo-reserved.md`. The
base DT in `vendor_boot.img` lists 88 reserved-memory carve-outs across 22 board
variants; the DTBO adds `sec_xbl_ramdump@A7D00000` (0xa7d00000 + 0x300000,
ending exactly at 0xa8000000). No carve-out in any variant overlaps
`[0xa8000000, 0xaa710000)`.

Rows still open after that:

| Value | How it is closed |
| --- | --- |
| `P0_KERNEL_PHYS_LOAD` | confirm on a running boot: root-side `/proc/iomem`, or the physical P0 oracle, which is the exploit's first step and fails before any kernel write; the BL declares the region base `0xa8000000` and writes it into `KernelBaseAddr` |
| lane/bank geometry (`SLIDE_BANK_SLOTS`, `SLIDE_S928_BANK_*`) | on-device: re-check against the reclaimed page layout |
| live reclaim and FOPS readback | on-device, after a build exists |

### The route result gate

Every race this build ran reported `triggered=0`, and the run stopped there:
`main.c` computes `verified = triggered && try_cfi_stage()`, so the FOPS readback
never executed and the log's `read_ok=0 write_ok=0` measured the absence of a
check, not the absence of a write.

Two gates caused that, both inherited:

| Signal | Published by | Reachable by the pselect writer |
| --- | --- | --- |
| `slide_pselect_write_window` | nowhere — every reference reads it, the only store is the reset to 0 | no |
| `slide_stack_write_window` | `ret > 0 && slide_consume_sched_ok` | no: the watched fds are `dup2`s of a timerfd that is created but never armed, so pselect6 always returns 0 at its timeout |

The live signals are `slide_waiter_ok` (the `FUTEX_CMP_REQUEUE_PI` deadlock was
accepted and the waiter route finished) and `slide_consume_sched_ok` (the
consumer's sched call ran while the pselect frame was live, which is what
carries the fd-set words onto the stale waiter). The route now returns
`waiter_ok && consume_sched_ok` under `APP_EZIF_VERIFY_PSELECT_TIMEOUT`, which is
the same shape the engine already uses for `APP_ACCEPT_SCHED_TRIGGER`, and the
readback decides.

The consequence of the old gate is also the explanation for the reboots seen
before this change: a rewrite that landed was reported as a miss, the payload
exited, and the next `/dev/ashmem` open in any process followed `misc_fops` into
the reclaimed page after that page was freed. `stack writer ran; refusing retry
on this boot` ended the run without ever restoring the pointer.

## Verification commands

```sh
# symbol offsets
tools/inspect_image.py sym out/kernel ashmem_miscs ashmem_fops nfulnl_logger \
  sysctl_bootid worker_thread

# struct offsets
tools/inspect_image.py btf out/kernel rt_mutex_waiter
tools/inspect_image.py btf out/kernel task_struct pi_lock pi_waiters \
  pi_top_task pi_blocked_on
tools/inspect_image.py btf out/kernel --find slab_cache

# frame arithmetic (any arm64-capable objdump over a flat ELF wrapper)
llvm-objdump -d --no-show-raw-insn \
  --start-address=0xffffffc0081a3b44 --stop-address=0xffffffc0081a3c60 kernel.elf

# fingerprint: regenerate and diff
perl tools/generate_p0_fingerprint.pl out/kernel 0x1f0000 out/p0_fingerprint.h

# boot-chain kernel region (BL member of the same package)
tools/extract_image.py prefix.dec stream --tar-hint BL \
  --image xbl_config.elf.lz4 --outdir out
lz4 -d out/xbl_config.elf.lz4 out/xbl_config.elf
tools/dtb_dump.py out/xbl_config.elf --offset 0x140c4 --path /soc/memorymap

# who publishes the region into the variables LinuxLoader reads
tools/extract_image.py prefix.dec stream --tar-hint BL \
  --image uefi.elf.lz4 --outdir out
lz4 -d out/uefi.elf.lz4 out/uefi.elf
tools/verify_uefi_chain.py out/uefi.elf

# profile geometry (host compiler; no NDK)
clang -std=c11 -fsyntax-only -I src tools/layout_check.c
```

## Offline gate

The target builds only when all of these are true:

1. `#error` removed **and** `ALLOW_UNVERIFIED_S928B` unnecessary because every
   pending row above is measured — **fails on `P0_KERNEL_PHYS_LOAD` only** (it
   is declared by the BL memory map, not read from a running boot);
2. generated fingerprint table matches the Image it was generated from — **passes**
   (regeneration is byte-identical);
3. symbol offsets are inside the Image and 4-byte aligned — **passes**
   (`tools/layout_check.c`);
4. `P0_KERNEL_PHYS_LOAD` is page aligned and does not fall in a reserved-memory
   region from the vendor DTB — **alignment and collision pass**
   (`evidence/dtbo-reserved.md`, `evidence/xbl-memorymap.md` and
   `tools/layout_check.c`); the address itself is unmeasured;
5. struct offsets keep every fake object inside its page — **passes** (BTF sizes
   above, asserted in `tools/layout_check.c`);
6. release payload is exactly 104128 bytes — **passes**, the stable recipe
   truncates to 104128 and asserts the size before doing so.

## Build

```sh
make stable TARGET=e3q-S928BXXU6EZIF \
  ANDROID_NDK_HOME=/path/to/android-ndk-r27c \
  TARGET_CFLAGS=-DALLOW_UNVERIFIED_S928B
```

`-DALLOW_UNVERIFIED_S928B` is required while `P0_KERNEL_PHYS_LOAD` stays in the
ledger as declared-but-unmeasured; it acknowledges the row rather than closing
it.

The payload carried by the handset build under test:

```text
build/e3q-S928BXXU6EZIF/cve-2026-43499-app.stable.so
size 104128
sha256 b507ad7d94a8f438ba06230374fb170c6c9f22ec52a79eb2d4d0d9295b67eeb1
```

## KernelSU

Not started. This kernel has `CONFIG_MODVERSIONS=y` and
`CONFIG_TRIM_UNUSED_KSYMS=y`, so the module must either be built against a
matching `Module.symvers` or use the manual-relocation path with a zero-length
`__versions` section. `vermagic` must read:

```text
6.1.162-android14-11-34343818-abS928BXXU6EZIF SMP preempt mod_unload modversions aarch64
```

The manager pairing is the same constraint as the reference device: the module
and manager must come from the same KernelSU release, because the manager
signing-block parser changed between releases.

## Not done

- no root yet: the payload has been built, installed and executed on the
  reference handset, and every attempt so far ended at the gate described above;
- no `support/targets-v3.json` entry, because that feed entry requires an
  artifact validated on-device;
- no on-device confirmation that a landed rewrite survives the readback, which
  is what the gate change makes measurable.

## Next step

Re-run the race with the gate above removed from the reporting path. Until that
run prints `triggered=1`, every `route result=0` in the log is this profile's
answer to a question the code could not ask, and no delay, bucket or reclaim
tuning is measurable.

Then, and only then, the delay sweep becomes meaningful: the attempt table in
`ezif_layout.h` walks outward from the 50 ms the reference device used, but
`writer_started` still ends the supervisor run after the first attempt that
reaches the stack writer, so one boot buys one race. `P0_KERNEL_PHYS_LOAD` stays
open until a running boot confirms it; the physical P0 oracle is the first step
that would confirm it and it runs before any kernel write.
