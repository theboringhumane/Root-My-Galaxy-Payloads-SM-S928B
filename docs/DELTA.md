# Triage: SM-S928N S928NKSU6EZIF -> SM-S928B S928BXXU6EZIF

This is the delta record for this port. It answers one question: which values
must be re-derived for B, and which are structurally identical and should not be
touched.

## Inputs

| Side | Role | File | SHA-256 |
| --- | --- | --- | --- |
| A | SM-S928N, `S928NKSU6EZIF`, Android 17 | `e3q-S928NKSU6EZIF/target.h` | `3e6ae6fdb9bea1f9b5162319e78bd259ce6ed79557cedd19956118b15d976391` |
| A | same | `e3q-S928NKSU6EZIF/ezif_layout.h` | `56e5a261297480e1682425b60791f2e5d2f123954d190c22d32d19fc196d3f78` |
| A | same | `e3q-S928NKSU6EZIF/p0_fingerprint.h` | `49f8c3f572bde0856f2bfaa548aeddf7914663ee0cc79cb36db93a7e25c20a45` |
| B-ref | SM-S928B, `S928BXXS6DZF2`, Android 16 | `e3q-S928BXXS6DZF2/target.h` | `d1cbf001bf5d9bda20280cf93144a350110508d6b4c2eabbc3a2886f0f520853` |
| U1-ref | SM-S928U1, `S928USQS6DZF2`, Android 16 | `e3q-S928USQS6DZF2/target.h` | `264a4a37a68c46c8a998634d02acc882054f87842b5d28cc0b13d42ece8d48a7` |

The reference profiles are not vendored in this repo; the hashes identify exactly
which versions the tables below were computed from.

## Headline numbers

```text
A (N EZIF) vs B-ref (B DZF2)     same=146  differ=29  A-only=67  B-only=1
B-ref (DZF2)  vs U1-ref (DZF2)   same=173  differ=3   B-only=0   U1-only=0
```

The control comparison matters more than the headline. Two models of the same
generation on the *same* build differ in three rows, one of which is a string
offset. Two builds of the *same* model, one Android release apart, differ in 29.
So the delta here is **build-level, not model-level**: what has to be ported is
"N EZIF -> B EZIF", and B's DZF2 profile is not the template.

## The 29 differences, by class

| cat | macro | A (N EZIF) | B-ref (DZF2) | delta |
| --- | --- | --- | --- | ---: |
| flag | `APP_PAYLOAD_ATTEMPT_DELAYS_USEC` | 12-value sweep | `50000` | expr |
| layout | `SLIDE_BANK_SLOTS` | 5 | 4 | -0x1 |
| layout | `SLIDE_S928_PROBE_TARGET_IMAGE_OFF` | 0x023dc200 | 0x023bb5b0 | -0x20c50 |
| physical | `P0_KERNEL_PHYS_LOAD` | 0xa8000000 | 0x80080000 ¹ | conditional |
| physical | `P0_PHYS_OFFSET` | 0x816e0000 | 0x80000000 | -0x16e0000 |
| slide | `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x000db39c | 0x000db1a0 | -0x1fc |
| symbol | `ANON_PIPE_BUF_OPS_OFF` | 0x0122ad50 | 0x01219d90 | -0x10fc0 |
| symbol | `ASHMEM_COMPAT_IOCTL_OFF` | 0x00d457c4 | 0x00d3ac4c | -0xab78 |
| symbol | `ASHMEM_FOPS_OFF` | 0x013e2e30 | 0x013d1140 | -0x11cf0 |
| symbol | `ASHMEM_IOCTL_OFF` | 0x00d44e8c | 0x00d3a314 | -0xab78 |
| symbol | `ASHMEM_MISC_FOPS_OFF` | 0x023dc200 | 0x023bb5b0 | -0x20c50 |
| symbol | `ASHMEM_MMAP_OFF` | 0x00d4581c | 0x00d3aca4 | -0xab78 |
| symbol | `ASHMEM_OPEN_OFF` | 0x00d45a48 | 0x00d3aed0 | -0xab78 |
| symbol | `ASHMEM_RELEASE_OFF` | 0x00d45ad0 | 0x00d3af58 | -0xab78 |
| symbol | `ASHMEM_SHOW_FDINFO_OFF` | 0x00d45bf0 | 0x00d3b078 | -0xab78 |
| symbol | `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x000d3be0 | 0x000d39cc | -0x214 |
| symbol | `CONFIGFS_BIN_WRITE_ITER_OFF` | 0x004730b4 | 0x004717d4 | -0x18e0 |
| symbol | `CONFIGFS_READ_ITER_OFF` | 0x00472b84 | 0x004712a4 | -0x18e0 |
| symbol | `COPY_SPLICE_READ_OFF` | 0x003f07c4 | 0x003ef340 | -0x1484 |
| symbol | `INIT_TASK_OFF` | 0x0226f6c0 | 0x0224f8c0 | -0x1fe00 |
| symbol | `KMALLOC_CACHES_OFF` | 0x01781458 | 0x0176c6f8 | -0x14d60 |
| symbol | `NOOP_LLSEEK_OFF` | 0x003a235c | 0x003a14e4 | -0xe78 |
| symbol | `ROOT_TASK_GROUP_OFF` | 0x0246dd80 | 0x0244cd80 | -0x21000 |
| symbol | `SELINUX_ENFORCING_OFF` | 0x02542618 | 0x02521588 | -0x21090 |
| symbol | `SLIDE_LOGGERS_0_1_OFF` | 0x02262828 | 0x02242a20 | -0x1fe08 |
| symbol | `SLIDE_NFULNL_LOGGER_OFF` | 0x016ba44f | 0x016a622a | -0x14225 |
| symbol | `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | 0x02396a98 | 0x023762f0 | -0x207a8 |
| symbol | `SLIDE_SYSCTL_BOOTID_OFF` | 0x02625768 | 0x026046e8 | -0x21080 |
| symbol | `SYSTEM_UNBOUND_WQ_OFF` | 0x0225ac60 | 0x0223ae60 | -0x1fe00 |

¹ The DZF2 header defines `P0_KERNEL_PHYS_LOAD` twice, behind
`APP_S928_STABLE_RACE`: `0xa8000000` under the stable-race build and
`0x80080000` otherwise. The flattener reports the last unconditional branch, so
this row is a build-mode difference, not evidence that the physical load moved.

## Constant-delta clusters

| delta | count | members |
| ---: | ---: | --- |
| `-0xab78` | 6 | `ashmem_{ioctl, compat_ioctl, mmap, open, release, show_fdinfo}` |
| `-0x18e0` | 2 | `configfs_read_iter`, `configfs_bin_write_iter` |
| `-0x1fe00` | 2 | `init_task`, `system_unbound_wq` |
| `-0x1fe08` | 1 | `loggers[][]` — 8 bytes off the previous block |
| `-0x20c50` | 2 | `ashmem_misc + 0x10`, probe slot (derived from it) |
| `-0x21000` / `-0x21080` / `-0x21090` | 1 each | `root_task_group`, `sysctl_bootid`, `selinux_enforcing` |
| `-0x11cf0` | 1 | `ashmem_fops` (a `const` table, separate section from the text) |
| `-0x10fc0` | 1 | `anon_pipe_buf_ops` |
| `-0x14d60` | 1 | `kmalloc_caches` (per-cache array, moved with its slab init) |
| `-0x1484` | 1 | `copy_splice_read` |
| `-0xe78` | 1 | `noop_llseek` |
| `-0x214` | 1 | `call_usermodehelper_exec_work` |
| `-0x14225` | 1 | `nfulnl_logger` name string |
| `-0x207a8` | 1 | `random_table[]` `boot_id` data pointer |
| `-0x1fc` | 1 | worker caller — a function changed length between builds |

The singleton members are the interesting ones. They do not share a delta with
their section neighbours, which is normal (a function changed length), but it
means the cluster cannot be used to predict them. The Image is the only source.
Note that `loggers[][]` sits 8 bytes away from the `init_task` cluster: close
enough to look interchangeable, far enough that using the wrong one misses.

## Control: same build, different model

```text
B-ref (S928BXXS6DZF2) vs U1-ref (S928USQS6DZF2)
  same=173  differ=3
  SLIDE_BANK_SLOTS            4 -> 1
  SLIDE_S928_BANK_LOCK_MAX_BUCKET  27 -> 28
  SLIDE_NFULNL_LOGGER_OFF     0x016a622a -> 0x016a61b8  (-0x72)
```

Two of those three are exploit policy, not addresses. The one address that
moves, `nfulnl_logger`, moves by 0x72 on the *same* build, which is a reminder
that even a 114-byte difference is enough to break a leak. Nothing in a
same-build comparison can be assumed identical without checking the Image.

## A-only rows: 67

All 67 are exploit-policy flags and diagnostic switches introduced in the A
profile (`APP_EZIF_*`, `APP_FOPS_*`, `APP_P0_*`, `APP_CONTROLLED_*`,
`KERNELSNITCH_*`, `S918_*`, `SLIDE_PSELECT_*`, `TARGET_GUARD_*`). They are not
addresses, but they are not free choices either: each one changes the shape or
timing of the exploit. The B profile starts from A's effective set and keeps the
values that A's own port report identifies as load-bearing:

```c
APP_P0_RETRY_AFTER_WRITER        1
APP_TRACEFS_KASLR_DIRECT         1   /* also selects canonical FOPS addressing */
APP_CONTROLLED_MM_GROUP_RECLAIM  0
APP_REQUIRE_FRESH_P0_SESSION     0
APP_FOPS_DATA_ALIAS_DIAG_ONLY    0
APP_FOPS_DATA_ALIAS_GATE_VERIFY  0
APP_FOPS_REUSE_VERIFIED_PAGE     0
APP_FOPS_RESTORE_SLOT            1
```

`APP_P0_RETRY_AFTER_WRITER` is the one that must not be inherited from the
upstream default: without it a failed first draw ends the boot, and the
supervisor's 24 attempts become one.

## B-only rows: 1

`BUILD_FINGERPRINT` — DZF2 puts the identity string in this macro. The N EZIF
profile instead carries identity in `TARGET_GUARD_MODEL`, `TARGET_GUARD_BUILD`,
`TARGET_GUARD_FINGERPRINT` and `TARGET_GUARD_KERNEL`, which the payload checks at
runtime. This port follows the N layout, so the B profile uses the guard macros
and does not define `BUILD_FINGERPRINT`.

## What this means for B

The template is A. Of A's 175 effective macros, 146 are structurally identical
and stay as they are. Of the 29 that differ from DZF2, the three that could be
closed without firmware are identity, `P0_PHYS_OFFSET`, and the event ID; the
worker caller was constrained by the tracefs capture. Everything else in the
symbol and layout classes had to be re-derived from the target Image.

## Closure against B EZIF

The tables above compare A with **B-ref (DZF2)**; they are not predictions for
**B EZIF**. The exact B EZIF Image was subsequently downloaded and every symbol
row was re-derived from it:

| Property | Value |
| --- | --- |
| Image | `out/kernel`, 38,140,416 bytes |
| SHA-256 | `a8c1638497ca1bff576c5a6d9426521ec545fd68da8ce5dfa47c40233391a179` |
| Symbols | kallsyms, base-relative, 107568 entries, relative base `0xffffffc008000000` |
| Types | BTF blob at image offset 0x1820e90 |
| Frames | `llvm-objdump` over a flat ELF wrapper |

Result: **22 of 23 inherited symbol values matched the B EZIF Image exactly**,
including all eight `ashmem_*` entries, both configfs iterators, both workqueue
anchors, `selinux_state`, `kmalloc_caches`, `anon_pipe_buf_ops`, the random-table
boot-id pointer and the sysctl anchor. The build id did turn out to describe the
same text layout. The worker caller, verified live earlier, also matches its own
disassembly (`worker_thread+0xa0`).

One row did not match:

| Macro | Inherited (A) | B EZIF | Cause |
| --- | --- | --- | --- |
| `SLIDE_NFULNL_LOGGER_OFF` | 0x016ba44f | **0x016ba45d** | `nfulnl_logger.name` is `base+0x016ba45d`; 0x016ba44f is 14 bytes early, inside the preceding `"packet message\n"` string |

The 14-byte error is not cosmetic. `slide_read_stext` computes
`stext = leaked - off`; with the inherited value it would return `real_stext+14`,
which fails `slide_commit_stext`'s `(slide & 0x7fff) == 0` test on every attempt.
This is the strongest argument against inheriting a symbol table on a shared KMI
build id: 23 values were identical, and the one that was not would have failed
silently at the alignment check rather than at a symbol.

The other classes closed the same way:

- **struct layout** — BTF confirms `rt_mutex_waiter` (0x58 bytes, exact field
  offsets), the eight `task_struct` fields used by the fake task,
  `file_operations`, `configfs_buffer`, the workqueue structs, `pipe_buffer`,
  `struct page` (0x40) and the `struct slab` overlay. `mm_struct` is 0x3c0 in
  BTF; the 0x400 macro is the slab stride, not `sizeof`.
- **slide** — `SLIDE_PSELECT_WORD_SHIFT = 3` follows from the Image's own frames:
  the requeue waiter is at `pt_regs-0x1e8`, the `core_sys_select` fd-set buffer
  at `pt_regs-0x200`.
- **fingerprint** — generated at probe 0x1f0000, regeneration byte-identical,
  generator re-reads 32 rows and 256 source qwords.
- **physical** — `P0_KERNEL_PHYS_LOAD` remains the only inherited value with no
  proof, because the live shell cannot read `/proc/iomem` or `/proc/cmdline` and
  the BL payload exposes no literal.

`docs/PORT-STATUS.md` carries the per-row table and the reproduction commands.

## Reproduce

```sh
tools/port_diff.py \
  --a <N>/ezif_layout.h --a <N>/target.h \
  --b <DZF2>/target.h \
  --label N->B_ref --clusters

tools/port_diff.py \
  --a <DZF2>/target.h --b <U1>/target.h \
  --label B_ref->U1_ref
```
