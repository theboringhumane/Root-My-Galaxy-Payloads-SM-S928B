Porting method: config tree A to config tree B
==============================================

The question this repo answers: given a working exploit profile for hardware
variant A, what is the disciplined way to produce the profile for closely
related variant B, without copying addresses that look right and are not?

The workflow below is the one that produced the files here. It is written for C
macros because a kernel target profile is a flat set of `#define`s, but the same
nine steps apply to a JSON device tree, a register map, or a board file. The
mechanical rule is identical in every case: **treat both sides as flat
key/value tables, diff the tables, and classify every delta before touching a
single value.**

## 0. Ground truth per variant, before diffing anything

Collect the identity of each side from the device or the shipped firmware, not
from memory or from the other profile:

| Field | Source |
| --- | --- |
| model, device, sales code | `ro.product.model`, `ro.product.device` |
| build id, fingerprint | `ro.build.display.id`, `ro.build.fingerprint` |
| Android release, SDK | `ro.build.version.release`, `.sdk` |
| kernel release | `uname -r` |
| security patch | `ro.build.version.security_patch` |
| page/VA/PA geometry | `/proc/config.gz` |

If the two sides differ in SoC vendor, KMI, or build id, stop: this is a new
port, not a variant port. This target shares `34343818` with the reference, so
a symbol-level port is worth attempting; that is the only reason the rest of
this method applies. See `evidence/live-probes.md`.

## 1. Normalize both sides into flat key/value form

C headers are hierarchical only visually. Continuation lines, `#undef`,
conditional blocks and expression-valued macros all have to be resolved before a
diff means anything. `tools/port_diff.py` does that:

- joins backslash continuations;
- applies `#undef` and redefinition in file order, later wins;
- strips integer suffixes and normalizes hex/decimal for comparison;
- keeps the raw text for the report, compares the parsed value.

Run it on a header pair:

```sh
tools/port_diff.py \
  --a /path/to/A/ezif_layout.h --a /path/to/A/target.h \
  --b /path/to/B/target.h \
  --label A->B --clusters
```

If the source is JSON, the same shape is one `jq` expression, and `paths` gives
the flattened key set:

```sh
jq -r 'paths(scalars) | map(tostring) | join(".")' a.json | sort > a.keys
jq -r 'paths(scalars) | map(tostring) | join(".")' b.json | sort > b.keys
comm -3 a.keys b.keys
```

The output of this step is not a diff yet. It is a ledger of three sets:
keys on both sides, keys only in A, keys only in B.

## 2. Set-diff, then triage by class

A raw value diff produces noise: two numbers that differ because the firmware
moved, and two numbers that differ because they mean different things. Every key
is therefore assigned a class, in this order:

| class | examples | what a delta means |
| --- | --- | --- |
| identity | `TARGET_GUARD_MODEL`, fingerprint | must differ; never ported |
| physical | `P0_PHYS_OFFSET`, `P0_KERNEL_PHYS_LOAD` | measured per device or per boot chain |
| symbol | `ASHMEM_*_OFF`, `INIT_TASK_OFF` | text/data layout; re-derive from B's Image |
| layout | `task_struct.pi_lock`, `sizeof(struct page)` | ABI; only changes with the KMI |
| slide | `SLIDE_TRACEFS_EVENT_ID`, `SLIDE_PSELECT_WORD_SHIFT` | kernel behaviour; verify per build |
| flag | `APP_*`, exploit policy | not an address; port only with a reason |

The classes matter because they fail differently. A wrong identity field refuses
to run. A wrong physical value sends reads to a real but unrelated page. A wrong
symbol offset writes to a real address that is not the symbol. A wrong struct
offset corrupts a field next to the intended one. Sorting the diff by class is
what turns "29 differences" into "four clusters and one decision".

## 3. Look for constant-delta clusters before looking at single values

Linker sections move as blocks. In this port the 29 differences collapsed into:

| delta | members |
| --- | --- |
| -0xab78 | six of the eight `ashmem_*` text entries |
| -0x18e0 | both `configfs_*` iterators |
| -0x1fe00 / -0x1fe08 | `init_task`, `system_unbound_wq`; `loggers[][]` 8 bytes apart |
| -0x21000 .. -0x21090 | `root_task_group`, `selinux_enforcing`, `sysctl_bootid` |
| -0x20c50 | `ashmem_misc + 0x10` and the probe slot |

Two members that should be contiguous but disagree by a few hundred bytes are a
better signal than any single mismatch: it means one of them was re-derived at a
different time, or a conditional `#define` changed between the two sides. That
is exactly what happened with `P0_KERNEL_PHYS_LOAD` in the reference profile,
which has two values behind `APP_S928_STABLE_RACE` and looked like a real delta
until the conditional was read.

`--clusters` prints this grouping. A cluster is a hypothesis, not a result: it
tells you which region moved together, and the Image then confirms or refutes
each member.

## 4. Use base + offset, not a copied table

A symbol offset is `symbol_address - KIMAGE_TEXT_BASE` from B's own Image. The
only legitimate shortcut is when B's Image is not available yet: then the A
value is an explicitly labelled *inherited candidate*, which is what the
`target.h` here contains and why it is fenced by `#error`.

The pipeline, from the upstream porting guide in `docs/` of the reference
project, is:

```text
AP tar -> boot.img.lz4 -> lz4 -d -> boot header v4
       -> kernel_size at 0x08, Image at 0x1000
       -> vmlinux-to-elf -> llvm-nm -> offsets
```

`tools/fusfetch` fetches only the head of the FUS package, because a full AP
plus its decrypted copy is roughly twice the archive size; `tools/extract_image.py`
walks the ZIP and tar inside that prefix and slices the Image out of the boot
header. Neither tool is used yet for this target: no `S928BXXU6EZIF` Image has
been downloaded in this work.

## 5. Overlay, do not fork

The B profile is A's shared exploit code plus a target directory. Source files
stay identical, and the target directory carries every firmware-dependent value:

```text
src/targets/<device>-<build>/target.h           symbols, identity, flags
src/targets/<device>-<build>/ezif_layout.h      physical constants, struct layout
src/targets/<device>-<build>/p0_fingerprint.h   generated table
```

The Makefile selects it with `TARGET=`, and `src/offset.h` includes
`targets/$(TARGET)/target.h`. A second copy of the exploit source is how ports
drift: a bug fixed upstream never reaches the fork.

## 6. Mechanical validation before any device run

Checks that need no phone:

- **alignment** — every text offset is 4-byte aligned; every physical anchor is
  page aligned;
- **range** — every `*_OFF` is inside `[0, image_size)`; every slide candidate is
  a multiple of 64 KiB;
- **no overlap** — payload placement constants (bank slots, fake waiter, fops
  page) do not collide;
- **reserved collision** — `P0_KERNEL_PHYS_LOAD` does not fall inside a
  reserved-memory region from the vendor DTB;
- **struct arithmetic** — a member offset plus its size stays inside the struct,
  and the fake-object layout covers every field the exploit writes;
- **fail-closed gate** — the profile cannot build while a required value is
  marked unverified.

The gate is deliberate and is the reason this repo's B target has an `#error`:
building an unverified profile is how phones get panicked, and a compile-time
stop is cheaper than a readback that returns an unrelated page.

## 7. On-target incremental verification

Only values that can be read without root are closed this way:

| value | oracle | result |
| --- | --- | --- |
| `P0_PHYS_OFFSET` | `/proc/zoneinfo` `start_pfn` | 0x816e0000 |
| `SLIDE_TRACEFS_EVENT_ID` | `events/sched/sched_blocked_reason/id` | 106 |
| worker caller | `per_cpu/*/trace_pipe_raw` | consistent with 0xdb39c |
| VA/PA geometry | `/proc/config.gz` | 39 / 48 |
| DMA32 presence | `/proc/zoneinfo` | zone exists, 0 pages |

Each one is a *constraint* on the Image-derived result, not a replacement for
it. The tracefs check is a good example of the difference: the raw caller
address only constrains the low 16 bits, because the slide is unknown, so it
confirms the bucket and nothing more.

## 8. Keep a provenance ledger per value

Every number in the profile should answer "where did this come from". The three
labels this port uses:

- **measured** — read from this device or this Image, with the command recorded;
- **inherited** — taken from the reference profile, deliberately, with the reason
  stated and the risk named;
- **pending** — not established; blocks the build.

`docs/PORT-STATUS.md` is that ledger. It is the file to read before changing a
value, because it records not just what is known but what would falsify it.

## 9. Do not trust a reference table you did not regenerate

Two shipped profiles in the reference project for the same device family, on
different Android releases (`BP4A`/16 and `UP1A`/14), carry a byte-identical
`p0_fingerprint.h`. A 2 MiB sweep of a kernel Image is not identical across two
Android releases. At least one of those tables was copied rather than generated,
which is precisely the failure this method exists to prevent. A fingerprint
table is cheap to regenerate with `tools/generate_p0_fingerprint.pl`; treat any
inherited table as unverified input.

## The one-line summary

Normalize to flat key/value, diff, classify each delta by how it fails, group
constant-delta clusters into relocation hypotheses, re-derive from B's own image,
overlay instead of forking, gate the build on the ledger, and verify what the
phone can tell you without root before you let it write anything.
