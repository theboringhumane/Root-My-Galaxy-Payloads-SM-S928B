# Root My Galaxy payload · SM-S928B / S928BXXU6EZIF

Port of the CVE-2026-43499 app payload to the Galaxy S24 Ultra `SM-S928B`
(product `e3q`, CSC `INS`), firmware `S928BXXU6EZIF`, Android 17 — plus the
method and tooling used to derive it from the validated `SM-S928N`
`S928NKSU6EZIF` profile.

> [!CAUTION]
> **Status: not built, not run, not rooted.**
>
> The profile's symbol offsets, struct offsets and P0 fingerprint are derived
> from the exact `S928BXXU6EZIF` kernel Image. One value — the physical load
> address — is declared by the shipped bootloader's memory map but has not been
> read from a running boot, so `target.h` contains an `#error` that refuses to
> compile. Do not remove it to "see what happens": a kernel exploit with the
> wrong physical anchor writes to a real address that is not the symbol, and the
> usual result is a panic.
>
> When it is finished, it will still be a kernel exploit. A failed attempt can
> panic and reboot the phone. Nothing here is signed, supported, or guaranteed.

## Target identity

| Property | Value |
| --- | --- |
| Model / sales code | `SM-S928B` / `INS` |
| Device | `e3q` |
| Firmware PDA / CSC | `S928BXXU6EZIF` / `S928BOXM6EZIF` |
| Fingerprint | `samsung/e3qxins/e3q:17/CP2A.260605.016/S928BXXU6EZIF:user/release-keys` |
| Display build | `CP2A.260605.016.S928BXXU6EZIF` |
| Android / SDK | 17 / 37 |
| Kernel release | `6.1.162-android14-11-34343818-abS928BXXU6EZIF` |
| KMI | `android14-6.1`, AArch64, `_text = 0xffffffc008000000` |
| Security patch | `2026-09-05` |

The reference profile is `SM-S928N` / `S928NKSU6EZIF`: same SoC family, same
KMI, same build id `34343818`, same Android 17 release. Only the model segment
and the kernel localversion suffix differ. That made a symbol-level port worth
attempting, and against the B Image 22 of 23 inherited symbol values did match;
the 23rd (`nfulnl_logger`'s name string) was 14 bytes off, which is more than
enough to break the slide leak.

## Where the port stands

| Item | Status |
| --- | --- |
| Device identity, build, kernel release | measured on the handset |
| `P0_PHYS_OFFSET = 0x816e0000` | measured without root (`/proc/zoneinfo`) |
| `SLIDE_TRACEFS_EVENT_ID = 106` | measured without root (tracefs) |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF = 0xdb39c` | verified by disassembly and the live raw-tracefs capture |
| 23 inherited symbol offsets | re-derived from the B Image: 22 identical, one corrected by 14 bytes |
| `SLIDE_PSELECT_WORD_SHIFT = 3` | derived from the Image's futex/pselect frames |
| struct layout (`task_struct`, waiter, fops, page, workqueue, …) | confirmed against the Image's BTF |
| `p0_fingerprint.h` | generated from the Image at probe `0x1f0000`; regeneration byte-identical |
| `P0_KERNEL_PHYS_LOAD` | declared `0xa8000000` by the BL's XBL memory map (`Kernel` region); not yet read from a running boot |
| Payload build | blocked: no NDK on the build host, and the gate is closed |
| KernelSU daemon | not started |

The full row-by-row ledger, with what would falsify each value, is
[`docs/PORT-STATUS.md`](docs/PORT-STATUS.md). The measured readings are in
[`evidence/`](evidence/), including the raw-tracefs decode.

## Why a port and not a copy

Nothing in a target profile transfers by model similarity alone. Two shipped
profiles for this device family, one Android release apart, differ in 29 of 175
macros, and those 29 move in constant-delta clusters that only make sense once
you know which linker section each symbol lives in. Two profiles for the *same*
build on different models differ in three rows — one of which is a 114-byte
symbol offset, which is more than enough to break a leak.

[`docs/DELTA.md`](docs/DELTA.md) is the triage record: the full 29-row table, the
cluster analysis, and the same-build control that proves the delta is
build-level, not model-level.

[`docs/METHOD.md`](docs/METHOD.md) is the reusable procedure: flatten both
profiles to key/value, set-diff, classify each delta by how it fails, group
constant-delta clusters into relocation hypotheses, re-derive from the target's
own Image, overlay instead of forking, gate the build on the ledger, and close
what the phone can tell you without root before letting it write anything.

## Repository layout

```text
src/                         shared exploit sources (unmodified upstream)
src/targets/e3q-S928BXXU6EZIF/
  target.h                   identity, symbols, policy flags, build gate
  ezif_layout.h              physical anchors, struct layout, payload placement
  p0_fingerprint.h           generated table from the B Image
tools/port_diff.py           flatten and diff two target profiles
tools/parse_raw.py           decode sched_blocked_reason out of raw tracefs pages
tools/verify-tracefs.sh      capture and check the worker caller on a live phone
tools/fusfetch/              fetch + decrypt a byte range from Samsung FUS
tools/extract_image.py       pull boot.img.lz4 and the kernel Image out of a prefix
tools/inspect_image.py       read kallsyms and BTF out of the stripped Image
tools/dtb_dump.py            walk an FDT embedded in a firmware image
tools/generate_p0_fingerprint.pl   build the P0 table from the raw Image
tools/layout_check.c         compile-time check of the profile's geometry
docs/                        method, delta record, status ledger
evidence/                    what was measured, with commands and outputs
```

## Finishing the port

The image-derived work is complete: the FUS prefix was fetched, `boot.img.lz4`
and the Image were extracted, symbols and BTF were read from the Image, the frame
arithmetic was disassembled, and the P0 table was generated and re-read. The
per-value evidence and commands are in
[`docs/PORT-STATUS.md`](docs/PORT-STATUS.md).

What remains:

1. confirm `P0_KERNEL_PHYS_LOAD` on a running boot (root-side `/proc/iomem`, or
   the physical P0 oracle); the BL memory map names the `Kernel` region at
   `0xa8000000` ([`evidence/xbl-memorymap.md`](evidence/xbl-memorymap.md)) and
   it is clear of every reserved-memory carve-out
   ([`evidence/dtbo-reserved.md`](evidence/dtbo-reserved.md));
2. build the payload with an NDK, which the current host does not have;
3. validate on the handset incrementally: reclaim, physical oracle, waiter
   rewrite, FOPS readback, `selinux_enforcing`;
4. rebuild KernelSU for this vermagic and publish a hashed artifact before
   adding a `support/targets-v3.json` entry.

Runtime identity is **not** enforced by the shared payload: it does not read the
`TARGET_GUARD_*` macros or call `getprop`. Those macros are the recorded contract
for whatever loads the payload, and the build gate plus `tools/layout_check.c`
are the only automatic checks in this repository. Confirm the model, build,
fingerprint, kernel release and patch level yourself before running anything.

## Rules for this port

- Do not reuse these offsets on another model or build. Every one of them is
  specific to a kernel Image.
- Do not widen the identity fields to make the profile load somewhere else.
- Do not remove the `#error` without closing the corresponding row in
  `docs/PORT-STATUS.md`.
- Do not commit firmware, boot images, dumped kernel memory, device serials,
  boot IDs, or anything read from `/data` on a real handset.

## Licence and attribution

The exploit sources in `src/` and `tools/generate_p0_fingerprint.pl` are from
BuSung's [Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads),
Apache-2.0. The SM-S928N profile this port starts from is the published record in
[zimza1abim/Root-My-Galaxy-Payloads-SM-S928N](https://github.com/zimza1abim/Root-My-Galaxy-Payloads-SM-S928N).
This repository adds the SM-S928B target directory, the porting tools, and the
records under `docs/` and `evidence/`. See [`NOTICE`](NOTICE) for the exact split.

Use only on a device you own or are authorised to test.
