# Root My Galaxy payload · SM-S928B / S928BXXU6EZIF

Port of the CVE-2026-43499 app payload to the Galaxy S24 Ultra `SM-S928B`
(product `e3q`, CSC `INS`), firmware `S928BXXU6EZIF`, Android 17 — plus the
method and tooling used to derive it from the validated `SM-S928N`
`S928NKSU6EZIF` profile.

> [!CAUTION]
> **Status: not built, not run, not rooted.**
>
> This target profile is a fail-closed scaffold. Symbol offsets are inherited
> from the SM-S928N build and are **not verified** against this kernel, and the
> P0 fingerprint table has not been generated. `target.h` contains an `#error`
> that refuses to compile until that changes. Do not remove it to "see what
> happens": a kernel exploit with the wrong offsets writes to a real address that
> is not the symbol, and the usual result is a panic.
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
and the kernel localversion suffix differ. That is what makes a symbol-level port
worth attempting — and it is not proof that the text layout is identical.

## Where the port stands

| Item | Status |
| --- | --- |
| Device identity, build, kernel release | measured on the handset |
| `P0_PHYS_OFFSET = 0x816e0000` | measured without root (`/proc/zoneinfo`) |
| `SLIDE_TRACEFS_EVENT_ID = 106` | measured without root (tracefs) |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF = 0xdb39c` | consistent with a live raw-tracefs capture; still to be confirmed by disassembly |
| 21 symbol offsets (`ashmem_*`, `configfs_*`, `init_task`, …) | inherited from SM-S928N, unverified |
| `p0_fingerprint.h` | not generated |
| `P0_KERNEL_PHYS_LOAD` | candidate `0xa8000000`, not measured |
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
  p0_fingerprint.h           generated table — currently a hard #error
tools/port_diff.py           flatten and diff two target profiles
tools/parse_raw.py           decode sched_blocked_reason out of raw tracefs pages
tools/verify-tracefs.sh      capture and check the worker caller on a live phone
tools/fusfetch/              fetch + decrypt a byte range from Samsung FUS
tools/extract_image.py       pull boot.img.lz4 and the kernel Image out of a prefix
tools/generate_p0_fingerprint.pl   build the P0 table from the raw Image
docs/                        method, delta record, status ledger
evidence/                    what was measured, with commands and outputs
```

## Finishing the port

The remaining work is deliberately mechanical and all of it needs the exact
firmware image. The commands are in
[`docs/PORT-STATUS.md`](docs/PORT-STATUS.md#pending-needs-the-s928bxxu6ezif-image);
the short version is: fetch the head of the FUS package, extract
`boot.img.lz4`, decompress and slice the Image, recover symbols with
`vmlinux-to-elf`, dump BTF, generate the P0 table, close
`P0_KERNEL_PHYS_LOAD` from the BL load path, then build and validate on the
handset. Each of those steps lands as its own commit with the Image size and
SHA-256 that produced it.

Runtime identity is **not** enforced by the shared payload: it does not read the
`TARGET_GUARD_*` macros or call `getprop`. Those macros are the recorded contract
for whatever loads the payload, and the build-time gate is the only automatic
check in this repository. Confirm the model, build, fingerprint, kernel release
and patch level yourself before running anything.

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
