# Port status: SM-S928B / S928BXXU6EZIF

**Status: not built, not run, not rooted.** The target is scaffolded and
fail-closed. This file is the ledger: every value is labelled measured, inherited
or pending, and the gate in `target.h` refuses to compile while anything required
is pending.

Do not remove the gate to "try it". A profile with inherited symbol offsets writes
to real kernel addresses that are not the symbols; the failure mode is a panic,
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

## Values closed without root

| Value | Status | Evidence |
| --- | --- | --- |
| `P0_PHYS_OFFSET = 0x816e0000` | measured | `/proc/zoneinfo`, `start_pfn 530144` (`evidence/live-probes.md`) |
| `KIMAGE_TEXT_BASE = 0xffffffc008000000` | measured | `CONFIG_ARM64_VA_BITS=39`, 6.1 text placement |
| `SLIDE_TRACEFS_EVENT_ID = 106` | measured | tracefs `sched_blocked_reason/id` |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF = 0xdb39c` | constrained, not proven | raw ring buffer: only 0xb39c-bucket caller, 147/358 events (`evidence/trace-callers.txt`) |
| `MM_STRUCT_SZ`, `SKB_DATA_DELTA`, waiter/task offsets | inherited | same KMI build; still require BTF confirmation |
| `P0_KERNEL_PHYS_LOAD = 0xa8000000` | **candidate, pending** | inherited from DZF2; see below |

`P0_PHYS_OFFSET` is `memstart_addr`, not a DRAM base. The value matches the
reference profile exactly, which is expected on the same platform binary, and it
is readable without root, so it does not need the firmware download.

`P0_KERNEL_PHYS_LOAD` cannot be closed from `memstart`: DZF2 pairs `0xa8000000`
with `memstart 0x80000000` (+0x28000000), and this device's `memstart` is
`0x816e0000`, so the same delta would give `0xa96e0000`. The load address is a
property of the boot chain, and has to be read from this build's BL archive
(`sboot.bin`/ABL), not inferred.

## Pending: needs the `S928BXXU6EZIF` Image

Downloading has not been done yet. The pipeline is prepared but unexecuted:

```sh
# 1. head of the exact package (AP entry is stored; boot.img.lz4 sits near its start)
cd tools/fusfetch && cargo build --release
./target/release/fusfetch \
  --model SM-S928B --region INS \
  --version S928BXXU6EZIF/S928BOXM6EZIF/S928BXXU6EZIF/S928BXXU6EZIF \
  --bytes 268435456 --out prefix.dec

# 2. list what the prefix contains, then extract boot.img.lz4
tools/extract_image.py prefix.dec scan
tools/extract_image.py prefix.dec extract --tar-hint AP --image boot.img.lz4 --outdir out

# 3. decompress boot.img and slice the Image out of page 1
tools/extract_image.py - kernel --image out/boot.img.lz4 --outdir out

# 4. symbols
vmlinux-to-elf out/kernel out/vmlinux.elf
llvm-nm --numeric-sort out/vmlinux.elf > out/vmlinux.nm

# 5. BTF (raw blob inside the Image; validate the full header, not the magic alone)
#    magic 9f eb 01 00, version 1, hdr_len >= 24, NUL at start of string section
bpftool btf dump file out/vmlinux.btf format raw > out/btf.raw

# 6. P0 fingerprint, 8 qwords per 64 KiB page over the first 2 MiB
tools/generate_p0_fingerprint.pl out/kernel 0x1f0000 out/p0_fingerprint.h
```

Rows still open after that:

| Value | How it is closed |
| --- | --- |
| 21 `*_OFF` symbol offsets | `llvm-nm` on `out/vmlinux.elf`, minus `KIMAGE_TEXT_BASE` |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | `llvm-objdump -d worker_thread`, address after the blocking `bl schedule` |
| `SLIDE_PSELECT_WORD_SHIFT` | frame delta between the requeue waiter and `core_sys_select` fd-set |
| `sizeof`/member offsets in `ezif_layout.h` | raw BTF dump |
| `p0_fingerprint.h` | generated, then read all 256 source qwords back from the Image |
| `P0_KERNEL_PHYS_LOAD` | disassemble the BL load path; `text_offset` is 0, so load = branch target minus 0x80000000 mapping |
| `SLIDE_BANK_SLOTS` and bank geometry | inherited; re-check against the reclaimed page layout |

## Offline gate

The target builds only when all of these are true:

1. `#error` removed **and** `ALLOW_UNVERIFIED_S928B` is unnecessary because every
   pending row above is measured;
2. generated fingerprint table matches the Image it was generated from (re-read
   verification, not just generation);
3. symbol offsets are inside the Image and 4-byte aligned;
4. `P0_KERNEL_PHYS_LOAD` is page aligned and does not fall in a reserved-memory
   region from the vendor DTB;
5. struct offsets keep every fake object inside its page;
6. release payload is exactly 104128 bytes.

## Build

```sh
make TARGET=e3q-S928BXXU6EZIF ANDROID_NDK_HOME=/path/to/ndk release
```

`ANDROID_NDK_HOME` is currently the blocker on the host used for this work; no
NDK is installed, so no artifact exists.

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

- no firmware downloaded, no Image extracted, no symbol or fingerprint derived;
- no payload built, loaded or executed; no root attempted;
- no `support/targets-v3.json` entry, because that feed entry requires a built,
  hashed artifact;
- structure offsets are not yet confirmed against this build's BTF.

## Next step

Run the five commands above. The first commit that changes a value in
`src/targets/e3q-S928BXXU6EZIF/` will carry the Image identity (size and
SHA-256) so the derived offsets can be checked against the exact source.
