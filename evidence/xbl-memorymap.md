P0_KERNEL_PHYS_LOAD: the XBL memory map
=======================================

Target : SM-S928B, S928BXXU6EZIF
Image  : out/kernel, image_size 0x2710000 (38,140,416 bytes)
Method : stream the BL tar out of the decrypted FUS prefix, decompress
         xbl_config.elf, parse its embedded FDTs, and read the
         /soc/memorymap the XBL firmware hands to the UEFI boot chain; then
         follow the UEFI driver that publishes the map's Kernel region into
         the variables LinuxLoader reads.

Access : offline.  Nothing was read from the running phone for this file; the
         one live number quoted below (/proc/zoneinfo) was measured earlier and
         is already recorded in evidence/live-probes.md.

Sources
-------

The BL member of the S928BXXU6EZIF FUS package:

  BL_S928BXXU6EZIF_S928BXXU6EZIF_MQB115064488_REV00_user_low_ship_MULTI_CERT

`tools/extract_image.py` already walks a stored tar in place and inflates a
deflated one, so no ad-hoc unzip is needed:

  $ tools/extract_image.py prefix.dec stream --tar-hint BL \
      --image xbl_config.elf.lz4 --outdir out
  inflating 268435324 compressed package bytes from the prefix
  found xbl_config.elf.lz4 (80806 bytes)
  wrote out/xbl_config.elf.lz4 (80806 bytes,
    sha256 9b044e54134178f309f9d46890303683c74d7e959f6d3a5c991b06252b1854ae)
  $ lz4 -d out/xbl_config.elf.lz4 out/xbl_config.elf
  $ sha256sum out/xbl_config.elf
  a4768cb8da8eb50a5a9268483b3c8b94f3582ec81b14868ced23d214cdb4e4ea

The result is 227,980 bytes.  Both files are firmware and are not committed.

Two FDTs are embedded, both rooted at `compatible = "qcom,lanai"`:

  $ tools/dtb_dump.py out/xbl_config.elf --scan
  0x00cb18  totalsize 0x75ac (30124 bytes)
  0x0140c4  totalsize 0x125f7 (75255 bytes)

Only the second carries `/soc/memorymap`; the first is the short board
fragment.  `tools/dtb_dump.py` was added with this record.

  $ tools/dtb_dump.py out/xbl_config.elf --offset 0x140c4 \
      --path /soc/memorymap

The kernel region
-----------------

The node that matters, quoted verbatim from that command:

  /soc/memorymap/memory@A8000000
    device_type = "memory"
    reg = <0x00000000 0xa8000000 0x00000000 0x10000000>
    MemLabel = "Kernel"
    ResourceAttribute = <0x00703c07>
    CacheAttributes = <0x22000000>

Decoded with the node's own `#address-cells = 2` / `#size-cells = 2`:

  Kernel region   0xa8000000 + 0x10000000   (256 MiB)
  Image span      0xa8000000 + 0x2710000    (41 MiB, fits with 215 MiB spare)

0xa8000000 is 2 MiB aligned.  This is the same value the B profile inherited
from the validated S928N profile, and it is the only region in this memory map
labelled `Kernel`.

The whole boot-time map, in address order (start + size, MemLabel):

  0x80000000 + 0x016e0000  NOMAP            no-map, not linear-mapped
  0x816e0000 + 0x00320000  RSRV0            first mapped page
  0x81a00000 + 0x00040000  XBL_DT
  0x81a40000 + 0x001c0000  XBL_Ramdump
  0x81c00000 + 0x000a0000  AOP
  0x81ce4000 + 0x00010000  UEFI_Log
  0x81d00000 + 0x00200000  SMEM
  0x824a0000 + 0x00100000  PvmFw
  0x8bc00000 + 0x16f80000  PIL_Reserved
  0xa3600000 + 0x02b00000  Display_Demura
  0xa6100000 + 0x00f00000  DBI_Dump
  0xa7000000 + 0x00400000  UEFI_FD
  0xa7400000 + 0x00200000  UEFI_FD_Reserved
  0xa7600000 + 0x00001000  CPU_Vectors
  0xa7601000 + 0x00001000  Info_Blk
  0xa7602000 + 0x00003000  MMU_PageTables
  0xa7605000 + 0x00008000  Log_Buffer
  0xa760d000 + 0x00040000  UEFI_Stack
  0xa764d000 + 0x0008c000  SEC_Heap
  0xa76d9000 + 0x00400000  Sched_Heap
  0xa7ad9000 + 0x00400000  FV_Region
  0xa7ed9000 + 0x00127000  UEFI_RESV
  0xa8000000 + 0x10000000  Kernel
  0xb8000000 + 0x1ba00000  DXE_Heap
  0xd5100000 + 0x02b00000  Display_Reserved
  0xd8800000 + 0x1b000000  TZApps_Reserved
  0xf3800000 + 0x04400000  DARE
  0x880000000 + 0x0b000000 SEC_Debug

Cross-checks
------------

1. Low boundary.  This map starts linear-mapped memory at 0x816e0000, and the
   live kernel agrees: `/proc/zoneinfo` reports `zone Normal start_pfn: 530144`
   = 0x816e0000 (evidence/live-probes.md).  That is also why `P0_PHYS_OFFSET`
   is 0x816e0000 and not the 0x80000000 that the vendor DT's gunyah node
   suggests: 0x80000000..0x816e0000 is the map's `NOMAP` region.

2. High boundary.  `UEFI_RESV` ends at 0xa7ed9000 + 0x127000 = 0xa8000000, so
   the `Kernel` region starts exactly where the firmware's own last reserved
   block ends.  There is no gap and no overlap.

3. Boot chain.  `UEFI_FD` is 0xa7000000 + 0x400000, and the UEFI image in the
   same BL package has VMA 0xa7000000 with a 0x2f0000 segment, which fits
   inside it.  `FV_Region` at 0xa7ad9000 matches the ABL firmware-volume
   placement used by the boot chain.  The map is not a generic platform
   template; it describes this package.

4. Linux DT.  The DTBO overlay's `sec_xbl_ramdump@A7D00000` ends at 0xa8000000,
   and no reserved-memory carve-out in any of the 22 base DTBs or 10 overlays
   overlaps [0xa8000000, 0xaa710000) (evidence/dtbo-reserved.md).  The kernel
   region does not collide with anything the kernel's own DT reserves.

5. Size and alignment.  The 41 MiB Image fits the 256 MiB region, and the base
   is 2 MiB aligned, which is the placement the arm64 Image header allows
   (`text_offset = 0`, `flags = 0xa`).

How the loader uses it
----------------------

`abl.elf` in the same BL tar is an ELF32 container whose inner firmware volume
carries the LinuxLoader PE32+ image (`ImageBase` 0, starting at +0xed0e8 in the
decompressed ABL).  Its boot path was read with a disassembler:

- It reads two Samsung UEFI variables through `gRT->GetVariable`
  (`[gRT + 0x48]`) under GUID 882f8c2b-9646-435f-8de5-f208ff80c1bd:
  `KernelBaseAddr` (string at 0xd7f1c) and `KernelSize` (0xd80fe).
- Success path at 0x1792c: `[sp+0x88] = KernelBaseAddr`, then either
  `+ text_offset` read from the arm64 header at the source kernel offset, or
  the constants 0x8000 / 0x80000 when that header is not recognised;
  `[sp+0x90] = KernelBaseAddr + KernelSize`.
- Fallback when the variables are absent: the minimum base of a memory table
  obtained through a Samsung UEFI protocol, OR'ed with 0x8000 or 0x80000, and
  a size of 0x3c00000 or 0x5600000.

The ABL firmware volume stores its apps compressed, and the extracted
LinuxLoader's boot path materialises no `0xa8000000` immediate: the address is
not baked into loader code.  It is authored by XBL in this memory map and passed
through the UEFI variables.  For this Image `text_offset` is 0, so a
`KernelBaseAddr` branch would place the Image file's first byte at the variable
value itself, and the map names that value 0xa8000000.

Who writes the variables
------------------------

`uefi.elf` in the same BL tar is the `UEFI_FD` image: one ELF segment at file
0x1000, VMA 0xa7000000, size 0x2f0000.  Its first firmware volume starts at
file 0x1000 (`FvLength` 0x2f0000, header 0x48), and the files chain as:

  0x01fe8  SEC       0x4f018
  0x51000  FREEFORM  0x00f7a   section name `uefiplat.cfg`, raw `uefiplatLA.cfg`
  0x51f80  FV_IMAGE  0x17112a  GUID-defined section, gzip payload at 0x51fb0
  0x1c30b0 FV_IMAGE  0x1273ff  same section GUID, gzip payload at 0x1c30e0

Both FV images carry the same GUID-defined section header
(`1d301fe9-be79-4353-91c2-d23bc959ae0c`, data offset 0x18, attributes 1) and a
payload beginning `1f 8b 08`: they are gzip streams, inflated with the Python
standard library.  The first gives 0x446008 bytes and a DXE volume at +0x8; one
of its drivers is the FFS file at +0x356660 (GUID
5a50aa81-c3ae-4608-a0e3-41a2e69baf94, stored as the EFI_GUID fields
`81 aa 50 5a ae c3 08 46 a0 e3 41 a2 e6 9b af 94`, 0x26038 bytes), a PE32+
image starting at +0x24.

That driver carries the Samsung GUID at VA 0x23078 and two adjacent UTF-16
names at 0x1c428 / 0x1c446: `KernelBaseAddr` and `KernelSize`.  gRT is held at
[0x2309e0].  The routine at 0x6f24 reads a platform-config entry named
`Kernel` (ASCII at 0x1cfb4) into a local structure, then writes both variables:

  6fd4  adrp x0, 0x1c000
  6fdc  add  x0, x0, #0xfb4      ; "Kernel"
  6fe4  bl   0x4300              ; lookup, result at sp+0x20
  6fe8  cbz  x0, 0x7024
  ...
  7024  ldr  x8, [x20, #0x9e0]   ; gRT
  7028  adrp x19, 0x23000
  7030  add  x19, x19, #0x78     ; 882f8c2b-9646-435f-8de5-f208ff80c1bd
  7034  add  x4, x21, #0x20      ; value = entry MemBase
  7038  add  x0, x0, #0x428      ; "KernelBaseAddr"
  7040  mov  w2, #0x2            ; EFI_VARIABLE_BOOTSERVICE_ACCESS
  7044  ldr  x8, [x8, #0x58]     ; SetVariable
  7048  mov  w3, #0x8
  704c  blr  x8
  7050  ldr  x8, [x20, #0x9e0]   ; gRT
  7058  add  x4, x21, #0x28      ; value = entry MemSize
  705c  add  x0, x0, #0x446      ; "KernelSize"
  7064  mov  w2, #0x2
  7068  mov  w3, #0x8
  706c  ldr  x8, [x8, #0x58]     ; SetVariable
  7070  blr  x8

0x4300 is a trampoline into a platform-config protocol; the same routine logs
`Failed to Get Kernel info from UEFI Plat cfg` on failure.  The entry is looked
up by the literal name `Kernel`, which is the `MemLabel` of the memorymap node
quoted above, and the two values written are the entry's `MemBase` and
`MemSize`.  The routine also publishes `Shared_IMEM_Base`,
`PvmFwBaseAddr` and `PvmFwSize` from the same table.  Its caller validates a
preloaded kernel against that entry with

  (KernelAddress >= Region.MemBase) &&
  ((KernelAddress + KernelSize) <= (Region.MemBase + Region.MemSize))

(string at 0x1cfbb, asserted from `PlatformBdsLib.c` line 1013).  The embedded
`uefiplatLA.cfg` contains no `Kernel` entry, so the value written is the
runtime platform-config entry, not a static constant in that file.

Both ends of the chain are therefore present in this BL package:

  memorymap memory@A8000000, MemLabel "Kernel", MemBase 0xa8000000,
  MemSize 0x10000000
    -> UEFI PlatformBds: SetVariable(KernelBaseAddr = MemBase,
                                     KernelSize = MemSize)
    -> LinuxLoader: GetVariable(KernelBaseAddr, KernelSize), Image at
                    KernelBaseAddr + text_offset (0)

No ABL app writes the two variables.  Only LinuxLoader names them, and its
`[gRT + 0x58]` sites do not exist; the other ABL apps use the same GUID for
`SODResult`, `KmsgOffset`, `CryptoResult` and `sha256Result`, and two of them
do call SetVariable, but never for these names.

Structural self-check
---------------------

The parse above is re-walked by `tools/verify_uefi_chain.py`, a stdlib-only
script that reads the same extracted `uefi.elf` and asserts:

  - the ELF has one PT_LOAD, file 0x1000, VMA 0xa7000000, size 0x2f0000;
  - the outer FV header is `_FVH`, `FvLength` 0x2f0000, `HeaderLength` 0x48,
    its 16-bit header checksum is 0, and its block map is 0x2f0 blocks of
    0x1000 = 0x2f0000 ending exactly at `HeaderLength`;
  - the five files chain with no gap: PAD 0xfa0, SEC 0x4f018, FREEFORM 0xf7a,
    FV_IMAGE 0x17112a, FV_IMAGE 0x1273ff, each landing on the next 8-byte
    aligned header;
  - both GUID-defined sections decompress with CRC32 and ISIZE verified by
    zlib, to 0x446008 and 0x342008 bytes, and each payload holds an FV whose
    own header checksum is 0 and whose block map covers its `FvLength`; the
    volume that holds the driver has 67 files, all chaining without a gap;
  - the DXE-core file (type 0x05) at nested +0x76e0 carries name bytes
    `7f cb a2 d6 18 6a 2f 4e ...`, which decode to
    `d6a2cb7f-6a18-4e2f-b43b-9920a733700a` under EFI_GUID field packing; the
    same decode of the driver's name yields the GUID given above, and the
    driver PE is aa64 with `ImageBase` 0;
  - `KernelBaseAddr` (UTF-16 at PE+0x1c428) and `KernelSize` (PE+0x1c446) are
    each present once, the ASCII key `Kernel` is at PE+0x1cfb4, and the
    Samsung variable GUID occurs once, at PE+0x23078.

`python3 tools/verify_uefi_chain.py out/uefi.elf` prints `PASS (0 failed)`.

The file-state bytes in these volumes are the complement of the usual ones
(a valid file reads 0xf8, not 0x06) because the erase polarity is 1, so a
header walk that tests the state byte stops at the first PAD.  Walking by the
24-bit size and validating each file's section chain lands exactly on every
file boundary instead, which is what the tool does.

What this does and does not establish
-------------------------------------

Establishes: the boot chain that ships with this exact BL package declares a
256 MiB region, labelled `Kernel`, starting at 0xa8000000; the region is free
of every Linux-side carve-out, fits the Image, and is 2 MiB aligned.  The map
matches the live kernel's linear-map start to the byte, and matches the UEFI
and ABL placements in the same package.  The same package also contains the
driver that looks this entry up by its `MemLabel` and writes its `MemBase` and
`MemSize` into the two UEFI variables LinuxLoader reads.  This is a boot-chain
source and an authoring path for the inherited value, not a coincidence of free
space.

Does not establish: that this boot dispatched that driver, that the platform
config resolved `Kernel` to this node, and that the variables held exactly
0xa8000000 when LinuxLoader read them.  Those are runtime facts: the shell
cannot read `/proc/iomem`, `/proc/cmdline` or the UEFI variables, and the
loader path materialises no such constant.
The row therefore stays **declared, not measured**, and the build gate stays
closed.  The first on-device check is the physical P0 oracle: if the anchor is
right it recovers the slide; if it is wrong it recovers nothing, before any
kernel write.

Not recorded here: the live board-id, device serial, boot_id, or the address of
anything read from RAM.
