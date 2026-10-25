P0_KERNEL_PHYS_LOAD: the XBL memory map
=======================================

Target : SM-S928B, S928BXXU6EZIF
Image  : out/kernel, image_size 0x2710000 (38,140,416 bytes)
Method : stream the BL tar out of the decrypted FUS prefix, decompress
         xbl_config.elf, parse its embedded FDTs, and read the
         /soc/memorymap the XBL firmware hands to the UEFI boot chain.

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

What this does and does not establish
-------------------------------------

Establishes: the boot chain that ships with this exact BL package declares a
256 MiB region, labelled `Kernel`, starting at 0xa8000000; the region is free
of every Linux-side carve-out, fits the Image, and is 2 MiB aligned.  The map
matches the live kernel's linear-map start to the byte, and matches the UEFI
and ABL placements in the same package.  This is a boot-chain source for the
inherited value, not a coincidence of free space.

Does not establish: that a particular running boot took the
`KernelBaseAddr` branch and that the variable held exactly 0xa8000000.  That is
a runtime fact: the shell cannot read `/proc/iomem`, `/proc/cmdline` or the
UEFI variables, and the loader path materialises no such constant.
The row therefore stays **declared, not measured**, and the build gate stays
closed.  The first on-device check is the physical P0 oracle: if the anchor is
right it recovers the slide; if it is wrong it recovers nothing, before any
kernel write.

Not recorded here: the live board-id, device serial, boot_id, or the address of
anything read from RAM.
