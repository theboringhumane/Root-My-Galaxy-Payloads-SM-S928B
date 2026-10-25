Reserved-memory check for P0_KERNEL_PHYS_LOAD
=============================================

Target : SM-S928B, S928BXXU6EZIF
Image  : out/kernel, image_size 0x2710000 (38,140,416 bytes)
Method : stream `dtbo.img.lz4` and `vendor_boot.img.lz4` out of the AP tar
         prefix, decompress both, parse the DTBO table and every embedded FDT,
         then compare every reserved-memory carve-out against the span the
         kernel Image would occupy if loaded at the inherited candidate.

Access : offline. The only thing read from the live device was the list of
         reserved-memory node names (`ls`); their `reg` properties are
         SELinux-denied to the shell.

Sources
-------

  $ tools/extract_image.py prefix.dec stream --tar-hint AP \
      --image vendor_boot.img.lz4 --outdir out
  found vendor_boot.img.lz4 (17898821 bytes)
  sha256 bbd8d9b48d6e64114a513588869c54c4bc5a8068f8f4856ed94814ea0c3ff0f7
  $ lz4 -d vendor_boot.img.lz4 vendor_boot.img
  sha256 37d2acf6ff687d7a6b09e6d0e0c67d863564db2e8d6d5fa9ae3b4509d73443b7
  100,663,296 bytes, header `VNDRBOOT`

  $ tools/extract_image.py prefix.dec stream --tar-hint AP \
      --image dtbo.img.lz4 --outdir out
  found dtbo.img.lz4 (2303984 bytes)
  sha256 c2a08df954461f09cf37d2075110f95da056214a929f39e879f78f7858fa16ff
  $ lz4 -d dtbo.img.lz4 dtbo.img
  sha256 aab87a43462bc3ba9b7c298d5d194bc42630b143671d42c8da0f5999d1f6cb4e
  16,777,216 bytes

Both files are firmware and are not committed.

Base DT (vendor_boot)
---------------------

`vendor_boot.img` carries 22 FDTs (version 17). They are the board DT
fragments; each contains `/reserved-memory` directly. Across all 22 there are
88 distinct carve-outs with a 16-byte `reg`, decoded as two u64 cells.

Nearest carve-out below the candidate: `wlan_msa_region@a6400000`,
0xa6400000 + 0x0c00000 = 0xa7000000.

Nearest carve-out above the candidate: `hwfence-shmem`,
0xd4e23000 (ends 0xd5100000); above that the splash and tz/qtee block start at
0xd5100000 and 0xd8000000.

In none of the 22 DTBs does a carve-out overlap
[0xa8000000, 0xaa710000). The candidate span sits entirely in the free window
0xa7000000..0xd4e23000.

DTBO overlays
-------------

DTBO header, all fields big-endian: magic 0xd7b7ab1e, total 0x8aae18, header 32
bytes, entry 32 bytes, 50 entries at 0x20, page 4096, version 0. Ten of the 50
entries are full board overlays; the rest are small.

All ten carry the same low-memory overlay:

  0xa7d00000 + 0x00300000 = 0xa8000000   sec_xbl_ramdump@A7D00000 (no-map)

That is the XBL ramdump carve-out, and it ends exactly at the candidate load
address. No 16-byte `reg` in any of the ten overlays overlaps
[0xa8000000, 0xaa710000), and the live `/proc/device-tree/reserved-memory`
listing has no address-bearing node name in 0xa8xxxxxx, 0xa9xxxxxx or
0xaaxxxxxx.

Boot-chain layout consistent with the above
-------------------------------------------

  ABL       ELF32, entry 0x9fa00000, segment 0x2520000   (0x9fa00000..0xa1f20000)
  UEFI      image, VMA 0xa7000000, segment 0x02f0000      (0xa7000000..0xa72f0000)
  wlan_msa  0xa6400000 + 0x0c00000                       (..0xa7000000)
  xbl dump  0xa7d00000 + 0x0300000                       (..0xa8000000)
  candidate 0xa8000000 + 0x2710000                       (..0xaa710000)
  next carve-out 0xd4e23000

ABL is a UEFI firmware volume whose sections are compressed, and UEFI is the
same; neither contains a plaintext DT or a load-address literal (searched
`kaslr_region`, `reserved-memory`, `boot.img`), and the Image's PE `ImageBase`
is 0. No property in the 22 base DTBs holds 0xa8000000 or 0xa96e0000.

What this does and does not establish
-------------------------------------

Establishes: the inherited candidate is 2 MiB aligned, and it is outside every
reserved-memory carve-out in both the shipped base DT and the shipped DTBO, in
all 22 + 10 board variants. The space it needs is unclaimed, and it begins at
the boundary where the XBL ramdump carve-out ends. The "reserved collision"
check on this candidate passes.

Does not establish: that the boot chain actually loads the Image at
0xa8000000. That address is a property of the ABL boot path, which is not
readable offline here: `/proc/iomem` and `/proc/cmdline` are denied to the
shell, `/proc/device-tree` properties are denied, and the bootloader images are
compressed UEFI volumes. The row therefore stays **pending** and the build gate
stays closed.

Not recorded here: the live board-id, device serial, boot_id, or the DTBO index
the boot selected.
