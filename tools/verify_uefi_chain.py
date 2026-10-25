#!/usr/bin/env python3
"""Re-walk uefi.elf's firmware volumes and check every structural claim that
evidence/xbl-memorymap.md makes about the driver that publishes KernelBaseAddr.

Chain: ELF -> FV -> FFS -> GUID-defined compressed section -> gzip -> nested
FV -> driver FFS -> PE32+.  Checks FV header checksums, block maps, file
chaining, gzip CRCs and the driver's strings and constant offsets.

Usage:
  tools/extract_image.py prefix.dec stream --tar-hint BL \
      --image uefi.elf.lz4 --outdir out
  lz4 -d out/uefi.elf.lz4 out/uefi.elf
  tools/verify_uefi_chain.py out/uefi.elf

Prints verdicts and offsets only; firmware content is not emitted.
"""
import gzip
import struct
import sys

FS_GUIDS = {
    bytes.fromhex('78e58c8c3d8a1c4f9935896185c32dd3'): 'FFS2',
    bytes.fromhex('7a9354d90468044a81ce0bf617d890df'): 'FFS1',
    bytes.fromhex('7ac0074acb3dca4dbd6f1e9689e7349a'): 'FFS3',
}
FFS_TYPES = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
             0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xF0}
SECTION_TYPES = set(range(0x01, 0x1A))


def efi_guid(text):
    a, b, c, rest = text.split('-', 3)
    return struct.pack('<IHH', int(a, 16), int(b, 16), int(c, 16)) + bytes.fromhex(rest.replace('-', ''))


COMPRESSED_SECTION = efi_guid('1d301fe9-be79-4353-91c2-d23bc959ae0c')
DRIVER_FILE = efi_guid('5a50aa81-c3ae-4608-a0e3-41a2e69baf94')
VARIABLE_GUID = efi_guid('882f8c2b-9646-435f-8de5-f208ff80c1bd')


class Checker:
    def __init__(self):
        self.failed = []

    def ok(self, cond, label, detail=''):
        if not cond:
            self.failed.append(label)
        print(('ok    ' if cond else 'FAIL  ') + label + (': ' + detail if detail else ''))
        return cond

    def note(self, label):
        print('      ' + label)


def parse_fv(chk, buf, base, label, expect_len=None):
    zeros = buf[base:base + 16]
    fsguid = buf[base + 0x10:base + 0x20]
    fvlen, = struct.unpack_from('<Q', buf, base + 0x20)
    sig, attrs = struct.unpack_from('<II', buf, base + 0x28)
    hdrlen, _csum, ext, _rsv, rev = struct.unpack_from('<HHHBB', buf, base + 0x30)
    chk.note('%s: fvlen 0x%x hdrlen 0x%x attrs 0x%08x rev %d erase-polarity %d '
             'zero-vector %s' % (label, fvlen, hdrlen, attrs, rev, (attrs >> 11) & 1,
                                 'zero' if zeros == b'\0' * 16 else 'non-zero'))
    chk.note('%s: filesystem %s (%s)' % (label, fsguid.hex(), FS_GUIDS.get(fsguid, 'unknown')))
    chk.ok(sig == 0x4856465f, label + ' _FVH signature')
    if expect_len is not None:
        chk.ok(fvlen == expect_len, label + ' FvLength', '0x%x' % fvlen)
    words = struct.unpack('<%dH' % (hdrlen // 2), buf[base:base + hdrlen])
    chk.ok(sum(words) & 0xffff == 0, label + ' header checksum', '0x%x' % (sum(words) & 0xffff))
    off, total = base + 0x38, 0
    while off + 8 <= base + hdrlen:
        blocks, length = struct.unpack_from('<II', buf, off)
        if blocks == 0 and length == 0:
            off += 8
            break
        total += blocks * length
        off += 8
    chk.ok(total == fvlen, label + ' block map covers FvLength', '0x%x' % total)
    chk.ok(off == base + hdrlen, label + ' block map ends at HeaderLength',
           '0x%x' % (off - base))
    return fvlen, hdrlen


def sections(buf, ffs_off, ffs_size):
    off, end = ffs_off + 24, ffs_off + ffs_size
    out = []
    while off + 4 <= end:
        size = int.from_bytes(buf[off:off + 3], 'little')
        if size < 4 or off + size > end:
            break
        out.append((off, size, buf[off + 3]))
        off += size if size % 4 == 0 else (size + 3) & ~3
    return out


def section_chain_ok(buf, ffs_off, ffs_size):
    secs = sections(buf, ffs_off, ffs_size)
    if not secs or any(t not in SECTION_TYPES for _, _, t in secs):
        return False
    last_off, last_size, _ = secs[-1]
    return (ffs_off + ffs_size) - (last_off + last_size) < 4


def find_files(chk, buf, fv_off, fvlen, hdrlen, label):
    """Walk by the 24-bit size and section chain.

    File state bytes in these volumes are the complement of the usual values
    (0xf8 for a valid file) because the erase polarity is 1, so a walk that
    tests the state byte stops at the first PAD file.
    """
    end, out = fv_off + fvlen, []

    def plausible(off):
        if off + 24 > end or off % 8:
            return False
        size = int.from_bytes(buf[off + 20:off + 23], 'little')
        if not (24 <= size <= fvlen) or buf[off + 18] not in FFS_TYPES:
            return False
        return buf[off + 18] == 0xF0 or section_chain_ok(buf, off, size)

    off = fv_off + hdrlen
    while off + 24 <= end:
        if plausible(off):
            out.append(off)
            off = (off + int.from_bytes(buf[off + 20:off + 23], 'little') + 7) & ~7
        else:
            off += 8
    chk.ok(len(out) > 0, label + ' file headers located', str(len(out)))
    prev = None
    for a in out:
        size = int.from_bytes(buf[a + 20:a + 23], 'little')
        gap = 0 if prev is None else a - prev
        chk.ok(gap == 0, label + ' file at +0x%x chains without a gap' % (a - fv_off),
               'gap 0x%x' % gap)
        prev = (a + size + 7) & ~7
    return out


def main(path):
    chk = Checker()
    data = open(path, 'rb').read()
    chk.ok(data[:4] == b'\x7fELF', 'ELF magic')
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
    loads = []
    for i in range(phnum):
        o = phoff + i * phentsize
        if struct.unpack_from('<I', data, o)[0] == 1:
            loads.append(struct.unpack_from('<QQQQQ', data, o + 8))
    chk.ok(len(loads) == 1, 'one PT_LOAD segment', str(len(loads)))
    p_off, p_vaddr, _p_paddr, p_filesz, _p_memsz = loads[0]
    chk.note('segment: file 0x%x vma 0x%x size 0x%x' % (p_off, p_vaddr, p_filesz))
    chk.ok(p_off == 0x1000, 'segment file offset', hex(p_off))
    chk.ok(p_vaddr == 0xa7000000, 'segment VMA', hex(p_vaddr))
    chk.ok(p_filesz == 0x2f0000, 'segment size', hex(p_filesz))

    fvlen, hdrlen = parse_fv(chk, data, p_off, 'FV', expect_len=0x2f0000)
    outer = find_files(chk, data, p_off, fvlen, hdrlen, 'FV')

    payloads = []
    for ffs in outer:
        size = int.from_bytes(data[ffs + 20:ffs + 23], 'little')
        for soff, ssize, stype in sections(data, ffs, size):
            if stype != 0x02 or data[soff + 4:soff + 20] != COMPRESSED_SECTION:
                continue
            dataoff, _attrs = struct.unpack_from('<HH', data, soff + 20)
            blob = data[soff + dataoff:soff + ssize]
            chk.ok(blob[:3] == b'\x1f\x8b\x08', 'compressed section at +0x%x gzip magic' % soff)
            try:
                plain = gzip.decompress(blob)
            except Exception as exc:                # CRC32/ISIZE failure
                chk.ok(False, 'compressed section at +0x%x gzip CRC' % soff, str(exc))
                continue
            chk.ok(True, 'compressed section at +0x%x gzip CRC + ISIZE' % soff,
                   '0x%x bytes' % len(plain))
            payloads.append(plain)
    chk.ok(len(payloads) == 2, 'two compressed FV_IMAGE sections', str(len(payloads)))

    driver = None
    for i, plain in enumerate(payloads):
        sig = plain.find(b'_FVH')
        if not chk.ok(sig == 0x30, 'nested FV %d signature at +0x30' % i, hex(sig)):
            continue
        start = sig - 0x28
        nfvlen, nhdrlen = parse_fv(chk, plain, start, 'nested FV %d' % i)
        chk.ok(start + nfvlen <= len(plain), 'nested FV %d fits its payload' % i,
               '0x%x <= 0x%x' % (start + nfvlen, len(plain)))
        files = find_files(chk, plain, start, nfvlen, nhdrlen, 'nested FV %d' % i)
        for ffs in files:
            if plain[ffs:ffs + 16] != DRIVER_FILE:
                continue
            size = int.from_bytes(plain[ffs + 20:ffs + 23], 'little')
            for soff, ssize, stype in sections(plain, ffs, size):
                if stype != 0x10:
                    continue
                pe = soff + 4
                chk.ok(plain[pe:pe + 2] == b'MZ', 'driver section MZ')
                pe_rel, = struct.unpack_from('<I', plain, pe + 0x3c)
                chk.ok(plain[pe + pe_rel:pe + pe_rel + 4] == b'PE\0\0', 'driver PE signature')
                machine, nsec = struct.unpack_from('<HH', plain, pe + pe_rel + 4)
                chk.ok(machine == 0xaa64, 'driver machine', hex(machine))
                image_base, = struct.unpack_from('<Q', plain, pe + pe_rel + 0x18 + 0x18)
                chk.ok(image_base == 0, 'driver ImageBase', hex(image_base))
                chk.note('driver: file +0x%x size 0x%x, PE at +0x%x, %d sections'
                         % (ffs - start, size, pe - ffs, nsec))
                driver = plain[pe:pe + ssize - 4]
            break
        if driver:
            break

    if not chk.ok(driver is not None, 'driver located in a nested FV'):
        return chk

    for name, want in (('KernelBaseAddr', 0x1c428), ('KernelSize', 0x1c446)):
        at = driver.find(name.encode('utf-16-le'))
        chk.ok(at == want, 'UTF-16 name %s at PE+0x%x' % (name, want),
               'found at 0x%x' % at if at >= 0 else 'missing')
    at = driver.find(b'Kernel\0')
    chk.ok(at == 0x1cfb4, 'ASCII key Kernel at PE+0x1cfb4', 'found at 0x%x' % at if at >= 0 else 'missing')
    at = driver.find(VARIABLE_GUID)
    chk.ok(at == 0x23078, 'variable GUID at PE+0x23078', 'found at 0x%x' % at if at >= 0 else 'missing')
    return chk


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: verify_uefi_chain.py <uefi.elf>')
    result = main(sys.argv[1])
    print('\n%s (%d failed)' % ('PASS' if not result.failed else 'FAIL', len(result.failed)))
    sys.exit(0 if not result.failed else 1)
