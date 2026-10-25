#!/usr/bin/env python3
"""Dump flattened device trees (FDT/DTB) embedded in a firmware image.

The BL archive ships xbl_config.elf, whose tail carries the Qualcomm XBL
configuration DTBs.  The package contains no plain .dtb file, so this walks the
FDT header, structure block and string block at a chosen offset.

Usage:
  tools/dtb_dump.py out/xbl_config.elf --scan
  tools/dtb_dump.py out/xbl_config.elf --offset 0x140c4
  tools/dtb_dump.py out/xbl_config.elf --offset 0x140c4 --path /soc/memorymap

--scan reports every offset whose header validates against the file size.
--path prints only nodes whose path starts with the given string.  Property
values print as quoted strings when printable, otherwise as big-endian 32-bit
cells, which is the FDT wire format.
"""
import argparse
import struct
import sys

FDT_MAGIC = 0xD00DFEED
BEGIN_NODE = 1
END_NODE = 2
PROP = 3
NOP = 4
END = 9


def fdt_header(buf, offset):
    if offset + 40 > len(buf):
        raise ValueError("offset 0x%x has no FDT header" % offset)
    fields = struct.unpack_from(">10I", buf, offset)
    (magic, totalsize, off_struct, off_strings, _rsvmap, _version,
     _last_comp, _boot_cpu, size_strings, size_struct) = fields
    if magic != FDT_MAGIC:
        raise ValueError("bad FDT magic 0x%08x at 0x%x" % (magic, offset))
    if totalsize < 0x48 or offset + totalsize > len(buf):
        raise ValueError("totalsize 0x%x at 0x%x exceeds file" % (totalsize, offset))
    for name, value in (("structure", off_struct), ("strings", off_strings)):
        if value >= totalsize:
            raise ValueError("%s block at 0x%x outside totalsize" % (name, value))
    if size_struct == 0 or size_strings == 0:
        raise ValueError("empty structure or string block")
    return totalsize, off_struct, off_strings


def cstring(buf, base, rel):
    start = base + rel
    end = buf.find(b"\0", start)
    if end < 0:
        raise ValueError("unterminated string at 0x%x" % start)
    return buf[start:end].decode("utf-8", "replace")


def walk(buf, offset):
    totalsize, off_struct, off_strings = fdt_header(buf, offset)
    limit = offset + totalsize
    pos = offset + off_struct
    stack = []
    while pos + 4 <= limit:
        (token,) = struct.unpack_from(">I", buf, pos)
        pos += 4
        if token == BEGIN_NODE:
            name = cstring(buf, offset + off_struct, pos - (offset + off_struct))
            pos = (pos + len(name) + 1 + 3) & ~3
            stack.append(name)
        elif token == END_NODE:
            if not stack:
                raise ValueError("unbalanced END_NODE at 0x%x" % (pos - 4))
            stack.pop()
        elif token == PROP:
            if pos + 8 > limit:
                raise ValueError("truncated property header at 0x%x" % pos)
            length, nameoff = struct.unpack_from(">II", buf, pos)
            pos += 8
            if pos + length > limit:
                raise ValueError("property value past totalsize at 0x%x" % pos)
            value = buf[pos:pos + length]
            pos = (pos + length + 3) & ~3
            path = "/" + "/".join(name for name in stack if name)
            yield path, cstring(buf, offset + off_strings, nameoff), value
        elif token == NOP:
            continue
        elif token == END:
            return
        else:
            raise ValueError("unknown FDT token %d at 0x%x" % (token, pos - 4))
    raise ValueError("structure block has no END token")


def printable(value):
    if not value or not value.endswith(b"\0"):
        return False
    for byte in value[:-1]:
        if byte < 0x20 or byte > 0x7e:
            if byte not in (0x09, 0x0a, 0x0d):
                return False
    return True


def render(value):
    if printable(value):
        text = value[:-1].decode("utf-8", "replace")
        if "\0" not in text:
            return '"%s"' % text
    cells = value + b"\0" * ((-len(value)) % 4)
    words = struct.unpack(">%dI" % (len(cells) // 4), cells)
    return "<%s>" % " ".join("0x%08x" % word for word in words)


def scan(buf):
    seen = 0
    cursor = 0
    while True:
        index = buf.find(struct.pack(">I", FDT_MAGIC), cursor)
        if index < 0:
            break
        cursor = index + 4
        try:
            totalsize, _off_struct, _off_strings = fdt_header(buf, index)
        except ValueError:
            continue
        seen += 1
        print("0x%06x  totalsize 0x%x (%d bytes)" % (index, totalsize, totalsize))
    if not seen:
        print("no valid FDT at any offset")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image", help="file that contains one or more FDTs")
    parser.add_argument("--offset", help="hex offset of the FDT header")
    parser.add_argument("--path", default="",
                        help="print only nodes whose path starts with this")
    parser.add_argument("--scan", action="store_true",
                        help="report every offset with a valid FDT header")
    args = parser.parse_args()

    buf = open(args.image, "rb").read()
    if args.scan:
        scan(buf)
        return 0
    if not args.offset:
        parser.error("--offset or --scan is required")

    offset = int(args.offset, 0)
    prefix = args.path.rstrip("/")
    last_path = None
    try:
        for path, name, value in walk(buf, offset):
            if prefix and not (path == prefix or path.startswith(prefix + "/")):
                continue
            if path != last_path:
                print(path)
                last_path = path
            print("  %s = %s" % (name, render(value)))
    except ValueError as error:
        print("error: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
