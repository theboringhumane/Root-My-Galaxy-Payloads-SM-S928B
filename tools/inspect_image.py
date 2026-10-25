#!/usr/bin/env python3
"""Read kallsyms and BTF out of a stripped arm64 kernel Image.

The S928BXXU6EZIF Image is a PE/COFF EFI stub: it has no ELF symbol table, and
no vmlinux or BTF file is shipped separately.  Both tables the port needs are
inside the Image:

  kallsyms  CONFIG_KALLSYMS_BASE_RELATIVE: s32 offsets, u64 relative base, u64
            count, compressed names, then the token table and token index.
  BTF       CONFIG_DEBUG_INFO_BTF blob, found by scanning for a header that
            validates (magic, version, hdr_len, section bounds, NUL-led strings).

Usage:
  tools/inspect_image.py sym out/kernel ashmem_fops
  tools/inspect_image.py sym out/kernel nfulnl
  tools/inspect_image.py btf out/kernel rt_mutex_waiter
  tools/inspect_image.py btf out/kernel task_struct pi_lock pi_waiters
  tools/inspect_image.py btf out/kernel --find slab_cache

The kallsyms offsets default to S928BXXU6EZIF; pass --kallsyms/--relative-base/
--count/--names/--token-table/--token-index for another build.
"""
import argparse
import struct
import sys
from pathlib import Path

# S928BXXU6EZIF (sha256 a8c1638497ca1bff576c5a6d9426521ec545fd68da8ce5dfa47c40233391a179)
KALLSYMS = 0x142f568
RELATIVE_BASE = 0x1498628
NUM_SYMS = 0x1498630
NAMES = 0x1498638
TOKEN_TABLE = 0x1653078
TOKEN_INDEX = 0x1653400


def read_kallsyms(data, args):
    rel_base = struct.unpack_from("<Q", data, args.relative_base)[0]
    count = struct.unpack_from("<Q", data, args.count)[0]
    tokens = []
    for index in struct.unpack_from("<256H", data, args.token_index):
        end = data.index(b"\0", args.token_table + index)
        tokens.append(data[args.token_table + index:end].decode("latin1"))

    symbols = []
    cursor = args.names
    for index in range(count):
        length = data[cursor]
        cursor += 1
        if length & 0x80:
            length = (length & 0x7f) | (data[cursor] << 7)
            cursor += 1
        name = ""
        for _ in range(length):
            name += tokens[data[cursor]]
            cursor += 1
        offset = struct.unpack_from("<i", data, args.kallsyms + 4 * index)[0]
        address = (rel_base + (offset & 0xffffffff)) & 0xffffffffffffffff
        symbols.append((address, name[0] if name else "?", name[1:]))
    return symbols


KIND_EXTRA = {1: lambda n: 4, 2: lambda n: 0, 3: lambda n: 12,
              4: lambda n: 12 * n, 5: lambda n: 12 * n, 6: lambda n: 8 * n,
              7: lambda n: 0, 8: lambda n: 0, 9: lambda n: 0, 10: lambda n: 0,
              11: lambda n: 0, 12: lambda n: 0, 13: lambda n: 8 * n,
              14: lambda n: 4, 15: lambda n: 12 * n, 16: lambda n: 0,
              17: lambda n: 4, 18: lambda n: 0, 19: lambda n: 12 * n}

KIND_NAMES = {1: "int", 2: "ptr", 3: "array", 4: "struct", 5: "union",
              6: "enum", 7: "fwd", 8: "typedef", 9: "volatile", 10: "const",
              11: "restrict", 12: "func", 13: "proto", 14: "var",
              15: "datasec", 16: "float", 17: "decl_tag", 18: "type_tag",
              19: "enum64"}


class Btf:
    def __init__(self, data, offset):
        head = struct.unpack_from("<HBBI", data, offset)
        magic, version, _flags, header_len = head
        type_off, type_len, str_off, str_len = struct.unpack_from(
            "<IIII", data, offset + 8)
        if magic != 0xeb9f or version != 1 or header_len < 24:
            raise ValueError(f"{offset:#x}: not a BTF header")
        self.start = offset + header_len
        self.types_end = self.start + type_off + type_len
        self.strs = self.start + str_off
        self.strs_end = self.strs + str_len
        if self.strs < self.types_end or self.strs_end > len(data):
            raise ValueError(f"{offset:#x}: BTF sections overlap or leave the Image")
        if data[self.strs:self.strs + 1] != b"\0":
            raise ValueError(f"{offset:#x}: string section does not start with NUL")
        self.data = data
        self.entries = [None]
        cursor = self.start + type_off
        while cursor < self.types_end:
            name_off, info, size = struct.unpack_from("<III", data, cursor)
            kind = (info >> 24) & 0x1f
            vlen = info & 0xffff
            extra = KIND_EXTRA.get(kind)
            if extra is None:
                raise ValueError(f"{cursor:#x}: unknown BTF kind {kind}")
            self.entries.append((name_off, kind, (info >> 31) & 1, vlen, size,
                                 cursor + 12))
            cursor += 12 + extra(vlen)
        if cursor != self.types_end:
            raise ValueError(f"{cursor:#x}: BTF types end at {self.types_end:#x}")

    def name(self, type_id):
        offset = self.entries[type_id][0]
        end = self.data.index(b"\0", self.strs + offset)
        return self.data[self.strs + offset:end].decode("latin1")

    def label(self, type_id, depth=0):
        """Spell out a type id for display, following pointers and typedefs."""
        if type_id == 0:
            return "void"
        if type_id >= len(self.entries) or depth > 4:
            return f"#{type_id}"
        name_off, kind, _flag, _vlen, size, body = self.entries[type_id]
        name = self.name(type_id) if name_off else ""
        if kind == 1:
            return name or "int"
        if kind == 2:
            return self.label(size, depth + 1) + " *"
        if kind == 3:
            elem, _index_type, count = struct.unpack_from("<III", self.data, body)
            return f"{self.label(elem, depth + 1)}[{count}]"
        if kind in (8, 9, 10, 11, 17, 18):
            return self.label(size, depth + 1)
        if kind == 13:
            return self.label(size, depth + 1) + " (*)()"
        return f"{KIND_NAMES.get(kind, f'kind{kind}')} {name}".strip()

    def members(self, type_id):
        _name_off, _kind, kind_flag, vlen, _size, body = self.entries[type_id]
        out = []
        for index in range(vlen):
            name_off, member_type, raw = struct.unpack_from(
                "<III", self.data, body + index * 12)
            name = self.data[self.strs + name_off:
                             self.data.index(b"\0", self.strs + name_off)]
            offset = (raw & 0xffffff) if kind_flag else raw
            out.append((name.decode("latin1"), member_type, offset))
        return out

    def flat_members(self, type_id, base=0, depth=0, seen=()):
        """Yield (name, bit offset, type) with anonymous aggregates inlined."""
        if depth > 4 or type_id in seen:
            return
        for name, member_type, offset in self.members(type_id):
            kind = self.entries[member_type][1] if member_type < len(self.entries) else 0
            if not name and kind in (4, 5):
                yield from self.flat_members(
                    member_type, base + offset, depth + 1, seen + (type_id,))
            else:
                yield name, base + offset, member_type

    def find(self, name, kinds=(4, 5)):
        return [index for index, entry in enumerate(self.entries)
                if index and entry[1] in kinds and self.name(index) == name]


def find_btf(data):
    cursor = 0
    while True:
        cursor = data.find(b"\x9f\xeb\x01\x00", cursor)
        if cursor < 0:
            sys.exit("no valid BTF blob found; pass --btf-offset")
        try:
            return Btf(data, cursor)
        except ValueError:
            cursor += 4


def cmd_sym(data, args):
    symbols = read_kallsyms(data, args)
    if args.patterns:
        needles = [pattern.lower() for pattern in args.patterns]
        symbols = [s for s in symbols if any(n in s[2].lower() for n in needles)]
    for address, kind, name in symbols:
        print(f"0x{address:016x} {kind} {name}")


def cmd_btf(data, args):
    btf = Btf(data, args.btf_offset) if args.btf_offset else find_btf(data)
    if args.find:
        for index, entry in enumerate(btf.entries):
            if not index or entry[1] not in (4, 5) or not entry[0]:
                continue
            for name, offset, member_type in btf.flat_members(index):
                if name == args.find:
                    print(f"{btf.name(index)} +0x{offset // 8:03x} "
                          f"{name}  {btf.label(member_type)}")
        return
    hits = btf.find(args.type_name)
    if not hits:
        sys.exit(f"no struct/union named {args.type_name!r} in the BTF")
    for index in hits:
        entry = btf.entries[index]
        print(f"{'struct' if entry[1] == 4 else 'union'} {args.type_name} "
              f"size=0x{entry[4]:x} members={entry[3]}")
        for name, offset, member_type in btf.flat_members(index):
            if args.members and name not in args.members:
                continue
            print(f"  +0x{offset // 8:03x} (bit {offset:4d}) {name}  "
                  f"{btf.label(member_type)}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sym = sub.add_parser("sym", help="print kallsyms entries matching a substring")
    sym.add_argument("image")
    sym.add_argument("patterns", nargs="*")
    sym.add_argument("--kallsyms", type=lambda v: int(v, 0), default=KALLSYMS)
    sym.add_argument("--relative-base", type=lambda v: int(v, 0), default=RELATIVE_BASE)
    sym.add_argument("--count", type=lambda v: int(v, 0), default=NUM_SYMS)
    sym.add_argument("--names", type=lambda v: int(v, 0), default=NAMES)
    sym.add_argument("--token-table", type=lambda v: int(v, 0), default=TOKEN_TABLE)
    sym.add_argument("--token-index", type=lambda v: int(v, 0), default=TOKEN_INDEX)

    btf = sub.add_parser("btf", help="dump a struct/union, or find a member")
    btf.add_argument("image")
    btf.add_argument("type_name", nargs="?")
    btf.add_argument("members", nargs="*")
    btf.add_argument("--find", help="print every struct holding this member")
    btf.add_argument("--btf-offset", type=lambda v: int(v, 0))

    args = parser.parse_args()
    data = Path(args.image).read_bytes()
    if args.command == "sym":
        cmd_sym(data, args)
    else:
        if not args.type_name and not args.find:
            parser.error("btf needs a type name or --find")
        cmd_btf(data, args)


if __name__ == "__main__":
    main()
