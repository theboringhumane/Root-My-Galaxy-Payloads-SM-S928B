#!/usr/bin/env python3
"""Recover boot.img.lz4 and the kernel Image from a partial FUS download.

FUS packages are ZIP archives whose payload entries are STORED (method 0), and
the AP entry is an uncompressed tar.  That means a prefix of the package is
usable on its own: the local file header gives the entry's name and length, and
the tar inside can be walked without the ZIP central directory (which lives at
the end of the file and is absent from a prefix).

Usage:
  tools/extract_image.py prefix.dec scan
  tools/extract_image.py prefix.dec extract --tar-hint AP --image boot.img.lz4 --outdir out
  tools/extract_image.py - kernel --image out/boot.img.lz4 --outdir out
"""
import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ZIP_LOCAL = b"PK\x03\x04"


def zip_entries(buf):
    cursor = 0
    while True:
        start = buf.find(ZIP_LOCAL, cursor)
        if start < 0 or start + 30 > len(buf):
            return
        (method,) = struct.unpack_from("<H", buf, start + 8)
        compressed, uncompressed = struct.unpack_from("<II", buf, start + 18)
        name_len, extra_len = struct.unpack_from("<HH", buf, start + 26)
        name = buf[start + 30:start + 30 + name_len].decode("utf-8", "replace")
        data = start + 30 + name_len + extra_len
        end = data + compressed
        yield {"name": name, "header": start, "data": data, "method": method,
               "compressed": compressed, "uncompressed": uncompressed, "end": end}
        # Skip the whole entry when it is present, so tar payloads cannot be
        # misread as nested ZIP headers; otherwise resume byte-wise.
        cursor = end if method == 0 and end <= len(buf) else start + 4


def tar_entries(buf, base, limit):
    offset = base
    long_name = None
    while offset + 512 <= limit:
        header = buf[offset:offset + 512]
        if header == b"\x00" * 512:
            return
        if header[257:262] != b"ustar":
            return
        raw_name = header[:100].split(b"\x00", 1)[0].decode("utf-8", "replace")
        try:
            size = int(header[124:136].split(b"\x00", 1)[0].strip() or b"0", 8)
        except ValueError:
            return
        data = offset + 512
        end = data + size
        typeflag = header[156:157]

        if typeflag == b"L":
            # GNU long name: the payload is the name of the next entry.
            long_name = buf[data:min(end, limit)].split(b"\x00", 1)[0].decode("utf-8", "replace")
            offset = data + ((size + 511) // 512) * 512
            continue
        if typeflag in (b"x", b"g"):
            # PAX extended/global header: metadata, not a file.
            offset = data + ((size + 511) // 512) * 512
            continue

        name = long_name if long_name else raw_name
        long_name = None
        if name.startswith("./"):
            name = name[2:]
        yield {"name": name, "header": offset, "data": data, "size": size,
               "end": end, "type": typeflag.decode("latin-1")}
        offset = data + ((size + 511) // 512) * 512


def wanted(item):
    name = item["name"]
    return not name.startswith(("PaxHeader/", "._")) and "/._" not in name


def find_tar(buf, name_hint):
    for entry in zip_entries(buf):
        if entry["name"].endswith((".tar", ".tar.md5")) and name_hint in entry["name"]:
            if entry["method"] != 0:
                sys.exit(f"{entry['name']} is compressed (method {entry['method']}); "
                         "a partial download cannot extract it")
            return entry
    sys.exit(f"no stored tar matching {name_hint!r} in the prefix")


def scan(buf):
    print(f"prefix bytes: {len(buf)}")
    entries = list(zip_entries(buf))
    if not entries:
        sys.exit("no ZIP local headers found - is this the decrypted prefix?")
    for entry in entries:
        state = "complete" if entry["end"] <= len(buf) else "truncated"
        print(f"zip  @0x{entry['header']:09x} method={entry['method']} "
              f"stored={entry['compressed']} plain={entry['uncompressed']} "
              f"{state:9s} {entry['name']}")
    for entry in entries:
        if not entry["name"].endswith((".tar", ".tar.md5")) or entry["method"] != 0:
            continue
        print(f"\ntar inside {entry['name']} (data @0x{entry['data']:09x}):")
        for item in tar_entries(buf, entry["data"], min(entry["end"], len(buf))):
            if not wanted(item):
                continue
            state = "complete" if item["end"] <= len(buf) else "TRUNCATED"
            print(f"  @0x{item['header']:09x} {item['size']:12d} {state:9s} {item['name']}")


def extract(buf, tar_hint, name, outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    archive = find_tar(buf, tar_hint)
    items = [item for item in tar_entries(buf, archive["data"], min(archive["end"], len(buf)))
             if wanted(item)]
    matches = [item for item in items if item["name"] == name]
    if not matches:
        matches = [item for item in items if Path(item["name"]).name == name]
    if not matches:
        listed = ", ".join(item["name"] for item in items[:20])
        sys.exit(f"{name} not found in {archive['name']}. First entries: {listed}")
    item = matches[0]
    if item["end"] > len(buf):
        need = item["end"] - archive["data"]
        sys.exit(f"{name} is truncated: it ends {need} bytes into the tar, "
                 f"the prefix holds {len(buf) - archive['data']}; refetch with a "
                 f"larger --bytes")
    payload = buf[item["data"]:item["end"]]
    target = outdir / name
    target.write_bytes(payload)
    print(f"wrote {target} ({len(payload)} bytes, sha256 {hashlib.sha256(payload).hexdigest()})")


def kernel(boot_lz4, outdir):
    """Decompress a Samsung boot image and slice out the ARM64 Image."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if not boot_lz4.exists():
        sys.exit(f"{boot_lz4} not found")
    boot = outdir / "boot.img"
    if shutil.which("lz4"):
        subprocess.run(["lz4", "-d", "-f", str(boot_lz4), str(boot)], check=True)
    else:
        try:
            import lz4.frame
        except ImportError:
            sys.exit("need the lz4 CLI or the python lz4 module to decompress")
        boot.write_bytes(lz4.frame.decompress(boot_lz4.read_bytes()))

    data = boot.read_bytes()
    if data[:8] != b"ANDROID!":
        sys.exit(f"unexpected boot magic {data[:8]!r}")
    (kernel_size,) = struct.unpack_from("<I", data, 0x08)
    (header_version,) = struct.unpack_from("<I", data, 0x28)
    if header_version < 3:
        sys.exit(f"boot header v{header_version}: kernel is not at page 1")
    image = data[0x1000:0x1000 + kernel_size]
    if len(image) != kernel_size:
        sys.exit(f"boot image holds {len(image)} kernel bytes, header says {kernel_size}")
    target = outdir / "kernel"
    target.write_bytes(image)
    print(f"boot header v{header_version}, kernel_size={kernel_size} (0x{kernel_size:x})")
    print(f"wrote {target} (sha256 {hashlib.sha256(image).hexdigest()})")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("prefix", nargs="?", help="decrypted FUS prefix (unused for 'kernel')")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan", help="list ZIP and tar entries with offsets")

    ex = sub.add_parser("extract", help="write one entry out of the AP/BL tar")
    ex.add_argument("--tar-hint", default="AP", help="substring of the tar entry name")
    ex.add_argument("--image", required=True, help="entry name, e.g. boot.img.lz4")
    ex.add_argument("--outdir", default="out")

    ker = sub.add_parser("kernel", help="decompress boot.img.lz4 and slice the Image")
    ker.add_argument("--image", default="boot.img.lz4", help="path to the compressed boot image")
    ker.add_argument("--outdir", default="out")

    args = parser.parse_args()
    if args.command == "kernel":
        kernel(Path(args.image), args.outdir)
        return
    if not args.prefix:
        parser.error("prefix is required for scan/extract")
    buf = Path(args.prefix).read_bytes()
    if args.command == "scan":
        scan(buf)
    else:
        extract(buf, args.tar_hint, args.image, args.outdir)


if __name__ == "__main__":
    main()
