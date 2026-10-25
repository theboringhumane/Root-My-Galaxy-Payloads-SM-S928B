#!/usr/bin/env python3
"""Flatten C target profiles to macro -> value and set-diff two variants.

Reads one or more headers per side (order matters: later definitions and
#undef win), normalizes integer literals, then emits a triaged markdown delta:
same / differ / left-only / right-only, each differing row classed as
identity, physical, symbol, layout, slide or flag.

Usage:
  tools/port_diff.py --a A/target.h --a A/ezif_layout.h \
                     --b B/target.h --label A->B [--clusters]

The category ordering is the triage order: identity fields never relocate,
physical anchors and symbols carry the real firmware delta, layout values are
BTF-derived, and flags are exploit-policy, not addresses.
"""
import argparse
import re
from collections import Counter
from pathlib import Path

DEFINE = re.compile(r'^\s*#\s*define\s+([A-Za-z_]\w*)\s*(.*)$')
UNDEF = re.compile(r'^\s*#\s*undef\s+([A-Za-z_]\w*)')
# Header guards differ by construction (they name the variant) and are not config.
GUARD = re.compile(r'^[A-Z][A-Z0-9_]*_H$')

PHYSICAL_PREFIXES = (
    "P0_PHYS", "P0_PAGE", "P0_KERNEL", "KIMAGE", "KERNELSNITCH_IDENTITY",
    "DIRECT_MAP", "VMEMMAP", "P0_ORACLE_PROBE_OFFSET", "MM_DMA32", "MM_NORMAL",
)
SYMBOL_PREFIXES = (
    "ASHMEM", "CONFIGFS", "COPY_SPLICE", "NOOP_LLSEEK", "INIT_TASK",
    "ROOT_TASK_GROUP", "SELINUX", "KMALLOC", "ANON_PIPE", "CALL_USERMODE",
    "SYSTEM_UNBOUND", "SLIDE_NFULNL", "SLIDE_LOGGERS", "SLIDE_RANDOM",
    "SLIDE_SYSCTL", "SLIDE_INIT_TASK", "SLIDE_ROOT_TASK",
)
LAYOUT_PREFIXES = (
    "FAKE_", "FOPS_", "STRUCT_", "CFG_", "WQ_", "PWQ_", "POOL_", "WORK_",
    "PIPE_BUF", "SLIDE_WAITER", "SLIDE_LOCK", "SLIDE_BANK", "SLIDE_S928",
    "SLIDE_P0_OFFSET", "SLIDE_SYNC", "SLIDE_GUARD", "SLIDE_USE", "COMPACT_",
    "LOCK_OFF", "W0_OFF", "RIGHT_OFF", "LEFT_OFF", "SCRATCH_OFF", "ROOT_UMH",
    "MM_STRUCT", "SLIDE_RB", "P0_ORACLE_GATE", "P0_ORACLE_PROD",
)
SLIDE_PREFIXES = ("SLIDE_", "P0_ORACLE")
FLAG_PREFIXES = ("APP_", "KERNELSNITCH_", "S918_", "MM_")


def category(name):
    if name.startswith(("TARGET_GUARD", "BUILD_", "EXACT_", "APP_REQUIRE",
                        "P0_FINGERPRINT_HEADER")):
        return "identity"
    if name.startswith(PHYSICAL_PREFIXES):
        return "physical"
    if name.startswith(SYMBOL_PREFIXES):
        return "symbol"
    if name.startswith(LAYOUT_PREFIXES):
        return "layout"
    if name.startswith(SLIDE_PREFIXES):
        return "slide"
    if name.startswith(FLAG_PREFIXES):
        return "flag"
    return "other"


def flatten(paths):
    out = {}
    for path in paths:
        text = re.sub(r'\\\n', ' ', Path(path).read_text())
        for line in text.splitlines():
            match = UNDEF.match(line)
            if match:
                out.pop(match.group(1), None)
                continue
            match = DEFINE.match(line)
            if not match:
                continue
            name, value = match.group(1), match.group(2).strip()
            if GUARD.match(name) or "(" in name:
                continue
            out[name] = {"raw": value, "src": Path(path).name}
    return out


def normalize(value):
    text = value.strip().strip('"')
    text = re.sub(r'(ULL|UL|LL)$', '', text, flags=re.I).strip()
    if re.fullmatch(r'-?0[xX][0-9a-fA-F]+', text):
        return ("num", int(text, 16), text.lower())
    if re.fullmatch(r'-?\d+', text):
        return ("num", int(text), text)
    return ("expr", None, text)


def compare(left, right):
    same, differ, left_only, right_only = [], [], [], []
    for name in sorted(set(left) | set(right)):
        if name not in right:
            left_only.append(name)
        elif name not in left:
            right_only.append(name)
        elif normalize(left[name]["raw"])[:2] == normalize(right[name]["raw"])[:2]:
            same.append(name)
        else:
            differ.append((name, normalize(left[name]["raw"]),
                           normalize(right[name]["raw"])))
    return same, differ, left_only, right_only


def render(left_paths, right_paths, label, left_name, right_name, clusters):
    left, right = flatten(left_paths), flatten(right_paths)
    same, differ, left_only, right_only = compare(left, right)
    out = [f"# {label}", "",
           f"same={len(same)} differ={len(differ)} "
           f"{left_name}-only={len(left_only)} {right_name}-only={len(right_only)}", "",
           f"| cat | macro | {left_name} | {right_name} | delta |",
           "|---|---|---|---|---:|"]
    for name, lhs, rhs in sorted(differ, key=lambda row: (category(row[0]), row[0])):
        if lhs[0] == "num" and rhs[0] == "num":
            delta = rhs[1] - lhs[1]
            delta_text = f"{delta:+#x}" if delta else "0"
        else:
            delta_text = "expr/string"
        out.append(f"| {category(name)} | {name} | {lhs[2]} | {rhs[2]} | {delta_text} |")
    out += ["", f"## only in {left_name}", "", ", ".join(left_only) or "(none)", "",
            f"## only in {right_name}", "", ", ".join(right_only) or "(none)", ""]

    if clusters and differ:
        grouped = {}
        for name, lhs, rhs in differ:
            if lhs[0] == "num" and rhs[0] == "num":
                grouped.setdefault(category(name), Counter())[rhs[1] - lhs[1]] += 1
        out += ["## delta clusters", "",
                "A cluster is a group of entries that move by the same amount, which",
                "means they sit in one linker section and one block moved. Verify the",
                "cluster against the new Image instead of trusting each member.", ""]
        for cat in sorted(grouped):
            counted = grouped[cat]
            for delta, count in counted.most_common():
                out.append(f"- {cat}: {delta:+#x} x{count}")
        out.append("")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", action="append", required=True, metavar="HEADER",
                        help="left-side header; repeat for layout + target")
    parser.add_argument("--b", action="append", required=True, metavar="HEADER",
                        help="right-side header; repeat for layout + target")
    parser.add_argument("--label", default="A->B")
    parser.add_argument("--left-name", default="A")
    parser.add_argument("--right-name", default="B")
    parser.add_argument("--clusters", action="store_true",
                        help="also group differing rows by identical numeric delta")
    parser.add_argument("--out", metavar="FILE", help="write markdown here instead of stdout")
    args = parser.parse_args()

    markdown = render(args.a, args.b, args.label,
                      args.left_name, args.right_name, args.clusters)
    if args.out:
        Path(args.out).write_text(markdown + "\n")
    else:
        print(markdown)


if __name__ == "__main__":
    main()
