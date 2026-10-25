#!/bin/sh
# Verify SLIDE_TRACEFS_WORKER_CALLER_OFF against a live phone.
#
# Captures sched_blocked_reason from the raw tracefs ring buffer, pulls the pages
# and decodes them with tools/parse_raw.py.  The tracefs text view only prints
# `worker_thread+0xa0/0x430`; the raw pages carry the actual return address, and
# subtracting KIMAGE_TEXT_BASE must leave worker_off plus a 64 KiB multiple.
#
# This kernel has no global trace_pipe_raw; every read goes through per_cpu/.
#
# Requirements: adb, python3, and a shell user that can read tracefs (Samsung
# user builds put shell in the readtracefs group).
# Set ANDROID_SERIAL when more than one device is attached.
#
# usage: tools/verify-tracefs.sh [seconds] [image_base] [worker_off]
set -eu

seconds=${1:-4}
image_base=${2:-0xffffffc008000000}
worker_off=${3:-0x000db39c}
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'adb shell rm -rf /data/local/tmp/btrace; rm -rf "$work"' EXIT

adb shell "set -e
T=/sys/kernel/tracing
[ -d \"\$T/events/sched/sched_blocked_reason\" ] || T=/sys/kernel/debug/tracing
E=\$T/events/sched/sched_blocked_reason
rm -rf /data/local/tmp/btrace; mkdir -p /data/local/tmp/btrace
echo event_id=\$(cat \$E/id)
echo 0 > \$T/tracing_on
echo > \$T/trace
echo 1 > \$E/enable
echo 1 > \$T/tracing_on
for f in \$T/per_cpu/cpu*/trace_pipe_raw; do
    cpu=\$(basename \$(dirname \$f))
    timeout $seconds dd if=\$f of=/data/local/tmp/btrace/\$cpu.raw bs=4096 count=256 2>/dev/null &
done
wait
cp \$T/trace /data/local/tmp/btrace/trace.txt 2>/dev/null || true
echo 0 > \$T/tracing_on
echo 0 > \$E/enable
wc -l \$T/trace | awk '{print \"text_lines=\"\$1}'
"

adb shell 'for f in /data/local/tmp/btrace/cpu*.raw; do printf "%s %s\n" "$(basename $f)" "$(wc -c < $f)"; done'

for cpu in $(adb shell ls /data/local/tmp/btrace | tr -d '\r' | grep '^cpu[0-9]*\.raw$'); do
    adb pull "/data/local/tmp/btrace/$cpu" "$work/$cpu" >/dev/null 2>&1 || true
done
adb pull /data/local/tmp/btrace/trace.txt "$work/trace.txt" >/dev/null 2>&1 || true

if [ -n "$(ls "$work"/cpu*.raw 2>/dev/null)" ]; then
    echo
    echo "== raw callers =="
    python3 "$here/parse_raw.py" "$work"/cpu*.raw --base "$image_base" --worker-off "$worker_off"
else
    echo "no raw pages captured" >&2
fi

if [ -s "$work/trace.txt" ]; then
    echo
    echo "== text callers (names only, no address) =="
    grep -o 'caller=[^ ]*' "$work/trace.txt" | sort | uniq -c | sort -rn | head -12 || true
fi
