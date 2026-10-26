Live values read without root
=============================

Device: SM-S928B, S928BXXU6EZIF, Android 17. Every command below ran in an
ordinary `adb shell` (uid 2000, no su). This is the whole set of port inputs that
can be closed before downloading firmware; everything else needs the Image.

Identity
--------

  $ getprop ro.product.model                 SM-S928B
  $ getprop ro.product.device                e3q
  $ getprop ro.build.display.id              CP2A.260605.016.S928BXXU6EZIF
  $ getprop ro.build.version.release         17
  $ getprop ro.build.version.sdk             37
  $ getprop ro.build.version.security_patch  2026-09-05
  $ uname -r
  6.1.162-android14-11-34343818-abS928BXXU6EZIF
  $ uname -m
  aarch64

  $ getprop ro.build.fingerprint
  samsung/e3qxins/e3q:17/CP2A.260605.016/S928BXXU6EZIF:user/release-keys

The build id 34343818 is the same integer as the SM-S928N profile this port
started from; only the model segment and the kernel localversion suffix differ.
That is what makes a symbol-level port plausible instead of a from-scratch port.
It is also not proof of identical text layout, which is why the Image is still
required.

memstart_addr
-------------

  $ grep -A2 "zone   Normal" /proc/zoneinfo
  Node 0, zone   Normal
          spanned  11004192
          present  2923738
          managed  2709645
    ...
    start_pfn:           530144

530144 * 4096 = 0x816e0000, which is the value p0_data_alias() needs. Read
again in a later session: same value. `spanned` is much larger than `present`,
so the physical map is sparse.

The hierarchy is worth recording, because an empty zone still exists:

  Node 0, zone    DMA32   spanned 0  present 0  managed 0
  Node 0, zone   Normal   spanned 11004192  present 2923738
  Node 0, zone  Movable   spanned 0  present 0
  Node 0, zone   Device   spanned 0  present 0

There are no DMA32 pages on this device, so DMA32-specific address handling is
dead weight here even though the zone object is present in /proc/zoneinfo.

Kernel configuration
--------------------

  $ zcat /proc/config.gz | grep -E 'ARM64_(VA|PA)_BITS|RANDOMIZE|MODVERSIONS|TRIM_UNUSED|ASHMEM|KALLSYMS'

  CONFIG_KALLSYMS=y
  CONFIG_KALLSYMS_ALL=y
  CONFIG_KALLSYMS_BASE_RELATIVE=y
  CONFIG_ARM64_VA_BITS=39
  CONFIG_ARM64_PA_BITS=48
  CONFIG_RANDOMIZE_BASE=y
  # CONFIG_RANDOMIZE_MODULE_REGION_FULL is not set
  # CONFIG_MODULE_FORCE_LOAD is not set
  CONFIG_MODVERSIONS=y
  CONFIG_TRIM_UNUSED_KSYMS=y
  CONFIG_ASHMEM=y

VA_BITS 39 fixes the linear-map window at 0xffffff8000000000, and KALLSYMS_ALL
means a module can be linked against every exported symbol the loader needs.
MODVERSIONS plus TRIM_UNUSED_KSYMS is the combination that forces a matching
Module.symvers or the manual-relocation build described in docs/PORT-STATUS.md.

Tracefs
-------

  $ cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id
  106

  $ ls -l /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw
  -r--r----- 1 root readtracefs ... trace_pipe_raw

The shell user is in group 3012(readtracefs), so the raw ring buffer is readable
without root. There is no global trace_pipe_raw on this kernel; reads must go
through per_cpu/cpuN/.

Pipe buffer budget
------------------

The reclaim stage sizes its pipes with `F_SETPIPE_SZ`, which is refused with
`EPERM` once the calling uid is over its per-uid pipe-page budget. For uid 2000
on a clean boot the largest accepted size lands between 16,352 and 16,368 pages,
measured by walking `F_SETPIPE_SZ` upward over one pipe from a shell-uid probe.
The route needs 240 drain plus 240 reclaim pipes at 32 slots, so 15,360 pages: it
fits, with about six percent to spare.

`EPERM` there is therefore not a firmware cap. The failure seen on the reference
handset came from a `cve43499-p0ref` reference keeper left behind by an earlier
run: it was days old, had 960 open pipe fds (about 8,160 pages) and kept them
because it was spawned on the retention path, which holds every reclaim and
gate-holder fd alive. Half the budget was already spent before the next run
began. Look for it with

  $ ps -A -o PID,NAME | grep cve43499
  $ ls /proc/<pid>/fd | wc -l

and kill the stale keeper before reading anything into the `EPERM`.

Not recorded here: device serial, adb transport, boot_id, and the KASLR slide of
any particular boot.
