#!/usr/bin/env python3
"""Port selinux_hide into the FLAT KernelSU-Next v1.0.6 tree with a POST-BOOT
deferred enable.

- Copies selinux_hide.c/.h (already committed in the repo) into
  KernelSU-Next/kernel/.
- Adds selinux_hide.o to the flat kernelsu-objs Makefile list.
- Includes selinux_hide.h in core_hook.c and calls
  ksu_selinux_hide_enable_deferred() from the EVENT_BOOT_COMPLETED branch
  (post-boot, NOT during early kernel init — early init was the hang suspect).

Usage: port_selinux_hide.py <kernel_root> <repo_root>
"""
import os
import sys


def main():
    kroot = sys.argv[1]
    repo = sys.argv[2]
    kdir = os.path.join(kroot, "KernelSU-Next", "kernel")

    src_c = os.path.join(repo, "selinux_hide.c")
    src_h = os.path.join(repo, "selinux_hide.h")
    for f in (src_c, src_h):
        if not os.path.isfile(f):
            sys.exit("FATAL: %s not committed in repo" % f)

    for name in ("selinux_hide.c", "selinux_hide.h"):
        with open(os.path.join(repo, name)) as r:
            data = r.read()
        with open(os.path.join(kdir, name), "w") as w:
            w.write(data)
    print("copied selinux_hide.c/.h into flat tree")

    # ---- Makefile: add selinux_hide.o after core_hook.o ----
    mk = os.path.join(kdir, "Makefile")
    with open(mk) as fh:
        s = fh.read()
    if "selinux_hide.o" not in s:
        anchor = "kernelsu-objs += core_hook.o"
        assert anchor in s, "Makefile: core_hook.o anchor not found"
        s = s.replace(anchor, anchor + "\nkernelsu-objs += selinux_hide.o", 1)
        with open(mk, "w") as fh:
            fh.write(s)
    if "selinux_hide.o" not in open(mk).read():
        sys.exit("FATAL: selinux_hide.o not added to Makefile")
    print("selinux_hide.o added to Makefile")

    # ---- core_hook.c: include + deferred call in EVENT_BOOT_COMPLETED ----
    ch = os.path.join(kdir, "core_hook.c")
    with open(ch) as fh:
        s = fh.read()
    if "ksu_selinux_hide_enable_deferred" not in s:
        inc_anchor = '#include "selinux/selinux.h"'
        assert inc_anchor in s, "core_hook.c: selinux.h include anchor not found"
        s = s.replace(inc_anchor, inc_anchor + '\n#include "selinux_hide.h"', 1)

        boot_anchor = '\t\t\t\tpr_info("boot_complete triggered\\n");\n'
        assert boot_anchor in s, "core_hook.c: boot_complete anchor not found"
        s = s.replace(
            boot_anchor,
            boot_anchor + "\t\t\t\tksu_selinux_hide_enable_deferred();\n",
            1,
        )
        with open(ch, "w") as fh:
            fh.write(s)
    if "ksu_selinux_hide_enable_deferred" not in open(ch).read():
        sys.exit("FATAL: deferred enable not wired into core_hook.c")
    print("deferred selinux_hide wired into EVENT_BOOT_COMPLETED (post-boot)")


if __name__ == "__main__":
    main()
