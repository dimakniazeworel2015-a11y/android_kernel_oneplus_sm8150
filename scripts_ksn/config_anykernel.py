#!/usr/bin/env python3
"""Configure AnyKernel3 anykernel.sh to flash ONLY the kernel and PRESERVE the
device's dtb + dtbo.

Mechanism: AnyKernel3 falls back to the unpacked originals for any component NOT
shipped in the zip. We ship only Image.gz-dtb (dtb appended to the kernel) and
NO separate `dtb` file and NO `dtbo.img`, so the boot ramdisk keeps its original
dtb and the dtbo partition is left completely untouched. This directly targets
the dtb/dtbo-mismatch black-screen suspicion.

Target: OnePlus 7T hotdogb (SM8150, A/B) -> is_slot_device=1, boot by-name.

Usage: config_anykernel.py <anykernel.sh path>
"""
import re
import sys


def setkv(s, k, v):
    pat = re.compile(r'^%s=[^\n]*$' % re.escape(k), re.M)
    if pat.search(s):
        return pat.sub('%s=%s' % (k, v), s, count=1)
    return s


def main():
    f = sys.argv[1]
    with open(f) as fh:
        s = fh.read()

    s = setkv(s, "kernel.string",
              "OP7T hotdogb KSN flat v1.0.6 + SUSFS + selinux_hide")
    s = setkv(s, "do.devicecheck", "0")
    s = setkv(s, "do.modules", "0")
    s = setkv(s, "do.systemless", "0")
    s = setkv(s, "do.cleanup", "1")
    s = setkv(s, "do.cleanuponabort", "0")
    # install-config shell vars are UPPERCASE with a trailing ; in AnyKernel3.
    s = setkv(s, "BLOCK", "/dev/block/bootdevice/by-name/boot;")
    s = setkv(s, "IS_SLOT_DEVICE", "1;")
    s = setkv(s, "RAMDISK_COMPRESSION", "auto;")
    s = setkv(s, "PATCH_VBMETA_FLAG", "auto;")

    with open(f, "w") as fh:
        fh.write(s)
    print("anykernel.sh configured (kernel-only, preserve dtb/dtbo, A/B)")


if __name__ == "__main__":
    main()
