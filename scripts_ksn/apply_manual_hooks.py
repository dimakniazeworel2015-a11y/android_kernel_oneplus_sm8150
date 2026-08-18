#!/usr/bin/env python3
"""Inject KernelSU-Next manual syscall-hook call sites into a 4.14 kernel tree.

Targets LineageOS android_kernel_oneplus_sm8150 lineage-23.0 (4.14.356), which
lacks the ksu_handle_* call sites required when KernelSU-Next is built WITHOUT
kprobes (CONFIG_KSU_WITH_KPROBES off). Idempotent + hard-asserted: if an anchor
is missing the script exits non-zero so the build fails loudly instead of
silently shipping a rootless kernel.

Usage: apply_manual_hooks.py <kernel_root>
Hooks: fs/exec.c (do_execve), fs/open.c (faccessat), fs/read_write.c (read),
       fs/stat.c (newfstatat). The generic ksu_handle_execveat (ksu.c) drives
       both the sucompat and ksud execve handlers.
"""
import os
import sys


def patch(path, marker, transform, label):
    with open(path) as fh:
        src = fh.read()
    if marker in src:
        print("%s already hooked" % label)
        return
    new = transform(src)
    with open(path, "w") as fh:
        fh.write(new)
    print("%s hooked" % label)


def hook_exec(kroot):
    p = os.path.join(kroot, "fs/exec.c")

    def t(s):
        decl = (
            "#ifdef CONFIG_KSU\n"
            "__attribute__((hot))\n"
            "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
            "\t\t\tvoid *argv, void *envp, int *flags);\n"
            "#endif\n\n"
        )
        anchor = "int do_execve(struct filename *filename,"
        assert anchor in s, "exec.c: do_execve anchor not found"
        s = s.replace(anchor, decl + anchor, 1)
        # insert the call right after envp is set up inside do_execve
        old = "\tstruct user_arg_ptr envp = { .ptr.native = __envp };\n"
        call = (
            old
            + "#ifdef CONFIG_KSU\n"
            + "\tksu_handle_execveat(&(int){AT_FDCWD}, &filename, &argv, &envp, NULL);\n"
            + "#endif\n"
        )
        i = s.index("int do_execve(struct filename *filename,")
        j = s.index(old, i)
        return s[:j] + call + s[j + len(old):]

    patch(p, "ksu_handle_execveat", t, "fs/exec.c")


def hook_open(kroot):
    p = os.path.join(kroot, "fs/open.c")

    def t(s):
        decl = (
            "#ifdef CONFIG_KSU\n"
            "__attribute__((hot))\n"
            "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n"
            "\t\t\tint *mode, int *flags);\n"
            "#endif\n\n"
        )
        anchor = "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{\n"
        assert anchor in s, "open.c: faccessat anchor not found"
        call = anchor + (
            "#ifdef CONFIG_KSU\n"
            "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
            "#endif\n"
        )
        return s.replace(anchor, decl + call, 1)

    patch(p, "ksu_handle_faccessat", t, "fs/open.c")


def hook_read(kroot):
    p = os.path.join(kroot, "fs/read_write.c")

    def t(s):
        decl = (
            "#ifdef CONFIG_KSU\n"
            "extern bool ksu_vfs_read_hook __read_mostly;\n"
            "extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,\n"
            "\t\t\tchar __user **buf_ptr, size_t *count_ptr);\n"
            "#endif\n\n"
        )
        anchor = "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n"
        assert anchor in s, "read_write.c: read anchor not found"
        s = s.replace(anchor, decl + anchor, 1)
        # insert after the first "ssize_t ret = -EBADF;" following the read syscall
        i = s.index("SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)")
        mark = "\tssize_t ret = -EBADF;\n"
        j = s.index(mark, i)
        call = (
            "#ifdef CONFIG_KSU\n"
            "\tif (unlikely(ksu_vfs_read_hook))\n"
            "\t\tksu_handle_sys_read(fd, &buf, &count);\n"
            "#endif\n"
        )
        return s[: j + len(mark)] + call + s[j + len(mark):]

    patch(p, "ksu_handle_sys_read", t, "fs/read_write.c")


def hook_stat(kroot):
    p = os.path.join(kroot, "fs/stat.c")

    def t(s):
        decl = (
            "#ifdef CONFIG_KSU\n"
            "__attribute__((hot))\n"
            "extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);\n"
            "#endif\n\n"
        )
        anchor = (
            "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n"
            "\t\tstruct stat __user *, statbuf, int, flag)\n{\n"
        )
        assert anchor in s, "stat.c: newfstatat anchor not found"
        call = anchor + (
            "#ifdef CONFIG_KSU\n"
            "\tksu_handle_stat(&dfd, &filename, &flag);\n"
            "#endif\n"
        )
        return s.replace(anchor, decl + call, 1)

    patch(p, "ksu_handle_stat", t, "fs/stat.c")


def main():
    kroot = sys.argv[1] if len(sys.argv) > 1 else "."
    hook_exec(kroot)
    hook_open(kroot)
    hook_read(kroot)
    hook_stat(kroot)

    # verify every hook landed
    checks = [
        ("fs/exec.c", "ksu_handle_execveat"),
        ("fs/open.c", "ksu_handle_faccessat"),
        ("fs/read_write.c", "ksu_handle_sys_read"),
        ("fs/stat.c", "ksu_handle_stat"),
    ]
    for rel, sym in checks:
        with open(os.path.join(kroot, rel)) as fh:
            if sym not in fh.read():
                sys.exit("FATAL: %s hook (%s) not applied" % (rel, sym))
    print("all manual hooks applied OK")


if __name__ == "__main__":
    main()
