#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

#include <linux/types.h>

/*
 * KernelSU-Next selinux_hide — FLAT v1.0.6 port (hotdogb / SM8150, 4.14.356).
 *
 * This is a stripped, deferred-enable port of the legacy modular
 * kernel/feature/selinux_hide.c. It keeps ONLY the SELinux-oracle defeat:
 * a fake /sys/fs/selinux/status page + a patched sel_handle_status_ops->open.
 * The modular init-thread, the ksu_input_hook wait, the feature-handler
 * framework and the avc-audit kprobe are all removed.
 *
 * ksu_selinux_hide_enable_deferred() is meant to be called POST-BOOT
 * (from the EVENT_BOOT_COMPLETED path in core_hook.c), never during early
 * kernel init. It is idempotent and safe to call more than once.
 */
void ksu_selinux_hide_enable_deferred(void);

#endif
