// SPDX-License-Identifier: GPL-2.0
/*
 * KernelSU-Next selinux_hide — FLAT v1.0.6 port for hotdogb (SM8150, 4.14.356).
 *
 * Ported from the legacy modular kernel/feature/selinux_hide.c. Keeps ONLY the
 * SELinux-status oracle defeat (fake /sys/fs/selinux/status page + patched
 * sel_handle_status_ops->open). Everything that needed the modular tree was
 * removed:
 *   - the ksu_feature_handler framework (register/unregister/get/set)
 *   - the ksu_input_hook busy-wait + kthread init-thread
 *   - the slow_avc_audit kprobe (KPROBES is OFF on this device)
 *   - ksu_late_loaded (does not exist in the flat tree)
 *
 * Enable is DEFERRED to post-boot: ksu_selinux_hide_enable_deferred() is called
 * from EVENT_BOOT_COMPLETED in core_hook.c, well after early init. It never runs
 * during kernel bring-up (early init was the hang suspect). Idempotent.
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include <asm/set_memory.h>
#else
#include <asm/cacheflush.h>
#endif
#include <linux/namei.h>
#include <linux/vmalloc.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/dcache.h>
#include <asm/page.h>

#include "klog.h" // IWYU pragma: keep
#include "selinux/selinux.h"
#include "selinux_hide.h"

/*
 * objsec.h (on the include path via the flat KSU Makefile,
 * -I$(srctree)/security/selinux/include) transitively pulls in the kernel's
 * security/selinux/include/security.h, which declares BOTH
 * `struct selinux_kernel_status` and, on this LineageOS 4.14.356 tree,
 * `struct selinux_state` + `selinux_kernel_status_page(struct selinux_state *)`.
 * This is exactly how the flat KSU selinux.c obtains them, so the ABI matches.
 */
#include "objsec.h"

/*
 * On this tree security.h defines `struct selinux_state`, so the flat Makefile
 * emits -DKSU_COMPAT_HAS_SELINUX_STATE and selinux.h then defines
 * KSU_COMPAT_USE_SELINUX_STATE -> selinux_kernel_status_page takes &selinux_state.
 * We keep both arms for portability across trees.
 */
#ifdef KSU_COMPAT_USE_SELINUX_STATE
extern struct selinux_state selinux_state;
#endif

static struct page *fake_status = NULL;
static DEFINE_MUTEX(fake_status_init_mutex);

/* userspace toggle; default on once the deferred enable fires */
static bool ksu_selinux_hide_is_enabled __read_mostly = true;

static void initialize_fake_status(void)
{
	struct page *real_page;
	struct selinux_kernel_status *status;
	struct page *new_page;
	struct selinux_kernel_status *new_status;

	if (READ_ONCE(fake_status))
		return;

	mutex_lock(&fake_status_init_mutex);
	if (fake_status) /* double-check after lock */
		goto out;

#ifdef KSU_COMPAT_USE_SELINUX_STATE
	real_page = selinux_kernel_status_page(&selinux_state);
#else
	real_page = selinux_kernel_status_page();
#endif
	if (!real_page) {
		pr_warn("ksu_selinux_hide: status_page not exists\n");
		goto out;
	}

	status = page_address(real_page);
	if (!status->enforcing) {
		/* only meaningful to fake a value when SELinux is enforcing */
		pr_warn("ksu_selinux_hide: skip, not enforcing\n");
		goto out;
	}

	new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!new_page) {
		pr_err("ksu_selinux_hide: failed to allocate fake status page\n");
		goto out;
	}

	new_status = page_address(new_page);
	memcpy(new_status, status, sizeof(*status));

	WRITE_ONCE(fake_status, new_page);
	pr_info("ksu_selinux_hide: fake status ready: sequence=%d policyload=%d enforcing=%d\n",
		new_status->sequence, new_status->policyload,
		new_status->enforcing);
out:
	mutex_unlock(&fake_status_init_mutex);
}

typedef int (*sel_open_handle_status_fn)(struct inode *inode,
					 struct file *filp);
static sel_open_handle_status_fn orig_sel_open_handle_status = NULL;

static int __nocfi my_sel_open_handle_status(struct inode *inode,
					     struct file *filp)
{
	if (likely(test_thread_flag(TIF_SECCOMP) &&
		   current_uid().val >= 10000 &&
		   ksu_selinux_hide_is_enabled)) {
		struct page *data = READ_ONCE(fake_status);
		if (data) {
			filp->private_data = page_address(data);
			return 0;
		}
	}

	return orig_sel_open_handle_status(inode, filp);
}

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

static int patch_fops_open(struct file_operations *ops,
			   sel_open_handle_status_fn new_open)
{
	unsigned long addr = (unsigned long)&ops->open;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK;
	struct page *page = phys_to_page(__pa(base));
	void *writable_addr;
	void **target_slot;

	if (!page)
		return -EFAULT;

	writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return -ENOMEM;

	target_slot = (void **)((unsigned long)writable_addr + offset);

	preempt_disable();
	local_irq_disable();
	FORCE_VOLATILE(*target_slot) = (void *)new_open;
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();
	return 0;
}

static int resolve_fops(const char *path_str, struct file_operations **out_fops)
{
	struct path path;
	int error = kern_path(path_str, LOOKUP_FOLLOW, &path);
	int ret = -ENOENT;

	if (error) {
		pr_err("ksu_selinux_hide: kern_path(%s) failed: %d\n", path_str,
		       error);
		return error;
	}

	if (!path.dentry || !d_inode(path.dentry))
		goto out;

	*out_fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
	if (!*out_fops)
		goto out;

	ret = 0;
out:
	path_put(&path);
	return ret;
}

static void hook_selinux_status_open(void)
{
	struct file_operations *ops = NULL;

	if (orig_sel_open_handle_status)
		return;

	if (resolve_fops("/sys/fs/selinux/status", &ops)) {
		pr_err("ksu_selinux_hide: sel_handle_status_ops not found, fake status disabled\n");
		return;
	}

	if (!ops->open) {
		pr_err("ksu_selinux_hide: sel_handle_status_ops->open is NULL\n");
		return;
	}

	orig_sel_open_handle_status = ops->open;
	patch_fops_open(ops, my_sel_open_handle_status);
	pr_info("ksu_selinux_hide: hooked sel_handle_status_ops->open\n");
}

/*
 * POST-BOOT entry point. Called once from EVENT_BOOT_COMPLETED in core_hook.c.
 * Builds the fake status page and patches the fops. Never runs during early
 * kernel init. Idempotent: guarded by fake_status / orig_sel_open_handle_status.
 */
void ksu_selinux_hide_enable_deferred(void)
{
	static bool done = false;

	if (done)
		return;

	if (!ksu_selinux_hide_is_enabled)
		return;

	initialize_fake_status();
	if (!READ_ONCE(fake_status)) {
		pr_warn("ksu_selinux_hide: fake status not ready, will retry on next event\n");
		return;
	}

	hook_selinux_status_open();
	done = true;
	pr_info("ksu_selinux_hide: deferred enable complete\n");
}
