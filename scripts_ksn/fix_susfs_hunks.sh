#!/bin/bash
# Fix the 3 hunks of susfs4ksu 10_enable_susfs_for_ksu.patch that REJECT on
# KernelSU-Next v1.0.6 (upstream-KSU macros EXPECTED_SIZE/HASH were renamed to
# EXPECTED_NEXT_SIZE/HASH and core_hook.c was restructured).
# Recipe verified end-to-end against KSU-Next tag v1.0.6 by the port agent.
# Run AFTER `patch ... 10_enable_susfs_for_ksu.patch || true`.
# Arg $1 = path to the KernelSU-Next dir (contains kernel/apk_sign.c, kernel/core_hook.c).
set -eu
KSU="${1:-KernelSU-Next}"
cd "$KSU"
echo "== fix_susfs_hunks in $(pwd) =="
rm -f kernel/*.rej kernel/*.orig

# ---------------- Fix 1: kernel/apk_sign.c (Hunk #1) ----------------
# rename is_manager_apk -> ksu_is_manager_apk and add the susfs manager signature.
perl -i -pe '
  s{^bool is_manager_apk\(char \*path\)}{bool ksu_is_manager_apk(char *path)};
  if (/^\treturn check_v2_signature\(path, EXPECTED_NEXT_SIZE, EXPECTED_NEXT_HASH\);$/) {
    $_ = "#ifdef CONFIG_KSU_SUSFS\n"
       . "\treturn (check_v2_signature(path, EXPECTED_NEXT_SIZE, EXPECTED_NEXT_HASH) ||\n"
       . "\t\t\tcheck_v2_signature(path, 384, \"7e0c6d7278a3bb8e364e0fcba95afaf3666cf5ff3c245a3b63c8833bd0445cc4\")); // 5ec1cff\n"
       . "#else\n"
       . "\treturn check_v2_signature(path, EXPECTED_NEXT_SIZE, EXPECTED_NEXT_HASH);\n"
       . "#endif\n";
  }
' kernel/apk_sign.c

# ---------------- Fix 2: kernel/core_hook.c (Hunk #2) ----------------
# insert susfs helper/extern block before ksu_module_mounted; rename
# handle_sepolicy -> ksu_handle_sepolicy and is_manager() -> ksu_is_manager().
cat > /tmp/susfs_block.txt <<'BLOCK'
#ifdef CONFIG_KSU_SUSFS
bool susfs_is_allow_su(void)
{
	if (ksu_is_manager()) {
		// we are manager, allow!
		return true;
	}
	return ksu_is_allow_uid(current_uid().val);
}

extern u32 susfs_zygote_sid;
extern bool susfs_is_mnt_devname_ksu(struct path *path);
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
extern bool susfs_is_log_enabled __read_mostly;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern void susfs_run_try_umount_for_current_mnt_ns(void);
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static bool susfs_is_umount_for_zygote_system_process_enabled = false;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
extern bool susfs_is_auto_add_sus_bind_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
extern bool susfs_is_auto_add_sus_ksu_default_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
extern bool susfs_is_auto_add_try_umount_for_bind_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT

static inline void susfs_on_post_fs_data(void) {
	struct path path;
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (!kern_path(DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS, 0, &path)) {
		susfs_is_umount_for_zygote_system_process_enabled = true;
		path_put(&path);
	}
	pr_info("susfs_is_umount_for_zygote_system_process_enabled: %d\n", susfs_is_umount_for_zygote_system_process_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_bind_mount_enabled: %d\n", susfs_is_auto_add_sus_bind_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_ksu_default_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_ksu_default_mount_enabled: %d\n", susfs_is_auto_add_sus_ksu_default_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_try_umount_for_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_try_umount_for_bind_mount_enabled: %d\n", susfs_is_auto_add_try_umount_for_bind_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
}

#endif // #ifdef CONFIG_KSU_SUSFS

BLOCK

awk -v blockfile="/tmp/susfs_block.txt" '
  BEGIN { done=0 }
  /^static bool ksu_module_mounted = false;\r?$/ && !done {
    while ((getline line < blockfile) > 0) print line; close(blockfile); done=1;
  }
  { print }
' kernel/core_hook.c > /tmp/ch1.c && mv /tmp/ch1.c kernel/core_hook.c

sed -i 's/^extern int handle_sepolicy(unsigned long arg3, void __user \*arg4);/extern int ksu_handle_sepolicy(unsigned long arg3, void __user *arg4);/' kernel/core_hook.c
sed -i 's/^\tif (is_manager()) {/\tif (ksu_is_manager()) {/' kernel/core_hook.c

# ---------------- Fix 3: kernel/core_hook.c (Hunk #16) ----------------
# rewrite the umount tail: guard zygote check with #ifndef SUS_MOUNT, rename
# is_zygote -> ksu_is_zygote, wrap umount list in susfs_try_umount_all / ksu_try_umount.
cat > /tmp/umount_block.txt <<'BLOCK'
#ifndef CONFIG_KSU_SUSFS_SUS_MOUNT
	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	bool is_zygote_child = ksu_is_zygote(old->security);
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n",
			current->pid);
		return 0;
	}
#endif
#ifdef CONFIG_KSU_DEBUG
	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid.val,
		current->pid);
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	// susfs come first, and lastly umount by ksu, make sure umount in reversed order
	susfs_try_umount_all(new_uid.val);
#else
	// fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
	// filter the mountpoint whose target is `/data/adb`
	ksu_try_umount("/system", true, 0);
	ksu_try_umount("/system_ext", true, 0);
	ksu_try_umount("/vendor", true, 0);
	ksu_try_umount("/product", true, 0);
	ksu_try_umount("/data/adb/modules", false, MNT_DETACH);

	// try umount ksu temp path
	ksu_try_umount("/debug_ramdisk", false, MNT_DETACH);
	ksu_try_umount("/sbin", false, MNT_DETACH);

	// try umount hosts file
	ksu_try_umount("/system/etc/hosts", false, MNT_DETACH);

	// try umount lsposed dex2oat bins
	ksu_try_umount("/apex/com.android.art/bin/dex2oat64", false, MNT_DETACH);
	ksu_try_umount("/apex/com.android.art/bin/dex2oat32", false, MNT_DETACH);
#endif
BLOCK

awk -v blockfile="/tmp/umount_block.txt" '
  BEGIN { inrange=0; done=0 }
  !done && /^\t\/\/ check old process.s selinux context, if it is not zygote, ignore it!\r?$/ {
    inrange=1; while ((getline line < blockfile) > 0) print line; close(blockfile); next;
  }
  inrange {
    if ($0 ~ /^\ttry_umount\("\/apex\/com\.android\.art\/bin\/dex2oat32", false, MNT_DETACH\);\r?$/) { inrange=0; done=1; }
    next;
  }
  { print }
' kernel/core_hook.c > /tmp/ch2.c && mv /tmp/ch2.c kernel/core_hook.c

rm -f kernel/*.rej kernel/*.orig

# ---------------- sanity gate (informative; the compile is the real gate) ----------------
echo "== sanity gate =="
FAIL=0
if grep -nE '(^|[^_])is_manager_apk' kernel/apk_sign.c | grep -v ksu_is_manager_apk; then echo "WARN: bare is_manager_apk remains"; FAIL=1; fi
if grep -nE '(^|[^a-z_])try_umount\(' kernel/core_hook.c | grep -vE 'ksu_try_umount|susfs_try_umount|should_umount'; then echo "WARN: bare try_umount remains"; FAIL=1; fi
if grep -nE '(^|[^_])is_zygote\(' kernel/core_hook.c | grep -v ksu_is_zygote; then echo "WARN: bare is_zygote remains"; FAIL=1; fi
if grep -q 'extern int handle_sepolicy' kernel/core_hook.c; then echo "WARN: bare extern handle_sepolicy remains"; FAIL=1; fi
grep -q 'bool susfs_is_allow_su(void)' kernel/core_hook.c || { echo "FATAL: susfs_is_allow_su not inserted"; exit 1; }
grep -q 'static inline void susfs_on_post_fs_data' kernel/core_hook.c || { echo "FATAL: susfs_on_post_fs_data not inserted"; exit 1; }
grep -q 'bool ksu_is_manager_apk(char \*path)' kernel/apk_sign.c || { echo "FATAL: ksu_is_manager_apk rename failed"; exit 1; }
echo "sanity gate FAIL=$FAIL (0 = clean)"
echo "== fix_susfs_hunks DONE =="
