#include <linux/fs.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "setuid_hook.h"

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC 0x1cd1
#endif

extern int ksu_handle_devpts(struct inode *inode);

static int ksu_inode_permission(struct inode *inode, int mask)
{
	if (inode && inode->i_sb && inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC) {
		ksu_handle_devpts(inode);
	}
	return 0;
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	kuid_t new_uid = new->uid;
	kuid_t new_euid = new->euid;
	return ksu_handle_setresuid((uid_t)new_uid.val, (uid_t)new_euid.val,
				    (uid_t)new_uid.val);
}

static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(inode_permission, ksu_inode_permission),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
static const struct lsm_id ksu_lsmid = {
	.name = "ksu",
	.id = 912,
};
#endif

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
}
